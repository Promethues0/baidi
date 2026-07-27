package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"
)

const webauthnCredCols = `id,user_id,account,credential_id,public_key,sign_count,transports,aaguid,name,created_at,last_used_at`

func scanWebauthnCreds(rows *sql.Rows) ([]WebauthnCredential, error) {
	defer rows.Close()
	out := []WebauthnCredential{}
	for rows.Next() {
		var c WebauthnCredential
		if err := rows.Scan(&c.ID, &c.UserID, &c.Account, &c.CredentialID, &c.PublicKey, &c.SignCount,
			&c.Transports, &c.AAGUID, &c.Name, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// WebauthnCredentialsFor 某账号（规范化匹配）已注册的全部 passkey。
func (s *SQLiteStore) WebauthnCredentialsFor(ctx context.Context, account string) ([]WebauthnCredential, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	rows, err := s.db.QueryContext(ctx, `SELECT `+webauthnCredCols+` FROM webauthn_credentials WHERE account=? ORDER BY created_at`, key)
	if err != nil {
		return nil, err
	}
	return scanWebauthnCreds(rows)
}

// WebauthnCredentialByID 按 credentialID（base64url rawId）点查凭据，断言校验用。
func (s *SQLiteStore) WebauthnCredentialByID(ctx context.Context, credentialID string) (WebauthnCredential, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+webauthnCredCols+` FROM webauthn_credentials WHERE credential_id=? LIMIT 1`, credentialID)
	if err != nil {
		return WebauthnCredential{}, false, err
	}
	cs, err := scanWebauthnCreds(rows)
	if err != nil || len(cs) == 0 {
		return WebauthnCredential{}, false, err
	}
	return cs[0], true, nil
}

// WebauthnCredentialCount 某账号已注册凭据数（供"是否已启用 passkey"判定与删除守卫）。
func (s *SQLiteStore) WebauthnCredentialCount(ctx context.Context, account string) (int, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_credentials WHERE account=?`, key).Scan(&n)
	return n, err
}

// SaveWebauthnCredential 落库一条新注册凭据。credential_id 撞库 → ErrCredentialExists。
func (s *SQLiteStore) SaveWebauthnCredential(ctx context.Context, c WebauthnCredential) (WebauthnCredential, error) {
	c.Account = strings.ToLower(strings.TrimSpace(c.Account))
	if c.ID == "" {
		c.ID = "cred-" + uuid.NewString()[:8]
	}
	if c.Name == "" {
		c.Name = "passkey"
	}
	c.CreatedAt = nowStr()
	c.LastUsedAt = ""

	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_credentials WHERE credential_id=?`, c.CredentialID).Scan(&exists); err != nil {
		return WebauthnCredential{}, err
	}
	if exists > 0 {
		return WebauthnCredential{}, ErrCredentialExists
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO webauthn_credentials(`+webauthnCredCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,'')`,
		c.ID, c.UserID, c.Account, c.CredentialID, c.PublicKey, c.SignCount, c.Transports, c.AAGUID, c.Name, c.CreatedAt); err != nil {
		return WebauthnCredential{}, err
	}
	return c, nil
}

// DeleteWebauthnCredential 删除本人一条凭据（account 规范化匹配，杜绝跨账号删）。
// 守卫：账号最后一个 passkey 不许删——否则强制 2FA 下用户会把自己锁在门外。
func (s *SQLiteStore) DeleteWebauthnCredential(ctx context.Context, account, id string) error {
	key := strings.ToLower(strings.TrimSpace(account))
	n, err := s.WebauthnCredentialCount(ctx, key)
	if err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastCredential
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id=? AND account=?`, id, key)
	if err != nil {
		return err
	}
	if aff, _ := res.RowsAffected(); aff != 1 {
		return ErrCredentialNotFound
	}
	return nil
}

// UpdateSignCount 断言成功后更新签名计数器 + 最后使用时间，并做克隆检测。
//
// ★同步 passkey（iCloud 钥匙串 / Google 密码管理器）恒报 signCount=0，库存也是 0——
// 此时 `WHERE sign_count < 0` 永不命中，会把最常见的 passkey 误判成克隆。故：
// 仅当新计数 > 0 时才做单调校验；新计数为 0 一律视为"该认证器无计数器"，跳过校验只更新时间。
func (s *SQLiteStore) UpdateSignCount(ctx context.Context, credentialID string, newCount uint32) error {
	if newCount == 0 {
		_, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET last_used_at=? WHERE credential_id=?`, nowStr(), credentialID)
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count=?, last_used_at=? WHERE credential_id=? AND sign_count<?`,
		newCount, nowStr(), credentialID, newCount)
	if err != nil {
		return err
	}
	if aff, _ := res.RowsAffected(); aff != 1 {
		// 计数器未前进：凭据被克隆或断言被重放。
		return ErrSignCountRegression
	}
	return nil
}

// ── challenge：服务端生成、单次消费、短 TTL ──

// CreateWebauthnChallenge 落一条仪式 challenge（含 go-webauthn SessionData 快照）。
func (s *SQLiteStore) CreateWebauthnChallenge(ctx context.Context, ch WebauthnChallenge) (WebauthnChallenge, error) {
	ch.ID = "chal-" + uuid.NewString()[:8]
	ch.Account = strings.ToLower(strings.TrimSpace(ch.Account))
	ch.ExpiresAt = time.Now().Unix() + challengeTTL
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_challenges(id,account,challenge,type,session_data,expires_at,consumed) VALUES(?,?,?,?,?,?,0)`,
		ch.ID, ch.Account, ch.Challenge, ch.Type, ch.SessionData, ch.ExpiresAt)
	if err != nil {
		return WebauthnChallenge{}, err
	}
	return ch, nil
}

// ConsumeWebauthnChallenge 按 challenge 值 + 仪式类型单次消费。
//
// ★按值而非按 id 查：登录 finish 时浏览器只回 clientDataJSON（内含 challenge 字节），
// 拿不到我们的 chal-id。强制带 type 匹配，堵住"注册 challenge 拿去登录复用"的跨仪式重放。
// UPDATE…WHERE consumed=0 + RowsAffected!=1 实现原子单次消费（并发重放第二次必失败）。
func (s *SQLiteStore) ConsumeWebauthnChallenge(ctx context.Context, challenge, typ string) (WebauthnChallenge, error) {
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_challenges SET consumed=1 WHERE challenge=? AND type=? AND consumed=0 AND expires_at>?`,
		challenge, typ, now)
	if err != nil {
		return WebauthnChallenge{}, err
	}
	if aff, _ := res.RowsAffected(); aff != 1 {
		return WebauthnChallenge{}, ErrChallengeInvalid
	}
	var ch WebauthnChallenge
	err = s.db.QueryRowContext(ctx,
		`SELECT id,account,challenge,type,session_data,expires_at FROM webauthn_challenges WHERE challenge=? AND type=?`,
		challenge, typ).Scan(&ch.ID, &ch.Account, &ch.Challenge, &ch.Type, &ch.SessionData, &ch.ExpiresAt)
	if err != nil {
		return WebauthnChallenge{}, err
	}
	return ch, nil
}

// PurgeExpiredChallenges 清理过期/已消费的 challenge 行（登录 begin 免认证可被匿名刷，
// 不清理会无界堆积成 DoS 面）。返回删除行数，调用方 best-effort。
func (s *SQLiteStore) PurgeExpiredChallenges(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_challenges WHERE expires_at<? OR consumed=1`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
