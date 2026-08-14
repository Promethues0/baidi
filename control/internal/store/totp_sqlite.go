package store

import (
	"context"
	"database/sql"
	"strings"
)

// TotpFor 某账号（规范化匹配）的 TOTP 密文行。
func (s *SQLiteStore) TotpFor(ctx context.Context, account string) (TotpRecord, bool, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	var rec TotpRecord
	rec.Account = key
	var confirmed int
	err := s.db.QueryRowContext(ctx,
		`SELECT nonce, cipher, confirmed, last_counter, created_at FROM totp_secrets WHERE account=?`,
		key).Scan(&rec.Nonce, &rec.Cipher, &confirmed, &rec.LastCounter, &rec.CreatedAt)
	if err == sql.ErrNoRows {
		return TotpRecord{}, false, nil
	}
	if err != nil {
		return TotpRecord{}, false, err
	}
	rec.Confirmed = confirmed == 1
	return rec, true, nil
}

// SaveTotpSecret 落一条新密钥（未确认态）。重复注册直接覆盖旧行并复位
// confirmed/last_counter——旧密钥立刻作废，不存在「两把都能验」的过渡态。
func (s *SQLiteStore) SaveTotpSecret(ctx context.Context, account string, nonce, cipher []byte) error {
	key := strings.ToLower(strings.TrimSpace(account))
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO totp_secrets(account,nonce,cipher,confirmed,last_counter,created_at) VALUES(?,?,?,0,0,?)
ON CONFLICT(account) DO UPDATE SET nonce=excluded.nonce, cipher=excluded.cipher,
  confirmed=0, last_counter=0, created_at=excluded.created_at`,
		key, nonce, cipher, nowStr())
	return err
}

// ConfirmTotp 确认注册转正。counter 是确认时消费的那个码的时间计数器——
// 必须一并落下：确认码本身也是用过的码，不落的话它在登录页还能再用一次。
func (s *SQLiteStore) ConfirmTotp(ctx context.Context, account string, counter uint64) error {
	key := strings.ToLower(strings.TrimSpace(account))
	_, err := s.db.ExecContext(ctx,
		`UPDATE totp_secrets SET confirmed=1, last_counter=? WHERE account=?`, counter, key)
	return err
}

// ConsumeTotpCounter 防重放执行点：只有 counter 严格大于已用过的最大计数器才成功，
// 且判定与更新是同一条 UPDATE（并发登录下也不会两次消费同一个码）。
// 返回 false = 该码已被用过（或行不存在/未确认）——调用方按验证失败处理。
func (s *SQLiteStore) ConsumeTotpCounter(ctx context.Context, account string, counter uint64) (bool, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	res, err := s.db.ExecContext(ctx,
		`UPDATE totp_secrets SET last_counter=? WHERE account=? AND confirmed=1 AND last_counter<?`,
		counter, key, counter)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteTotp 解绑。返回是否真的删了行（幂等：没注册过不算错）。
func (s *SQLiteStore) DeleteTotp(ctx context.Context, account string) (bool, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	res, err := s.db.ExecContext(ctx, `DELETE FROM totp_secrets WHERE account=?`, key)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
