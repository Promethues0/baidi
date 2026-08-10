package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const notifyChanCols = `id,name,kind,enabled,config,last_status,last_detail,last_event,last_at,created_at,updated_at`

func (s *SQLiteStore) scanNotifyChannel(row interface{ Scan(...any) error }) (NotifyChannel, error) {
	var r NotifyChannel
	var enabled int
	var lastStatus, lastDetail, lastEvent sql.NullString
	var lastAt sql.NullInt64
	err := row.Scan(&r.ID, &r.Name, &r.Kind, &enabled, &r.Config,
		&lastStatus, &lastDetail, &lastEvent, &lastAt, &r.CreatedAt, &r.UpdatedAt)
	r.Enabled = enabled != 0
	r.LastStatus, r.LastDetail, r.LastEvent, r.LastAt = lastStatus.String, lastDetail.String, lastEvent.String, lastAt.Int64
	return r, err
}

// NotifyChannels 返回全部消息通道（按创建时间）。响应里绝不含密文，只补元信息。
func (s *SQLiteStore) NotifyChannels(ctx context.Context) ([]NotifyChannel, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+notifyChanCols+` FROM notify_channels ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotifyChannel{}
	for rows.Next() {
		r, err := s.scanNotifyChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 凭据只补**存在性与指纹**，不与配置同表读——列表路径根本碰不到密文。
	for i := range out {
		has, fp, err := s.notifySecretMeta(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].HasSecret, out[i].SecretFingerprint = has, fp
	}
	return out, nil
}

func (s *SQLiteStore) NotifyChannelByID(ctx context.Context, id string) (NotifyChannel, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+notifyChanCols+` FROM notify_channels WHERE id=?`, id)
	r, err := s.scanNotifyChannel(row)
	if err == sql.ErrNoRows {
		return NotifyChannel{}, false, nil
	}
	if err != nil {
		return NotifyChannel{}, false, err
	}
	has, fp, err := s.notifySecretMeta(ctx, id)
	if err != nil {
		return NotifyChannel{}, false, err
	}
	r.HasSecret, r.SecretFingerprint = has, fp
	return r, true, nil
}

// SaveNotifyChannel 新增 / 修改一条通道（upsert）。
//
// ★ON CONFLICT 分支刻意**不含** created_at、不碰凭据表，也**不碰 last_* 四列**：
//   - 改一次配置就把凭据清掉，会让"改个显示名"变成"告警突然全发不出去"；
//   - 覆盖 last_*（哪怕只是清空）等于让保存动作伪造一次"发送状态"，
//     而那四列的全部意义就是"数据面真正发出去那一次的结果"。
func (s *SQLiteStore) SaveNotifyChannel(ctx context.Context, rec NotifyChannel) (NotifyChannel, error) {
	if strings.TrimSpace(rec.ID) == "" {
		rec.ID = "nc-" + uuid.NewString()[:8]
	}
	if strings.TrimSpace(rec.Config) == "" {
		rec.Config = "{}"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO notify_channels(`+notifyChanCols+`)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind,
  enabled=excluded.enabled, config=excluded.config, updated_at=excluded.updated_at`,
		rec.ID, rec.Name, rec.Kind, b2i(rec.Enabled), rec.Config,
		"", "", "", 0, nowStr(), nowStr())
	if err != nil {
		return NotifyChannel{}, err
	}
	out, _, err := s.NotifyChannelByID(ctx, rec.ID)
	return out, err
}

// DeleteNotifyChannel 删除通道，连同它的凭据。
//
// ★凭据必须一起删：留着孤儿密文行的话，管理员删掉再用**同一个 id** 重建时
// （id 由前端回填是完全可能的），新通道会静默继承旧凭据——一条谁都不记得设过的口令。
func (s *SQLiteStore) DeleteNotifyChannel(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM notify_channel_secrets WHERE channel_id=?`,
		`DELETE FROM notify_channels WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// notifySecretMeta 只读凭据的**元信息**（是否存在 + 指纹），绝不触碰密文。
func (s *SQLiteStore) notifySecretMeta(ctx context.Context, id string) (bool, string, error) {
	var fp sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT fingerprint FROM notify_channel_secrets WHERE channel_id=?`, id).Scan(&fp)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, fp.String, nil
}

func (s *SQLiteStore) SaveNotifyChannelSecret(ctx context.Context, sec NotifyChannelSecret) error {
	if strings.TrimSpace(sec.ChannelID) == "" {
		return fmt.Errorf("消息通道凭据缺少 channel id（AAD 就是它，不能为空）")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO notify_channel_secrets(channel_id,nonce,cipher,fingerprint,updated_at) VALUES(?,?,?,?,?)
ON CONFLICT(channel_id) DO UPDATE SET nonce=excluded.nonce, cipher=excluded.cipher,
  fingerprint=excluded.fingerprint, updated_at=excluded.updated_at`,
		sec.ChannelID, sec.Nonce, sec.Cipher, sec.Fingerprint, nowStr())
	return err
}

func (s *SQLiteStore) NotifyChannelSecret(ctx context.Context, id string) (NotifyChannelSecret, bool, error) {
	sec := NotifyChannelSecret{ChannelID: id}
	err := s.db.QueryRowContext(ctx,
		`SELECT nonce,cipher FROM notify_channel_secrets WHERE channel_id=?`, id).Scan(&sec.Nonce, &sec.Cipher)
	if err == sql.ErrNoRows {
		return NotifyChannelSecret{}, false, nil
	}
	if err != nil {
		return NotifyChannelSecret{}, false, err
	}
	return sec, true, nil
}

// RecordNotifySend 记一次已经发生的发送结果。
//
// detail 会被截断到 512 字符：它来自对端的错误信息，一个返回整页 HTML 的网关
// 能把这一列撑成几十 KB × 每次告警。
func (s *SQLiteStore) RecordNotifySend(ctx context.Context, id, status, detail, event string, at int64) error {
	if len([]rune(detail)) > 512 {
		detail = string([]rune(detail)[:512]) + "…"
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE notify_channels SET last_status=?, last_detail=?, last_event=?, last_at=? WHERE id=?`,
		status, detail, event, at, id)
	return err
}
