package store

import (
	"context"
	"database/sql"
	"time"
)

// ── login_lockouts：锁定记录的持久化（重启不丢锁定）──

// SaveLockout upsert 一条锁定记录（同维度同键重复触发时刷新截止时间与原因）。
func (s *SQLiteStore) SaveLockout(ctx context.Context, l Lockout) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO login_lockouts(kind,key,until,reason,created_at) VALUES(?,?,?,?,?)
ON CONFLICT(kind,key) DO UPDATE SET until=excluded.until, reason=excluded.reason, created_at=excluded.created_at`,
		l.Kind, l.Key, l.Until, l.Reason, l.CreatedAt)
	return err
}

// DeleteLockout 删除一条锁定记录（管理员解锁）。返回是否真的删掉了行——
// 调用方据此决定要不要写「已解锁」审计：没删到就不许记，审计只记已发生的事实。
func (s *SQLiteStore) DeleteLockout(ctx context.Context, kind, key string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM login_lockouts WHERE kind=? AND key=?`, kind, key)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ActiveLockouts 返回未到期的锁定清单，顺手懒清理已到期的行
// （到期即自动解锁，不需要后台任务；与 api 层 s.revoked 的懒清理同一策略）。
func (s *SQLiteStore) ActiveLockouts(ctx context.Context) ([]Lockout, error) {
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM login_lockouts WHERE until<=?`, now); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT kind,key,until,reason,created_at FROM login_lockouts WHERE until>? ORDER BY kind, key`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Lockout{}
	for rows.Next() {
		var l Lockout
		if err := rows.Scan(&l.Kind, &l.Key, &l.Until, &l.Reason, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ── settings：运行时配置覆盖（键值）。首个消费者：登录防爆破配置（BAIDI_LOCKOUT_* 的运行时覆盖）──

// Setting 读一个运行时设置值。not found → ok=false 无错。
func (s *SQLiteStore) Setting(ctx context.Context, k string) (string, bool, error) {
	var v string
	switch err := s.db.QueryRowContext(ctx, `SELECT v FROM settings WHERE k=?`, k).Scan(&v); err {
	case nil:
		return v, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, err
	}
}

// SetSetting upsert 一个运行时设置值。
func (s *SQLiteStore) SetSetting(ctx context.Context, k, v string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(k,v,updated_at) VALUES(?,?,?)
ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at`, k, v, nowStr())
	return err
}
