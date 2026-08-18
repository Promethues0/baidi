package store

import (
	"context"
	"database/sql"
)

// ── device_sessions 取数（判定纯函数在 devsession.go）──

// scanDevSessions 公共扫描。
func scanDevSessions(rows *sql.Rows) ([]DeviceSession, error) {
	defer rows.Close()
	out := []DeviceSession{}
	for rows.Next() {
		var d DeviceSession
		var lastActive sql.NullInt64
		var reason sql.NullString
		if err := rows.Scan(&d.Account, &d.Fingerprint, &d.Platform, &d.IP,
			&d.FirstSeen, &d.LastKnock, &lastActive, &d.State, &reason); err != nil {
			return nil, err
		}
		// ★NULL 与 0 必须分开：NULL = 没有任何网关报过这条会话的活跃时刻（不可判定），
		// 0 = 网关报了「自建立起从未有业务连接」。两者在 FR-POLICY-30 下的处置相反。
		d.ActivityKnown = lastActive.Valid
		d.LastActive = lastActive.Int64
		d.EndedReason = reason.String
		out = append(out, d)
	}
	return out, rows.Err()
}

const devSessionCols = `account,fingerprint,platform,ip,first_seen,last_knock,last_active,state,ended_reason`

// DeviceSessions 该账号名下全部接入会话。
func (s *SQLiteStore) DeviceSessions(ctx context.Context, account string) ([]DeviceSession, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+devSessionCols+` FROM device_sessions WHERE account=? ORDER BY fingerprint`,
		normAccount(account))
	if err != nil {
		return nil, err
	}
	return scanDevSessions(rows)
}

// AllDeviceSessions 全量（按最近敲门倒序）。
func (s *SQLiteStore) AllDeviceSessions(ctx context.Context) ([]DeviceSession, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+devSessionCols+` FROM device_sessions ORDER BY last_knock DESC`)
	if err != nil {
		return nil, err
	}
	return scanDevSessions(rows)
}

// TouchDeviceSession 记一次敲门。返回**续期前**的那一行——判定要看的是上一次的状态
// （比如"这条会话上次被判超时了吗"），先写后读会把它自己覆盖掉。
func (s *SQLiteStore) TouchDeviceSession(ctx context.Context, account, fingerprint, platform, ip string,
	now int64) (DeviceSession, bool, error) {
	acct := normAccount(account)
	var prev DeviceSession
	found := false
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+devSessionCols+` FROM device_sessions WHERE account=? AND fingerprint=?`, acct, fingerprint)
	if err != nil {
		return DeviceSession{}, false, err
	}
	list, err := scanDevSessions(rows)
	if err != nil {
		return DeviceSession{}, false, err
	}
	if len(list) > 0 {
		prev, found = list[0], true
	}
	if found {
		// ★平台/IP 用 COALESCE(NULLIF(?,''), 原值)：客户端偶尔不报平台时不该把已知的抹掉。
		// state 与 last_active **不在这里改**——注销状态只能由 EndDeviceSession/Revive 改，
		// 活跃时刻只能由网关回执改。敲门保活不是业务流量（见 devsession.go 的判据说明）。
		_, err = s.db.ExecContext(ctx, `UPDATE device_sessions
SET last_knock=?, platform=COALESCE(NULLIF(?,''),platform), ip=COALESCE(NULLIF(?,''),ip)
WHERE account=? AND fingerprint=?`, now, platform, ip, acct, fingerprint)
	} else {
		// last_active 建行时是 NULL（不可判定），不是 0。
		_, err = s.db.ExecContext(ctx, `INSERT INTO device_sessions
(account,fingerprint,platform,ip,first_seen,last_knock,last_active,state,ended_reason)
VALUES(?,?,?,?,?,?,NULL,?,'')`, acct, fingerprint, platform, ip, now, now, DevSessionActive)
	}
	if err != nil {
		return DeviceSession{}, false, err
	}
	// 顺手回收陈旧行（无界增长的唯一入口就是这里）。只删本账号的，避免一次敲门扫全表。
	_, _ = s.db.ExecContext(ctx,
		`DELETE FROM device_sessions WHERE account=? AND last_knock < ?`,
		acct, now-int64(DevSessionStaleDays)*86400)
	return prev, found, nil
}

// EndDeviceSession 标记注销。
func (s *SQLiteStore) EndDeviceSession(ctx context.Context, account, fingerprint, reason string, now int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_sessions SET state=?, ended_reason=?, last_knock=? WHERE account=? AND fingerprint=?`,
		DevSessionTimeout, reason, now, normAccount(account), fingerprint)
	return err
}

// ReviveDeviceSessions 重新登录后恢复可接入（fingerprint 为空则恢复该账号全部**已注销**的）。
//
// ★实现是**删行**而不是改状态：重新登录开的是一段新会话，first_seen / last_active
// 都该从头算。只把 state 改回 active 的话，网关下一次报「这条会话从未有业务连接」
// 时，空闲时长会从**上一段会话**的 first_seen 起算 → 一登录就再次被判超时，
// 用户看到的是「登录成功，然后立刻又被踢」。行删掉后，下一次敲门自然重建一条干净的。
//
// **只删 state=timeout 的行**：正在用的会话不能碰，否则从 B 机登录会把 A 机的
// 活跃时刻抹掉，A 机的空闲判定跟着重置。
func (s *SQLiteStore) ReviveDeviceSessions(ctx context.Context, account, fingerprint string) error {
	q := `DELETE FROM device_sessions WHERE account=? AND state=?`
	args := []any{normAccount(account), DevSessionTimeout}
	if fingerprint != "" {
		q += ` AND fingerprint=?`
		args = append(args, fingerprint)
	}
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

// MarkDeviceActivity 网关回执落库：该账号在某源 IP 上的最近业务连接时刻。
//
// ★按 (账号, IP) 匹配是这条链路唯一可用的键：网关的会话表按源 IP 记，
// 它不知道设备指纹（SPA 单包里没有）。同一 NAT 出口下的两台终端会共用一个 IP，
// 于是活跃时刻互相顶替——方向是 fail-open（不该踢的不踢），页面上写明了这条边界。
//
// **只往前推，不倒退**：多台网关各报一份，取最大值；否则一台刚接手的网关会用
// 它自己那份较早的时刻把真实活跃时刻覆盖掉，表现为"人在用、却被判超时"。
func (s *SQLiteStore) MarkDeviceActivity(ctx context.Context, account, ip string, lastActive int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE device_sessions
SET last_active=MAX(COALESCE(last_active,0), ?) WHERE account=? AND ip=?`,
		lastActive, normAccount(account), ip)
	return err
}

// DeleteDeviceSession 删掉一条会话行（新终端被上限拒绝时回滚记账）。
func (s *SQLiteStore) DeleteDeviceSession(ctx context.Context, account, fingerprint string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM device_sessions WHERE account=? AND fingerprint=?`, normAccount(account), fingerprint)
	return err
}
