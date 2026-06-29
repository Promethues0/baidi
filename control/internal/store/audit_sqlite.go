package store

import (
	"context"
	"time"
)

// ── 真实审计日志（管理操作 / 安全事件实时落库；覆盖 Memory 静态种子）──

// RecordAudit 追加一条审计日志条目。
func (s *SQLiteStore) RecordAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log(ts,category,actor,src_ip,event,verdict) VALUES(?,?,?,?,?,?)`,
		e.Time, e.Category, e.User, e.SrcIP, e.Event, e.Verdict)
	return err
}

// Audit 覆盖：日志从 audit_log 实时读取（最近 200 条），分类计数与今日总量按库聚合；
// 磁盘水位等静态指标沿用 Memory 种子。
func (s *SQLiteStore) Audit(ctx context.Context) (AuditBundle, error) {
	base, _ := s.Memory.Audit(ctx) // 复用 Disk 等静态字段
	out := AuditBundle{Disk: base.Disk, Categories: []KV{}, Logs: []AuditEntry{}}

	rows, err := s.db.QueryContext(ctx, `SELECT ts,category,actor,src_ip,event,verdict FROM audit_log ORDER BY id DESC LIMIT 200`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Time, &e.Category, &e.User, &e.SrcIP, &e.Event, &e.Verdict); err != nil {
			rows.Close()
			return out, err
		}
		out.Logs = append(out.Logs, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	// 分类计数（全表），按固定顺序铺满四类（缺失类计 0）。
	counts := map[string]int{}
	crows, err := s.db.QueryContext(ctx, `SELECT category, COUNT(*) FROM audit_log GROUP BY category`)
	if err != nil {
		return out, err
	}
	for crows.Next() {
		var cat string
		var n int
		if err := crows.Scan(&cat, &n); err != nil {
			crows.Close()
			return out, err
		}
		counts[cat] = n
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return out, err
	}
	labels := []struct{ key, label string }{
		{"access", "访问决策"}, {"auth", "登录认证"}, {"admin", "管理操作"}, {"security", "安全事件"},
	}
	for _, l := range labels {
		out.Categories = append(out.Categories, KV{Name: l.label, Value: counts[l.key]})
	}

	today := time.Now().Format("2006-01-02")
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE ts LIKE ?`, today+"%").Scan(&out.TodayTotal)
	return out, nil
}
