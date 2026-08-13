package store

import (
	"context"
	"fmt"
	"time"
)

// OpsReport 聚合 audit_log 与 alerts 产出运营报表。实现细节里的几个刻意选择：
//
//   - ts 是本地时间文本（YYYY-MM-DD HH:MM:SS，RecordAudit 落库口径），按日分桶用
//     substr(ts,1,10)，窗口过滤用字符串比较——该格式下字典序与时间序一致，
//     不引入一次会因时区二义性出错的解析。
//   - 每一类计数都写明白名单条件，绝不用 ELSE 兜底：审计将来新增类别时，
//     新类别只进 Total 不进任何专栏——宁可"报表少一栏"也不把新类别错记进旧栏。
func (s *SQLiteStore) OpsReport(ctx context.Context, days int) (OpsReport, error) {
	if days <= 0 {
		return OpsReport{}, fmt.Errorf("报表窗口必须为正，收到 %d", days)
	}
	out := OpsReport{Days: days, RetainDays: s.auditRetainDays}

	// 留存截断：窗口比留存长时，留存边界之前的日子在库里**必然**是 0 行——
	// 那是清理的结果不是事实，补零会把"数据没了"伪装成"什么都没发生"。
	if s.auditRetainDays > 0 && days > s.auditRetainDays {
		out.Days = s.auditRetainDays
		out.Truncated = true
	}
	now := time.Now()
	since := now.AddDate(0, 0, -(out.Days - 1)).Format("2006-01-02")
	out.Since = since
	sinceTS := since + " 00:00:00"

	// ── 逐日分桶 ──
	rows, err := s.db.QueryContext(ctx, `
SELECT substr(ts,1,10) AS d,
       SUM(CASE WHEN category='auth'   AND verdict='ok'                THEN 1 ELSE 0 END),
       SUM(CASE WHEN category='auth'   AND verdict='fail'              THEN 1 ELSE 0 END),
       SUM(CASE WHEN category='access' AND verdict='allow'             THEN 1 ELSE 0 END),
       SUM(CASE WHEN category='access' AND verdict IN ('deny','fail')  THEN 1 ELSE 0 END),
       SUM(CASE WHEN category IN ('admin','system')                    THEN 1 ELSE 0 END),
       SUM(CASE WHEN category='security'                               THEN 1 ELSE 0 END),
       COUNT(*)
FROM audit_log WHERE ts >= ? GROUP BY d`, sinceTS)
	if err != nil {
		return out, err
	}
	byDate := map[string]OpsDay{}
	for rows.Next() {
		var d OpsDay
		if err := rows.Scan(&d.Date, &d.AuthOK, &d.AuthFail, &d.AccessAllow, &d.AccessDeny,
			&d.AdminOps, &d.Security, &d.Total); err != nil {
			rows.Close()
			return out, err
		}
		byDate[d.Date] = d
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	// 补全零日（理由见 OpsDay 注释），并顺手算合计——合计从日桶累加而不是再查一遍，
	// 两条 SQL 各自过滤迟早在边界上差一条，页面上"合计 ≠ 各日之和"没人能解释。
	for i := 0; i < out.Days; i++ {
		date := now.AddDate(0, 0, -(out.Days - 1 - i)).Format("2006-01-02")
		d := byDate[date]
		d.Date = date
		out.Daily = append(out.Daily, d)
		out.Totals.Entries += d.Total
		out.Totals.AuthOK += d.AuthOK
		out.Totals.AuthFail += d.AuthFail
		out.Totals.AccessAllow += d.AccessAllow
		out.Totals.AccessDeny += d.AccessDeny
		out.Totals.AdminOps += d.AdminOps
		out.Totals.Security += d.Security
	}

	// ── 去重活跃账号 ──
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT actor) FROM audit_log
WHERE ts >= ? AND category='auth' AND verdict='ok' AND actor NOT IN ('', '—', 'system')`,
		sinceTS).Scan(&out.Totals.ActiveAccounts); err != nil {
		return out, err
	}

	// ── 账号榜单（登录成功 / 被拒）──
	top := func(query string) ([]KV, error) {
		rs, err := s.db.QueryContext(ctx, query, sinceTS)
		if err != nil {
			return nil, err
		}
		defer rs.Close()
		kvs := []KV{}
		for rs.Next() {
			var kv KV
			if err := rs.Scan(&kv.Name, &kv.Value); err != nil {
				return nil, err
			}
			kvs = append(kvs, kv)
		}
		return kvs, rs.Err()
	}
	if out.TopLogin, err = top(`
SELECT actor, COUNT(*) n FROM audit_log
WHERE ts >= ? AND category='auth' AND verdict='ok' AND actor NOT IN ('', '—', 'system')
GROUP BY actor ORDER BY n DESC, actor LIMIT 8`); err != nil {
		return out, err
	}
	if out.TopDenied, err = top(`
SELECT actor, COUNT(*) n FROM audit_log
WHERE ts >= ? AND verdict IN ('deny','fail') AND actor NOT IN ('', '—', 'system')
GROUP BY actor ORDER BY n DESC, actor LIMIT 8`); err != nil {
		return out, err
	}

	// ── 业务告警（alerts 表按 triggered_at 过滤；unix 秒）──
	sinceUnix := now.AddDate(0, 0, -(out.Days - 1)).Truncate(24 * time.Hour).Unix()
	// Truncate 是 UTC 口径的粗略对齐；告警窗口与审计窗口差最多一个时区偏移，
	// 对"最近 N 天"这个粒度可接受，两者口径差写在这儿而不是让人对表时自己发现。
	sevRows, err := s.db.QueryContext(ctx, `
SELECT severity, status, COUNT(*) FROM alerts WHERE triggered_at >= ? GROUP BY severity, status`, sinceUnix)
	if err != nil {
		return out, err
	}
	sev := map[string]int{}
	for sevRows.Next() {
		var severity, status string
		var n int
		if err := sevRows.Scan(&severity, &status, &n); err != nil {
			sevRows.Close()
			return out, err
		}
		sev[severity] += n
		out.Alerts.Total += n
		if status == AlertPending {
			out.Alerts.Pending += n
		}
	}
	sevRows.Close()
	if err := sevRows.Err(); err != nil {
		return out, err
	}
	for _, s := range []string{AlertSevCritical, AlertSevWarning, AlertSevInfo} {
		out.Alerts.BySeverity = append(out.Alerts.BySeverity, KV{Name: s, Value: sev[s]})
	}
	return out, nil
}
