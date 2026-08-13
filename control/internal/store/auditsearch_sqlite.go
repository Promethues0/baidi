package store

import (
	"context"
	"strings"
)

// ── 审计在线检索（wave7 行动 6 / B 组：FR-AUDIT-01/03/05 + NFR-OBS-02）──
//
// ★回归背景：审计页此前只有 `Audit()` 固定拉最近 200 条，检索控件与时间快选
// pill 是装饰件——查"某账号最近 30 天做过什么"只能全量 CSV 导出自行 grep，
// 180 天留存的取用价值被折掉大半。列全在库里，缺的只是 WHERE。

// AuditQuery 一次检索的条件。零值字段 = 该维不过滤。
type AuditQuery struct {
	Category string // access|auth|admin|security|dataplane|system（空=全部）
	Actor    string // 账号，规范化后精确匹配（查证据链用精确，模糊会把 li 匹配到 alice）
	SrcIP    string // 源 IP 前缀匹配（10.8. 查整段是真实用法）
	Keyword  string // event 文本包含
	From, To string // YYYY-MM-DD（含当日；To 补到当日 23:59:59）
	Limit    int    // ≤500，缺省 100
	Offset   int
}

// SearchAudit 按条件检索，返回（本页行，总命中数）。
// 总数与行数同一组 WHERE——两处条件不同构的话，分页控件会说"共 3 页"而第 2 页是空的。
func (s *SQLiteStore) SearchAudit(ctx context.Context, q AuditQuery) ([]AuditEntry, int, error) {
	where, args := []string{"1=1"}, []any{}
	if q.Category != "" {
		where, args = append(where, "category=?"), append(args, q.Category)
	}
	if a := strings.ToLower(strings.TrimSpace(q.Actor)); a != "" {
		where, args = append(where, "lower(trim(actor))=?"), append(args, a)
	}
	if ip := strings.TrimSpace(q.SrcIP); ip != "" {
		// 前缀匹配用 LIKE，通配符经转义——源 IP 里的字面 % 没有合法场景，但别赌。
		where, args = append(where, `src_ip LIKE ? ESCAPE '\'`), append(args, escapeLike(ip)+"%")
	}
	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		where, args = append(where, `event LIKE ? ESCAPE '\'`), append(args, "%"+escapeLike(kw)+"%")
	}
	if q.From != "" {
		where, args = append(where, "ts>=?"), append(args, q.From+" 00:00:00")
	}
	if q.To != "" {
		where, args = append(where, "ts<=?"), append(args, q.To+" 23:59:59")
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ts,category,actor,src_ip,event,verdict,
COALESCE(seq,0),COALESCE(mac,'') FROM audit_log WHERE `+cond+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, limit, max(q.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Time, &e.Category, &e.User, &e.SrcIP, &e.Event, &e.Verdict, &e.Seq, &e.MAC); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// escapeLike 转义 LIKE 通配符（% _ \）。
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
