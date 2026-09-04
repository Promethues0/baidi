package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ── audit_log 查询计划的守卫（EXPLAIN QUERY PLAN）──
//
// 为什么是「查询计划」而不是「耗时」：本轨道实测过一个反直觉的结果——
// 给 audit_log 加一条 idx_audit_log_category 之后，SQLite 会改用 category 索引去跑
// 「WHERE ts>=? GROUP BY category」（按 category 有序扫可以省掉 GROUP BY 的排序），
// 代价是扫完全部索引项再逐条回表，200 万行实测从 229ms 退化到 1.5s，
// **同时存在 ts 索引也救不回来**。也就是说：加索引可以让系统变慢，
// 而且在页面上与「本来就慢」完全同形。耗时断言在开发机上又必须留出很大的余量
// （不然 CI 一抖就红），大到根本盖不住这种退化——只有计划断言盖得住。
//
// 这些用例跑在**空库**上：SQLite 没跑过 ANALYZE（全仓无 ANALYZE，无 sqlite_stat1），
// planner 用的是固定的默认行数估计，与库里有多少行无关，所以计划在空库上就能定。
// 这也正是这道守卫便宜到可以放进普通 go test 的原因——它测的是计划，不是数据量。

// planOf 返回一条 SQL 的查询计划（各行 detail 用 " ;; " 连起来，便于整体断言）。
func planOf(t *testing.T, st *SQLiteStore, q string, args ...any) string {
	t.Helper()
	rows, err := st.db.Query("EXPLAIN QUERY PLAN "+q, args...)
	if err != nil {
		t.Fatalf("EQP 失败：%v\nSQL: %s", err, q)
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(parts, " ;; ")
}

func TestAuditQueryPlansUseTimeIndex(t *testing.T) {
	st := openTestStore(t)
	cutoff := time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	today := time.Now()
	searchCond, searchArgs := auditWhere(AuditQuery{
		From: today.AddDate(0, 0, -7).Format("2006-01-02"),
		To:   today.Format("2006-01-02"),
	})

	cases := []struct {
		name    string
		sql     string
		args    []any
		want    []string // 计划里必须出现
		notWant []string // 计划里绝不能出现
		why     string
	}{{
		name: "态势总览·窗口内按类别聚合",
		sql:  auditWindowGroupSQL("category"), args: []any{cutoff},
		want:    []string{"idx_audit_log_ts", "SEARCH"},
		notWant: []string{"idx_audit_log_category"},
		why: "退化成全表扫（索引没了）或改走 category 索引（有人新加了索引）都会命中这一条。" +
			"200 万行实测：走 ts 索引 29ms、全表扫 229ms、走 category 索引 1.5s",
	}, {
		name: "态势总览·窗口内按判定聚合",
		sql:  auditWindowGroupSQL("verdict"), args: []any{cutoff},
		want:    []string{"idx_audit_log_ts", "SEARCH"},
		notWant: []string{"idx_audit_log_verdict"},
		why:     "同上；verdict 也不许单独建索引，理由与 category 一样",
	}, {
		name: "审计页·今日总量",
		sql:  auditTodayCountSQL, args: []any{"2026-09-04 00:00:00", "2026-09-05 00:00:00"},
		want:    []string{"idx_audit_log_ts", "SEARCH"},
		notWant: []string{"SCAN audit_log ;;", "USE TEMP B-TREE"},
		why: "改回 `ts LIKE '今天%'` 时计划会退成 SCAN（参数化 LIKE 看不出前缀常量，" +
			"有索引也只是全索引扫）：200 万行 2ms → 225ms",
	}, {
		name: "审计页·检索取一页（带时间窗）",
		sql:  auditSearchSQL(searchCond), args: append(append([]any{}, searchArgs...), 100, 0),
		want:    []string{"idx_audit_log_ts"},
		notWant: []string{"USE TEMP B-TREE FOR ORDER BY"},
		why: "把 ORDER BY 改回 `id DESC` 就会出现临时 B 树排序——那正是" +
			"「只加索引不改排序」的回退形态，200 万行实测 <1ms → 496ms",
	}, {
		name:    "审计页·首屏最近 200 条",
		sql:     auditRecentSQL,
		want:    []string{"idx_audit_log_ts"},
		notWant: []string{"USE TEMP B-TREE FOR ORDER BY"},
		why:     "同上；首屏与检索必须同一个序，否则两种视图里同一批行的先后会变",
	}, {
		name: "分类计数·增量段",
		sql:  auditCatSinceSQL, args: []any{int64(1), int64(1 << 40)},
		want:    []string{"rowid>?"},
		notWant: []string{"idx_audit_log_ts"},
		why: "增量段必须靠主键定位（只看新增的那一小段）。走成别的索引就会变成" +
			"每次都扫全表，缓存等于白做",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := planOf(t, st, c.sql, c.args...)
			for _, w := range c.want {
				if !strings.Contains(plan, w) {
					t.Errorf("查询计划里应出现 %q 却没有。\n计划：%s\nSQL：%s\n为什么守这一条：%s", w, plan, c.sql, c.why)
				}
			}
			for _, w := range c.notWant {
				if strings.Contains(plan, w) {
					t.Errorf("查询计划里出现了 %q。\n计划：%s\nSQL：%s\n为什么守这一条：%s", w, plan, c.sql, c.why)
				}
			}
		})
	}
}

// TestAuditLogIndexSetIsExactlyTimeOnly 直接钉住 audit_log 上**有哪些索引**。
//
// 上面那组计划断言是"后果侧"的守卫，这一条是"原因侧"的：新加一条索引时，
// 作者未必会去跑态势总览那条用例，但这一条会指着他刚加的索引名字失败，
// 并把那 1.5s 的实测摆在错误信息里。两道都留着是有意的——只留后果侧的话，
// 一条暂时没被任何用例覆盖的查询上的退化会静默溜过去。
func TestAuditLogIndexSetIsExactlyTimeOnly(t *testing.T) {
	st := openTestStore(t)
	rows, err := st.db.Query(`PRAGMA index_list(audit_log)`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for rows.Next() {
		var seq int
		var name, origin string
		var unique, partial int
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		got[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got["idx_audit_log_ts"] {
		t.Fatalf("audit_log 的索引集合应当**只有** idx_audit_log_ts，实际是 %v。\n"+
			"删掉它：态势总览/今日总量/检索翻页全部退回全表扫（200 万行 0.2~1.7s 一发，大屏每 15s 打一次）。\n"+
			"新加一条：实测过 idx_audit_log_category 会把「WHERE ts>=? GROUP BY category」"+
			"从 229ms 拖到 1.5s，且同时存在 ts 索引也救不回来——加索引把系统改慢了，"+
			"而页面上与「本来就慢」完全同形。\n"+
			"真要加，先按 audit_bench_test.go 造够行数量一遍，并把 EQP 计划一起看了。", got)
	}
	// 叶子列必须是 ts：改成别的列（哪怕索引名不变）上面的计划断言未必都能红，
	// 但那条索引就不再服务任何一条真实查询了。
	cols, err := st.db.Query(`PRAGMA index_info(idx_audit_log_ts)`)
	if err != nil {
		t.Fatal(err)
	}
	defer cols.Close()
	var names []string
	for cols.Next() {
		var seqno, cid int
		var name string
		if err := cols.Scan(&seqno, &cid, &name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if len(names) != 1 || names[0] != "ts" {
		t.Fatalf("idx_audit_log_ts 的列应当只有 ts，实际是 %v。"+
			"加第二列会让索引项从 (ts, rowid) 变成 (ts, 第二列, rowid)，"+
			"于是 ORDER BY ts DESC, id DESC 不再是它的逆序，检索翻页会重新出现临时 B 树排序", names)
	}
}

// TestAuditRecentAndSearchShareOrder 首屏与检索必须是同一个序。
// 页面在「什么都没筛」时显示首屏快照、筛过就换成检索结果，两者序不同的话，
// 同一批行的先后会在两种视图之间跳，而两边都不报错。
func TestAuditRecentAndSearchShareOrder(t *testing.T) {
	const want = "ORDER BY ts DESC, id DESC"
	if !strings.Contains(auditRecentSQL, want) {
		t.Errorf("首屏取行 SQL 少了 %q：%s", want, auditRecentSQL)
	}
	if !strings.Contains(auditSearchSQL("1=1"), want) {
		t.Errorf("检索取行 SQL 少了 %q：%s", want, auditSearchSQL("1=1"))
	}
}

// TestAuditSearchOrderIsDeterministic 同一秒内的多条记录必须有确定的先后。
// 只按 ts 排的话，LIMIT/OFFSET 翻页会重复或漏行——页面上表现为
// 「某条记录怎么翻都找不到」，而接口一路 200。
//
// ★这条用例的**能力边界**（变异实测出来的，写在这儿免得后人高估它）：
// 把 SQL 里的 `, id DESC` 去掉，它**仍然绿**——因为 idx_audit_log_ts 的索引项
// 就是 (ts, rowid)，走索引出来的顺序天然带了 rowid 这一维。
// 也就是说"同一秒的先后"这件事目前是由索引形状兜着的，不是由 ORDER BY 兜着的。
// 真正钉住那个次级键的是上面的 TestAuditRecentAndSearchShareOrder（比字符串）。
// 本用例守的是另一件事：翻页整体不重不漏（改坏 LIMIT/OFFSET 或 WHERE 时会红）。
func TestAuditSearchOrderIsDeterministic(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	const ts = "2026-09-04 10:00:00"
	for i := 0; i < 6; i++ {
		if err := st.RecordAudit(ctx, AuditEntry{
			Time: ts, Category: "admin", User: "a", SrcIP: "10.0.0.1",
			Event: string(rune('A' + i)), Verdict: "ok",
		}); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	for off := 0; off < 6; off += 2 {
		page, _, err := st.SearchAudit(ctx, AuditQuery{Limit: 2, Offset: off, From: "2026-09-04", To: "2026-09-04"})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			seen = append(seen, e.Event)
		}
	}
	if got := strings.Join(seen, ""); got != "FEDCBA" {
		t.Fatalf("同一秒内 6 条记录分 3 页翻出来应当是 FEDCBA（新→旧、无重复无遗漏），实际 %q", got)
	}
}
