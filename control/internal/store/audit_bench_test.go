package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// ── audit_log 的规模基准（wave10）──
//
// ★这一族成本的特点，也是这个文件存在的全部理由：**它只在数据攒了几周之后才显形**。
// 本机开发库 520 KB，单测、e2e、演示站各造几十上百行——仓里原有的每一道守卫，
// 在「审计表 200 万行」这件事上都恒绿。而按「放行也留痕」的 5min/键节流，
// 50 用户 × 4 资源 ≈ 200 键 × 288 条/天 ≈ 5.8 万条/天，35 天就到 200 万行；
// 默认 180 天留存下是千万级。改造前那张表**一条索引都没有**，
// 大屏每 15s 同时打 /overview + /online + /audit，每一发都是全表扫。
//
// 所以这个文件的定位是：**给这一族成本装一个能长期跑的测量点**，
// 让「性能只有在生产上攒够数据才暴露」这件事至少有一处可复现的对照。
// 与 subjects_bench_test.go 同一条口径纪律——先说口径，再给数字，绝不写成"达标"：
//   - 数字是「某台开发机 + modernc 纯 Go SQLite（免 CGO，与 CGO 版性能特征不同）
//     + 刚建好刚写完的库（无碎片、页缓存全热）」上的相对差，不构成任何容量承诺；
//   - 生产上的冷库、并发写入、更宽的 event 文本都会让绝对值变差；
//   - 有意义的是**同一台机器上改造前 / 改造后的比值**，不是毫秒数本身。
//
// 怎么跑（默认 20 万行；第二条是各处注释引用的那一档，约 4 分钟）：
//
//	go test ./internal/store/ -run '^$' -bench 'Audit' -benchtime 1x
//	BAIDI_BENCH_AUDIT_ROWS=2000000 go test ./internal/store/ -run '^$' -bench 'Audit' -benchtime 1x -timeout 30m
//
// ★为什么不放进普通 go test：造 200 万行 + 建索引要几十秒，而它每次跑都一样。
// Go 的 Benchmark 函数在没有 -bench 时根本不会执行，这本身就是门控；
// 另外 -short 时显式跳过并打印原因（静默跳过的测试等于没有）。
// 但 fixture 本身有一条**真的会跑**的用例（TestAuditBenchFixtureStillWorks）——
// 只在 -bench 下才编译执行的代码会悄悄腐烂，等下次想量的时候先要修半天。

// benchAuditRows 造多少行。默认 20 万：十几秒跑完全套，改造前后的差距已经很清楚
// （首屏 172ms → 2.4ms）。各处注释引用的 200 万那一档用环境变量开——
// 每条基准都要各造一份 fixture（11~20s），跑全套约 4 分钟。
func benchAuditRows(tb testing.TB) int {
	if v := os.Getenv("BAIDI_BENCH_AUDIT_ROWS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			tb.Fatalf("BAIDI_BENCH_AUDIT_ROWS=%q 不是正整数", v)
		}
		return n
	}
	return 200000
}

// benchAuditSpanDays 造出来的行覆盖多少天（决定"今天"占全表的比例，也决定
// 时间窗查询能筛掉多少）。35 天 = 上面那笔账里 200 万行攒起来的天数。
const benchAuditSpanDays = 35

// seedAuditLog 造 n 行审计。
//
// ★刻意**不走 RecordAudit**：那条路径每行一个事务（读链尾 + INSERT + 外送入队），
// 造 200 万行要跑上小时级。这里在单个事务里批量插，但 seq/mac **仍按真链算**
// （auditMAC 逐行串联）——行宽与真实数据一致，VerifyAuditChain 也能在这份 fixture 上跑。
// 写成随便填个 mac 的话，行宽偏窄，量出来的扫描成本会系统性偏乐观。
func seedAuditLog(tb testing.TB, st *SQLiteStore, n int) {
	tb.Helper()
	cats := make([]string, 0, len(AuditCategories))
	for _, c := range AuditCategories {
		cats = append(cats, c.Key)
	}
	verdicts := []string{"allow", "ok", "deny", "fail", "observing"}

	tx, err := st.db.Begin()
	if err != nil {
		tb.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO audit_log(ts,category,actor,src_ip,event,verdict,seq,mac) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		tb.Fatal(err)
	}
	defer stmt.Close()

	ctx := context.Background()
	prevSeq, prevMac, err := auditChainTail(ctx, tx)
	if err != nil {
		tb.Fatal(err)
	}
	start := time.Now().AddDate(0, 0, -benchAuditSpanDays)
	step := time.Duration(benchAuditSpanDays) * 24 * time.Hour / time.Duration(n)
	t0 := time.Now()
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(i) * step).Format("2006-01-02 15:04:05")
		cat := cats[i%len(cats)]
		actor := fmt.Sprintf("bench.user%03d", i%50)
		ip := fmt.Sprintf("10.8.%d.%d", i%256, (i/7)%256)
		ev := fmt.Sprintf("放行 资源%d（经网关 gw-%d）", i%4, i%3)
		vd := verdicts[i%len(verdicts)]
		prevSeq++
		prevMac = auditMAC(st.auditKey, prevMac, ts, cat, actor, ip, ev, vd)
		if _, err := stmt.Exec(ts, cat, actor, ip, ev, vd, prevSeq, prevMac); err != nil {
			tb.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		tb.Fatal(err)
	}
	tb.Logf("造 %d 行审计用时 %v", n, time.Since(t0).Round(time.Millisecond))
}

// benchAuditStore 开一个装满 n 行的库。withIndex=false 时把 idx_audit_log_ts 删掉，
// 用来量「改造前」——这也让基准顺带成了一道守卫：谁把索引删了，
// "有索引"那几条会当场掉回"无索引"的数量级。
func benchAuditStore(tb testing.TB, n int, withIndex bool) *SQLiteStore {
	tb.Helper()
	st, err := OpenSQLite(filepath.Join(tb.TempDir(), "audit-bench.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { st.Close() })
	if !withIndex {
		// 先删索引再灌数据：省掉建索引的时间，也更贴近"这张表从来没有过索引"的真实形态。
		if _, err := st.db.Exec(`DROP INDEX IF EXISTS idx_audit_log_ts`); err != nil {
			tb.Fatal(err)
		}
	}
	seedAuditLog(tb, st, n)
	return st
}

// shortNotice 保证 -short 下的跳过**说得出声**。
//
// ★为什么不能只用 b.Skip：它的理由只在 -v 下打印，不带 -v 时被跳过的基准
// 在输出里连名字都不出现——与"这个文件不存在"完全同形。本仓的纪律是
// 静默跳过的测试等于没有，所以这里额外往 stderr 打一行（用 Once 保证只打一次，
// 十几条基准各打一遍就成了噪声）。
var shortNotice sync.Once

func skipIfShort(b *testing.B) bool {
	if testing.Short() {
		const why = "-short：跳过 audit_log 规模基准（要造几十万行、耗时以秒计）。" +
			"去掉 -short 即可跑；行数用 BAIDI_BENCH_AUDIT_ROWS 调"
		shortNotice.Do(func() { fmt.Fprintln(os.Stderr, why) })
		b.Skip(why)
		return true
	}
	return false
}

// ── 审计页首屏（GET /api/v1/audit）──
//
// 改造前的一次请求 = 磁盘水位 COUNT(*) + 最近 200 条 + **全表** GROUP BY category
// + `ts LIKE '今天%'` 四条。200 万行实测 1859ms/发，其中全表 GROUP BY 占 1.3s 以上。
// 大屏每 15s 打一次。改造后 22ms；冷缓存那一发（进程刚起 / 刚清过留存）仍是 1444ms。

func BenchmarkAudit首屏_改造前(b *testing.B) {
	if skipIfShort(b) {
		return
	}
	st := benchAuditStore(b, benchAuditRows(b), false)
	ctx := context.Background()
	today := time.Now().Format("2006-01-02")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var n int64
		if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
			b.Fatal(err)
		}
		drain(b, st, `SELECT ts,category,actor,src_ip,event,verdict,
COALESCE(seq,0),COALESCE(mac,'') FROM audit_log ORDER BY id DESC LIMIT 200`)
		drain(b, st, auditCatFullSQL, int64(1)<<40)
		if err := st.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM audit_log WHERE ts LIKE ?`, today+"%").Scan(&n); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAudit首屏_改造后(b *testing.B) {
	if skipIfShort(b) {
		return
	}
	st := benchAuditStore(b, benchAuditRows(b), true)
	ctx := context.Background()
	// 预热一次：冷缓存那一发要付一次整体 GROUP BY（进程生命周期内一次，
	// 以及每次留存清理后一次）。这里量的是稳态——它才是每 15s 发生的那一次。
	if _, err := st.Audit(ctx); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Audit(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAudit首屏_改造后冷缓存 单独量「进程刚起 / 刚清理过留存」的那一发。
// 它仍然要整体 GROUP BY 一次——这是增量方案明确的代价，不藏。
func BenchmarkAudit首屏_改造后冷缓存(b *testing.B) {
	if skipIfShort(b) {
		return
	}
	st := benchAuditStore(b, benchAuditRows(b), true)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		st.auditCats.mu.Lock()
		st.auditCats.ready = false
		st.auditCats.mu.Unlock()
		b.StartTimer()
		if _, err := st.Audit(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// ── 审计检索取一页 ──
// 三种形态的完整对照表见 auditSearchSQL 的注释。这里排四对：
// 最近窗口第 1 页 / 第 5 页 / 旧窗口，加上「只加索引不改排序」那个半程状态。

func benchSearchPage(b *testing.B, withIndex bool, sql func(cond string) string, offset int) {
	benchSearchWindow(b, withIndex, sql, offset, 7, 0)
}

// benchSearchWindow fromDaysAgo/toDaysAgo 圈出窗口（都以"今天"为基准往回数）。
func benchSearchWindow(b *testing.B, withIndex bool, sql func(cond string) string, offset, fromDaysAgo, toDaysAgo int) {
	if skipIfShort(b) {
		return
	}
	st := benchAuditStore(b, benchAuditRows(b), withIndex)
	now := time.Now()
	cond, args := auditWhere(AuditQuery{
		From: now.AddDate(0, 0, -fromDaysAgo).Format("2006-01-02"),
		To:   now.AddDate(0, 0, -toDaysAgo).Format("2006-01-02"),
	})
	q := sql(cond)
	full := append(append([]any{}, args...), 100, offset)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		drain(b, st, q, full...)
	}
}

func oldSearchSQL(cond string) string {
	return `SELECT ts,category,actor,src_ip,event,verdict,
COALESCE(seq,0),COALESCE(mac,'') FROM audit_log WHERE ` + cond + ` ORDER BY id DESC LIMIT ? OFFSET ?`
}

// 最近 7 天 · 第 1 页：改造前后都快，而且改造后**略慢**（200 万行 139µs → 190µs）——
// ts 与 id 天然同序，旧计划从表尾倒扫 rowid、凑够 100 行就停，本来就很快。
// 这一对刻意留着并且刻意不粉饰：这次改造在最常见的那一发上是**付出**，
// 收益在下面的「旧窗口」那一对，以及「只加索引不改排序」那一条避免掉的回退上。
func BenchmarkAudit检索首页_改造前(b *testing.B) { benchSearchPage(b, false, oldSearchSQL, 0) }

// BenchmarkAudit检索首页_只加索引不改排序 = 半程状态。加了索引反而更慢的那一档。
func BenchmarkAudit检索首页_只加索引不改排序(b *testing.B) {
	benchSearchPage(b, true, oldSearchSQL, 0)
}

func BenchmarkAudit检索首页_改造后(b *testing.B) { benchSearchPage(b, true, auditSearchSQL, 0) }

// 第 5 页（OFFSET 400），窗口仍是最近 7 天。
func BenchmarkAudit检索翻页_改造前(b *testing.B) { benchSearchPage(b, false, oldSearchSQL, 400) }
func BenchmarkAudit检索翻页_改造后(b *testing.B) {
	benchSearchPage(b, true, auditSearchSQL, 400)
}

// ★**旧时间窗**（fixture 里最早的那一天）——这一对才是这次改造真正的收益所在，
// 也是审计检索这个功能的立身之本（它的注释原话：查"某账号最近 30 天做过什么"）。
//
// 旧计划从表尾倒扫 rowid，要先趟过全部更新的行才够得着那个窗口：窗口越旧越贵，
// 而"翻旧账"恰恰是取证时最常做的事。新计划直接在索引上定位到那一段。
// 上面几对里改造后略慢那点开销，买的就是这一条。
func BenchmarkAudit检索旧窗口_改造前(b *testing.B) {
	benchSearchWindow(b, false, oldSearchSQL, 0, benchAuditSpanDays, benchAuditSpanDays-1)
}

func BenchmarkAudit检索旧窗口_改造后(b *testing.B) {
	benchSearchWindow(b, true, auditSearchSQL, 0, benchAuditSpanDays, benchAuditSpanDays-1)
}

// ── 分类计数：全表现算 vs 增量缓存 ──

func BenchmarkAudit分类计数_全表现算(b *testing.B) {
	if skipIfShort(b) {
		return
	}
	st := benchAuditStore(b, benchAuditRows(b), true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		drain(b, st, auditCatFullSQL, int64(1)<<40)
	}
}

func BenchmarkAudit分类计数_增量缓存(b *testing.B) {
	if skipIfShort(b) {
		return
	}
	st := benchAuditStore(b, benchAuditRows(b), true)
	ctx := context.Background()
	if _, err := st.auditCategoryCounts(ctx); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.auditCategoryCounts(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// ── 写入侧的代价：多一棵 B 树要多少钱 ──
//
// 索引不是白拿的。审计落库在很多条热路径上（每次敲门、每次登录、每次拒绝），
// 所以「读快了多少」必须与「写慢了多少」摆在一起看。
// ts 单调递增 → 新键恒落最右叶子，是索引维护里最便宜的形态；开发机实测约 −19%。

func benchRecordAudit(b *testing.B, withIndex bool) {
	if skipIfShort(b) {
		return
	}
	// 写入基准只需要一个"已经有些行"的库，不必造满：B 树深度在几万行时就稳定了。
	st := benchAuditStore(b, 20000, withIndex)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.RecordAudit(ctx, AuditEntry{
			Category: "access", User: "bench.user", SrcIP: "10.8.1.2",
			Event: "放行 资源1（经网关 gw-1）", Verdict: "allow",
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAudit落库_无索引(b *testing.B) { benchRecordAudit(b, false) }
func BenchmarkAudit落库_有索引(b *testing.B) { benchRecordAudit(b, true) }

// drain 跑一条查询并读完，只为计入真实的扫描成本（不 Scan 列值：
// 这里要量的是 SQLite 侧的行为，不是 Go 侧的反射开销）。
func drain(b *testing.B, st *SQLiteStore, q string, args ...any) {
	b.Helper()
	rows, err := st.db.Query(q, args...)
	if err != nil {
		b.Fatalf("%v\nSQL: %s", err, q)
	}
	for rows.Next() {
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		b.Fatal(err)
	}
}

// TestAuditBenchFixtureStillWorks 让 fixture 在**普通** go test 里也被跑一遍（2000 行，秒级）。
// 只在 -bench 下才执行的代码会悄悄腐烂：等下一个人想量一量的时候，
// 先得花半天修这个文件——而他多半会选择不量。
//
// 顺带把 fixture 的两条正确性前提钉住：造出来的行接得上真链（VerifyAuditChain 通过），
// 且"无索引"变体确实没有索引（否则"改造前"那几条基准量的其实是改造后）。
func TestAuditBenchFixtureStillWorks(t *testing.T) {
	ctx := context.Background()
	for _, withIndex := range []bool{true, false} {
		st := benchAuditStore(t, 2000, withIndex)
		res, err := st.VerifyAuditChain(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK {
			t.Fatalf("withIndex=%v：fixture 造出来的行接不上防篡改链（断在 seq=%d）——"+
				"基准量的就不是真实行宽了", withIndex, res.BrokenAt)
		}
		if res.Checked < 2000 {
			t.Fatalf("withIndex=%v：只校验到 %d 行，fixture 没造够", withIndex, res.Checked)
		}
		var idx int
		if err := st.db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_audit_log_ts'`).Scan(&idx); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 1, false: 0}[withIndex]; idx != want {
			t.Fatalf("withIndex=%v 时 idx_audit_log_ts 应当有 %d 条，实际 %d", withIndex, want, idx)
		}
	}
}
