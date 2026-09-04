package store

import (
	"context"
	"fmt"
	"testing"
)

// fullCatCounts 直接对全表做一次 GROUP BY——**不经缓存**的参照答案。
// 每个断言都拿它对账：这层缓存唯一被允许的差别是"更快"，不是"更接近"。
func fullCatCounts(t *testing.T, st *SQLiteStore) map[string]int {
	t.Helper()
	// 上界给一个大到不可能命中的值 = 不设限，等价于改造前那条无上界的全表 GROUP BY。
	// 生产路径传的是"刚读到的 maxID"，理由见 auditcat_sqlite.go 里那段竞态说明。
	rows, err := st.db.Query(auditCatFullSQL, int64(1)<<40)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var cat string
		var n int
		if err := rows.Scan(&cat, &n); err != nil {
			t.Fatal(err)
		}
		out[cat] = n
	}
	return out
}

func sameCounts(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// recordN 落 n 条指定类别、指定时刻的审计。
func recordN(t *testing.T, st *SQLiteStore, ctx context.Context, cat, ts string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.RecordAudit(ctx, AuditEntry{
			Time: ts, Category: cat, User: "u", SrcIP: "10.0.0.1",
			Event: fmt.Sprintf("%s-%d", cat, i), Verdict: "ok",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAuditCategoryCountsMatchFullScan 分类计数在三种时序下都必须与全表 GROUP BY 一致：
// 首次（冷缓存整体算）→ 追加（走增量段）→ 头部清理（必须整体重算）。
//
// 第三段是这道用例的重点：留存轮转把最早那一段删掉之后，如果增量判定不看 minID，
// 计数会**永远偏大**且再也回不来（maxID 只增不减，之后每次都只加新增段）。
// 症状是审计页四张卡加起来比库里的总行数多，而库、接口、页面都不报错。
func TestAuditCategoryCountsMatchFullScan(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	check := func(stage string) map[string]int {
		t.Helper()
		got, err := st.auditCategoryCounts(ctx)
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		want := fullCatCounts(t, st)
		if !sameCounts(got, want) {
			t.Fatalf("%s：分类计数 %v 与全表 GROUP BY %v 不一致", stage, got, want)
		}
		return got
	}

	// 冷缓存：库里此刻只有 openTestStore 建库时落下的（若有）行。
	base := check("冷缓存")

	recordN(t, st, ctx, "access", "2026-01-02 10:00:00", 5)
	recordN(t, st, ctx, "auth", "2026-01-02 10:00:00", 3)
	first := check("首批落库")
	if first["access"] != base["access"]+5 || first["auth"] != base["auth"]+3 {
		t.Fatalf("首批落库后计数没跟上：%v（基线 %v）", first, base)
	}

	// 追加：这一段走的是增量分支（id > 上次 maxID）。
	// ★若增量分支忘了把上次的结果拷进来当基数，这里就会掉回只剩本批的 2/4。
	recordN(t, st, ctx, "access", "2026-03-02 10:00:00", 2)
	recordN(t, st, ctx, "security", "2026-03-02 10:00:00", 4)
	second := check("追加一批")
	if second["access"] != first["access"]+2 || second["security"] != first["security"]+4 {
		t.Fatalf("增量分支算错：%v（上一轮 %v）", second, first)
	}

	// 头部清理：把 2026-01-02 那一天整段删掉。
	deleted, err := st.purgeAuditBefore(ctx, "2026-02-01 00:00:00")
	if err != nil {
		t.Fatal(err)
	}
	if deleted == 0 {
		t.Fatal("这一段本该删掉若干行，实际删了 0 行——用例前提没成立")
	}
	third := check("头部清理之后")
	if third["auth"] != 0 {
		t.Fatalf("auth 那 3 条已随头部清理删掉，计数应回到 0，实际 %v", third)
	}
}

// TestAuditBundleCategoriesMatchDB 从 Audit() 这一端再对一次账：
// 页面上那四张卡的数字必须能在库里逐条指得出来。
// 缓存拦在中间，出错的形态正是「页面上的数字与库里对不上，而两边都不报错」。
func TestAuditBundleCategoriesMatchDB(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	recordN(t, st, ctx, "admin", "2026-05-06 08:00:00", 7)
	recordN(t, st, ctx, "policy", "2026-05-06 08:00:00", 2)

	bundle, err := st.Audit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := fullCatCounts(t, st)
	byLabel := map[string]int{}
	for _, kv := range bundle.Categories {
		byLabel[kv.Name] = kv.Value
	}
	for _, c := range AuditCategories {
		if byLabel[c.Label] != want[c.Key] {
			t.Errorf("类别卡「%s」显示 %d，库里是 %d", c.Label, byLabel[c.Label], want[c.Key])
		}
	}
}

// TestAuditCategoryCountsCacheActuallyCaches 证明增量真的生效——
// 没有这一条的话，一个「每次都整体重算」的实现同样能通过上面所有断言，
// 而本轨道要修的恰恰就是那个实现。
//
// 判据用缓存里的 maxID 而不是计时：耗时断言在这么小的库上分辨不出两者。
func TestAuditCategoryCountsCacheActuallyCaches(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	recordN(t, st, ctx, "access", "2026-05-06 08:00:00", 3)
	if _, err := st.auditCategoryCounts(ctx); err != nil {
		t.Fatal(err)
	}
	st.auditCats.mu.Lock()
	ready, maxID := st.auditCats.ready, st.auditCats.maxID
	st.auditCats.mu.Unlock()
	if !ready || maxID == 0 {
		t.Fatalf("第一次调用之后缓存应当已就绪（ready=%v maxID=%d）", ready, maxID)
	}

	// 一行都没新增时，必须命中"直接返回"分支：把这一行删掉（改成每次重算）
	// 用例仍然会绿——所以这里进一步用一个只有缓存分支看得见的手法验证：
	// 直接改写缓存里的计数，若实现走了整体重算，这个假值会被覆盖掉。
	st.auditCats.mu.Lock()
	st.auditCats.counts["access"] = 9999
	st.auditCats.mu.Unlock()
	got, err := st.auditCategoryCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got["access"] != 9999 {
		t.Fatalf("没有新增行时应当直接返回上次的结果（这里用一个不可能的值证明它没重算），实际 %v", got)
	}

	// 再落一条：增量分支会在那个假值基础上累加，于是 9999+1。
	// 这同时证明了增量确实是"以上次结果为基数"，而不是重头数。
	recordN(t, st, ctx, "access", "2026-05-06 09:00:00", 1)
	got, err = st.auditCategoryCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got["access"] != 10000 {
		t.Fatalf("增量分支应当在上次结果上累加（9999+1），实际 %v", got)
	}
}

// TestAuditCatSQLBoundedByMaxID 钉住「计数集合按刚读到的 maxID 封上界」。
//
// ★守的是一条**单调向上、且几十天不自愈**的重复计数竞态（复核实测复现过：库里真实 4 条、
// 缓存回 5）。`SELECT MAX(id)` 与随后的 GROUP BY 是两条独立语句，两者之间提交的行会被
// 本轮计入，而 c.maxID 只停在刚读到的那个值——下一轮 `WHERE id > c.maxID` 把它们再数一遍。
// 偏差只有在留存清理换掉 minID 或进程重启时才被重算。
//
// 症状是审计页那四张卡（副标题「条 · 累计留痕」）加起来**比库里的总行数多**，
// 而列表 / CSV / 外送三个出口都对得上，没有任何一处报错。
//
// 这里用**行为**断言而不是源码文本断言：真正要守的是「上界之后的行不进这一轮计数」，
// 而竞态窗口本身（两条语句之间的并发提交）在测试里造不出确定性，只能钉它的结构性前提。
func TestAuditCatSQLBoundedByMaxID(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// ★基线不是 0：openTestStore 建库时就会落下若干审计行（种子/迁移），
	//   断言必须相对基线算，写死 4 的话用例自己先红（第一版就是这么错的）。
	var base int64
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&base); err != nil {
		t.Fatal(err)
	}
	recordN(t, st, ctx, "access", "2026-01-02 10:00:00", 4)
	var hi int64
	if err := st.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM audit_log`).Scan(&hi); err != nil {
		t.Fatal(err)
	}
	// 模拟「两条语句之间又提交了几行」——生产里这是并发写，这里显式造出来
	recordN(t, st, ctx, "access", "2026-01-02 10:00:01", 3)

	countWith := func(q string, args ...any) int {
		rows, err := st.db.QueryContext(ctx, q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		total := 0
		for rows.Next() {
			var cat string
			var n int
			if err := rows.Scan(&cat, &n); err != nil {
				t.Fatal(err)
			}
			total += n
		}
		return total
	}

	// 全表分支：上界 hi 之后那 3 行不该进来
	if got := countWith(auditCatFullSQL, hi); int64(got) != base+4 {
		t.Errorf("全表分支必须按 maxID 封上界：期望 %d（基线 %d + 4；hi 之后新增的 3 行不计），实得 %d。\n"+
			"不封上界的话，这 3 行本轮被数一次、下一轮 `id > c.maxID` 再数一次——"+
			"偏差单调向上且只有重启或留存清理才会被重算", base+4, base, got)
	}
	// 增量分支：(lo, hi] 半开区间，同样不该越过 hi
	if got := countWith(auditCatSinceSQL, int64(0), hi); int64(got) != base+4 {
		t.Errorf("增量分支必须是 (lo, hi] 而不是 id > lo：期望 %d，实得 %d", base+4, got)
	}
	// 反面：把上界放开，7 行都在——证明上面两条不是因为行根本没落库
	if got := countWith(auditCatFullSQL, int64(1)<<40); int64(got) != base+7 {
		t.Fatalf("测试前提不成立：放开上界应得 %d 行，实得 %d", base+7, got)
	}
}
