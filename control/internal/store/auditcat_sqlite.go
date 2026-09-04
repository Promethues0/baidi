package store

import (
	"context"
	"sync"
)

// ── 审计分类计数的增量缓存 ──
//
// 改造前 Audit() 每次请求都跑一条**无 WHERE** 的
// `SELECT category, COUNT(*) FROM audit_log GROUP BY category`：200 万行实测 1.32s
// （建了 ts 索引之后 planner 改走覆盖索引，1.45s，一样慢），
// 而大屏（BigScreen.vue）每 15s 就同时打 /overview + /online + /audit 三发。
// 这条查询是审计页那一发里最大的一块，且**加索引救不了它**——没有 WHERE，
// 无论走表还是走覆盖索引都得看完每一行（还得再排一次序）。
// 改造后同一台机器上这一步是 0.044ms（首屏整发 1859ms → 22ms）。
//
// ★为什么不是「改成按 ts 窗口算」（最省事的那条路，这里刻意没走）：
// 审计页那四张分类卡的副标题逐字写着「条 · 累计留痕」。把分子悄悄换成「最近 24h」
// 而标签仍写「累计」，正是本仓最忌讳的那类改动——数字变了、接口 200、页面不报错，
// 没有任何人看得出它现在数的是别的东西。要改语义就得连页面文案一起改，
// 那不在本轨道的范围里；本轨道只负责把**重复计算**去掉，语义一字不动。
//
// 增量为什么成立：audit_log 的写入形态是「只追加 + 只从头部整段删」——
// RecordAudit 只 INSERT；两条留存路径（按天、按水位）共用 purgeAuditBefore，
// 而它按 `id <= 边界` 删一段连续前缀（这是链锚点能成立的前提，见那里的注释）。
// 这个形态下，(minID, maxID, counts) 三元组就足以判断该不该增量：
//   - maxID 变大 → 只对 `id > 上次 maxID` 那一段做 GROUP BY（实测 2ms）再累加；
//   - minID 变了（头部被清理过）→ 整体重算；
//   - 两者都没变 → 直接返回上次的结果。
//
// 缓存**完全派生自表**：不落库、不由 RecordAudit 反向写入、进程重启即重算。
// 它不是第二个真相来源——库里少一行，下一次读就少一条，没有"忘了同步"这种失效形态。
//
// ★两个坑，都实测过：
//
//  ① `SELECT MIN(id), MAX(id) FROM audit_log` 写成一条语句时，SQLite 的 min/max
//     优化**不生效**（那条优化只对"整条查询里只有一个聚合函数"成立），退化成全表扫，
//     200 万行实测 235ms——那样这层缓存每次先付 235ms，等于白做。
//     拆成两条各自 O(log n) 的语句后各 <1ms。别再把它们合回去。
//
//  ② 若有人绕开 purgeAuditBefore 直接 DELETE 掉中间某一行，min/max 都不变，
//     这份计数会**一直**偏大，直到下一次头部清理或进程重启。不为它再加一道更贵的
//     探针（比如每次都 COUNT(*) 对账）是有意的：那种改动本身就是防篡改链要抓的事，
//     VerifyAuditChain 会当场指出断点，而这里多花的钱要由每一次正常请求来付。

// auditCatCache 分类计数缓存的三元组。零值 = 尚未算过（ready=false）。
type auditCatCache struct {
	mu     sync.Mutex
	ready  bool
	minID  int64
	maxID  int64
	counts map[string]int
}

// auditCategoryCounts 返回 audit_log **全表**按 category 的计数（键为 category 机读值）。
// 语义与改造前那条全表 GROUP BY 逐字相同，只是不再每请求重算一遍。
func (s *SQLiteStore) auditCategoryCounts(ctx context.Context) (map[string]int, error) {
	c := &s.auditCats
	// 探针查询放在锁内：并发两发 Audit() 时，锁外读到的 min/max 与锁内看到的缓存
	// 可能来自不同时刻，判定会退化成"每次都整体重算"——正确但把优化全吃掉了。
	c.mu.Lock()
	defer c.mu.Unlock()

	var minID, maxID int64
	// 两条独立语句，理由见文件头 ①。
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MIN(id),0) FROM audit_log`).Scan(&minID); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM audit_log`).Scan(&maxID); err != nil {
		return nil, err
	}

	// 增量的前提：头部没被删过（minID 未变）且尾部只长不缩（maxID 未倒退）。
	// 任一条不成立就整体重算——包括空表（minID=maxID=0）这种边界。
	incremental := c.ready && c.minID == minID && c.maxID <= maxID
	if incremental && c.maxID == maxID {
		return cloneCounts(c.counts), nil // 一行都没新增
	}

	// ★计数集合必须按**刚读到的 maxID** 封上界，与随后存进缓存的 (minID, maxID) 严格一致。
	//
	// 不封的话有一条单调向上、且几十天不自愈的重复计数竞态：`SELECT MAX(id)` 与这条
	// GROUP BY 是两条独立语句，两者之间提交的行会被本轮计入（全表分支根本没有上界；
	// 增量分支的下界是**上一轮**的 c.maxID），而 c.maxID 只停在刚读到的那个值——
	// 于是下一轮 `WHERE id > c.maxID` 把这批行**再数一遍**。
	// 偏差只在留存清理换掉 minID 或进程重启时才被重算，中间可能是几十天。
	// 症状：审计页那四张卡（副标题写着「条 · 累计留痕」）加起来比库里的总行数**多**，
	// 而列表 / CSV / 外送三个出口的行数都对得上，没有任何一处报错——
	// 与本文件上方注释点名批评过的老缺陷同族、方向相反。
	// audit_log 是全系统写入最快的表，窗口一点都不窄。
	q, args := auditCatFullSQL, []any{maxID}
	counts := map[string]int{}
	if incremental {
		q, args = auditCatSinceSQL, []any{c.maxID, maxID}
		counts = cloneCounts(c.counts)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cat string
		var n int
		if err := rows.Scan(&cat, &n); err != nil {
			return nil, err
		}
		counts[cat] += n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	c.ready, c.minID, c.maxID, c.counts = true, minID, maxID, counts
	return cloneCounts(counts), nil
}

// auditCatFullSQL / auditCatSinceSQL 抽成常量是为了让 EQP 守卫（audit_index_test.go）
// 测的就是**生产在跑的那两条**——测试里另抄一份 SQL 的话，改了生产语句而守卫仍绿。
const (
	// 两条都带 id 上界（见上方那段竞态说明）。空表时 maxID=0，全表分支自然返回空，语义不变。
	auditCatFullSQL  = `SELECT category, COUNT(*) FROM audit_log WHERE id <= ? GROUP BY category`
	auditCatSinceSQL = `SELECT category, COUNT(*) FROM audit_log WHERE id > ? AND id <= ? GROUP BY category`
)

// cloneCounts 返回一份拷贝：缓存里那张表是共享的，直接交出去等于把内部状态
// 暴露给调用方随手改（类别只有个位数，拷贝成本可忽略）。
func cloneCounts(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
