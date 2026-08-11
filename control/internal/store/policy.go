package store

// PolicyBundle 策略管理页所需的组织/组继承树。
//
// ★原来还有一个 List []UserPolicy 字段（5 条「销售部高敏策略 / 86 人 / 2026-06-20 14:32」
// 之类的清单），已整体删除。它是「方法实现了、字段仍来自种子」的第三例，也是最没有
// 辩护余地的一个：SQLiteStore.PolicyBundle 以 s.Memory.PolicyBundle(ctx) 打底、
// 只把 Tree 换成真实组织树，List 原样继承 5 条编造记录——**而控制台从来没有渲染过它**。
// 一份没有消费方的假数据仍然是假数据：它会经 GET /api/v1/policies 原样出现在接口响应里，
// 下一个照着响应写页面的人会理所当然地把它画出来。
//
// 真实存在的"自定义策略"事实是 policy_overrides 表，它已经通过 OrgNode.HasCustom
// 出现在树上（哪个节点自己定了、哪个继承父级），不需要第二份互相矛盾的清单。
type PolicyBundle struct {
	Tree []OrgNode `json:"tree"`
}

// OrgNode 组织/用户组节点，承载"是否有自定义策略"用于继承可视化。
type OrgNode struct {
	Key       string    `json:"key"`
	Title     string    `json:"title"`
	HasCustom bool      `json:"hasCustom"` // 该节点是否定义了自定义策略（否则继承父级）
	Members   int       `json:"members"`
	Children  []OrgNode `json:"children,omitempty"`
}

// ★这里刻意**没有** (m *Memory) PolicyBundle：种子版本连同它那棵「华东大区 / 华南大区」
// 的虚构继承树一起删了。留着它的唯一后果是给 SQLiteStore 留一条静默回退的路——
// 现在 PolicyBundle 只有 SQLiteStore 一份实现，哪天有人把它删掉是编译错误，
// 而不是页面上悄悄换回四个不存在的大区。
