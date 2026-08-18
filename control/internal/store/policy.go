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
// 同批（wave8 行动 13-①）又摘掉了 OrgNode.HasCustom：它读的是 policy_overrides，
// 而那张表存的 8 个设置项**全仓零消费方**——一个「该节点定了自定义策略」的标记，
// 指向的是一份谁也不执行的配置。
type PolicyBundle struct {
	Tree []OrgNode `json:"tree"`
}

// OrgNode 组织节点（含子树人数合计）。
type OrgNode struct {
	Key      string    `json:"key"`
	Title    string    `json:"title"`
	Members  int       `json:"members"`
	Children []OrgNode `json:"children,omitempty"`
}

// ★这里刻意**没有** (m *Memory) PolicyBundle：种子版本连同它那棵「华东大区 / 华南大区」
// 的虚构继承树一起删了。留着它的唯一后果是给 SQLiteStore 留一条静默回退的路——
// 现在 PolicyBundle 只有 SQLiteStore 一份实现，哪天有人把它删掉是编译错误，
// 而不是页面上悄悄换回四个不存在的大区。

// ★注意（wave8 行动 13-①）：PolicyBundle **已不再有任何 HTTP 消费方**。
// 「策略管理 → 用户策略」那套继承编辑器整批摘除后，这棵树只剩 orgs_sqlite.go 里
// 的构建实现与它自己的用例。刻意保留而不删：它是从 org_units 真实构建的，
// 将来若要把接入策略做成"按组织分级"（PRD FR-POLICY-02~05），它就是现成的取数；
// 但**在那之前它不该出现在任何页面上**——一棵能点开、点开却什么都改不了的树，
// 与此前那套假编辑器是同一种误导。
