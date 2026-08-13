package store

import "context"

// ── 运营报表（PRD ch15）────────────────────────────────────────────────────
//
// 报表不引入任何新的数据采集：每一个数字都是对**既有真实落库**（audit_log、alerts）
// 的 SQL 聚合。没有独立的"报表事实表"，也就没有"报表与审计对不上"这种事——
// 分歧只能来自聚合口径，而口径写死在 OpsReport 各字段的注释里。
//
// ★归 PermAudit 而不是 PermSystem：报表的原料是审计正文（谁登录了几次、谁被拒了），
// 三权分立下安全/系统管理员本就读不到 /api/v1/audit*，给系统管理员一份"聚合过的
// 审计"等于开了条侧门——聚合并不脱敏，登录次数榜单本身就是行为数据。
// 路由因此也挂在 /api/v1/audit/report 下，维持「审计管理员只读 /api/v1/audit*」
// 这条既有约定原样成立。

// OpsReport 一次运营报表。
type OpsReport struct {
	// Days 实际聚合的天数；Since 窗口起点（含）。
	Days  int    `json:"days"`
	Since string `json:"since"` // YYYY-MM-DD
	// Truncated 请求窗口被审计留存策略截短（与设备状态时序的留存截断同一条纪律：
	// 留存 30 天时报"90 天报表"，前 60 天会是一排真实存在过、但已被清理的 0——
	// 那不是"没发生"，必须如实说"更早的数据已按留存策略清理"）。
	Truncated  bool     `json:"truncated"`
	RetainDays int      `json:"retainDays"` // 0=未配置滚动清理
	Daily      []OpsDay `json:"daily"`
	Totals     OpsTotal `json:"totals"`
	// TopLogin / TopDenied 窗口内登录成功次数 / 被拒（deny+fail）次数最多的账号（≤8）。
	TopLogin  []KV      `json:"topLogin"`
	TopDenied []KV      `json:"topDenied"`
	Alerts    OpsAlerts `json:"alerts"`
}

// OpsDay 一天的聚合行。
//
// ★与设备状态"空桶不返回"相反，这里**补全零日**：指标是采样，缺样 ≠ 0；
// 审计是全量落库，窗口内某天 COUNT=0 就是真的零条（留存截断的那段除外，
// 它们根本不进 Daily——见 Truncated）。断开的折线适合采样，连续的表格适合台账。
type OpsDay struct {
	Date        string `json:"date"` // YYYY-MM-DD
	AuthOK      int    `json:"authOk"`
	AuthFail    int    `json:"authFail"`
	AccessAllow int    `json:"accessAllow"`
	AccessDeny  int    `json:"accessDeny"` // access 类 verdict ∈ {deny, fail}
	AdminOps    int    `json:"adminOps"`   // category ∈ {admin, system}
	Security    int    `json:"security"`
	Total       int    `json:"total"` // 该日全部审计条目（含未列入前几列的 mfa / dataplane 等）
}

// OpsTotal 窗口合计。
type OpsTotal struct {
	Entries int `json:"entries"`
	// ActiveAccounts 窗口内至少成功登录过一次的去重账号数（category=auth, verdict=ok）。
	ActiveAccounts int `json:"activeAccounts"`
	AuthOK         int `json:"authOk"`
	AuthFail       int `json:"authFail"`
	AccessAllow    int `json:"accessAllow"`
	AccessDeny     int `json:"accessDeny"`
	AdminOps       int `json:"adminOps"`
	Security       int `json:"security"`
}

// OpsAlerts 窗口内业务告警的聚合（alerts 表，按 triggered_at 过滤）。
type OpsAlerts struct {
	Total      int  `json:"total"`
	Pending    int  `json:"pending"`
	BySeverity []KV `json:"bySeverity"` // critical / warning / info 固定序，缺失计 0
}

// OpsReporter 运营报表的读口。
//
// ★独立接口、刻意不进 Store（照 UpgradeStore 的先例）：报表是对真实历史的 SQL 聚合，
// Memory 种子没有可聚合的历史——给它编一份假实现，恰是「设备状态/业务告警两页
// 刻意例外」那条纪律要防的东西：编造的报表与真实聚合在页面上无法区分。
// api 层按类型断言探测，探不到就如实说当前存储不支持。
type OpsReporter interface {
	OpsReport(ctx context.Context, days int) (OpsReport, error)
}
