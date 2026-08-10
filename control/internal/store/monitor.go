package store

import "context"

// ── 监控中心 · 在线用户（实时会话）──

// OnlineSession 一条实时在线会话。监控中心据此做"就近处置"（强制下线）。
type OnlineSession struct {
	ID         string `json:"id"`
	User       string `json:"user"`    // 显示名
	Account    string `json:"account"` // 登录账号
	Org        string `json:"org"`
	IP         string `json:"ip"`
	Location   string `json:"location"` // 接入地点（GeoIP 推断）
	Device     string `json:"device"`
	OS         string `json:"os"`
	Auth       string `json:"auth"`    // 认证方式
	App        string `json:"app"`     // 当前访问应用
	Gateway    string `json:"gateway"` // 接入网关
	LoginAt    string `json:"loginAt"`
	Duration   string `json:"duration"` // 在线时长
	Trust      string `json:"trust"`    // trusted | untrusted | unknown
	Risk       string `json:"risk"`     // none | low | high
	Status     string `json:"status"`   // online | offline（已被强制下线）
	KickReason string `json:"kickReason,omitempty"`
}

// ★曾经这里有一份 10 条的演示会话种子（李明/王芳/外包-赵磊…），由
// api.handleOnline 在「没有网关上报真实会话」时回退渲染。已整体删除：
// 「在线用户」是安全读数——管理员看着 10 条编造的在线会话，得到的是
// "系统正在被使用、接入链路是通的"这种错误的安全感，而真实情况可能是
// 一台网关都没起。无网关上报时正确的答案是空态，不是好看的假数据。
// 会话现在**只有一个来源**：网关注册心跳里的 sessions（见 api.handleOnline）。

// ── 监控中心 · 用户状态（风险 / 异常态势）──

// UserStateBucket 状态分桶聚合（聚合头的计数卡）。
type UserStateBucket struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
	Tone  string `json:"tone"` // danger | warning | info | normal
}

// UserStateItem 一名受关注用户的当前态势。
type UserStateItem struct {
	ID      string `json:"id"`
	User    string `json:"user"`
	Account string `json:"account"`
	Org     string `json:"org"`
	// State 用户当前所处的档位。★口径与风险引擎的处置四档**统一**：
	// block / degrade / gray 直接就是 risk.Verdict.Disposal 的取值，
	// locked / disabled 是与风险正交的目录账号状态（优先级高于风险档）。
	//
	// 此前这里是另一套名字（risk-high / risk-low / idle），与四档没有任何对应关系：
	// 同一个"被降权的用户"在安全中心叫 degrade、在用户状态页叫 risk-low，
	// 管理员无法判断两处说的是不是同一件事，也无法从这页看出「谁正在被降权」。
	// idle（空闲挂起）一并删除——它从来没有真实来源，真实实现恒为 0。
	State     string   `json:"state"` // block | degrade | gray | locked | disabled
	Risk      string   `json:"risk"`  // none | low | high
	Online    bool     `json:"online"`
	Reasons   []string `json:"reasons"` // 命中的风险 / 异常原因
	LastEvent string   `json:"lastEvent"`
	LastSeen  string   `json:"lastSeen"`
	// BruteLocked 该账号当前有生效的登录防爆破锁定（login_lockouts）。只由 api 层
	// 叠加（overlayBruteLocks），store 实现不填——它与目录 status=locked 是两种锁：
	// 前者到期自动解除、解锁走 /security/lockouts/unlock；后者是管理员权威状态、
	// 解锁走 /users/{id}/status。控制台的「就地解锁」按此字段选路。
	BruteLocked bool `json:"bruteLocked,omitempty"`
}

// UserStateBundle 用户状态页：分桶聚合 + 受关注用户清单。
type UserStateBundle struct {
	Buckets []UserStateBucket `json:"buckets"`
	Items   []UserStateItem   `json:"items"`
}

// UserStates 返回演示用的用户态势数据。
func (m *Memory) UserStates(_ context.Context) (UserStateBundle, error) {
	items := []UserStateItem{
		{ID: "u-ext-zhao", User: "外包-赵磊", Account: "ext.zhao", Org: "外部协作 / 驻场", State: DisposalBlock, Risk: "high", Online: true, Reasons: []string{"磁盘未加密", "终端防护未在线"}, LastEvent: "终端环境不合规，接入已阻断", LastSeen: "2 分钟前"},
		{ID: "u-ext-sun", User: "外包-孙伟", Account: "ext.sun", Org: "外部协作 / 远程", State: DisposalDegrade, Risk: "high", Online: true, Reasons: []string{"系统完整性保护未开启"}, LastEvent: "高敏资源已暂停访问（降权，普通资源不受影响）", LastSeen: "5 分钟前"},
		{ID: "u-svc-bot-04", User: "svc-bot-04", Account: "svc.bot.04", Org: "系统账号 / 自动化", State: DisposalDegrade, Risk: "high", Online: true, Reasons: []string{"客户端版本过低"}, LastEvent: "高敏资源已暂停访问（降权，普通资源不受影响）", LastSeen: "1 分钟前"},
		{ID: "u-chen-jing", User: "陈静", Account: "chen.jing", Org: "市场中心 / 品牌组", State: DisposalGray, Risk: "low", Online: true, Reasons: []string{"主机防火墙未开启"}, LastEvent: "灰度观察中（访问权未变更）", LastSeen: "8 分钟前"},
		{ID: "u-wu-min", User: "吴敏", Account: "wu.min", Org: "财务中心 / 资金组", State: DisposalGray, Risk: "low", Online: true, Reasons: []string{"操作系统版本落后"}, LastEvent: "灰度观察中（访问权未变更）", LastSeen: "12 分钟前"},
		{ID: "u-li-fang", User: "李芳", Account: "li.fang", Org: "研发中心 / 测试组", State: "locked", Risk: "high", Online: false, Reasons: []string{"连续 5 次口令错误，账号已锁定", "疑似暴力破解"}, LastEvent: "账号锁定（自动）", LastSeen: "31 分钟前"},
		{ID: "u-zhang-wei", User: "张伟", Account: "zhang.wei", Org: "销售中心 / 华南", State: "disabled", Risk: "none", Online: false, Reasons: []string{"离职流程已触发，账号被禁用"}, LastEvent: "管理员禁用账号", LastSeen: "3 天前"},
		{ID: "u-zhao-lei2", User: "赵雷", Account: "zhao.lei", Org: "人力中心", State: "disabled", Risk: "none", Online: false, Reasons: []string{"长期未登录，已临时停用"}, LastEvent: "策略自动停用", LastSeen: "21 天前"},
	}
	count := func(states ...string) int {
		n := 0
		for _, it := range items {
			for _, st := range states {
				if it.State == st {
					n++
				}
			}
		}
		return n
	}
	return UserStateBundle{Buckets: userStateBuckets(count), Items: items}, nil
}

// userStateBuckets 分桶定义的**唯一出处**（种子与 SQLite 真实现共用）。
// 两处各写一份的话，键名一改就会出现"演示态与真实态的桶对不上、前端筛选失灵"。
func userStateBuckets(count func(states ...string) int) []UserStateBucket {
	return []UserStateBucket{
		{Key: DisposalBlock, Label: "已阻断", Count: count(DisposalBlock), Tone: "danger"},
		{Key: DisposalDegrade, Label: "已降权", Count: count(DisposalDegrade), Tone: "warning"},
		{Key: DisposalGray, Label: "灰度观察", Count: count(DisposalGray), Tone: "info"},
		{Key: "locked", Label: "锁定账号", Count: count("locked"), Tone: "danger"},
		{Key: "disabled", Label: "禁用账号", Count: count("disabled"), Tone: "normal"},
	}
}
