package store

import "context"

// ── 监控中心 · 在线用户（实时会话）──

// OnlineSession 一条实时在线会话。监控中心据此做"就近处置"（强制下线）。
// OnlineSession 一条真实接入会话（唯一来源：网关注册心跳里的 sessions）。
//
// ★网关按会话上报的只有四样东西：`{IP, User, Role, Since}`（见 api.GwSession）。
// 其余每一格要么由控制面**按账号**从库里取真值，要么就不该存在——
// 曾经这里有 Location / Device / OS / App 四个字段，全部由 api.handleOnline
// 逐条填 "—"，页面上并排渲染成四列永远空着的表头；而「异地·公网接入」那个 KPI
// 与筛选页签因此**结构性恒为 0**（判据是 location 含「异地」或「公网」，
// 而 location 永远是那个破折号）。一个永远匹配不到东西的筛选比没有筛选更坏：
// 它让人以为「查过了，没有异地接入」。四个字段连同那个 KPI 已整体删除——
// 白帝没有 GeoIP 库（SCOPE 也不打算做），网关也不按会话上报设备与当前应用。
type OnlineSession struct {
	ID      string `json:"id"`
	User    string `json:"user"`    // 显示名
	Account string `json:"account"` // 登录账号
	// Org 该账号所属组织（users.org_id → 组织名）。取不到显示「—」，那是真的没归属。
	Org string `json:"org"`
	IP  string `json:"ip"`
	// Auth 接入方式。会话经 SPA 敲门 + 隧道建立，这是它唯一确定的事实——
	// **不是**登录因子（口令/MFA/证书）：那发生在控制面登录时，与这条隧道会话不同源，
	// 网关也无从得知。页面表头据此写「接入方式」而不是「认证方式」。
	Auth     string `json:"auth"`
	Gateway  string `json:"gateway"` // 接入网关
	LoginAt  string `json:"loginAt"`
	Duration string `json:"duration"` // 在线时长
	// Trust 该**账号**名下终端的授信态：trusted | untrusted | unknown。
	//
	// ★这是账号级判断，不是"这条会话背后那台机器"——网关的会话上报里没有设备指纹，
	// 控制面无从知道是哪台机器建的这条隧道。判据：名下有 revoked/pending 的设备即
	// untrusted；全部 trusted 才是 trusted；**一台都没登记过就是 unknown**。
	// 此前这一格对每条真实会话硬编码 "trusted"——那不是补 0，是**正向断言**：
	// observe 模式下被放行的未授信终端在这一页上显示为「授信」，
	// 与项目在网关指标与 posture 上立的「采不到就报不可判定」纪律方向相反。
	Trust string `json:"trust"`
	// TrustNote 上面那个结论的依据（"名下 3 台终端：2 已授信 / 1 已吊销"），
	// 页面挂 title。只给结论不给依据，管理员没法判断该不该处置。
	TrustNote string `json:"trustNote,omitempty"`
	// Risk 该账号的终端合规风险档：none | low | high | unknown。
	// 判据是 posture 的跨设备最差判定（与降权/阻断执行的是同一份）：
	// block/degrade → high，gray → low，allow → none，**从未上报 → unknown**。
	Risk string `json:"risk"`
	// RiskNote 判定理由（posture 的 reasons），页面挂 title。
	RiskNote   string `json:"riskNote,omitempty"`
	Status     string `json:"status"` // online | offline（已被强制下线）
	KickReason string `json:"kickReason,omitempty"`
}

// 在线会话的授信态与风险档取值。unknown 是**一等取值**，不是缺省占位。
const (
	SessionTrustTrusted   = "trusted"
	SessionTrustUntrusted = "untrusted"
	SessionTrustUnknown   = "unknown"

	SessionRiskNone    = "none"
	SessionRiskLow     = "low"
	SessionRiskHigh    = "high"
	SessionRiskUnknown = "unknown"
)

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
	State string `json:"state"` // block | degrade | gray | locked | disabled
	Risk  string `json:"risk"`  // none | low | high
	// Online 此刻有没有在线网关上报着这个账号的接入会话。
	//
	// ★三态指针，**缺席 = 不可判定**：控制面此刻一台在线网关都没有（心跳断了 /
	// 刚重启 / mTLS 口挂了）时，"谁连着"这件事**没有数据源**，而敲门与隧道
	// 并不受影响——用户可能正连着。由 api.handleUserState 现算填入。
	//
	// 改造前是 bool：无在线网关时整页绿点全灭、一句提示都没有。这一页的定位
	// 写在它自己的注释里——"就近处置：要不要现在踢他，取决于他现在有没有连着"，
	// 把"不知道"渲染成"已经离线了"，管理员就不会动手。
	Online    *bool    `json:"online,omitempty"`
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
		{ID: "u-ext-zhao", User: "外包-赵磊", Account: "ext.zhao", Org: "外部协作 / 驻场", State: DisposalBlock, Risk: "high", Reasons: []string{"磁盘未加密", "终端防护未在线"}, LastEvent: "终端环境不合规，接入已阻断", LastSeen: "2 分钟前"},
		{ID: "u-ext-sun", User: "外包-孙伟", Account: "ext.sun", Org: "外部协作 / 远程", State: DisposalDegrade, Risk: "high", Reasons: []string{"系统完整性保护未开启"}, LastEvent: "高敏资源已暂停访问（降权，普通资源不受影响）", LastSeen: "5 分钟前"},
		{ID: "u-svc-bot-04", User: "svc-bot-04", Account: "svc.bot.04", Org: "系统账号 / 自动化", State: DisposalDegrade, Risk: "high", Reasons: []string{"客户端版本过低"}, LastEvent: "高敏资源已暂停访问（降权，普通资源不受影响）", LastSeen: "1 分钟前"},
		{ID: "u-chen-jing", User: "陈静", Account: "chen.jing", Org: "市场中心 / 品牌组", State: DisposalGray, Risk: "low", Reasons: []string{"主机防火墙未开启"}, LastEvent: "灰度观察中（访问权未变更）", LastSeen: "8 分钟前"},
		{ID: "u-wu-min", User: "吴敏", Account: "wu.min", Org: "财务中心 / 资金组", State: DisposalGray, Risk: "low", Reasons: []string{"操作系统版本落后"}, LastEvent: "灰度观察中（访问权未变更）", LastSeen: "12 分钟前"},
		{ID: "u-li-fang", User: "李芳", Account: "li.fang", Org: "研发中心 / 测试组", State: "locked", Risk: "high", Reasons: []string{"连续 5 次口令错误，账号已锁定", "疑似暴力破解"}, LastEvent: "账号锁定（自动）", LastSeen: "31 分钟前"},
		{ID: "u-zhang-wei", User: "张伟", Account: "zhang.wei", Org: "销售中心 / 华南", State: "disabled", Risk: "none", Reasons: []string{"离职流程已触发，账号被禁用"}, LastEvent: "管理员禁用账号", LastSeen: "3 天前"},
		{ID: "u-zhao-lei2", User: "赵雷", Account: "zhao.lei", Org: "人力中心", State: "disabled", Risk: "none", Reasons: []string{"长期未登录，已临时停用"}, LastEvent: "策略自动停用", LastSeen: "21 天前"},
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

// ── 终端版本分布（FR-UPG-19 AC-12：灰度放开的决策依据）──

// ClientVersionStat 一个 (平台, 客户端版本) 桶的终端数。
//
// ★这是全系统唯一权威的「谁在跑哪个版本」：灰度计划只决定「告诉谁有新版」，
// 不决定任何人**实际**装了什么（客户端不自动下载、不自动安装）。
// 管理员把比例从 10% 调到 50% 之前要看的正是这份分布——改造前它根本不存在，
// AC-12「先小范围验证再放开」在真机上无从验证。
type ClientVersionStat struct {
	Platform string `json:"platform"`
	// Version 客户端自报版本。**空串保留为一个独立的桶**（渲染成「未上报」），
	// 绝不并进任何一个具体版本里——把它算进稳定版会让「有一批终端根本没报过版本」
	// 这件事消失，而那批机器恰恰是升级里最需要盯的。
	Version string `json:"version"`
	Count   int    `json:"count"`
}
