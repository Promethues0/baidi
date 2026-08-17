// Package store 定义白帝控制中心的数据访问接口与内存实现（首版 mock，
// 后续替换为 SQLite/PostgreSQL，接口不变）。
package store

import "context"

// Store 控制中心数据访问接口。模块处理器只依赖此接口，便于切换持久化后端。
type Store interface {
	// Overview 态势总览。windowHours 是审计派生统计的时间窗（<=0 取默认 24h）。
	// ★窗口只对审计派生的那几项生效；账号/终端两条防线是当前状态快照，
	// 由 DefenseLine.Scope 逐条标出（见那里的注释）。
	Overview(ctx context.Context, windowHours int) (Overview, error)
	PolicyBundle(ctx context.Context) (PolicyBundle, error)
	Apps(ctx context.Context) (AppBundle, error)
	// AppCategories 应用分类字典（app_categories 表，含各分类下的应用数）。
	// Apps() 的分类筛选条由它构建；管理台的分类维护弹窗也读它。
	AppCategories(ctx context.Context) ([]AppCategoryDef, error)
	Users(ctx context.Context) (UserDirBundle, error)
	Devices(ctx context.Context) (DeviceBundle, error)
	// DeviceByFingerprint 授信终端准入闸的取数点（api.deviceAdmissionGate）：
	// 敲门令牌签发前查「这个账号名下的这个指纹是什么状态」。
	DeviceByFingerprint(ctx context.Context, account, fingerprint string) (Device, bool, error)
	// DeviceTrustSetting 准入模式（observe|strict）与绑定方式（auto|approval）。
	// 敲门闸与设备登记分别消费这两项——没有真实消费方的开关不进这个结构体。
	DeviceTrustSetting(ctx context.Context) (DeviceTrustSetting, error)
	Audit(ctx context.Context) (AuditBundle, error)
	// ★这里曾经有 Gateway(ctx) (GatewayBundle, error)：网关与隐身页的「华东/华南
	// 出口」区域拓扑。它已从 Store 移除而不是补一份 SQLite 实现——网关的权威事实
	// 不在库里，而在 api.Server.gateways（mTLS 注册心跳的在线登记，与 GET /gateways、
	// diag 的 checkGateways/checkStealth 同源）。落一张网关表反而会造出第二个真相。
	System(ctx context.Context) (SystemBundle, error)
	AuthSrc(ctx context.Context) (AuthSrcBundle, error)
	Security(ctx context.Context) (SecurityBundle, error)
	Baselines(ctx context.Context) ([]BaselinePolicy, error)
	PostureReports(ctx context.Context) ([]PostureReport, error)
	PostureVerdict(ctx context.Context, account string) (PostureReport, bool, error)
	PostureReportFor(ctx context.Context, user, device string) (PostureReport, bool, error)
	PostureFreshest(ctx context.Context, account string) (PostureReport, bool, error)
	PostureBlockedUsers(ctx context.Context) ([]string, error)
	// PostureUsersByDisposal 任一设备最新判定落在指定处置档的账号。
	// degrade（降权：摘除高敏资源）与 gray（灰度观察：记 observing 审计）的执行方从这里取名单，
	// 见 api.handleGatewayPolicy 与 api.buildProfile。
	PostureUsersByDisposal(ctx context.Context, disposal string) ([]string, error)
	Resources(ctx context.Context) ([]Resource, error)
	// ★这里曾经有 OnlineSessions(ctx) ([]OnlineSession, error)：无网关上报时回退的
	// 10 条演示会话。已移除——在线会话的唯一来源是网关注册心跳（api.Server.gwSess），
	// 没有网关就是空态。安全读数宁可空着，也不能编。
	UserStates(ctx context.Context) (UserStateBundle, error)
	Ipsec(ctx context.Context) ([]IpsecSite, error)
	Objects(ctx context.Context) (ObjectBundle, error)
	ObjectUsage(ctx context.Context) (map[string][]ObjectRef, error)
	ObjectExists(ctx context.Context, kind, id string) (bool, error)
	AuthPolicies(ctx context.Context) ([]AuthPolicy, error)
	Credential(ctx context.Context, account string) (Credential, bool, error)
	// JIT 即时访问：申请单 + 时限授予（真实数据域，Memory 返回空）
	AccessRequests(ctx context.Context) ([]AccessRequest, error)
	AccessRequestsFor(ctx context.Context, user string) ([]AccessRequest, error)
	JitGrants(ctx context.Context) ([]JitGrant, error)
	ActiveGrants(ctx context.Context) ([]JitGrant, error)
	ActiveGrantsFor(ctx context.Context, user string) ([]JitGrant, error)
	// WebAuthn passkey 凭据（真实数据域，Memory 返回空）
	WebauthnCredentialsFor(ctx context.Context, account string) ([]WebauthnCredential, error)
	WebauthnCredentialByID(ctx context.Context, credentialID string) (WebauthnCredential, bool, error)
	WebauthnCredentialCount(ctx context.Context, account string) (int, error)
	// TOTP 二次认证密文行（真实数据域，Memory 恒未注册）
	TotpFor(ctx context.Context, account string) (TotpRecord, bool, error)
	// 网关客户端证书白名单（mTLS 机器身份）
	GatewayCerts(ctx context.Context) ([]GatewayCert, error)
	GatewayCertTrusted(ctx context.Context, fingerprint string) (GatewayCert, bool, error)
	// 组织与用户组（真实数据域，只有 SQLite 实现）
	// SubjectIndex 是「组织子树 / 用户组 → 账号」的展开索引：资源授权的组织与组两维
	// 在控制面靠它展开成账号，网关只收账号。两个判定点（网关策略下发 / 客户端剖面）
	// 必须都从它取答案，见 subjects.go 顶部说明。
	SubjectIndex(ctx context.Context) (SubjectIndex, error)
	// 管理员分级分权（三权分立）。AdminRoleFor 是 api.requirePerm 的取数点：
	// 每次请求现算，角色不进令牌——降权要立刻算数，不能等 8h 会话过期。
	AdminRoles(ctx context.Context) ([]AdminRole, error)
	AdminRoleFor(ctx context.Context, account string) (AdminRole, bool, error)
	// 业务告警（真实数据域，Memory 返回空——刻意不给种子告警，见 alerts.go）。
	// StaleGrants 是「已过期未回收」这条规则的取数点：它要的是**库里那一份**状态，
	// 与 JitGrants 的展示层到期纠正刻意不同源。
	Alerts(ctx context.Context, q AlertQuery) ([]Alert, error)
	AlertRules(ctx context.Context) ([]AlertRule, error)
	AlertCounts(ctx context.Context) (AlertCounts, error)
	StaleGrants(ctx context.Context, before int64) ([]JitGrant, error)
	// GatewayMetrics 监控中心「设备状态」页的取数点：各网关最新一条原始采样 +
	// 查询窗内的降采样时序（PRD ch5 FR-MON-01/02）。降采样在 SQL 里做，
	// 不把 72 小时的原始点整包打给前端；空桶不返回，掉线段在图上表现为断线而非零线。
	GatewayMetrics(ctx context.Context, q MetricsQuery) ([]GatewayMetricSeries, error)
	OrgUnits(ctx context.Context) ([]Org, error)
	UserGroups(ctx context.Context) ([]UserGroup, error)
	GroupMembers(ctx context.Context, groupID string) ([]string, error)
	GroupMemberships(ctx context.Context) (map[string][]string, error)
}

// Overview 态势总览（对应 PRD 第 5 章监控中心的一屏聚合）。
//
// ★整个结构体**没有一个字段来自种子**（见 overview_sqlite.go）：每一项都能指到
// 一张表或一份上报上。改这里加字段时，先回答"这个数从哪张表数出来"——答不上来
// 就别加，页面上多一个说不清出处的数字比少一块面板贵得多。
type Overview struct {
	GeneratedAt string     `json:"generatedAt"`
	Devices     DeviceStat `json:"devices"`
	Users       UserStat   `json:"users"`
	Threats     ThreatStat `json:"threats"`
	// Sessions 当前活跃接入会话数。**store 层恒为 0**：会话的权威事实在网关上报里
	// （api.Server.gwSess），库里没有这回事。由 api.handleOverview 在有在线网关时注入；
	// 没有任何网关上报就是 0——那是"控制面确实不知道有谁接入"的如实表达，
	// 不是"平时都有 186 个人在线"。
	Sessions    int           `json:"sessions"`
	AuditByKind []KV          `json:"auditByKind"`
	Verdicts    []KV          `json:"verdicts"`
	Defense     []DefenseLine `json:"defense"`
	// Attack 近 24h 攻击源统计（数据面拒绝事件的机读聚合，见 attack.go）。
	// ★指针：nil = 本后端没有攻击表（Memory 种子模式），前端整块面板不画——
	// 绝不造种子攻击源，「有没有人在打」这件事只有真实数据有资格回答。
	Attack *AttackStat `json:"attack,omitempty"`
	// ── 统计口径（wave8 行动 9）──
	//
	// ★这一段存在的理由：改造前同一屏上「威胁事件 N」是**建库以来累计**
	// （auditAggregates 那两条 SQL 一个 WHERE 都没有），而「攻击源」是**严格 24 小时**，
	// 标题却写着「实时判定态势」。两个不同口径的数字并排显示、页面一处不标，
	// 而且 BAIDI_AUDIT_RETENTION_DAYS 轮转一到期，那个累计数还会无缘由地往下掉。
	//
	// WindowHours 本次统计的时间窗（小时）。审计派生的那几项（AuditByKind /
	// Verdicts / Threats / Attack）都按它算，只有一个窗口。
	WindowHours int `json:"windowHours"`
	// WindowNote 口径说明，含"实际能覆盖多久"——审计留存期短于所选窗口时，
	// 数据只能回溯到留存期为止，页面必须说出来而不是让人以为查的是全期。
	WindowNote string `json:"windowNote"`
	// Truncated 所选窗口被审计留存期截断了（页面据此加提示）。
	Truncated bool `json:"truncated"`
}

// DeviceStat 授信终端台账统计（trusted_devices 真实计数）。
//
// ★原来是 {Online:186, Total:240, Rate:0.775} 三个凭空数字，页面上写作
// 「在线设备 186 / 240 · 在线率 78%」。"设备此刻是否在线"这件事控制面无从得知：
// 它手上只有设备**台账**（谁登记过、批没批、有没有被吊销），而"在线"只有网关上报的
// 会话知道——那份数据按账号计，没有设备维度，两者接不上。
// 于是口径换成台账本身，每个数都能在 trusted_devices 里数出来。
type DeviceStat struct {
	Total   int `json:"total"`   // 登记在册的终端总数
	Trusted int `json:"trusted"` // 已授信（敲门闸放行的那一档）
	Pending int `json:"pending"` // 待审批绑定
	Revoked int `json:"revoked"` // 已吊销（两种准入模式下都拒）
	// Rate 纳管率 = Trusted/Total；Total=0（一台都没登记）时为 0。
	Rate float64 `json:"rate"`
}

type UserStat struct {
	Total    int `json:"total"`
	Disabled int `json:"disabled"`
	Locked   int `json:"locked"`
}

type ThreatStat struct {
	Rejected  int `json:"rejected"`
	Failed    int `json:"failed"`
	Secondary int `json:"secondary"`
}

// KV 通用的「名称→计数」对，供图表使用。
type KV struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// DefenseLine 三道防线之一（设备/账号/终端）的风险态势。
//
// ★刻意没有 Trend（up | down | flat）字段：趋势要有历史快照才算得出来，而白帝
// 一张历史态势表都没有，种子里那三个箭头（down/up/flat）是纯画上去的。
// 一个永远指着"下降"的绿箭头，比没有箭头更容易让人以为风险在收敛。
type DefenseLine struct {
	Key  string   `json:"key"`  // attack | account | endpoint（SQLite；Memory 种子仍是 device 首格）
	Name string   `json:"name"` // 隐身防线 / 账号防线 / 终端防线
	Risk int      `json:"risk"` // 0-100 风险分（由真实计数粗算，单调可解释，见 riskScore）
	Top  []string `json:"top"`  // TOP 风险实体（真实账号 / 设备，没有就是空）
	// Scope 这条防线的数是**窗口内累计**还是**当前状态**（wave8 行动 9）。
	//
	// ★三条线里只有隐身防线真的按时间窗算：账号防线读的是 users 表的当前状态
	// （锁定/禁用是此刻的属性，不是"这段时间内发生过几次"），终端防线读的是
	// posture_reports 的最新一份（每个 (账号,设备) 只存一行，压根没有历史）。
	// 时间选择器对后两条**不生效**——不标出来的话，管理员切到「近 7 天」看到的
	// 是当前状态，却以为那是七天内的情况。**一个悄悄不生效的筛选比没有筛选更坏。**
	Scope string `json:"scope"` // window | current
	// Note 口径的人话说明（页面挂在卡片上）。
	Note string `json:"note"`
}

// 防线统计口径。
const (
	// ScopeWindow 按所选时间窗聚合。
	ScopeWindow = "window"
	// ScopeCurrent 当前状态快照，与时间窗无关。
	ScopeCurrent = "current"
)

// ── 态势总览的时间窗与 TOP 条数（wave8 行动 9）──

// OverviewTopN 各防线 TOP 风险实体的条数。
// 3 条太少：一台网关下 3 个攻击源在真实扫描里一分钟就填满，看不出面上的形状。
const OverviewTopN = 5

// 态势总览时间窗边界（小时）。
const (
	DefaultOverviewWindowHours = 24
	MinOverviewWindowHours     = 1
	MaxOverviewWindowHours     = 24 * 90
)

// ClampOverviewWindow 把时间窗钳进 [Min,Max]；<=0（未指定）取默认 24h。
//
// ★上界 90 天不是随口定的：审计留存默认 180 天，攻击源小时桶另有留存
// （BAIDI_ATTACK_RETENTION_DAYS 默认 30）——窗口开得比数据存在的时间还长，
// 只会得到一个"越往前越少"的假趋势。真实覆盖范围由 Overview.WindowNote 说明。
func ClampOverviewWindow(h int) int {
	switch {
	case h <= 0:
		return DefaultOverviewWindowHours
	case h < MinOverviewWindowHours:
		return MinOverviewWindowHours
	case h > MaxOverviewWindowHours:
		return MaxOverviewWindowHours
	default:
		return h
	}
}
