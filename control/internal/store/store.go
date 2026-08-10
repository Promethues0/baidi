// Package store 定义白帝控制中心的数据访问接口与内存实现（首版 mock，
// 后续替换为 SQLite/PostgreSQL，接口不变）。
package store

import "context"

// Store 控制中心数据访问接口。模块处理器只依赖此接口，便于切换持久化后端。
type Store interface {
	Overview(ctx context.Context) (Overview, error)
	PolicyBundle(ctx context.Context) (PolicyBundle, error)
	Apps(ctx context.Context) (AppBundle, error)
	Users(ctx context.Context) (UserDirBundle, error)
	Devices(ctx context.Context) (DeviceBundle, error)
	// DeviceByFingerprint 授信终端准入闸的取数点（api.deviceAdmissionGate）：
	// 敲门令牌签发前查「这个账号名下的这个指纹是什么状态」。
	DeviceByFingerprint(ctx context.Context, account, fingerprint string) (Device, bool, error)
	// DeviceTrustSetting 准入模式（observe|strict）与绑定方式（auto|approval）。
	// 敲门闸与设备登记分别消费这两项——没有真实消费方的开关不进这个结构体。
	DeviceTrustSetting(ctx context.Context) (DeviceTrustSetting, error)
	Audit(ctx context.Context) (AuditBundle, error)
	Gateway(ctx context.Context) (GatewayBundle, error)
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
	OnlineSessions(ctx context.Context) ([]OnlineSession, error)
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
type Overview struct {
	GeneratedAt string        `json:"generatedAt"`
	Devices     DeviceStat    `json:"devices"`
	Users       UserStat      `json:"users"`
	Threats     ThreatStat    `json:"threats"`
	Sessions    int           `json:"sessions"`
	AuditByKind []KV          `json:"auditByKind"`
	Verdicts    []KV          `json:"verdicts"`
	Defense     []DefenseLine `json:"defense"`
}

type DeviceStat struct {
	Online int     `json:"online"`
	Total  int     `json:"total"`
	Rate   float64 `json:"rate"`
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
type DefenseLine struct {
	Key   string   `json:"key"`   // device | account | endpoint
	Name  string   `json:"name"`  // 设备防线 / 账号防线 / 终端防线
	Risk  int      `json:"risk"`  // 0-100 风险分
	Trend string   `json:"trend"` // up | down | flat
	Top   []string `json:"top"`   // TOP 风险实体
}
