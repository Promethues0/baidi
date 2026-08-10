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
