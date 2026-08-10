// Package api 装配白帝控制中心的 HTTP 路由与模块处理器。
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/lockout"
	"baidi.dev/control/internal/pki"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/webauthnx"
)

// Version 控制中心版本号。
const Version = "0.3.0"

// tokenTTL 会话令牌有效期；knockTTL 短时效一次性敲门令牌有效期；
// kickBanTTL 强制下线后的接入封禁时长（期内拒发敲门令牌、网关拒敲门，到期自然恢复）。
const (
	tokenTTL   = 8 * time.Hour
	knockTTL   = 90 * time.Second
	kickBanTTL = 5 * time.Minute
	// pwResetTTL 首登强制改密受限令牌（Use=pwreset）的有效期：够完成一次改密，不够当会话用。
	pwResetTTL = 15 * time.Minute
	// seedInitialPassword 新建用户未指定初始口令时的 demo 默认口令。
	seedInitialPassword = "baidi@123"
)

// Server 持有依赖（store 读 + writer 写 + JWT 密钥），按模块注册路由。
type Server struct {
	store        store.Store
	writer       store.Writer
	keys         *auth.Keys // Ed25519 签发/双验（迁移期兼容 HS256 存量令牌）
	env          string
	downloadsDir string        // 客户端安装包目录（manifest.json + 安装包），BAIDI_DOWNLOADS
	rp           *webauthnx.RP // WebAuthn 依赖方；nil = 未配置 RP ID/Origin，登录回落 legacy 演示路径
	ca           *pki.CA       // 内部 CA：签发网关 mTLS 客户端证书；nil = 未启用
	// gwPlaintextCompat 迁移期是否允许明文 :8090 上用 JWT role=gateway 调网关接口。
	// 收口后置 false，网关接口就只剩 mTLS 一条路。
	gwPlaintextCompat bool
	postureStrict     bool // BAIDI_POSTURE_ENFORCE=strict：无新鲜 posture 报告也拒发敲门令牌（fail-closed）
	// trustedProxies 审计源 IP 的信任边界（BAIDI_TRUSTED_PROXIES，CIDR 逗号分隔）：
	// 只有直连对端落在这些网段内，X-Forwarded-For 才被采信。见 clientIP。
	trustedProxies []netip.Prefix
	// lockout 登录防爆破守卫：账号/源 IP 滑动窗计数 + 限时锁定（锁定落库，重启不丢）。
	lockout  *lockout.Guard
	mu       sync.Mutex
	gateways map[string]GatewayInfo // 已注册（在线）网关，按 id
	gwSess   map[string][]GwSession // 各网关上报的活跃会话，按网关 id（监控中心真实在线用户来源）
	// gwTunnelFP 各网关隧道 TLS 证书的 SHA-256 指纹，按网关 id。网关证书是启动期自签的，
	// 无公共 CA 可依赖；控制面作为信任根，把指纹转发给客户端做证书钉扎（见 clientprofile.go）。
	// 网关每次重启会换证书，故指纹随注册心跳刷新，不落库。
	gwTunnelFP map[string]string
	kicked     map[string]string     // 已被强制下线的会话 id → 处置说明（监控中心 · 在线用户显示层）
	revoked    map[string]revokeInfo // 强制下线封禁：账号 → {原因, 截止}（拒发敲门令牌 + 经网关策略下发数据面处置）
	// grayObserved 灰度观察审计的节流水位：账号 → 上次落审计的 Unix 秒。
	// 内存态、重启即失（最坏结果是重启后多记一条 observing，无害）。
	grayObserved map[string]int64
}

// revokeInfo 一条强制下线封禁（内存态，与在线会话生命周期一致，重启即失）。
// s.revoked 以规范化账号（normUser）为键，杜绝换大小写/空格重登绕过封禁；Display 保留原始显示形态。
type revokeInfo struct {
	Reason  string
	Until   int64  // 封禁截止 Unix 秒
	Display string // 原始账号显示形态（下发网关 / 审计用）
}

// normUser 规范化账号（去首尾空格 + 小写），与数据面 spa/proxy 的 normUser 同义。
func normUser(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// statusZh 目录账号状态中文名（审计/提示文案共用）。
var statusZh = map[string]string{"active": "启用", "disabled": "禁用", "locked": "锁定", "idle": "挂起"}

// pwStrengthZh 口令强度标记中文名（审计文案用；unknown = 判定存在之前设的口令）。
var pwStrengthZh = map[string]string{auth.PwWeak: "弱", auth.PwStrong: "强", auth.PwUnknown: "未知"}

// accountBlocked 报告目录状态是否禁止接入（禁用/锁定拒登录、拒发敲门令牌）。
func accountBlocked(status string) bool { return status == "disabled" || status == "locked" }

// lookupDirUser 按谓词查目录用户。store 读失败时返回 error——调用方须 fail-closed，
// 不得把"查不到状态"当"状态正常"放行。
func (s *Server) lookupDirUser(ctx context.Context, match func(store.DirUser) bool) (store.DirUser, bool, error) {
	b, err := s.store.Users(ctx)
	if err != nil {
		return store.DirUser{}, false, err
	}
	for _, u := range b.Users {
		if match(u) {
			return u, true, nil
		}
	}
	return store.DirUser{}, false, nil
}

// blockedDirAccount 按账号（规范化匹配）查目录，报告该账号是否处于禁用/锁定态。
// 不在目录中的账号视为不受限（演示模式门户接受任意用户名）。
func (s *Server) blockedDirAccount(ctx context.Context, account string) (store.DirUser, bool, error) {
	key := normUser(account)
	u, found, err := s.lookupDirUser(ctx, func(du store.DirUser) bool { return normUser(du.Account) == key })
	if err != nil {
		return store.DirUser{}, false, err
	}
	return u, found && accountBlocked(u.Status), nil
}

// GatewayInfo 一台已注册数据面网关的运行信息（含网关上报的真实活性指标）。
type GatewayInfo struct {
	ID       string `json:"id"`
	Proxy    string `json:"proxy"`
	SPA      string `json:"spa"`
	LastSeen int64  `json:"lastSeen"`
	Clients  int    `json:"clients"` // 当前放行窗口内已授权源数
	Tunnels  int    `json:"tunnels"` // 活跃隧道连接数
	Uptime   int64  `json:"uptime"`  // 网关运行秒数
	Version  string `json:"version"` // 网关上报的二进制版本（编译期注入）；旧网关不上报则为空，前端显示 "—"
}

// GwSession 网关上报的一条活跃会话（真实敲门放行记录）。
type GwSession struct {
	IP    string `json:"ip"`
	User  string `json:"user"`
	Role  string `json:"role"`
	Since int64  `json:"since"`
}

// New 构造 Server。postureStrict 由 BAIDI_POSTURE_ENFORCE=strict 开启（默认 observe：缺报放行、坏报告仍执行）。
// rp 为已装配的 WebAuthn 依赖方，nil 表示未配置（登录回落 legacy 演示验证码路径）。
func New(st store.Store, wr store.Writer, keys *auth.Keys, env string, downloadsDir string, rp *webauthnx.RP, ca *pki.CA, gwPlaintextCompat bool) *Server {
	s := &Server{store: st, writer: wr, keys: keys, env: env, downloadsDir: downloadsDir, rp: rp,
		ca: ca, gwPlaintextCompat: gwPlaintextCompat,
		postureStrict:  os.Getenv("BAIDI_POSTURE_ENFORCE") == "strict",
		trustedProxies: parseTrustedProxies(os.Getenv("BAIDI_TRUSTED_PROXIES")),
		gateways:       map[string]GatewayInfo{}, gwSess: map[string][]GwSession{}, kicked: map[string]string{},
		revoked: map[string]revokeInfo{}, gwTunnelFP: map[string]string{},
		grayObserved: map[string]int64{}}
	// 登录防爆破守卫：SQLite 后端实现持久化（重启不丢锁定）；纯 Memory 后端退化为进程内锁定。
	var ls lockout.Store
	if v, ok := wr.(lockout.Store); ok {
		ls = v
	}
	s.lockout = lockout.New(ls)
	return s
}

// IsOpen 报告某路径是否免认证（登录/健康检查/门户登录/下载中心清单/安装包分发）。供 auth 中间件使用。
func (s *Server) IsOpen(_, path string) bool {
	switch path {
	case "/healthz", "/api/v1/auth/login", "/api/v1/portal/login", "/api/v1/portal/downloads":
		return true
	// WebAuthn 登录断言两回合：此时尚无会话令牌，身份由「口令已验」的一次性 mfaTicket 承载
	// （handler 内 verifyMfaTicket 强校验，非免鉴权——只是不走 Bearer 中间件）。
	case "/api/v1/webauthn/login/begin", "/api/v1/webauthn/login/finish":
		return true
	}
	// /downloads/{file} 路径可变，前缀豁免；白名单校验在 handler 内（manifest available 条目）。
	if strings.HasPrefix(path, "/downloads/") {
		return true
	}
	return false
}

// requireAdmin 校验调用方此刻仍是管理员，否则 403。
//
// ★令牌里的 role 只是入场券，**不是判据**：它是签发那一刻（最长 8h 前）的快照。
// 只信它的话，被 RemoveAdmin 撤销身份、被禁用的人拿旧令牌照样读得到整个用户目录、
// 在线会话（账号 + 源 IP + 网关）、资源策略与全部管理员账号——写面因 requirePerm
// 现算而立刻 403，读面却停在快照上，"降权立刻算数"只兑现了一半，且这一半在
// 日志里完全看不出异常（每一次都是一个合法管理员令牌的正常读取）。
// 真正的判据与 requirePerm 同一处取数（store.AdminRoleFor：users.role 仍为 admin
// 且角色未悬空），两面同真同假；读不到一律 fail-closed。
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	_, ok := s.currentAdminRole(w, r)
	return ok
}

// requireGateway 校验调用方是数据面网关。
//
// 优先认 mTLS 客户端证书 CN（阶段 2 的目标形态：机器身份在传输层完成、与用户身份分家）；
// 迁移期回退到 JWT role=gateway。★注意 admin 兜底已移除：留着它，任何 admin 令牌都能调
// 网关接口，「机器身份走 mTLS」就只是多一条路而没关掉旧路。
func (s *Server) requireGateway(w http.ResponseWriter, r *http.Request) bool {
	if cn := GatewayCN(r.Context()); cn != "" {
		return true // 已过 mTLS 握手 + 证书白名单校验
	}
	if !s.gwPlaintextCompat {
		httpx.Error(w, http.StatusForbidden, "网关接口须经 mTLS 客户端证书访问")
		return false
	}
	c, ok := auth.FromContext(r.Context())
	if !ok || c.Role != "gateway" {
		httpx.Error(w, http.StatusForbidden, "需要网关身份")
		return false
	}
	return true
}

// Routes 返回已注册全部路由的 mux（Go 1.22+ 方法+路径路由）。
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// 健康检查
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// 产品元信息
	mux.HandleFunc("GET /api/v1/meta", func(w http.ResponseWriter, _ *http.Request) {
		httpx.JSON(w, http.StatusOK, map[string]any{
			"product":   "白帝",
			"subtitle":  "零信任访问控制系统",
			"component": "baidi-control · 控制中心",
			"version":   Version,
			"env":       s.env,
		})
	})

	// 管理员登录 / 当前身份
	mux.HandleFunc("POST /api/v1/auth/login", s.handleAdminLogin)
	mux.HandleFunc("GET /api/v1/auth/me", s.handleMe)
	mux.HandleFunc("POST /api/v1/knock-token", s.handleKnockToken) // 签发短时效一次性敲门令牌（需登录）

	// 态势总览（监控中心一屏聚合）
	mux.HandleFunc("GET /api/v1/overview", s.handleOverview)

	// 策略：继承树 + 用户策略清单
	mux.HandleFunc("GET /api/v1/policies", s.handlePolicies)

	// 应用管理：分类 + 应用清单
	mux.HandleFunc("GET /api/v1/apps", s.handleApps)

	// 访问者目录：身份源 + 组织树 + 用户清单
	mux.HandleFunc("GET /api/v1/users", s.handleUsers)

	// 终端管理：信任设置 + 设备清单 + 绑定审批
	mux.HandleFunc("GET /api/v1/devices", s.handleDevices)
	// 审计中心：分类聚合 + 磁盘水位 + 日志（admin）+ 防篡改链校验 + CSV 导出
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	mux.HandleFunc("GET /api/v1/audit/verify", s.handleAuditVerify)
	mux.HandleFunc("GET /api/v1/audit/export", s.handleAuditExport)
	// 网关与隐身：区域/节点拓扑 + SPA
	mux.HandleFunc("GET /api/v1/gateway", s.handleGateway)

	// 系统管理：三权分立（管理员角色 + 管理员账号）+ 集群状态。
	// 读=任意 admin（审计管理员要能监督权限分布）；写=PermAdmins（只有超管持有）。
	mux.HandleFunc("GET /api/v1/system", s.handleSystem)
	mux.HandleFunc("POST /api/v1/admin-roles", s.handleSaveAdminRole)
	mux.HandleFunc("DELETE /api/v1/admin-roles/{key}", s.handleDeleteAdminRole)
	mux.HandleFunc("POST /api/v1/admins", s.handleCreateAdmin)
	mux.HandleFunc("PUT /api/v1/admins/{account}/role", s.handleSetAdminRole)
	mux.HandleFunc("DELETE /api/v1/admins/{account}", s.handleRemoveAdmin)
	// 认证源接入：认证源 + 自适应规则
	mux.HandleFunc("GET /api/v1/authsrc", s.handleAuthSrc)
	// 认证源接入（真落库、真探测、真参与登录）：
	mux.HandleFunc("GET /api/v1/authsrc/sources", s.handleAuthSources)
	mux.HandleFunc("POST /api/v1/authsrc/sources", s.handleSaveAuthSource)
	mux.HandleFunc("DELETE /api/v1/authsrc/sources/{id}", s.handleDeleteAuthSource)
	mux.HandleFunc("PUT /api/v1/authsrc/sources/{id}/secret", s.handleSetAuthSourceSecret)
	mux.HandleFunc("POST /api/v1/authsrc/sources/{id}/probe", s.handleProbeAuthSource)
	// 登录防爆破：生效锁定清单 + 管理员解锁 + 阈值配置读写（admin，配置消费方=登录链路 Guard）
	mux.HandleFunc("GET /api/v1/security/lockouts", s.handleLockouts)
	mux.HandleFunc("POST /api/v1/security/lockouts/unlock", s.handleUnlockLockout)
	mux.HandleFunc("GET /api/v1/security/lockout-config", s.handleLockoutConfig)
	mux.HandleFunc("PUT /api/v1/security/lockout-config", s.handleSaveLockoutConfig)
	// 安全中心：安全基线 + SPA
	mux.HandleFunc("GET /api/v1/security", s.handleSecurity)
	mux.HandleFunc("POST /api/v1/security/baselines", s.handleSaveBaseline)          // 保存基线（admin）
	mux.HandleFunc("DELETE /api/v1/security/baselines/{id}", s.handleDeleteBaseline) // 删基线（admin）
	// 终端 posture：上报评估（登录用户）+ 最新报告清单（admin）+ 删除设备报告（admin，设备退役）
	mux.HandleFunc("POST /api/v1/posture", s.handlePostureReport)
	mux.HandleFunc("GET /api/v1/posture", s.handlePostureList)
	mux.HandleFunc("DELETE /api/v1/posture/{user}/{device}", s.handleDeletePostureReport)
	// JIT 即时访问：门户自助申请 + 我的申请（登录用户）；管理台待办/审批/授予清单/撤销（admin）
	mux.HandleFunc("POST /api/v1/portal/access-requests", s.handlePortalCreateAccessRequest)
	mux.HandleFunc("GET /api/v1/portal/access-requests", s.handlePortalMyRequests)
	mux.HandleFunc("GET /api/v1/access-requests", s.handleAccessRequests)
	mux.HandleFunc("POST /api/v1/access-requests/{id}/decide", s.handleDecideAccessRequest)
	mux.HandleFunc("GET /api/v1/jit/grants", s.handleJitGrants)
	mux.HandleFunc("POST /api/v1/jit/grants/{id}/revoke", s.handleRevokeGrant)
	// WebAuthn / passkey 二次认证：注册仪式与凭据管理（需登录）+ 登录断言（凭口令已验票据）
	mux.HandleFunc("POST /api/v1/webauthn/register/begin", s.handleWebauthnRegisterBegin)
	mux.HandleFunc("POST /api/v1/webauthn/register/finish", s.handleWebauthnRegisterFinish)
	mux.HandleFunc("POST /api/v1/webauthn/login/begin", s.handleWebauthnLoginBegin)
	mux.HandleFunc("POST /api/v1/webauthn/login/finish", s.handleWebauthnLoginFinish)
	mux.HandleFunc("GET /api/v1/webauthn/credentials", s.handleWebauthnCredentials)
	mux.HandleFunc("DELETE /api/v1/webauthn/credentials/{id}", s.handleWebauthnDeleteCredential)
	// 运维诊断：控制面/存储/数据面/隐身/集群/身份/态势/密钥多维真实自检（admin）
	mux.HandleFunc("GET /api/v1/diag", s.handleDiag)

	// 监控中心：在线用户（实时会话）+ 强制下线 + 用户状态
	mux.HandleFunc("GET /api/v1/online", s.handleOnline)
	mux.HandleFunc("POST /api/v1/online/{id}/kick", s.handleKickSession) // 强制下线（admin）
	mux.HandleFunc("GET /api/v1/userstate", s.handleUserState)

	// IPSec VPN 组网：站点清单（配置 + 网关实测运行态）+ CRUD + 启停意图 + PSK 只写不读
	// ★数据面侧的三个 ipsec 端点只挂 mTLS 监听（见 MTLSHandler），明文口没有它们——
	// PSK 原文在 :8090 上不存在任何形态的出口。
	mux.HandleFunc("GET /api/v1/ipsec", s.handleIpsec)
	mux.HandleFunc("POST /api/v1/ipsec", s.handleSaveIpsec)               // 新增/改站点（admin）
	mux.HandleFunc("DELETE /api/v1/ipsec/{id}", s.handleDeleteIpsec)      // 删站点（admin）
	mux.HandleFunc("POST /api/v1/ipsec/{id}/toggle", s.handleToggleIpsec) // 翻转启用意图（admin，不再直接写 status）
	mux.HandleFunc("PUT /api/v1/ipsec/{id}/psk", s.handleSetIpsecPSK)     // 设置 PSK（admin，只写不读）

	// 对象库：地址 / 服务 / 时间对象 + 被引用反查（复用闭环）
	mux.HandleFunc("GET /api/v1/objects", s.handleObjects)
	mux.HandleFunc("GET /api/v1/objects/usage", s.handleObjectsUsage)          // 被引用反查（资源/IPSec）
	mux.HandleFunc("POST /api/v1/objects/{kind}", s.handleSaveObject)          // 新增/改对象（admin）
	mux.HandleFunc("DELETE /api/v1/objects/{kind}/{id}", s.handleDeleteObject) // 删对象（admin，被引用拒删 409）

	// 认证策略：PC/WEB 端与移动端分栏认证方式 + 自适应规则
	mux.HandleFunc("GET /api/v1/authpolicy", s.handleAuthPolicies)
	mux.HandleFunc("POST /api/v1/authpolicy", s.handleSaveAuthPolicy)          // 新增/改策略（admin）
	mux.HandleFunc("DELETE /api/v1/authpolicy/{id}", s.handleDeleteAuthPolicy) // 删策略（admin）

	// ── 写操作（落 SQLite）──
	mux.HandleFunc("POST /api/v1/apps", s.handleCreateApp)                         // 发布应用
	mux.HandleFunc("POST /api/v1/approvals/{id}/decide", s.handleDecideApproval)   // 设备绑定审批
	mux.HandleFunc("PUT /api/v1/policies/{node}", s.handleSavePolicy)              // 保存用户策略覆盖
	mux.HandleFunc("GET /api/v1/policies/{node}", s.handleGetPolicy)               // 读取用户策略覆盖
	mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)                       // 新增用户
	mux.HandleFunc("POST /api/v1/users/{id}/status", s.handleSetUserStatus)        // 禁用/启用/解锁
	mux.HandleFunc("POST /api/v1/users/{id}/password", s.handleResetUserPassword)  // 管理员重置口令
	mux.HandleFunc("PUT /api/v1/users/{id}/membership", s.handleSetUserMembership) // 改组织归属 / 所属用户组

	// 组织与用户组（业务管理 · 用户与角色页内维护；全部 admin）
	mux.HandleFunc("GET /api/v1/orgs", s.handleOrgs)
	mux.HandleFunc("POST /api/v1/orgs", s.handleSaveOrg)
	mux.HandleFunc("DELETE /api/v1/orgs/{id}", s.handleDeleteOrg)
	mux.HandleFunc("GET /api/v1/groups", s.handleGroups)
	mux.HandleFunc("POST /api/v1/groups", s.handleSaveGroup)
	mux.HandleFunc("DELETE /api/v1/groups/{id}", s.handleDeleteGroup)
	mux.HandleFunc("PUT /api/v1/groups/{id}/members", s.handleSetGroupMembers)
	mux.HandleFunc("POST /api/v1/auth/password", s.handleChangePassword) // 自助改密

	// ── 网关数据面：注册 + 拉策略（需 gateway/admin 身份）；资源 CRUD（admin）──
	// ★网关数据面接口只挂 mTLS 监听（见 MTLSHandler）。明文侧仅在迁移期挂载，
	// 收口后 /api/v1/gateways/{register,policy} 在 :8090 上根本不存在。
	if s.gwPlaintextCompat {
		mux.HandleFunc("POST /api/v1/gateways/register", s.handleGatewayRegister)
		mux.HandleFunc("GET /api/v1/gateways/policy", s.handleGatewayPolicy)
	}
	// 网关客户端证书：签发 / 清单 / 吊销（admin）
	mux.HandleFunc("POST /api/v1/pki/gateway-certs", s.handleIssueGatewayCert)
	mux.HandleFunc("GET /api/v1/pki/gateway-certs", s.handleGatewayCerts)
	mux.HandleFunc("POST /api/v1/pki/gateway-certs/{fingerprint}/revoke", s.handleRevokeGatewayCert)
	mux.HandleFunc("GET /api/v1/gateways", s.handleGateways)                // 在线网关清单（管理）
	mux.HandleFunc("GET /api/v1/resources", s.handleResources)              // 资源清单（管理）
	mux.HandleFunc("POST /api/v1/resources", s.handleSaveResource)          // 新增/改资源
	mux.HandleFunc("DELETE /api/v1/resources/{id}", s.handleDeleteResource) // 删资源

	// ── 终端用户门户（B/S 免客户端）──
	mux.HandleFunc("POST /api/v1/portal/login", s.handlePortalLogin)
	mux.HandleFunc("GET /api/v1/portal/apps", s.handlePortalApps)
	// 终端客户端接入剖面：网关落点 + 路由表 + 资源映射，一次下发，客户端照做即可接入。
	// 这是「点开应用真的走隧道」的前提——此前客户端只能手填一个与业务地址无关的网段。
	mux.HandleFunc("GET /api/v1/client/profile", s.handleClientProfile)
	mux.HandleFunc("GET /api/v1/portal/downloads", s.handleDownloadsManifest) // 客户端下载清单（免认证）
	mux.HandleFunc("GET /downloads/{file}", s.handleDownloadFile)             // 客户端安装包分发（公开；白名单校验在 handler 内）

	return mux
}

// handlePortalLogin 终端用户登录（演示口令 baidi@123）。
// 二次认证：口令通过后，若该账号已注册 passkey（或属自适应触发的风险账号），
// 返回 needWebauthn + 一次性票据，客户端据此走 /webauthn/login/begin|finish 完成抗钓鱼断言。
// 未配置 WebAuthn RP（BAIDI_WEBAUTHN_RPID/ORIGIN 缺失，如裸 IP 演示站）则回落 legacy 演示验证码。
func (s *Server) handlePortalLogin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
		MfaCode  string `json:"mfaCode"`
		// DeviceID 客户端自报的终端指纹（与 posture 上报同一个值）。
		// 消费方是认证策略的「授信终端」豁免：这台设备以本账号上报过 posture 且判定通过时，
		// 可免掉策略驱动的二次认证。浏览器登录不带它 = 未知设备 = 不给豁免（fail-closed）。
		DeviceID string `json:"deviceId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Username == "" || b.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "用户名/密码不能为空")
		return
	}
	// 防爆破进门锁：账号锁或 IP 锁命中直接 403（锁定期内正确口令也不放行）。
	if s.loginGateLocked(w, r, b.Username) {
		return
	}
	// 认证策略按**用户目录**分组，而"这个人是被哪个目录认出来的"只有登录链路当场知道：
	// 本地哈希命中 = local，外部源命中 = 该源的 kind。猜不得——猜错就会挑到别的目录的策略。
	lc := loginCtx{Directory: "local", DeviceID: strings.TrimSpace(b.DeviceID)}
	// 真实凭据校验：查目录账号 + bcrypt 口令哈希（不再是"任意用户名 + baidi@123"）
	cred, found, err := s.store.Credential(r.Context(), b.Username)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load credential")
		return
	}
	if !found || !auth.VerifyPassword(cred.PassHash, b.Password) {
		// 本地目录没认出他 → 依次问外部认证源（LDAP/AD）。
		//
		// ★顺序是「先本地、后外部」而不是反过来：本地目录里有 admin 这种
		// 高权账号，把它交给外部目录先答，等于把本地管理员的认证权外包出去。
		extCred, srcName, srcKind, hit, aerr := s.authenticateExternal(r.Context(), b.Username, b.Password)
		switch {
		case aerr != nil:
			// ★认证源故障绝不能回「用户名或密码错误」：那会让运维去查用户而不是查目录，
			// 也不该计入账号锁定计数（用户什么都没做错）。
			s.auditAs(r, b.Username, "auth", "终端用户登录失败（认证源不可用）", "fail")
			slog.Error("外部认证源不可用", "账号", b.Username, "err", aerr.Error())
			httpx.JSON(w, http.StatusOK, map[string]any{
				"ok": false, "reason": "认证服务暂时不可用，请稍后重试或联系管理员"})
			return
		case !hit:
			// 本地与外部都没认出他 → 计一次失败（认证源故障走上面的分支，刻意不计）。
			s.noteLoginFailure(r, b.Username)
			s.auditAs(r, b.Username, "auth", "终端用户登录失败（账号或口令错误）", "fail")
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "用户名或密码错误"})
			return
		}
		cred = extCred
		lc.Directory = srcKind // 认证策略按目录分组：这一步之后才知道是哪个目录认出的他
		s.auditAs(r, cred.Account, "auth", "经外部认证源「"+srcName+"」认证通过", "ok")
	}
	// 账号状态门：禁用/锁定的目录账号口令对了也不放行（也不进 MFA 流程）
	// ★外部源认证成功的账号同样要过这道闸：本地把某个外部用户禁用了，
	// 就必须挡住，否则「在白帝上禁用」对外部账号形同虚设。
	if accountBlocked(cred.Status) {
		s.auditAs(r, cred.Account, "auth", "终端用户登录被拒（账号已"+statusZh[cred.Status]+"）", "deny")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "账号已被" + statusZh[cred.Status] + "，请联系管理员"})
		return
	}
	// legacy 回落路径需要读 mfaCode，经 context 传给 secondFactor（避免重复解码请求体）。
	if resp, done := s.secondFactor(r.WithContext(withLegacyMfaCode(r.Context(), b.MfaCode)), cred, lc); done {
		httpx.JSON(w, http.StatusOK, resp)
		return
	}
	s.lockout.Success(normUser(b.Username)) // 成功登录清零该账号的失败计数（与 Fail 同键口径）
	// 首登强制改密（管理员新建/重置口令后置位）：不发会话令牌，改签受限改密令牌。
	// 有 passkey 的账号不走这里——secondFactor 已在上面把流程引去断言，
	// 断言通过后由 handleWebauthnLoginFinish 做同样的判定（改密页必须在完整认证态之后）。
	if cred.MustChangePw {
		s.mustChangeLogin(w, r, cred)
		return
	}
	s.auditAs(r, cred.Account, "auth", "终端用户登录成功", "ok")
	// 令牌 Name=账号（数据面网关按 claims.Name 做放行/封禁匹配，必须是规范账号，不能放显示名）；
	// 显示名单独经响应体 displayName 回给前端。
	tok := s.keys.Sign(auth.Claims{Sub: cred.Account, Role: cred.Role, Name: cred.Account}, tokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "token": tok, "displayName": cred.Name})
}

// PortalTile 应用门户卡片。
type PortalTile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Addr        string `json:"addr"`
	Sensitivity string `json:"sensitivity"` // low | normal | high，取自关联资源的 Sensitivity
	Accessible  bool   `json:"accessible"`  // false = 需申请，或已被终端风险降权
	ResourceID  string `json:"resourceId"`  // 关联受控资源（JIT 申请用；空=不接入自助申请）
	// Degraded 该磁贴此刻因终端风险降权不可访问（而非缺授权）。申请审批在这种状态下无效，
	// 门户据此把"申请访问"换成"请先修复终端环境"，免得用户提交必然被否的申请。
	Degraded bool `json:"degraded,omitempty"`
}

// handlePortalApps 返回当前用户可见的应用门户（复用 SQLite 中的已发布应用；高敏类需申请）。
// 高敏磁贴默认 Accessible=false（需申请）；若当前用户对该资源持有效 JIT 授予，则翻回可访问——JIT 闭环的门户侧收口。
func (s *Server) handlePortalApps(w http.ResponseWriter, r *http.Request) {
	// 门户是人机面：只认 admin/user 会话，拒 gateway 身份与 WebAuthn 中间票据(role=mfa)——
	// 票据只用于换取一次断言，绝不能当会话令牌消费业务数据。
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	b, err := s.store.Apps(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load portal apps")
		return
	}
	// 敏感度取自**受控资源**而非应用分类。此前这里写死 `a.Category == "finance"`，
	// 于是"哪些要走审批"永远只有财务一类，管理员新建的高敏资源静默变成人人可点。
	resources, err := s.store.Resources(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load resources")
		return
	}
	sensOf := make(map[string]string, len(resources))
	for _, res := range resources {
		sensOf[res.ID] = res.Sensitivity
	}
	// 调用方的有效授予集合（resource_id）：把「需申请」磁贴翻回可访问。best-effort，读失败按未授予处理。
	granted := map[string]bool{}
	if gs, err := s.store.ActiveGrantsFor(r.Context(), normUser(c.Name)); err == nil {
		for _, g := range gs {
			granted[g.ResourceID] = true
		}
	}
	// 终端风险降权：高敏磁贴一律标不可访问，且**JIT 授予也翻不回来**——与网关侧
	// DenyUsers 先于允许集合判定同构，否则门户显示"可访问"而隧道那边照拒。
	degraded, _ := s.degradeStateOf(r.Context(), normUser(c.Name))
	tiles := []PortalTile{}
	for _, a := range b.Apps {
		if a.Status != "running" {
			continue
		}
		sens, acc, deg := store.SensitivityNormal, true, false
		if a.ResourceID != "" {
			sens = store.NormalizeSensitivity(sensOf[a.ResourceID])
		}
		if sens == store.SensitivityHigh {
			acc = false // 高敏资源默认需走自助申请审批
			if a.ResourceID != "" && granted[a.ResourceID] {
				acc = true // 持有效 JIT 授予 → 临时可访问
			}
			if degraded {
				acc, deg = false, true // 降权否决恒胜于 JIT 授予
			}
		}
		tiles = append(tiles, PortalTile{ID: a.ID, Name: a.Name, Mode: a.Mode, Addr: a.Addr,
			Sensitivity: sens, Accessible: acc, ResourceID: a.ResourceID, Degraded: deg})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"apps": tiles})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var u store.DirUser
	// PassHash 是 json:"-" 不从请求体解，改由独立 password 字段承接后哈希落库
	var extra struct {
		Password string `json:"password"`
	}
	raw, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(raw, &u); err != nil || u.Name == "" || u.Account == "" {
		httpx.Error(w, http.StatusBadRequest, "用户名/账号不能为空")
		return
	}
	_ = json.Unmarshal(raw, &extra)
	pw := extra.Password
	if pw == "" {
		pw = seedInitialPassword // 未指定初始口令时给 demo 默认，保证新用户可登录
	}
	if len(pw) < 6 {
		httpx.Error(w, http.StatusBadRequest, "初始口令至少 6 位")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	u.PassHash = hash
	// ★这条路只建**普通用户**：DirUser.Role 是可从请求体解出来的字段，放任它带 "admin"
	// 就意味着持 security 权的管理员一次请求即可给自己造一个管理员账号——三权分立
	// 立刻失效，且列表上看不出异常。管理员的建立与角色分派唯一入口是
	// POST /api/v1/admins（需 PermAdmins，只有超管持有）。
	u.Role = "user"
	u.AdminRole = ""
	// 建号是明文唯一可得的另一处：强度判定必须在这里落，否则新账号的 pw_strength 是
	// unknown，「弱密码」增强规则对刚建的账号永远不命中（静默失效的经典形态）。
	u.PwStrength = auth.PasswordStrength(u.Account, pw)
	// 初始口令是管理员定的（或 demo 默认），不是本人私密——首登必须换掉（FR-DEPLOY-09）。
	u.MustChangePw = true
	// orgId / groups 直接由 DirUser 的 json 标签承接（见 store.DirUser）；
	// 组织不存在或组不可写时回 4xx 而不是 500——那是调用方选错了目标，不是服务端故障。
	created, err := s.writer.CreateUser(r.Context(), u)
	if err != nil {
		orgStoreErr(w, err, "failed to create user")
		return
	}
	s.audit(r, "admin", "新增用户「"+created.Name+"」("+created.Account+"，组织 "+
		pickStr(created.OrgID, "无归属")+")，已置首登改密", "ok")
	httpx.JSON(w, http.StatusCreated, created)
}

func (s *Server) handleSetUserStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Status string `json:"status"`
	}
	ok := map[string]bool{"active": true, "disabled": true, "locked": true, "idle": true}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !ok[body.Status] {
		httpx.Error(w, http.StatusBadRequest, "status must be active|disabled|locked|idle")
		return
	}
	// 目录回查提到写之前：既是为了在动手前判「目标是不是管理员」（安全管理员不得
	// 禁用/锁定另外两权的管理员，见 guardAdminTarget），也让回查失败变成
	// fail-closed 的 500 而不是"状态已改、数据面封禁没挂上"的半成品。
	target, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool { return du.ID == id })
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if !s.guardAdminTarget(w, r, target, "置「"+statusZh[body.Status]+"」") {
		return
	}
	if err := s.writer.SetUserStatus(r.Context(), id, body.Status); err != nil {
		// 防自锁：禁用/锁定最后一名超管回 409（与降权、撤销同一道闸，只是走了另一个端点）。
		s.audit(r, "admin", "用户 "+id+" 置「"+statusZh[body.Status]+"」未生效："+err.Error(), "fail")
		adminStoreErr(w, err, "failed to set user status")
		return
	}
	// 数据面联动：禁用/锁定 → 入封禁表（经网关策略轮询捎带撤窗+断隧道，同强制下线管道）；
	// 恢复启用 → 立即解除封禁（管理员显式信任动作，同时豁免残余的强制下线封禁）。
	// 新令牌来源由登录/knock-token 的账号状态门永久把守，限时封禁只负责掐掉存量在线。
	zh := statusZh[body.Status]
	detail := ""
	if found {
		u := target
		key := normUser(u.Account)
		s.mu.Lock()
		switch body.Status {
		case "disabled", "locked":
			s.revoked[key] = revokeInfo{Reason: "账号已" + zh, Until: time.Now().Add(kickBanTTL).Unix(), Display: u.Account}
			detail = "（" + u.Account + " 数据面撤窗断隧道）"
		case "active":
			delete(s.revoked, key)
		}
		s.mu.Unlock()
	}
	s.audit(r, "admin", "用户 "+id+" 状态置「"+zh+"」"+detail, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "status": body.Status})
}

// handleResetUserPassword 管理员重置指定用户口令（admin 门）。
func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Password) < 6 {
		httpx.Error(w, http.StatusBadRequest, "口令至少 6 位")
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	// 口令强度只能在这一刻判（登录时只有 bcrypt 哈希）——判定结果随口令同语句落库，
	// 供认证策略的「弱密码」增强规则消费。
	u, found, uerr := s.lookupDirUser(r.Context(), func(du store.DirUser) bool { return du.ID == id })
	if uerr != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	// ★重置管理员的口令 = 拿到那名管理员的全部权限：新口令是操作者自己定的，
	// 他随即就能用目标账号登录（种子 admin 无 passkey 时连二次认证都不需要）。
	// 这条路比 handleCreateUser 的提权路更短，那边已收口，这边必须同样收口。
	if !s.guardAdminTarget(w, r, u, "重置登录口令") {
		return
	}
	acct := ""
	if found {
		acct = u.Account
	}
	strength := auth.PasswordStrength(acct, body.Password)
	// 管理员知道这把新口令 → 它只是过渡口令，置首登改密逼本人换掉。
	if err := s.writer.SetUserPassword(r.Context(), id, hash, true, strength); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to set password")
		return
	}
	s.audit(r, "admin", "重置用户 "+id+" 的登录口令（强度判定："+pwStrengthZh[strength]+"），已置首登改密", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleChangePassword 当前登录用户自助改密（校验旧口令）。
// requireUser：拒 gateway 身份与 WebAuthn 中间票据(role=mfa)——半程认证态不得改口令
// （首登受限令牌 Use=pwreset 带的是 admin/user 角色，能过这道门，且中间件唯独放行本端点）。
// 改密成功清 must_change_pw：这是走出首登受限态的唯一出口。
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.New) < 8 {
		httpx.Error(w, http.StatusBadRequest, "新口令至少 8 位")
		return
	}
	if body.New == body.Old {
		// 换汤不换药会让「首登强制改密」形同虚设：初始口令原样续用。
		httpx.Error(w, http.StatusBadRequest, "新口令不得与旧口令相同")
		return
	}
	cred, found, err := s.store.Credential(r.Context(), c.Sub) // Sub=规范账号
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load credential")
		return
	}
	if !found || !auth.VerifyPassword(cred.PassHash, body.Old) {
		s.audit(r, "auth", "自助改密失败（旧口令错误）", "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "旧口令错误"})
		return
	}
	hash, err := auth.HashPassword(body.New)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	strength := auth.PasswordStrength(cred.Account, body.New)
	if err := s.writer.SetUserPassword(r.Context(), cred.ID, hash, false, strength); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to set password")
		return
	}
	// 强度判定随改密落库，登录链路的「弱密码」规则消费的就是这一刻的结论。
	s.audit(r, "auth", "自助修改登录口令（强度判定："+pwStrengthZh[strength]+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "pwStrength": strength})
}

// handleAdminLogin 管理员登录（真实凭据校验，要求 admin 角色）→ 签发 admin 角色 JWT。
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Username == "" || b.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "用户名/密码不能为空")
		return
	}
	// 防爆破进门锁：管理台是权限最高面，同门户一样先查锁。
	if s.loginGateLocked(w, r, b.Username) {
		return
	}
	// 真实凭据校验 + 要求 admin 角色（普通账号口令对也拿不到管理台）
	cred, found, err := s.store.Credential(r.Context(), b.Username)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load credential")
		return
	}
	if !found || !auth.VerifyPassword(cred.PassHash, b.Password) {
		s.noteLoginFailure(r, b.Username) // 口令错误计一次（角色不符/账号被禁不计——那时口令是对的）
		s.auditAs(r, b.Username, "auth", "管理员登录失败（用户名或密码错误）", "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "用户名或密码错误"})
		return
	}
	if cred.Role != "admin" {
		s.auditAs(r, cred.Account, "auth", "管理员登录被拒（非管理员角色）", "deny")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "该账号无管理台权限"})
		return
	}
	if accountBlocked(cred.Status) {
		s.auditAs(r, cred.Account, "auth", "管理员登录被拒（账号已"+statusZh[cred.Status]+"）", "deny")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "账号已被" + statusZh[cred.Status]})
		return
	}
	// 管理台是权限最高面，同门户一样过二次因子（已注册 passkey 即强制断言）。
	// 管理台是浏览器面：目录恒为 local（管理员账号只可能来自本地目录），且没有终端指纹。
	if resp, done := s.secondFactor(r, cred, loginCtx{Directory: "local"}); done {
		httpx.JSON(w, http.StatusOK, resp)
		return
	}
	s.lockout.Success(normUser(b.Username)) // 成功登录清零该账号的失败计数
	// 首登强制改密：口令对了也不发会话令牌，只给受限改密令牌。
	if cred.MustChangePw {
		s.mustChangeLogin(w, r, cred)
		return
	}
	s.auditAs(r, cred.Name, "auth", "管理员登录成功", "ok")
	// Name=账号（同门户：数据面身份匹配用规范账号）；显示名走 displayName。
	tok := s.keys.Sign(auth.Claims{Sub: cred.Account, Role: "admin", Name: cred.Account}, tokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "token": tok, "displayName": cred.Name, "role": "admin"})
}

// mustChangeLogin 首登强制改密的登录收尾：口令（及二次因子）都已验过，但初始口令未改，
// 不发 8h 会话令牌，改签 15min 受限令牌（Use=pwreset）。中间件只放行 POST /auth/password
// 与 GET /auth/me，业务端点与 /knock-token 一律 403——受限态碰不到数据面。
// 审计记的是事实：认证确已通过，只是令牌被降级。
func (s *Server) mustChangeLogin(w http.ResponseWriter, r *http.Request, cred store.Credential) {
	s.auditAs(r, cred.Account, "auth", "登录认证通过，但初始口令未修改，签发受限改密令牌", "ok")
	tok := s.keys.Sign(auth.Claims{
		Sub: cred.Account, Role: cred.Role, Name: cred.Account,
		Jti: auth.RandJTI(), Use: auth.UsePwReset,
	}, pwResetTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "mustChangePassword": true, "token": tok,
		"displayName": cred.Name, "role": cred.Role,
		"reason": "首次登录须修改初始口令",
	})
}

// handleMe 返回当前令牌身份。
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c, _ := auth.FromContext(r.Context())
	httpx.JSON(w, http.StatusOK, map[string]any{"sub": c.Sub, "role": c.Role, "name": c.Name, "exp": c.Exp})
}

// handleKnockToken 为已登录会话签发短时效一次性敲门令牌（带随机 jti）。
// 客户端用它敲门、网关按 jti 一次性放行，杜绝令牌被解出后主动重放（90s 内也仅一次）。
// 强制下线封禁期内拒发——掐断客户端 reknock 保活的令牌来源。
func (s *Server) handleKnockToken(w http.ResponseWriter, r *http.Request) {
	// requireUser 是第 0 道闸：敲门令牌直通数据面，绝不能签给 WebAuthn 中间票据(role=mfa)
	// 这类半程认证态——二次因子没走完就拿到敲门令牌，等于绕过 2FA 直连业务。
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if ri, banned := s.revokedActive(c.Name); banned {
		s.audit(r, "security", "拒发敲门令牌："+c.Name+" 在强制下线封禁期内（"+ri.Reason+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "已被强制下线，暂时无法接入")
		return
	}
	// 账号状态门（永久闸，区别于上面的限时封禁）：禁用/锁定账号拒发，掐断 reknock 保活令牌来源
	if u, blocked, err := s.blockedDirAccount(r.Context(), c.Name); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to check account status")
		return
	} else if blocked {
		s.audit(r, "security", "拒发敲门令牌："+u.Account+" 账号已"+statusZh[u.Status], "deny")
		httpx.Error(w, http.StatusForbidden, "账号已被"+statusZh[u.Status]+"，无法接入")
		return
	}
	// 终端环境闸（第三道）：最新判定 block 一直拦（不看新鲜度，直到被合规报告替换——防停报逃逸）；
	// strict 模式下无新鲜报告也拒（fail-closed，生产开 BAIDI_POSTURE_ENFORCE=strict）。
	if rep, found, err := s.store.PostureVerdict(r.Context(), c.Name); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to check posture")
		return
	} else if found && rep.Verdict == "block" {
		s.audit(r, "security", "拒发敲门令牌："+c.Name+" 终端环境不合规（"+strings.Join(rep.Reasons, "、")+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "终端环境不合规："+strings.Join(rep.Reasons, "、"))
		return
	} else if s.postureStrict {
		// strict 缺报/过期拒发。新鲜度须按「最新」报告判（不是上面 rep 那条跨设备最差——
		// 一台旧设备的陈旧 degrade 行会把当前持续合规的用户永久拒之门外）。
		fresh, found, err := s.store.PostureFreshest(r.Context(), c.Name)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to check posture freshness")
			return
		}
		if !found || time.Now().Unix()-fresh.TS > int64(postureFreshTTL.Seconds()) {
			s.audit(r, "security", "拒发敲门令牌："+c.Name+" 无有效终端环境报告（strict）", "deny")
			httpx.Error(w, http.StatusForbidden, "无有效终端环境报告，无法接入")
			return
		}
	}
	// Use=knock 是给数据面的用途自证：网关 strict 模式只接受本处签发的令牌，
	// 会话令牌/MFA 票据（Use 为空）一律拒绝敲门——堵死"持 8h 会话令牌直连数据面、
	// 绕过封禁/账号状态/终端合规三道闸"的旁路。改 knockTTL 须同步网关 -knock-max-ttl 上界。
	tok := s.keys.Sign(auth.Claims{
		Sub: c.Sub, Role: c.Role, Name: c.Name, Jti: auth.RandJTI(), Use: auth.UseKnock,
	}, knockTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"token": tok, "expires_in": int(knockTTL.Seconds())})
}

// revokedActive 报告某账号是否在强制下线封禁期内（懒清理过期条目）。按规范化账号匹配。
func (s *Server) revokedActive(user string) (revokeInfo, bool) {
	key := normUser(user)
	s.mu.Lock()
	defer s.mu.Unlock()
	ri, ok := s.revoked[key]
	if !ok {
		return revokeInfo{}, false
	}
	if time.Now().Unix() >= ri.Until {
		delete(s.revoked, key)
		return revokeInfo{}, false
	}
	return ri, true
}

// handleGatewayRegister 记录一台数据面网关上线/心跳（网关用自签 gateway 令牌认证）。
func (s *Server) handleGatewayRegister(w http.ResponseWriter, r *http.Request) {
	if !s.requireGateway(w, r) {
		return
	}
	var b struct {
		ID       string      `json:"id"`
		Proxy    string      `json:"proxy"`
		SPA      string      `json:"spa"`
		Clients  int         `json:"clients"`
		Tunnels  int         `json:"tunnels"`
		Uptime   int64       `json:"uptime"`
		Sessions []GwSession `json:"sessions"`
		// TunnelFP 网关隧道 TLS 证书的 SHA-256 指纹（hex）。网关自签证书每次重启都变，
		// 随心跳上报即可；控制面转发给客户端做证书钉扎（见 handleClientProfile）。
		TunnelFP string `json:"tunnelFp"`
		// Version / Events 是新网关才上报的字段：旧网关缺省即零值，处理逻辑对空值必须无感
		// （version 空串照存、events 空切片零循环），不得因缺字段报错。
		Version string    `json:"version"` // 网关二进制版本（编译期注入）
		Events  []gwEvent `json:"events"`  // 数据面回执：网关报告已实际执行的控制面指令
	}
	// ★解码前先限体：events/sessions 是数组，64 条截断发生在整包解析完之后，
	// 拦不住解码期内存——一张失陷网关证书发多 GB 心跳就能耗尽控制面内存。
	// 上限与 ipsec/status 同口径（1 MiB），正常心跳远够；超限明确回 413 而不是
	// 静默注册出一台零统计的网关。其余解码错误维持既往宽容（缺字段零值照常心跳）。
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&b); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			httpx.Error(w, http.StatusRequestEntityTooLarge, "注册心跳请求体过大（上限 1 MiB）")
			return
		}
	}
	c, _ := auth.FromContext(r.Context())
	id := b.ID
	if id == "" {
		id = c.Sub
	}
	s.mu.Lock()
	s.gateways[id] = GatewayInfo{
		ID: id, Proxy: b.Proxy, SPA: b.SPA, LastSeen: time.Now().Unix(),
		Clients: b.Clients, Tunnels: b.Tunnels, Uptime: b.Uptime, Version: b.Version,
	}
	s.gwSess[id] = b.Sessions
	s.gwTunnelFP[id] = b.TunnelFP
	s.mu.Unlock()

	// 数据面回执逐条落审计：category=dataplane，行为人=网关自身。措辞只转述网关报告的
	// 既成事实（「网关 X 报告：…」），控制面不在此替网关下任何断言——审计失实是大忌。
	// 上限与网关侧队列同界（64）：不放大一次异常心跳的日志量。
	events := b.Events
	if len(events) > 64 {
		events = events[:64]
	}
	actor := GatewayCN(r.Context()) // 优先 mTLS 证书 CN（机器身份权威来源）
	if actor == "" {
		actor = id // 迁移期明文口回退注册 id
	}
	for _, ev := range events {
		detail := strings.TrimSpace(ev.Detail)
		if detail == "" {
			detail = ev.Kind // 空 detail 至少留下事件种类，不落一条空话
		}
		s.auditAs(r, actor, "dataplane", "网关 "+id+" 报告："+detail, "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// gwEvent 网关随心跳捎带的一条数据面回执（与 gateway/internal/cplane 的 Event 同构）。
type gwEvent struct {
	TS     int64  `json:"ts"`     // 网关侧执行时刻（Unix 秒；仅参考，审计时间以控制面落库为准）
	Kind   string `json:"kind"`   // revoke-applied | policy-applied
	Detail string `json:"detail"` // 网关侧生成的事实描述
}

// handleGatewayPolicy 网关拉取当前资源授权策略（替代静态 resources.json）+ 强制下线撤销名单。
func (s *Server) handleGatewayPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireGateway(w, r) {
		return
	}
	rs, err := s.store.Resources(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load resources")
		return
	}
	// 数据面执行只需 user + until；reason 为运营敏感文本，按最小披露不下发网关。
	type revokedDTO struct {
		User  string `json:"user"`
		Until int64  `json:"until"`
	}
	now := time.Now().Unix()
	s.mu.Lock()
	revoked := make([]revokedDTO, 0, len(s.revoked))
	for k, ri := range s.revoked {
		if now >= ri.Until {
			delete(s.revoked, k) // 懒清理过期封禁
			continue
		}
		u := ri.Display
		if u == "" {
			u = k
		}
		revoked = append(revoked, revokedDTO{User: u, Until: ri.Until})
	}
	s.mu.Unlock()

	// 目录中 disabled/locked 账号动态并入撤销名单（滚动续期至 now+kickBanTTL）：
	// 补上"5min 限时封禁到期后，被禁账号的 8h 会话令牌仍可直连网关"的洞——
	// 只要账号保持禁用，每次轮询都续窗，网关就一直拒；账号恢复 active 后自然从名单消失。
	seen := make(map[string]bool, len(revoked))
	for _, d := range revoked {
		seen[normUser(d.User)] = true
	}
	until := now + int64(kickBanTTL.Seconds())
	if b, err := s.store.Users(r.Context()); err == nil {
		for _, u := range b.Users {
			if !accountBlocked(u.Status) {
				continue
			}
			if k := normUser(u.Account); !seen[k] {
				seen[k] = true
				revoked = append(revoked, revokedDTO{User: u.Account, Until: until})
			}
		}
	}
	// posture-blocked 用户同款并入（滚动续期）：即使持 8h 会话令牌直敲网关也被拒；
	// 合规报告替换判定后自然从名单消失（读失败静默跳过，与目录并入同策略；令牌闸仍 fail-closed 把守新令牌）。
	if blocked, err := s.store.PostureBlockedUsers(r.Context()); err == nil {
		for _, acc := range blocked {
			if k := normUser(acc); !seen[k] {
				seen[k] = true
				revoked = append(revoked, revokedDTO{User: acc, Until: until})
			}
		}
	}

	// 组织 / 用户组两维在**控制面**展开成账号后并进 AllowUsers，网关零改动。
	// ★数据面刻意不知道组织树：判定权留在控制面，且展开每次现算（不缓存），
	// 把人移出组织后下一轮轮询就失效。展开实现只有 store.SubjectIndex 一份，
	// 客户端剖面 buildProfile 用的是同一份——两处同构是硬要求，见 subjects.go。
	//
	// 终端风险降权（disposal=degrade）同轮现算：这批账号进高敏资源的 DenyUsers，
	// 网关据此**只**拒他们访问高敏资源，普通资源照旧——这就是「优先降权而非终止会话」
	// 的执行方（PRD 1.5）。恢复合规后下一轮名单里就没有他，无需任何人工操作。
	degraded := s.degradedUsers(r.Context())
	gwRes := expandForGateway(rs, s.subjectIndex(r.Context()), degraded)

	// 灰度观察（disposal=gray）：访问权一字不改，但每轮下发都留痕，
	// 让「谁正在被观察」这件事在审计里可查、在用户状态页可见。
	s.auditGrayObserved(r)

	// JIT 即时访问：把有效授予（active 且未到期）临时并入对应资源的 AllowUsers——网关零改动即经
	// proxy.Authorize 命中放行。★必须在 seen 排除集（revoked+禁用/锁定+posture-block）完全构建之后：
	// grant 只加正向 allow，被上游否决的账号在此先剔除（撤销恒胜于授予）。只改内存 DTO（每次现构造），
	// 绝不 SaveResource 写回；到期后 ActiveGrants 不再 emit，网关下轮 reg.Replace 即失效（惰性回收）。
	if grants, err := s.store.ActiveGrants(r.Context()); err == nil {
		idx := make(map[string]int, len(gwRes))
		for i := range gwRes {
			idx[gwRes[i].ID] = i
		}
		for _, g := range grants {
			if now >= g.ExpiresAt || seen[normUser(g.User)] {
				continue // 双保险到期过滤 + 撤销/禁用/posture-block 恒胜
			}
			if i, ok := idx[g.ResourceID]; ok {
				gwRes[i].AllowUsers = append(gwRes[i].AllowUsers, g.User)
			}
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"resources": gwRes, "revoked": revoked})
}

// GatewayDetail 网关清单条目：注册信息 + 该网关上报的活跃会话明细（就近处置/审计用）。
type GatewayDetail struct {
	GatewayInfo
	Sessions []GwSession `json:"sessions"`
}

// handleGateways 返回当前已注册（在线）的数据面网关清单 + 每网关活跃会话明细（管理台用）。
func (s *Server) handleGateways(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.Lock()
	list := make([]GatewayDetail, 0, len(s.gateways))
	for id, g := range s.gateways {
		sess := s.gwSess[id]
		if sess == nil {
			sess = []GwSession{}
		}
		list = append(list, GatewayDetail{GatewayInfo: g, Sessions: sess})
	}
	s.mu.Unlock()
	httpx.JSON(w, http.StatusOK, map[string]any{"gateways": list})
}

// handleResources 资源清单 + 可选授权主体（管理台用）。
//
// 主体清单里的 accounts 是**已展开**的（组织含全部后代组织的成员），展开在服务端做：
// 控制台只需把选中的几个主体的账号数组求并集，就能显示"生效账号数"。
// ★不把组织树丢给浏览器自己走：那等于把子树语义实现第二遍，两份实现迟早对不上，
// 而管理员看到的数字与网关实际放行的人不一致，是最不该出现的那种偏差。
func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rs, err := s.store.Resources(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load resources")
		return
	}
	orgs, groups, err := s.subjectOptions(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load authorization subjects")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"resources": rs, "orgs": orgs, "groups": groups})
}

// subjectOption 一个可选授权主体（组织或用户组）+ 它当前展开出的账号。
type subjectOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"` // 用户组：static | role
	Path string `json:"path,omitempty"` // 组织：物化路径，供前端画层级缩进
	// Accounts 该主体覆盖的账号。组织的这份**已含全部后代组织**的成员——
	// 与下发网关时并进 AllowUsers 的那份出自同一次展开，数字必然对得上。
	Accounts []string `json:"accounts"`
}

// subjectOptions 组装资源编辑器的主体候选清单（组织树 + 用户组），账号已展开。
func (s *Server) subjectOptions(ctx context.Context) ([]subjectOption, []subjectOption, error) {
	ix, err := s.store.SubjectIndex(ctx)
	if err != nil {
		return nil, nil, err
	}
	orgUnits, err := s.store.OrgUnits(ctx)
	if err != nil {
		return nil, nil, err
	}
	groupList, err := s.store.UserGroups(ctx)
	if err != nil {
		return nil, nil, err
	}
	orgs := make([]subjectOption, 0, len(orgUnits))
	for _, o := range orgUnits {
		accts := ix.OrgAccounts[o.ID]
		if accts == nil {
			accts = []string{}
		}
		orgs = append(orgs, subjectOption{ID: o.ID, Name: o.Name, Path: o.Path, Accounts: accts})
	}
	groups := make([]subjectOption, 0, len(groupList))
	for _, g := range groupList {
		accts := ix.GroupAccounts[g.ID]
		if accts == nil {
			accts = []string{}
		}
		groups = append(groups, subjectOption{ID: g.ID, Name: g.Name, Kind: g.Kind, Accounts: accts})
	}
	return orgs, groups, nil
}

// handleSaveResource 新增/修改一条受控资源（admin），落库后网关下次轮询即生效。
func (s *Server) handleSaveResource(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var res store.Resource
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil || res.ID == "" || res.Backend == "" {
		httpx.Error(w, http.StatusBadRequest, "id/backend 必填")
		return
	}
	// 敏感度：空 = 未标注，收敛成 normal；给了值就必须是三档之一。
	// ★不静默丢弃拼错的值（如 "High"/"敏感"）：静默收敛成 normal 会让管理员以为
	// 自己标了高敏，而降权对这个资源根本不生效——又一处"配置齐全却不生效"。
	if res.Sensitivity == "" {
		res.Sensitivity = store.SensitivityNormal
	} else if !store.ValidSensitivity(res.Sensitivity) {
		httpx.Error(w, http.StatusBadRequest, "sensitivity 取值须为 low|normal|high")
		return
	}
	// 对象库引用须指向真实对象（backend 仍是权威拨号目标，refs 仅供编辑器回填 + 反查）。
	if res.AddrRef != "" {
		if ok, err := s.objectExists(r.Context(), "addr", res.AddrRef); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to validate addr ref")
			return
		} else if !ok {
			httpx.Error(w, http.StatusBadRequest, "引用的地址对象不存在")
			return
		}
	}
	if res.SvcRef != "" {
		if ok, err := s.objectExists(r.Context(), "service", res.SvcRef); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to validate svc ref")
			return
		} else if !ok {
			httpx.Error(w, http.StatusBadRequest, "引用的服务对象不存在")
			return
		}
	}
	// 组织/用户组主体必须真实存在。★不静默丢弃拼错的 id：一个打错的组织 id
	// 会让整批人拿不到权限，而资源列表上那个标签看起来完全正常——
	// 与用户组成员写入拒绝未知账号（ErrUnknownAccount）是同一条纪律。
	if msg, err := s.validateSubjects(r.Context(), res); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to validate authorization subjects")
		return
	} else if msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.writer.SaveResource(r.Context(), res); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save resource")
		return
	}
	s.audit(r, "admin", "保存受控资源「"+res.ID+"」("+res.Backend+"，敏感度 "+res.Sensitivity+"，授权 "+
		strconv.Itoa(len(res.AllowRoles))+" 角色/"+strconv.Itoa(len(res.AllowUsers))+" 账号/"+
		strconv.Itoa(len(res.AllowGroups))+" 用户组/"+strconv.Itoa(len(res.AllowOrgs))+" 组织)", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "resource": res})
}

// validateSubjects 校验资源引用的组织/用户组都真实存在。
// 返回非空 msg = 校验不通过（400 文案）；error = 读库失败（500）。
func (s *Server) validateSubjects(ctx context.Context, res store.Resource) (string, error) {
	return s.validateSubjectRefs(ctx, res.AllowOrgs, res.AllowGroups)
}

// validateSubjectRefs 校验一组组织 id / 用户组 id 都真实存在。
// 资源授权（allowOrgs/allowGroups）与认证策略的适用范围（scopeOrgs/scopeGroups）
// 共用这一份：两处引用的是同一批主体，校验各写一份迟早只有一边严。
func (s *Server) validateSubjectRefs(ctx context.Context, orgIDs, groupIDs []string) (string, error) {
	if len(orgIDs) > 0 {
		orgs, err := s.store.OrgUnits(ctx)
		if err != nil {
			return "", err
		}
		known := make(map[string]bool, len(orgs))
		for _, o := range orgs {
			known[o.ID] = true
		}
		for _, id := range orgIDs {
			// 空串一并拒：它进了列表就让"限定了主体"成立（网关侧下发哨兵 = 对所有人关闭），
			// 却谁也匹配不到——与拼错 id 是同一种错，不该只挡住其中一种。
			if !known[strings.TrimSpace(id)] {
				return "授权组织 " + id + " 不存在", nil
			}
		}
	}
	if len(groupIDs) > 0 {
		gs, err := s.store.UserGroups(ctx)
		if err != nil {
			return "", err
		}
		known := make(map[string]bool, len(gs))
		for _, g := range gs {
			known[g.ID] = true
		}
		for _, id := range groupIDs {
			if !known[strings.TrimSpace(id)] {
				return "授权用户组 " + id + " 不存在", nil
			}
		}
	}
	return "", nil
}

// handleDeleteResource 删除一条受控资源（admin）。
func (s *Server) handleDeleteResource(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	if err := s.writer.DeleteResource(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete resource")
		return
	}
	s.audit(r, "admin", "删除受控资源 "+id, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var a store.App
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil || a.Name == "" || a.Mode == "" {
		httpx.Error(w, http.StatusBadRequest, "invalid app payload")
		return
	}
	created, err := s.writer.CreateApp(r.Context(), a)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to create app")
		return
	}
	s.audit(r, "admin", "发布应用「"+created.Name+"」", "ok")
	httpx.JSON(w, http.StatusCreated, created)
}

func (s *Server) handleDecideApproval(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Decision != "approved" && body.Decision != "rejected") {
		httpx.Error(w, http.StatusBadRequest, "decision must be approved|rejected")
		return
	}
	if err := s.writer.DecideApproval(r.Context(), id, body.Decision, body.Reason); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to decide approval")
		return
	}
	decZh := map[string]string{"approved": "通过", "rejected": "驳回"}[body.Decision]
	s.audit(r, "admin", "设备绑定审批 "+id+"："+decZh, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "decision": body.Decision})
}

func (s *Server) handleSavePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	node := r.PathValue("node")
	var body struct {
		Title       string `json:"title"`
		Settings    any    `json:"settings"`
		CustomCount int    `json:"customCount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid policy payload")
		return
	}
	raw, _ := json.Marshal(body.Settings)
	if err := s.writer.SavePolicyOverride(r.Context(), node, body.Title, string(raw), body.CustomCount); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save policy")
		return
	}
	s.audit(r, "admin", "保存用户策略覆盖「"+body.Title+"」("+node+")", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "node": node})
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	po, ok, err := s.writer.GetPolicyOverride(r.Context(), node)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load policy")
		return
	}
	if !ok {
		httpx.JSON(w, http.StatusOK, map[string]any{"exists": false, "node": node})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"exists": true, "override": po})
}

func (s *Server) handleAuthSrc(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.AuthSrc(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load authsrc")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.Security(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load security")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.Devices(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load devices")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	// 审计日志本身是敏感面：全量行为轨迹 + 源 IP。放给 role=user 等于
	// 让任意登录终端摸清管理员操作节奏。三权分立下更进一步：**只有审计权**能读——
	// 安全管理员能定策略却读不到全量日志，才谈得上"定策略的人不看自己的痕迹"。
	if !s.requirePerm(w, r, store.PermAudit) {
		return
	}
	b, err := s.store.Audit(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load audit")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

func (s *Server) handleGateway(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.Gateway(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load gateway")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.Apps(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load apps")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

// handleUsers 访问者目录（身份源 + 组织树 + 用户清单）。
//
// ★这里此前**一道闸都没有**：任何登录用户（含门户普通账号）都能拉走全量账号、
// 组织归属与在线态，而它同时也是"哪个账号是管理员"的枚举入口。加 requireAdmin
// 之后它与 /online、/userstate 同门槛，并随 requireAdmin 一起吃「角色现算」——
// 被撤销管理员身份的人拿旧令牌也读不到。
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	b, err := s.store.Users(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	pb, err := s.store.PolicyBundle(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load policies")
		return
	}
	httpx.JSON(w, http.StatusOK, pb)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ov, err := s.store.Overview(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load overview")
		return
	}
	// 在线会话数只有 api 层掌握（网关上报的真实敲门会话）；有真实会话时覆盖种子，
	// 并把在线设备数按真实会话对齐（无真实会话则保留种子，诚实降级）。
	if n := s.onlineSessionCount(); n >= 0 {
		ov.Sessions = n
		if n > ov.Devices.Total {
			ov.Devices.Total = n
		}
		ov.Devices.Online = n
		if ov.Devices.Total > 0 {
			ov.Devices.Rate = float64(n) / float64(ov.Devices.Total)
		}
	}
	httpx.JSON(w, http.StatusOK, ov)
}

// onlineSessionCount 返回在线数据面网关上报的真实敲门会话数；无任何在线网关会话则返回 -1
// （表示"无真实来源"，调用方保留种子值）。
func (s *Server) onlineSessionCount() int {
	now := time.Now()
	window := int64(gatewayOnlineWindow / time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()
	count, hasLiveGw := 0, false
	for id, sess := range s.gwSess {
		gw, ok := s.gateways[id]
		if !ok || now.Unix()-gw.LastSeen > window {
			continue
		}
		hasLiveGw = true
		count += len(sess)
	}
	if !hasLiveGw {
		return -1
	}
	return count
}
