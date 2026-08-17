// Package api 装配白帝控制中心的 HTTP 路由与模块处理器。
package api

import (
	"context"
	"crypto/ed25519"
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
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/lockout"
	"baidi.dev/control/internal/notify"
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
	lockout *lockout.Guard
	// metricsRetentionHours 设备状态时序的留存小时数，由 main 用清理循环真正消费的
	// 那一份注入（SetMetricsRetentionHours）。读端点据此把时间窗截断到库里真有数据的
	// 那一段——不截断的话「周」档会承诺一段早被清掉的历史。0 = 未注入（测试栈）。
	metricsRetentionHours int
	// notices 安全事件通知的异步派发器（有界队列 + 单 worker，见 internal/notify）。
	// 消费方在主流程上（爆破锁定 / 终端判 block），故入队非阻塞、满则丢并计数——
	// 通知是观测通道，发不出去不改变任何已经做出的安全处置。
	//
	// ★业务告警走的是**同一批通道、另一条路径**（api/alerts.go 的 notifyAlert 同步发）：
	// 告警评估跑在后台循环里没人等，同步换来"这一条发出去没有"当场可知；
	// 而这里的消费方在登录主流程上，必须异步。两条路径共用 sendVia 与通道配置。
	notices *notify.Dispatcher
	// nat 地址转换策略与网关网卡台账（PRD 第 18 章）。独立接口、按需断言：
	// 纯 Memory 后端（未连库的降级演示栈）拿不到它，端点如实回 503 而不是空列表——
	// 空列表会让「没配 NAT 策略」与「这个后端根本不支持 NAT」长得一模一样。
	nat store.NATStore
	// gwAccess 网关对外接入地址登记（SQLite 后端才有；纯内存栈为 nil，剖面退回自报+兜底）。
	gwAccess store.GatewayAccessStore
	// upg 升级配置持久化（灰度计划 + 校验规则）。同 nat：纯内存后端拿不到，端点如实回 503。
	upg store.UpgradeStore
	// upgradeKeys 升级包发布公钥（BAIDI_UPGRADE_PUBKEY，base64，逗号分隔可多把供轮换）。
	// 空 = 无法验签，VerifySignature 会**拒绝**而不是跳过（见那里的注释）。
	upgradeKeys []ed25519.PublicKey
	// licenseKeys License 发行公钥（BAIDI_LICENSE_PUBKEY）。与 upgradeKeys 是两个信任域，
	// 刻意不共用一个变量/环境变量：升级发布方与 License 发行方不必是同一把钥匙的主人。
	licenseKeys []ed25519.PublicKey
	// oidcFlow OIDC 登录的服务端会话（state/nonce/verifier）与交接票据单次登记。
	oidcFlow *oidcFlows
	// testRedirectAuth 测试注入缝：协议实现另有 30 条真密码学用例，
	// 这里换桩测的是编排（state 单次性 / 重定向 / 票据交接）。生产恒 nil。
	testRedirectAuth func(store.AuthSourceRec) (authsrc.RedirectAuthenticator, error)
	// testStatusChecker 外部账号回验的测试注入缝（同上：LDAP 协议路径另有真服务端用例）。
	testStatusChecker func(store.AuthSourceRec) (authsrc.StatusChecker, error)
	// sb 温备节点台账（PRD 15.5）。同 nat/upg：纯内存后端拿不到，集群视图如实回
	// 「不可判定」而不是「未配置备机」——后者是另一件事（确实没配 vs 记不下来）。
	sb store.StandbyStore
	// standbyPass 温备同步用的备份加密口令（BAIDI_STANDBY_PASSPHRASE）。
	// 空 = 同步端点一律 503：备份必须加密，没有口令就不产出（fail-closed）。
	standbyPass string
	// standbyStale 判「备机落后」的全局阈值（BAIDI_STANDBY_STALE_SECONDS）。
	// 逐节点实际阈值 = max(它, 3×备机自报间隔) 并封顶，见 standby.Evaluate。
	standbyStale time.Duration

	// auditMaxDiskPct 审计磁盘水位上限（BAIDI_AUDIT_MAX_DISK_PERCENT，0=未启用），
	// 由 StartAuditPurgeLoop 注入——/diag 显示的必须是**轮转循环真正消费的那一份**，
	// 而不是在展示侧再读一遍环境变量（与 SetAuditRetentionDays 同一条纪律）。
	auditMaxDiskPct int
	// auditWrite 审计写入失败的进程内计数（自带锁，见 audit_health.go）。
	// 刻意不挂在 s.mu 下：那把锁保护网关热数据，两组无关争用不该互相干扰。
	auditWrite auditWriteTracker

	mu       sync.Mutex
	gateways map[string]GatewayInfo // 已注册（在线）网关，按 id
	gwSess   map[string][]GwSession // 各网关上报的活跃会话，按网关 id（监控中心真实在线用户来源）
	// gwTunnelFP 各网关隧道 TLS 证书的 SHA-256 指纹，按网关 id。网关证书是启动期自签的，
	// 无公共 CA 可依赖；控制面作为信任根，把指纹转发给客户端做证书钉扎（见 clientprofile.go）。
	// 网关每次重启会换证书，故指纹随注册心跳刷新，不落库。
	gwTunnelFP map[string]string
	// gwReach 各网关最近心跳捎带的后端拨测快照（wave7 行动 9；心跳刷新态，不落库）。
	gwReach map[string]gwReachInfo
	// gwNAT 各网关最近心跳捎带的地址转换运行态（wave8 行动 3；心跳刷新态，不落库）。
	// ★不落库是有意的：它是「此刻内核里是什么样」的读数，重启控制面后重新收心跳
	// 才有意义——把陈值存下来会让一台已经下线的网关在页面上继续显示「已灌入内核」。
	gwNAT map[string]gwNATInfo
	// gwStealth 各网关最近心跳捎带的内核态隐身实测态（wave8 行动 7；同 gwNAT 不落库）。
	gwStealth map[string]gwStealthInfo
	kicked    map[string]string     // 已被强制下线的会话 id → 处置说明（监控中心 · 在线用户显示层）
	revoked   map[string]revokeInfo // 强制下线封禁：账号 → {原因, 截止}（拒发敲门令牌 + 经网关策略下发数据面处置）
	// knockIssued 敲门令牌签发审计的节流水位：(账号|指纹) → 上次落审计的 Unix 秒。
	// 敲门是 15s 一次的保活热路径，不节流会把审计冲成噪声（见 auditKnockIssued）。
	knockIssued map[string]int64
	// grayObserved 灰度观察审计的节流水位：账号 → 上次落审计的 Unix 秒。
	// 内存态、重启即失（最坏结果是重启后多记一条 observing，无害）。
	grayObserved map[string]int64
	// deviceObserved 授信终端「观察模式放行」审计的节流水位："账号|指纹" → 上次落审计的 Unix 秒。
	// 与 grayObserved 同一条理由：敲门令牌是每 15s 一次的保活热路径，不节流会把审计冲垮。
	deviceObserved map[string]int64
	// deviceTrustSeen 最近一次**成功**读到的设备准入设置（Mode 为空 = 从未读到过）。
	//
	// ★存在的理由是方向性：设备闸对 DeviceByFingerprint 的读失败在 strict 下 fail-closed，
	// 但准入设置本身读失败时若回落到默认值（observe + inherit），strict 就被一次数据库抖动
	// **整体关掉**了——未登记 / pending / 完全不带指纹的客户端全部拿到敲门令牌，
	// 而现场唯一的痕迹是一条 slog。宁可沿用上一次已知的设置（多半正是 strict），
	// 也不能让一次读失败把闸降到全局最宽的那一档。
	// 缓存整份而不只是 Mode：personalPolicy 同属收缩方向的开关（见 deviceTrustPolicy）。
	deviceTrustSeen store.DeviceTrustSetting
	// standbyAudited 温备**成功**类审计的节流水位：key（节点 id / 节点 id|status）→ 上次落审计的
	// Unix 秒。失败一条都不节流——「备机连续拉失败」正是这套机制唯一需要被看见的信号。
	standbyAudited map[string]int64
	// fwdDropReported / fwdDropReportAt 审计外送队列溢出转审计的节流水位：
	// 出口 id → 已上报过的累计丢弃数 / 上次上报的 Unix 秒（见 reportForwardDrops）。
	// 内存态、重启即失（最坏结果是重启后多记一条溢出告警，而那本来就该被看见）。
	fwdDropReported map[string]int64
	fwdDropReportAt map[string]int64
	// fwdPumpMu 让审计外送的投递轮次**串行**。后台循环与「立即投递」按钮会同时
	// 触发 PumpAuditForward，而队列取批不做认领标记（见 ClaimAuditForwardBatch），
	// 两轮并发就会把同一批送两遍——重复优于丢失，但能避免就别留着。
	fwdPumpMu sync.Mutex
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

// lastLoginWriter TouchLastLogin 的可选实现（SQLiteStore 有；Memory 种子没有——
// 演示数据的"最后登录"本来就是编的，不值得为它造一个假写入）。
type lastLoginWriter interface {
	TouchLastLogin(ctx context.Context, account string) error
}

// noteLoginSuccess 登录成功的统一记账：刷 users.last_login。
// 失败只记日志绝不影响登录——观测字段的写失败不该把人挡在门外。
// 四个调用点：门户口令登录、管理台口令登录、passkey 断言完成、首登受限令牌
// （受限态也是一次成功认证，闲置判定该把它算作活跃）。
func (s *Server) noteLoginSuccess(ctx context.Context, account string) {
	w, ok := s.writer.(lastLoginWriter)
	if !ok {
		return
	}
	if err := w.TouchLastLogin(ctx, account); err != nil {
		slog.Warn("last_login 刷新失败（不影响本次登录）", "account", account, "err", err.Error())
	}
}

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
	// Web 七层 Web 代理的监听地址；空 = 这台网关没开（旧网关也是空）。
	// 控制面据此拼浏览器该跳的入口 URL；为空就如实说"未开启"，绝不猜一个地址。
	Web    string `json:"web"`
	WebTLS bool   `json:"webTls"` // 该监听自身是否已是 HTTPS（决定入口 URL 的 scheme）
	// SkewSec 网关时钟相对控制面的偏差（网关钟 − 控制面钟，秒；正 = 网关快）。
	// ★指针：nil = 旧网关不上报时钟，**不可判定**，与「偏差为 0」必须分得开——
	// 塌缩成 0 会让一台从不上报的网关永远显示"时钟一致"，而它可能正因漂移拒掉所有敲门。
	// 数值含约半个 RTT 的系统性误差（网关在发送时刻盖章），对 10s 级阈值可忽略。
	SkewSec *int64 `json:"skewSec"`
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
		revoked: map[string]revokeInfo{}, gwTunnelFP: map[string]string{}, gwReach: map[string]gwReachInfo{},
		gwNAT:           map[string]gwNATInfo{},
		gwStealth:       map[string]gwStealthInfo{},
		knockIssued:     map[string]int64{},
		grayObserved:    map[string]int64{},
		deviceObserved:  map[string]int64{},
		standbyAudited:  map[string]int64{},
		fwdDropReported: map[string]int64{}, fwdDropReportAt: map[string]int64{}}
	// 登录防爆破守卫：SQLite 后端实现持久化（重启不丢锁定）；纯 Memory 后端退化为进程内锁定。
	var ls lockout.Store
	if v, ok := wr.(lockout.Store); ok {
		ls = v
	}
	s.lockout = lockout.New(ls)
	if v, ok := wr.(store.NATStore); ok {
		s.nat = v
	}
	if v, ok := wr.(store.GatewayAccessStore); ok {
		s.gwAccess = v
	}
	if v, ok := wr.(store.UpgradeStore); ok {
		s.upg = v
	}
	if v, ok := wr.(store.StandbyStore); ok {
		s.sb = v
	}
	// 温备（PRD 15.5）：口令与落后阈值都走 BAIDI_* 环境变量，与 postureStrict 同一条既有做法。
	s.standbyPass = os.Getenv("BAIDI_STANDBY_PASSPHRASE")
	s.standbyStale = standbyStaleFromEnv(os.Getenv("BAIDI_STANDBY_STALE_SECONDS"))
	s.upgradeKeys = parseUpgradeKeys(os.Getenv("BAIDI_UPGRADE_PUBKEY"))
	s.licenseKeys = parseLicenseKeys(os.Getenv("BAIDI_LICENSE_PUBKEY"))
	s.oidcFlow = newOIDCFlows()
	// 消息通道派发器：sink 是 deliverNotice（读通道配置、解凭据、真发、记结果与审计）。
	s.notices = notify.NewDispatcher(0, s.deliverNotice, slog.Default())
	return s
}

// Close 释放 Server 持有的后台资源（当前只有通知派发器）。
// 在 http.Server.Shutdown 之后调用：先停止收新请求，再把在途通知发完。
func (s *Server) Close() {
	if s.notices != nil {
		s.notices.Close()
	}
}

// IsOpen 报告某路径是否免认证（登录/健康检查/门户登录/下载中心清单/安装包分发）。供 auth 中间件使用。
func (s *Server) IsOpen(_, path string) bool {
	switch path {
	case "/healthz", "/api/v1/auth/login", "/api/v1/portal/login", "/api/v1/portal/downloads":
		return true
	// WebAuthn 登录断言两回合 / TOTP 登录第二回合：此时尚无会话令牌，身份由
	// 「口令已验」的一次性 mfaTicket 承载（handler 内 verifyMfaTicket 强校验，
	// 非免鉴权——只是不走 Bearer 中间件）。
	case "/api/v1/webauthn/login/begin", "/api/v1/webauthn/login/finish", "/api/v1/auth/totp":
		return true
	}
	// OIDC 登录四端点免认证：authorize/callback 发生在拿到任何令牌之前，
	// providers 是登录页渲染按钮用的公开清单，session 用交接票据自证（handler 内强校验）。
	if strings.HasPrefix(path, "/api/v1/auth/oidc/") {
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

	// 应用分类字典（可自建可修改；此前是编译进二进制的两个常量，管理员改不了）。
	// 读=任意管理员（角色现算），写=PermSecurity——与 POST /apps 同权。
	mux.HandleFunc("GET /api/v1/app-categories", s.handleAppCategories)
	mux.HandleFunc("POST /api/v1/app-categories", s.handleCreateAppCategory)
	mux.HandleFunc("PUT /api/v1/app-categories/{key}", s.handleUpdateAppCategory)
	mux.HandleFunc("DELETE /api/v1/app-categories/{key}", s.handleDeleteAppCategory)

	// 访问者目录：身份源 + 组织树 + 用户清单
	mux.HandleFunc("GET /api/v1/users", s.handleUsers)

	// 终端管理 · 授信终端（PRD ch9 FR-EP-10/12/13/14/15）：准入设置 + 设备台账 + 绑定审批。
	// 读=任意管理员（角色现算）；写=PermSecurity（与设备绑定审批、posture 报告删除同一权——
	// 它们改的是同一件事：谁的哪台终端能进来）。真实消费方 = deviceAdmissionGate（敲门令牌闸）。
	mux.HandleFunc("GET /api/v1/devices", s.handleDevices)
	mux.HandleFunc("PUT /api/v1/devices/settings", s.handleSaveDeviceTrustSetting)
	mux.HandleFunc("POST /api/v1/devices/{id}/status", s.handleSetDeviceStatus) // 批准 / 吊销 / 打回
	mux.HandleFunc("PUT /api/v1/devices/{id}/name", s.handleRenameDevice)
	// 资产分类与标签（wave7 行动 15）。分类是准入判据（personal 受 personalPolicy 约束），
	// 故与批准/吊销同权；标签无执行方，只是台账属性，随分类一起写。
	mux.HandleFunc("PUT /api/v1/devices/{id}/asset", s.handleSetDeviceAsset)
	mux.HandleFunc("DELETE /api/v1/devices/{id}", s.handleDeleteDevice)
	mux.HandleFunc("POST /api/v1/devices/cleanup-stale", s.handleCleanupStaleDevices)
	// 审计中心：分类聚合 + 磁盘水位 + 日志（admin）+ 防篡改链校验 + CSV 导出
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	mux.HandleFunc("GET /api/v1/audit/verify", s.handleAuditVerify)
	mux.HandleFunc("GET /api/v1/audit/export", s.handleAuditExport)
	mux.HandleFunc("GET /api/v1/audit/report", s.handleOpsReport)
	mux.HandleFunc("GET /api/v1/auth/oidc/providers", s.handleOIDCProviders)
	mux.HandleFunc("GET /api/v1/auth/oidc/{id}/authorize", s.handleOIDCAuthorize)
	mux.HandleFunc("GET /api/v1/auth/oidc/{id}/callback", s.handleOIDCCallback)
	mux.HandleFunc("POST /api/v1/auth/oidc/session", s.handleOIDCSession)
	mux.HandleFunc("GET /api/v1/license", s.handleLicense)
	mux.HandleFunc("POST /api/v1/license", s.handleImportLicense)
	// 审计日志外送（PRD ch16 + ch21.6）：RFC 5424 syslog over TCP/TLS + 通用 HTTP JSON。
	// 归 PermSystem 一权（理由见 auditforward.go 顶部）。真实消费方 = 后台投递循环
	// StartAuditForwardLoop，队列在 audit_forward_queue，发送成功才出队。
	mux.HandleFunc("GET /api/v1/audit/forward", s.handleAuditForwardTargets)
	mux.HandleFunc("POST /api/v1/audit/forward", s.handleSaveAuditForwardTarget)
	mux.HandleFunc("DELETE /api/v1/audit/forward/{id}", s.handleDeleteAuditForwardTarget)
	mux.HandleFunc("PUT /api/v1/audit/forward/{id}/secret", s.handleSetAuditForwardSecret)
	mux.HandleFunc("POST /api/v1/audit/forward/{id}/test", s.handleTestAuditForwardTarget)
	mux.HandleFunc("POST /api/v1/audit/forward/{id}/flush", s.handleFlushAuditForwardTarget)
	// 网关与隐身：已注册网关节点 + 敲门口径（数据源 = mTLS 注册心跳，见 gatewaypage.go）
	mux.HandleFunc("GET /api/v1/gateway", s.handleGateway)
	mux.HandleFunc("PUT /api/v1/gateway/{id}/access", s.handleSetGatewayAccess) // 登记对外接入地址（PermSystem）

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
	// 消息通道（PRD ch15.2）：SMTP / webhook / 短信(=webhook 适配)。归 PermSystem 一权。
	// 真实消费方：安全事件通知（爆破锁定、终端判 block），见 notify.go 尾部。
	mux.HandleFunc("GET /api/v1/notify/channels", s.handleNotifyChannels)
	mux.HandleFunc("POST /api/v1/notify/channels", s.handleSaveNotifyChannel)
	mux.HandleFunc("DELETE /api/v1/notify/channels/{id}", s.handleDeleteNotifyChannel)
	mux.HandleFunc("PUT /api/v1/notify/channels/{id}/secret", s.handleSetNotifyChannelSecret)
	mux.HandleFunc("POST /api/v1/notify/channels/{id}/test", s.handleTestNotifyChannel)
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
	// TOTP 二次认证：注册/确认/解绑（需登录）+ 登录第二回合（凭口令已验票据）
	mux.HandleFunc("GET /api/v1/totp", s.handleTotpStatus)
	mux.HandleFunc("POST /api/v1/totp/enroll", s.handleTotpEnroll)
	mux.HandleFunc("POST /api/v1/totp/confirm", s.handleTotpConfirm)
	mux.HandleFunc("POST /api/v1/totp/disable", s.handleTotpDisable)
	mux.HandleFunc("POST /api/v1/auth/totp", s.handleTotpLogin)
	// 运维诊断：控制面/存储/数据面/隐身/集群/身份/态势/密钥多维真实自检（admin）
	mux.HandleFunc("GET /api/v1/diag", s.handleDiag)

	// 监控中心 · 业务告警：告警实体（列表/过滤/处置）+ 规则 CRUD + 立即检测。
	// 读=任意管理员（角色现算），写=PermSecurity，理由见 alerts.go 顶部。
	mux.HandleFunc("GET /api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("POST /api/v1/alerts/{id}/ignore", s.handleIgnoreAlert)
	mux.HandleFunc("POST /api/v1/alerts/{id}/handle", s.handleHandleAlert)
	mux.HandleFunc("GET /api/v1/alerts/rules", s.handleAlertRules)
	mux.HandleFunc("POST /api/v1/alerts/rules", s.handleSaveAlertRule)
	mux.HandleFunc("DELETE /api/v1/alerts/rules/{id}", s.handleDeleteAlertRule)
	mux.HandleFunc("POST /api/v1/alerts/evaluate", s.handleEvaluateAlerts)

	// 监控中心：在线用户（实时会话）+ 强制下线 + 用户状态
	mux.HandleFunc("GET /api/v1/online", s.handleOnline)
	mux.HandleFunc("POST /api/v1/online/{id}/kick", s.handleKickSession) // 强制下线（admin）
	mux.HandleFunc("GET /api/v1/userstate", s.handleUserState)
	// 设备状态：各网关宿主机的当前水位 + 按 range 降采样的趋势（PRD ch5 FR-MON-01/02）
	mux.HandleFunc("GET /api/v1/monitor/device-stat", s.handleDeviceStat)

	// IPSec VPN 组网：站点清单（配置 + 网关实测运行态）+ CRUD + 启停意图 + PSK 只写不读
	// ★数据面侧的三个 ipsec 端点只挂 mTLS 监听（见 MTLSHandler），明文口没有它们——
	// PSK 原文在 :8090 上不存在任何形态的出口。
	// 地址转换（PRD 第 18 章）。读=任意管理员现算角色，写=PermSystem（见 nat.go 文件头）。
	// 产品升级管理（PRD 第 4 章）。读=任意管理员现算角色，写=PermSystem（见 upgrade.go 文件头）。
	mux.HandleFunc("GET /api/v1/upgrade", s.handleUpgrade)
	mux.HandleFunc("PUT /api/v1/upgrade/rules", s.handleSaveUpgradeRules)
	mux.HandleFunc("POST /api/v1/upgrade/check", s.handleUpgradeCheck)
	mux.HandleFunc("PUT /api/v1/upgrade/gray", s.handleSaveGrayPlan)
	mux.HandleFunc("POST /api/v1/upgrade/backup", s.handleBackup)
	mux.HandleFunc("POST /api/v1/upgrade/backup/inspect", s.handleBackupInspect)
	mux.HandleFunc("GET /api/v1/client/update", s.handleClientUpdate) // 终端检查更新（灰度判定在服务端）
	mux.HandleFunc("GET /api/v1/nat", s.handleNAT)
	mux.HandleFunc("POST /api/v1/nat/policies", s.handleSaveNATPolicy)
	mux.HandleFunc("DELETE /api/v1/nat/policies/{id}", s.handleDeleteNATPolicy)
	mux.HandleFunc("PUT /api/v1/nat/ifaces/{gw}/{name}", s.handleSetIfaceType)
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
	mux.HandleFunc("POST /api/v1/apps", s.handleCreateApp)                        // 发布应用
	mux.HandleFunc("POST /api/v1/approvals/{id}/decide", s.handleDecideApproval)  // 设备绑定审批
	mux.HandleFunc("PUT /api/v1/policies/{node}", s.handleSavePolicy)             // 保存用户策略覆盖
	mux.HandleFunc("GET /api/v1/policies/{node}", s.handleGetPolicy)              // 读取用户策略覆盖
	mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)                      // 新增用户
	mux.HandleFunc("POST /api/v1/users/{id}/status", s.handleSetUserStatus)       // 禁用/启用/解锁
	mux.HandleFunc("POST /api/v1/users/{id}/password", s.handleResetUserPassword) // 管理员重置口令
	mux.HandleFunc("DELETE /api/v1/users/{id}/totp", s.handleAdminResetTotp)      // 管理员清除 TOTP（丢认证器）
	// 闲置账号治理：识别（读=任意管理员）+ 批量锁定（写=PermSecurity，管理员目标逐个抬 PermAdmins）
	mux.HandleFunc("GET /api/v1/users/idle", s.handleIdleAccounts)
	mux.HandleFunc("POST /api/v1/users/idle/lock", s.handleIdleLock)
	// 台账批量导出 / 导入（wave7 行动 14）。导出流式 CSV 附件、**每一个单元格**都过公式注入中和；
	// 导入逐行回报成功与失败原因（部分失败不回滚），且**只建普通用户**——CSV 里出现角色列
	// 一律整份拒收并落 security 审计，建管理员的唯一入口仍是 POST /api/v1/admins。
	// 设备导入是 strict 准入模式上线前完成预授信的唯一路径（此前只能 observe 下逐台上报再批准）。
	mux.HandleFunc("GET /api/v1/users/export", s.handleUsersExport)
	mux.HandleFunc("POST /api/v1/users/import", s.handleUsersImport)
	mux.HandleFunc("GET /api/v1/devices/export", s.handleDeviceExport)
	mux.HandleFunc("POST /api/v1/devices/import", s.handleDeviceImport)
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
	// ── 控制面温备（PRD 15.5）──
	// 同步接口**只挂 mTLS 监听**（见 MTLSHandler）。明文口挂一个显式 403：
	// 让"管理员令牌拉不走整套信任材料"这条纪律在明文口上有个说得清的答案，
	// 而不是一个会被读成"路径写错了"的 404。
	mux.HandleFunc("/api/v1/standby/", s.handleStandbyPlaintextDenied)

	// 网关客户端证书：签发 / 清单 / 吊销（admin）
	mux.HandleFunc("POST /api/v1/pki/gateway-certs", s.handleIssueGatewayCert)
	mux.HandleFunc("GET /api/v1/pki/gateway-certs", s.handleGatewayCerts)
	mux.HandleFunc("POST /api/v1/pki/gateway-certs/{fingerprint}/revoke", s.handleRevokeGatewayCert)
	mux.HandleFunc("GET /api/v1/gateways", s.handleGateways)                // 在线网关清单（管理）
	mux.HandleFunc("GET /api/v1/resources", s.handleResources)              // 资源清单（管理）
	mux.HandleFunc("GET /api/v1/resources/reach", s.handleResourceReach)    // 逐资源后端可达性（网关拨测聚合）
	mux.HandleFunc("POST /api/v1/resources", s.handleSaveResource)          // 新增/改资源
	mux.HandleFunc("DELETE /api/v1/resources/{id}", s.handleDeleteResource) // 删资源

	// ── 终端用户门户（B/S 免客户端）──
	mux.HandleFunc("POST /api/v1/portal/login", s.handlePortalLogin)
	mux.HandleFunc("GET /api/v1/portal/apps", s.handlePortalApps)
	// 七层 Web 代理（B/S 免客户端）：门户点开 Web 应用时换一张短时效一次性访问票据。
	// 需登录 + 按资源鉴权后才发；真实消费方是网关的 L7 监听（gateway/internal/webproxy）。
	mux.HandleFunc("POST /api/v1/portal/web-ticket", s.handleWebTicket)
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
	s.noteLoginSuccess(r.Context(), cred.Account)
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
	Accessible  bool   `json:"accessible"`  // false = 未获授权（可申请），或已被终端风险降权
	ResourceID  string `json:"resourceId"`  // 关联受控资源（JIT 申请用；空=不接入自助申请）
	// Degraded 该磁贴此刻因终端风险降权不可访问（而非缺授权）。申请审批在这种状态下无效，
	// 门户据此把"申请访问"换成"请先修复终端环境"，免得用户提交必然被否的申请。
	Degraded bool `json:"degraded,omitempty"`
	// Unavailable 该应用**结构上不可用**（未关联受控资源 / 后端不是 host:port）——
	// **配置缺口，不是授权结论**。隧道与七层两条路都必然不通，而 JIT 闸也会以
	// 「该应用不支持自助申请」拒掉申请，所以它既不能渲染成「可访问」（按钮亮着点了打不开），
	// 也不能渲染成「需申请」（申请是死路）。剖面对这类应用是「丢弃 + 给管理员一条 warning」，
	// 门户没有 warnings 通道，故如实标在磁贴上。判据与剖面的丢弃分支同源（appAccessState）。
	Unavailable bool `json:"unavailable,omitempty"`
	// UnavailableReason 具体原因，直接渲染给用户看（他要拿这句话去找管理员）。
	UnavailableReason string `json:"unavailableReason,omitempty"`
}

// handlePortalApps 返回当前用户可见的应用门户。
//
// ★可访问性判定与客户端剖面、七层票据**同一个函数**（appAccessState → accessibleFor）：
// 静态 ACL ∪ 组织/用户组展开 ∪ 有效 JIT 授予，减去终端降权否决。
// 此前这里自己写了一份只看 sensitivity 的判据（普通恒可访问 / 高敏恒需申请），
// 那是控制面第四个判定点且方向与另外三处相反，三种失败形态全部无报错——见 appAccessState 的注释。
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
	byRes := make(map[string]store.Resource, len(resources))
	for _, res := range resources {
		byRes[res.ID] = res
	}
	user := normUser(c.Name)
	// 组织/用户组主体的展开索引。与剖面、网关策略下发同一个 store 方法、同一份展开实现
	// ——门户上「能不能点」与隧道里「放不放行」必须同真同假。
	subjects := s.subjectIndex(r.Context())
	// 调用方的有效授予集合（resource_id）：把「需申请」磁贴翻回可访问。best-effort，读失败按未授予处理。
	granted := map[string]bool{}
	if gs, err := s.store.ActiveGrantsFor(r.Context(), user); err == nil {
		for _, g := range gs {
			granted[g.ResourceID] = true
		}
	}
	// 终端风险降权：高敏磁贴一律标不可访问，且**JIT 授予也翻不回来**——与网关侧
	// DenyUsers 先于允许集合判定同构，否则门户显示"可访问"而隧道那边照拒。
	degraded, _ := s.degradeStateOf(r.Context(), user)
	tiles := []PortalTile{}
	for _, a := range b.Apps {
		if a.Status != "running" {
			continue
		}
		_, st := appAccessState(user, c.Role, a, byRes, subjects, granted, degraded)
		tiles = append(tiles, PortalTile{ID: a.ID, Name: a.Name, Mode: a.Mode, Addr: a.Addr,
			Sensitivity: st.Sensitivity, Accessible: st.Accessible, ResourceID: a.ResourceID,
			Degraded: st.Degraded, Unavailable: st.Unavailable, UnavailableReason: st.Reason})
	}
	// 七层入口此刻能不能用，如实随磁贴一起下发：Web 磁贴的「访问」按钮要不要给点、
	// 点不动时该说什么，都靠它。不下发的话用户只会拿到一个一闪而过的 503。
	webReady, webNote := s.webProxyStatus()
	httpx.JSON(w, http.StatusOK, map[string]any{
		"apps": tiles, "webProxy": map[string]any{"ready": webReady, "note": webNote}})
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
	// License 用户席位闸（demo 模式恒放行；判定与理由见 licenseAdmit）。
	if reason, ok := s.licenseAdmit(r, "user"); !ok {
		s.audit(r, "admin", "新增用户「"+u.Account+"」被 License 拒绝："+reason, "fail")
		httpx.Error(w, http.StatusConflict, reason)
		return
	}
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
	// ★旧口令校验同样要过防爆破闸。它需要已持有会话，所以不是未认证爆破面，
	// 但它是一个**口令预言机**：拿到会话（终端被盗、共享机器上没登出）的人可以
	// 在这里无限次试旧口令，把「拿到会话」升级成「知道口令」，进而横向复用到别的系统。
	// 其余四个认证入口（门户/管理台登录、TOTP 第二回合、passkey 断言）早就接了这道闸，
	// 唯独这里漏了——补上，判据与它们完全一致。
	if s.loginGateLocked(w, r, c.Sub) {
		return
	}
	cred, found, err := s.store.Credential(r.Context(), c.Sub) // Sub=规范账号
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load credential")
		return
	}
	if !found || !auth.VerifyPassword(cred.PassHash, body.Old) {
		s.noteLoginFailure(r, c.Sub)
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
	s.noteLoginSuccess(r.Context(), cred.Account)
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
	s.noteLoginSuccess(r.Context(), cred.Account) // 受限态也是一次成功认证，闲置判定算活跃
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
	// 终端指纹（可选请求体）：客户端自报，与 posture 上报、登录 deviceId 是同一个值。
	// 旧客户端不发请求体 → 空指纹 → 观察模式放行、严格模式拒（见 deviceAdmissionGate）。
	// 解码失败不报错：这里的语义是"没带指纹"，不是"请求非法"——把老客户端打成 400
	// 会在升级窗口里把整批终端断在门外。
	var kb struct {
		Device string `json:"device"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&kb)
	if !s.entryGates(w, r, c.Name, "敲门令牌") {
		return
	}
	// 授信终端闸（第四道）：这台设备是不是被允许接入。
	// ★放在最后一道：前三道（封禁 / 账号状态 / 终端合规）都是**账号**维度的否决，
	// 它们成立时连"这是哪台设备"都不必问；设备闸是账号通过之后的最后一层收缩。
	// 严格模式拒发；观察模式放行并按 (账号,指纹) 节流留痕；已吊销设备两种模式都拒。
	if adm := s.deviceAdmissionGate(r, c.Name, kb.Device); !adm.Allowed {
		s.audit(r, "security", "拒发敲门令牌："+c.Name+" 的终端未获授信（"+adm.Reason+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "终端未获授信："+adm.Reason)
		return
	}
	// Use=knock 是给数据面的用途自证：网关 strict 模式只接受本处签发的令牌，
	// 会话令牌/MFA 票据（Use 为空）一律拒绝敲门——堵死"持 8h 会话令牌直连数据面、
	// 绕过封禁/账号状态/终端合规三道闸"的旁路。改 knockTTL 须同步网关 -knock-max-ttl 上界。
	tok := s.keys.Sign(auth.Claims{
		Sub: c.Sub, Role: c.Role, Name: c.Name, Jti: auth.RandJTI(), Use: auth.UseKnock,
	}, knockTTL)
	// ★放行也要留痕（wave8 行动 8）。此前这条**主路径**成功时零审计，而同一函数与
	// entryGates 里五处拒绝全部落审计——于是审计里只有拒绝没有放行。
	// 对照最刺眼的是：过同一道 entryGates 的 B/S 路径**签票时是落审计的**。
	// wave7 那句「拒绝比放行更需要留痕」是排序不是排除。
	s.auditKnockIssued(r, c.Name, kb.Device)
	httpx.JSON(w, http.StatusOK, map[string]any{"token": tok, "expires_in": int(knockTTL.Seconds())})
}

// entryGates 是「这个账号此刻还能不能进数据面」的三道**账号维度**闸，
// 由两条接入形态共用：敲门令牌（C/S 隧道）与 Web 访问票据（B/S 七层）。
//
//	① 强制下线封禁期  ② 目录账号被禁用/锁定  ③ 终端环境判定 block（strict 下缺报亦拒）
//
// ★共用同一段代码是硬要求。两条路各写一套的话，「已强制下线的人换浏览器还能进」
// 这类洞会在某一次单边改动后无声出现，而管理台只显示其中一条路的状态。
// 设备准入（第四道）**不在这里**：它需要客户端自报的终端指纹，而浏览器没有，
// 见 handleKnockToken 尾部与 docs/ARCHITECTURE.md 的边界说明。
//
// label 只影响审计与错误文案（"拒发<label>：…"），判据完全一致。
// 返回 false 时响应已写好，调用方直接 return。
func (s *Server) entryGates(w http.ResponseWriter, r *http.Request, account, label string) bool {
	if ri, banned := s.revokedActive(account); banned {
		s.audit(r, "security", "拒发"+label+"："+account+" 在强制下线封禁期内（"+ri.Reason+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "已被强制下线，暂时无法接入")
		return false
	}
	// 账号状态门（永久闸，区别于上面的限时封禁）：禁用/锁定账号拒发，掐断 reknock 保活令牌来源
	if u, blocked, err := s.blockedDirAccount(r.Context(), account); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to check account status")
		return false
	} else if blocked {
		s.audit(r, "security", "拒发"+label+"："+u.Account+" 账号已"+statusZh[u.Status], "deny")
		httpx.Error(w, http.StatusForbidden, "账号已被"+statusZh[u.Status]+"，无法接入")
		return false
	}
	// 终端环境闸（第三道）：最新判定 block 一直拦（不看新鲜度，直到被合规报告替换——防停报逃逸）；
	// strict 模式下无新鲜报告也拒（fail-closed，生产开 BAIDI_POSTURE_ENFORCE=strict）。
	//
	// ★strict + 浏览器接入是**互斥**的：浏览器上报不了 posture，于是 B/S 路径会被
	// 一并拒绝。这是刻意的 fail-closed（"判不了"不等于"合规"），不是遗漏——
	// 要 B/S 免客户端接入就不能同时开 strict，边界写在 docs/ARCHITECTURE.md 第七节。
	if rep, found, err := s.store.PostureVerdict(r.Context(), account); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to check posture")
		return false
	} else if found && rep.Verdict == "block" {
		s.audit(r, "security", "拒发"+label+"："+account+" 终端环境不合规（"+strings.Join(rep.Reasons, "、")+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "终端环境不合规："+strings.Join(rep.Reasons, "、"))
		return false
	} else if s.postureStrict {
		// strict 缺报/过期拒发。新鲜度须按「最新」报告判（不是上面 rep 那条跨设备最差——
		// 一台旧设备的陈旧 degrade 行会把当前持续合规的用户永久拒之门外）。
		fresh, found, err := s.store.PostureFreshest(r.Context(), account)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to check posture freshness")
			return false
		}
		if !found || time.Now().Unix()-fresh.TS > int64(postureFreshTTL.Seconds()) {
			s.audit(r, "security", "拒发"+label+"："+account+" 无有效终端环境报告（strict）", "deny")
			httpx.Error(w, http.StatusForbidden, "无有效终端环境报告，无法接入")
			return false
		}
	}
	return true
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
		// Version / Events / Metrics 是新网关才上报的字段：旧网关缺省即零值，处理逻辑
		// 对空值必须无感（version 空串照存、events 空切片零循环、metrics 为 nil 即不落点），
		// 不得因缺字段报错。
		Version string `json:"version"` // 网关二进制版本（编译期注入）
		// Web / WebTLS 七层 Web 代理落点。未开启的网关**连字段都不发**，
		// 空串即"没开"，控制面据此如实回报而不是拼一个 http://host:/ 的坏地址。
		Web    string    `json:"web"`
		WebTLS bool      `json:"webTls"`
		Events []gwEvent `json:"events"` // 数据面回执：网关报告已实际执行的控制面指令
		// Metrics 宿主机设备状态采样。★是指针：nil（字段缺席）= 这台网关根本不上报指标
		// （旧版本），与「上报了但一项都没采到」（非 nil 但各项为 nil）必须分得开——
		// 前者去升级网关，后者去查这台机器为什么读不到 /proc。
		Metrics *gwMetrics `json:"metrics"`
		// Now 网关发送心跳时刻的本机时钟（Unix 秒）。★指针：nil = 旧网关不上报，
		// 时钟偏差按不可判定处理（不告警、页面显示"未上报"），绝不当 0。
		Now *int64 `json:"now"`
		// Ifaces 网关实测枚举的网卡清单（地址转换选接口用）。★同样是指针：
		// nil（字段缺席，旧网关）必须**保留**库里已有的记录，而空数组才表示
		// 「这台网关真的一张可用网卡都没有」。混为一谈的话，升级前的旧网关
		// 每次心跳都会把网卡表连同管理员定的 LAN/WAN 定性一起清空。
		Ifaces *[]gwIface `json:"ifaces"`
		// Reach 后端可达性拨测结果（wave7 行动 9）。★指针：nil（字段缺席，旧网关）
		// = 该网关不会测，聚合时按「未探测」；空数组 = 测了但当前零资源。
		Reach *[]gwReachResult `json:"reach"`
		// NAT 地址转换运行态回执（wave8 行动 3）。★指针：nil（字段缺席）= 旧网关，
		// 它对 NAT 什么都没说；非 nil 且 enabled=false = 新网关明确说「我没开 -nat」。
		// 这两者必须分得开——后者是最常见的失效（deploy 生成的 env 不含 -nat 项，
		// 管理员在控制台配好 DNAT、页面绿灯，而网关侧 applyNAT 首行就 return 了）。
		NAT *gwNATState `json:"nat"`
		// Stealth 内核态隐身实测回执（wave8 行动 7）。★同款三态：nil（字段缺席）=
		// 旧网关，它对隐身什么都没说；非 nil 且 wanted=false = 新网关明确说「我没带 -pf」。
		// 后者正是参考部署的默认形态，而页面上此前写着「攻击面 = 0」。
		Stealth *gwStealthState `json:"stealth"`
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
	// ★mTLS 在场时，证书 CN 是**权威身份**，压过网关自报的 b.ID。
	// 签发时 CN 就等于 gwID（pki.go），两者本该一致；不一致有两种成因，都很难自查：
	//   - 运维把 -gwid 写成了与证书 CN 不同的值：网卡台账记在自报 id 下，
	//     而 NAT 策略按 CN 下发（handleGatewayPolicy 用 gatewayIDFrom），
	//     结果管理员照着页面上的网卡配好策略，网关永远收不到，全程无报错；
	//   - 冒名：一张合法网关证书自报成别人的 id，就能覆写那台网关的网卡台账。
	// 故以 CN 为准并留一条响亮日志。明文兼容路径没有 CN，维持既有行为（自报 id）。
	if cn := mtlsCN(r); cn != "" && cn != id {
		slog.Warn("网关自报 id 与证书 CN 不符，按证书 CN 记账",
			"declared", id, "cn", cn,
			"提示", "多半是 -gwid 与签发证书时的 gwID 写岔了；不改的话地址转换策略会下发不到这台网关")
		id = cn
	}
	// 时钟偏差 = 网关自报时刻 − 控制面收包时刻。在锁外先算好：
	// 敲门令牌（knockTTL=90s）是控制面签、网关验的，两侧漂过有效期时
	// 每次敲门都以"过期"被拒且全链路无报错——这个减法是那次事故唯一的前置可见信号。
	var skew *int64
	if b.Now != nil {
		d := *b.Now - time.Now().Unix()
		skew = &d
	}
	s.mu.Lock()
	s.gateways[id] = GatewayInfo{
		ID: id, Proxy: b.Proxy, SPA: b.SPA, LastSeen: time.Now().Unix(),
		Clients: b.Clients, Tunnels: b.Tunnels, Uptime: b.Uptime, Version: b.Version,
		Web: b.Web, WebTLS: b.WebTLS, SkewSec: skew,
	}
	s.gwSess[id] = b.Sessions
	s.gwTunnelFP[id] = b.TunnelFP
	// 后端拨测快照：旧网关（nil）不覆盖不清空——它没说任何事。
	if b.Reach != nil {
		s.gwReach[id] = gwReachInfo{Results: *b.Reach, At: time.Now().Unix()}
	}
	// 地址转换运行态：同款三态——nil（旧网关，字段缺席）不覆盖不清空。
	// 覆盖的话，一台旧网关的心跳会把同 id 新网关刚报过的运行态抹成「从未上报」。
	if b.NAT != nil {
		s.gwNAT[id] = gwNATInfo{State: *b.NAT, At: time.Now().Unix()}
	}
	// 内核态隐身实测态：同款三态——nil（旧网关）不覆盖不清空。
	if b.Stealth != nil {
		s.gwStealth[id] = gwStealthInfo{State: *b.Stealth, At: time.Now().Unix()}
	}
	s.mu.Unlock()

	// 设备状态落时序表（缺字段的旧网关在这里是空操作，双向兼容）。
	// 落库失败只记日志：指标是观测通道，不该让一次写库抖动把网关判成离线。
	s.recordGatewayMetrics(r, id, b.Metrics)
	s.recordGatewayIfaces(r, id, b.Ifaces)

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
	as, _ := s.writer.(store.AttackStore) // Memory 后端没有攻击表：审计照落，统计跳过
	for _, ev := range events {
		detail := strings.TrimSpace(ev.Detail)
		if detail == "" {
			detail = ev.Kind // 空 detail 至少留下事件种类，不落一条空话
		}
		// ★verdict 按事件种类：拒绝落 deny，放行落 allow，回执类落 ok。
		// 此前一律硬编码 "ok"——「网关报告了一次拒绝」在审计判定分布里被数成"允许"，
		// 安全概览的"拒绝"计数对数据面事件永远为零。
		verdict := "ok"
		switch ev.Kind {
		case "sec-deny":
			verdict = "deny"
			if ev.Src != "" && ev.Cat != "" && as != nil {
				// 机读半边：按 (网关, 源IP, 类别) 计入攻击源小时桶。落库失败只记日志——
				// 统计是观测通道，绝不能挡住同一条事件的审计留痕。
				if err := as.RecordAttack(r.Context(), id, ev.Src, ev.Cat, ev.Count, time.Now().Unix()); err != nil {
					slog.Warn("攻击源计数落库失败（审计已留痕）", "gw", id, "src", ev.Src, "err", err.Error())
				}
			}
		case "sec-allow":
			// ★放行**绝不**进攻击源统计：把一次正常访问数进「攻击源 TOP」，
			// 是最容易误导排障的一种错记。
			verdict = "allow"
		}
		// ★源 IP：数据面事件的真实来源是网关报上来的那个（攻击者 / 访问者的地址），
		// 不是网关自己的地址。此前一律记 clientIP(r) = 网关地址，于是按 src_ip 检索
		// 审计根本找不到攻击者，那个地址只活在事件正文的自由文本里；
		// FR-AUDIT-05 的「出向四元组检索」也就没有数据源。
		s.auditDataplane(r, actor, ev.Src, "网关 "+id+" 报告："+detail, verdict)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// gwEvent 网关随心跳捎带的一条数据面回执或安全事件（与 gateway/internal/cplane 的 Event 同构）。
type gwEvent struct {
	TS     int64  `json:"ts"`     // 网关侧执行时刻（Unix 秒；仅参考，审计时间以控制面落库为准）
	Kind   string `json:"kind"`   // revoke-applied | policy-applied | nat-applied | sec-deny
	Detail string `json:"detail"` // 网关侧生成的事实描述
	// 以下仅安全事件（sec-deny）携带；旧网关不发，零值即无统计（审计照落）。
	Src   string `json:"src"`   // 拒绝来源 IP
	Cat   string `json:"cat"`   // 细分类别（枚举见 store.AttackCatZh）
	Count int    `json:"count"` // 网关节流窗口内的聚合次数
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
	// 的执行方（PRD 1.5）。恢复合规后下一轮名单里就没有他，网关侧无需任何人工操作
	// ——但客户端那半要重连才拿得回路由（隧道参数拉起即定死，见 api.degradeWarning）。
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
	// 地址转换策略：只下发**这台网关**启用中的那几条（NAT 是设备本地能力，
	// 各网关网卡名与拓扑都不同，一条规则被所有网关领走会灌出一堆不匹配的规则）。
	// 网关拿到后编译成 nft/pf 灌内核；它不知道「哪个网段该上网」，只执行算好的结果。
	// 取不到时下发空数组而不是省略字段：省略会让新网关误以为「控制面还不支持 NAT」
	// 从而保留上一轮的旧规则，而空数组的语义是明确的「本网关当前无 NAT 策略」。
	natOut := []store.NATPolicy{}
	if s.nat != nil {
		if all, err := s.nat.NATPolicies(r.Context()); err == nil {
			natOut = store.NATForGateway(all, gatewayIDFrom(r))
		} else {
			slog.Error("下发 NAT 策略失败，本轮按空集下发", "err", err.Error())
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"resources": gwRes, "revoked": revoked, "nat": natOut})
}

// gatewayIDFrom 取本次请求的网关身份，**以已认证的那个为准**：
// mTLS 侧是客户端证书 CN（签发时就等于 gwID，见 pki.go），明文兼容侧是令牌主体。
// 两条路都拿不到返回空串，NATForGateway 会据此下发空集（fail-closed：
// 认不出是哪台网关时，宁可不下发规则，也不能把别人的 NAT 规则灌进这台机器）。
//
// ★注册心跳里那个 b.ID 是网关**自报**的，不作为权威身份：mTLS 在场时
// handleGatewayRegister 会用 CN 覆盖它（见那里的注释），两个出口因此一致。
//
// 明文兼容路径（gwPlaintextCompat，过渡逃生舱）没有 CN，只能退回令牌主体。
// 那条路上令牌主体与网关自报 id 未必相同，NAT 分发要求两者一致——生产部署
// 走的是 mTLS，`/api/v1/gateways/*` 本就只挂 mTLS 监听，故不为此增加特例。
func gatewayIDFrom(r *http.Request) string {
	if cn := mtlsCN(r); cn != "" {
		return cn
	}
	if c, ok := auth.FromContext(r.Context()); ok {
		return c.Sub
	}
	return ""
}

// mtlsCN 取客户端证书的 CN；非 mTLS 请求回空串。
func mtlsCN(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return ""
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
	// 七层 Web 代理两项：后端协议 + 对外入口覆盖。空 = 由 store.NormalizeWebScheme
	// 按端口推默认，给了值就必须合法——静默丢弃拼错的 "HTTPS "/"tls" 会让网关
	// 拿 HTTP 去撞一个 TLS 端口，症状是浏览器上一个空白页，谁也想不到是协议猜错。
	if res.WebScheme != "" && !strings.EqualFold(res.WebScheme, store.WebSchemeHTTP) &&
		!strings.EqualFold(res.WebScheme, store.WebSchemeHTTPS) {
		httpx.Error(w, http.StatusBadRequest, "webScheme 取值须为 http|https")
		return
	}
	if err := validateWebEntry(res.WebEntry); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
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
	switch {
	case err == nil:
	case errors.Is(err, store.ErrUnknownAppCategory):
		// ★400 而不是默默落库：分类字典里没有的 key 会让这个应用在筛选条的
		// 任何一栏都不出现（只有「全部应用」看得到），而接口若回 201，
		// 管理员没有任何线索知道自己发布到了一个不存在的分类里。
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	default:
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
	// ★同事务联动设备状态：通过 → trusted，驳回 → revoked。
	// 分两步写的话，「批了但设备还是 pending」会是一个无报错、只在用户连不上时
	// 才被发现的状态——设备生命周期与审批单必须一起翻。
	dev, linked, err := s.writer.DecideApproval(r.Context(), id, body.Decision, body.Reason, actorOf(r))
	switch {
	case err == nil:
	case errors.Is(err, store.ErrApprovalNotFound):
		// ★不能回 200：那会落一条「设备绑定审批 xxx：通过」的审计，
		// 而库里根本没有这张单子——审计里出现一件没发生过的事。
		httpx.Error(w, http.StatusNotFound, "审批单不存在")
		return
	case errors.Is(err, store.ErrApprovalDecided):
		// ★重放拦在这里：放过去的话，一张已驳回的单子再"通过"一次就能把 revoked
		// 的设备改回 trusted，而审批行与时间线仍停在「驳回」。
		httpx.Error(w, http.StatusConflict, "该审批单已处置，不能重复处置（设备授信状态未改动）")
		return
	default:
		httpx.Error(w, http.StatusInternalServerError, "failed to decide approval")
		return
	}
	decZh := map[string]string{"approved": "通过", "rejected": "驳回"}[body.Decision]
	resp := map[string]any{"ok": true, "id": id, "decision": body.Decision, "deviceLinked": linked}
	switch {
	case !linked:
		// 审计只记已发生的事：这张单子没有关联设备，批了也不会有任何终端被置为授信。
		s.audit(r, "admin", "设备绑定审批 "+id+"："+decZh+"（该审批单未关联任何终端登记，未改变任何设备的授信状态）", "ok")
	case body.Decision == "approved":
		resp["device"] = dev
		s.audit(r, "security", "设备绑定审批 "+id+"：通过，终端已置为授信——"+dev.Account+" / "+dev.Name+
			"（指纹 "+shortFP(dev.Fingerprint)+"）", "ok")
	default:
		until := s.banAccountForDevice(dev, body.Reason)
		resp["device"] = dev
		resp["banUntil"] = until
		resp["blastRadius"] = deviceRevokeBlastRadius
		s.audit(r, "security", "设备绑定审批 "+id+"：驳回。"+deviceRevokeAudit(dev, body.Reason, until), "deny")
	}
	httpx.JSON(w, http.StatusOK, resp)
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

// handleAuthSrc 认证源页顶部聚合（源清单 + 归属账号计数）。
//
// ★权限必须与 GET /api/v1/authsrc/sources 同档（requireAdmin，角色现算）：
// 两个端点读的是同一批库行，聚合这份还多带账号计数。低一档就等于给同一份数据
// 开了条侧门——"外部目录接了哪些源、各接进来多少人"是攻击者做社工的现成情报。
func (s *Server) handleAuthSrc(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
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
	// checkCatalog 采集器真的会上报的检查项目录，随基线一起下发。
	//
	// ★页面的「添加检测项」必须从它里面选，不能让管理员自由填 key：采集器不报的 key
	// 会让该基线对全平台终端永远判违规（详见 handleSaveBaseline 里那道入口校验）。
	// 与入口校验读的是同一份 store.CollectableChecks——前端自己抄一份的话，
	// 加采集项时前端不跟进，页面上就永远选不到新项。
	httpx.JSON(w, http.StatusOK, map[string]any{
		"baselines": b.Baselines, "checkCatalog": store.CollectableChecks()})
}

// handleDevices 已搬到 devices.go（授信终端主线）：它现在有权限闸、有真实数据源、
// 且与准入判定共用同一份设置，留在这里只会让下一个改设备逻辑的人漏掉半边。

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	// 审计日志本身是敏感面：全量行为轨迹 + 源 IP。放给 role=user 等于
	// 让任意登录终端摸清管理员操作节奏。三权分立下更进一步：**只有审计权**能读——
	// 安全管理员能定策略却读不到全量日志，才谈得上"定策略的人不看自己的痕迹"。
	if !s.requirePerm(w, r, store.PermAudit) {
		return
	}
	// 带任一检索参数 → 走 SearchAudit（同一响应结构里以 search 段返回，首屏聚合不变）。
	qs := r.URL.Query()
	q := store.AuditQuery{
		Category: qs.Get("category"), Actor: qs.Get("actor"), SrcIP: qs.Get("srcIp"),
		Keyword: qs.Get("q"), From: qs.Get("from"), To: qs.Get("to"),
		Limit: atoiDefault(qs.Get("limit"), 0), Offset: atoiDefault(qs.Get("offset"), 0),
	}
	searching := q.Category != "" || q.Actor != "" || q.SrcIP != "" || q.Keyword != "" || q.From != "" || q.To != "" ||
		qs.Get("limit") != "" || qs.Get("offset") != ""
	if searching {
		if q.Category != "" && !map[string]bool{"access": true, "auth": true, "admin": true,
			"security": true, "dataplane": true, "system": true}[q.Category] {
			httpx.Error(w, http.StatusBadRequest, "未知的审计类别："+q.Category)
			return
		}
		as, ok := s.store.(auditSearcher)
		if !ok {
			// Memory 种子只有 8 条演示日志，装一个"检索"是在演示一个假能力。
			httpx.Error(w, http.StatusNotImplemented, "当前存储后端不支持审计检索（内存种子模式）")
			return
		}
		logs, total, err := as.SearchAudit(r.Context(), q)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "审计检索失败")
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"logs": logs, "total": total,
			"limit": q.Limit, "offset": q.Offset})
		return
	}
	b, err := s.store.Audit(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load audit")
		return
	}
	// ★writeHealth 挂在**读**响应上是有意的：审计写不进去的时候，读路径通常还活着，
	// 这一格就是那种状态下唯一还能自曝家丑的地方。健康时（零失败）整段不下发，
	// 页面上不占位——常态零噪声，出事才现身。
	httpx.JSON(w, http.StatusOK, auditResponse{AuditBundle: b, WriteHealth: s.auditWriteOrNil()})
}

// auditResponse 审计首屏 = 原 AuditBundle + 控制面自身的审计写入健康。
// 用嵌入而不是往 store.AuditBundle 加字段：那是存储层的数据模型，
// 「本进程写失败了几次」是 api 层的运行态，不该混进去。
type auditResponse struct {
	store.AuditBundle
	WriteHealth *auditWriteHealth `json:"writeHealth,omitempty"`
}

// auditWriteOrNil 零失败时回 nil（omitempty 整段不下发）。
func (s *Server) auditWriteOrNil() *auditWriteHealth {
	h := s.auditWrite.snapshot()
	if h.Failures == 0 {
		return nil
	}
	return &h
}

// auditSearcher 审计在线检索能力（SQLiteStore 实现）。
type auditSearcher interface {
	SearchAudit(ctx context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error)
}

// atoiDefault 解析非负整数，解析不了回缺省值。
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}

// handleGateway 已搬到 gatewaypage.go：它现在按 mTLS 注册心跳的真实网关构建，
// 不再读 store 的区域拓扑种子（那张「华东/华南出口」是编的）。

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
	// 时间窗（?hours=）：审计派生统计与攻击源共用它，钳边界在 store 一处。
	// 不传就是默认 24h——与改造前"攻击源 24h"那一半口径一致，页面不会突然换语义。
	ov, err := s.store.Overview(r.Context(), atoiDefault(r.URL.Query().Get("hours"), 0))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load overview")
		return
	}
	// 在线会话数只有 api 层掌握（网关上报的真实敲门会话），store 层恒为 0。
	//
	// ★这里原来还顺手把「在线设备数」按会话数对齐：会话是按账号计的、一个账号可以
	// 同时开几条，拿它当设备数只是让那个来自种子的 186/240 看起来像被更新过。
	// 设备口径已改成 trusted_devices 台账（store.DeviceStat），与会话不是一回事，
	// 不再互相顶替。
	if n := s.onlineSessionCount(); n >= 0 {
		ov.Sessions = n
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
