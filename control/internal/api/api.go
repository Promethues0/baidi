// Package api 装配白帝控制中心的 HTTP 路由与模块处理器。
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// Version 控制中心版本号。
const Version = "0.3.0"

// tokenTTL 会话令牌有效期；knockTTL 短时效一次性敲门令牌有效期；
// kickBanTTL 强制下线后的接入封禁时长（期内拒发敲门令牌、网关拒敲门，到期自然恢复）。
const (
	tokenTTL   = 8 * time.Hour
	knockTTL   = 90 * time.Second
	kickBanTTL = 5 * time.Minute
	// seedInitialPassword 新建用户未指定初始口令时的 demo 默认口令。
	seedInitialPassword = "baidi@123"
)

// Server 持有依赖（store 读 + writer 写 + JWT 密钥），按模块注册路由。
type Server struct {
	store    store.Store
	writer   store.Writer
	secret   []byte
	env      string
	mu       sync.Mutex
	gateways map[string]GatewayInfo   // 已注册（在线）网关，按 id
	gwSess   map[string][]GwSession   // 各网关上报的活跃会话，按网关 id（监控中心真实在线用户来源）
	kicked   map[string]string        // 已被强制下线的会话 id → 处置说明（监控中心 · 在线用户显示层）
	revoked  map[string]revokeInfo    // 强制下线封禁：账号 → {原因, 截止}（拒发敲门令牌 + 经网关策略下发数据面处置）
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
}

// GwSession 网关上报的一条活跃会话（真实敲门放行记录）。
type GwSession struct {
	IP    string `json:"ip"`
	User  string `json:"user"`
	Role  string `json:"role"`
	Since int64  `json:"since"`
}

// New 构造 Server。
func New(st store.Store, wr store.Writer, secret []byte, env string) *Server {
	return &Server{store: st, writer: wr, secret: secret, env: env, gateways: map[string]GatewayInfo{}, gwSess: map[string][]GwSession{}, kicked: map[string]string{}, revoked: map[string]revokeInfo{}}
}

// IsOpen 报告某路径是否免认证（登录/健康检查/门户登录）。供 auth 中间件使用。
func (s *Server) IsOpen(_, path string) bool {
	switch path {
	case "/healthz", "/api/v1/auth/login", "/api/v1/portal/login":
		return true
	}
	return false
}

// requireAdmin 校验上下文中的角色为 admin，否则 403。
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	c, ok := auth.FromContext(r.Context())
	if !ok || c.Role != "admin" {
		httpx.Error(w, http.StatusForbidden, "需要管理员权限")
		return false
	}
	return true
}

// requireGateway 校验上下文角色为 gateway 或 admin（数据面拉策略/注册用）。
func (s *Server) requireGateway(w http.ResponseWriter, r *http.Request) bool {
	c, ok := auth.FromContext(r.Context())
	if !ok || (c.Role != "gateway" && c.Role != "admin") {
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
	// 审计中心：分类聚合 + 磁盘水位 + 日志
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	// 网关与隐身：区域/节点拓扑 + SPA
	mux.HandleFunc("GET /api/v1/gateway", s.handleGateway)

	// 系统管理：三权分立 + 集群
	mux.HandleFunc("GET /api/v1/system", s.handleSystem)
	// 认证源接入：认证源 + 自适应规则
	mux.HandleFunc("GET /api/v1/authsrc", s.handleAuthSrc)
	// 安全中心：安全基线 + SPA
	mux.HandleFunc("GET /api/v1/security", s.handleSecurity)
	// 运维诊断：控制面/存储/数据面/隐身/集群/身份/态势/密钥多维真实自检（admin）
	mux.HandleFunc("GET /api/v1/diag", s.handleDiag)

	// 监控中心：在线用户（实时会话）+ 强制下线 + 用户状态
	mux.HandleFunc("GET /api/v1/online", s.handleOnline)
	mux.HandleFunc("POST /api/v1/online/{id}/kick", s.handleKickSession) // 强制下线（admin）
	mux.HandleFunc("GET /api/v1/userstate", s.handleUserState)

	// IPSec VPN 组网：站点清单 + CRUD + 启停
	mux.HandleFunc("GET /api/v1/ipsec", s.handleIpsec)
	mux.HandleFunc("POST /api/v1/ipsec", s.handleSaveIpsec)            // 新增/改站点（admin）
	mux.HandleFunc("DELETE /api/v1/ipsec/{id}", s.handleDeleteIpsec)   // 删站点（admin）
	mux.HandleFunc("POST /api/v1/ipsec/{id}/toggle", s.handleToggleIpsec) // 启停隧道（admin）

	// 对象库：地址 / 服务 / 时间对象 + 被引用反查（复用闭环）
	mux.HandleFunc("GET /api/v1/objects", s.handleObjects)
	mux.HandleFunc("GET /api/v1/objects/usage", s.handleObjectsUsage)          // 被引用反查（资源/IPSec）
	mux.HandleFunc("POST /api/v1/objects/{kind}", s.handleSaveObject)       // 新增/改对象（admin）
	mux.HandleFunc("DELETE /api/v1/objects/{kind}/{id}", s.handleDeleteObject) // 删对象（admin，被引用拒删 409）

	// 认证策略：PC/WEB 端与移动端分栏认证方式 + 自适应规则
	mux.HandleFunc("GET /api/v1/authpolicy", s.handleAuthPolicies)
	mux.HandleFunc("POST /api/v1/authpolicy", s.handleSaveAuthPolicy)          // 新增/改策略（admin）
	mux.HandleFunc("DELETE /api/v1/authpolicy/{id}", s.handleDeleteAuthPolicy) // 删策略（admin）

	// ── 写操作（落 SQLite）──
	mux.HandleFunc("POST /api/v1/apps", s.handleCreateApp)                       // 发布应用
	mux.HandleFunc("POST /api/v1/approvals/{id}/decide", s.handleDecideApproval) // 设备绑定审批
	mux.HandleFunc("PUT /api/v1/policies/{node}", s.handleSavePolicy)            // 保存用户策略覆盖
	mux.HandleFunc("GET /api/v1/policies/{node}", s.handleGetPolicy)             // 读取用户策略覆盖
	mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)                     // 新增用户
	mux.HandleFunc("POST /api/v1/users/{id}/status", s.handleSetUserStatus)      // 禁用/启用/解锁
	mux.HandleFunc("POST /api/v1/users/{id}/password", s.handleResetUserPassword) // 管理员重置口令
	mux.HandleFunc("POST /api/v1/auth/password", s.handleChangePassword)          // 自助改密

	// ── 网关数据面：注册 + 拉策略（需 gateway/admin 身份）；资源 CRUD（admin）──
	mux.HandleFunc("POST /api/v1/gateways/register", s.handleGatewayRegister) // 网关注册/心跳
	mux.HandleFunc("GET /api/v1/gateways/policy", s.handleGatewayPolicy)      // 网关拉资源策略
	mux.HandleFunc("GET /api/v1/gateways", s.handleGateways)                  // 在线网关清单（管理）
	mux.HandleFunc("GET /api/v1/resources", s.handleResources)                // 资源清单（管理）
	mux.HandleFunc("POST /api/v1/resources", s.handleSaveResource)            // 新增/改资源
	mux.HandleFunc("DELETE /api/v1/resources/{id}", s.handleDeleteResource)   // 删资源

	// ── 终端用户门户（B/S 免客户端）──
	mux.HandleFunc("POST /api/v1/portal/login", s.handlePortalLogin)
	mux.HandleFunc("GET /api/v1/portal/apps", s.handlePortalApps)

	return mux
}

// handlePortalLogin 终端用户登录（演示口令 baidi@123；未授信/外包账号触发自适应二次认证，验证码 123456）。
func (s *Server) handlePortalLogin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
		MfaCode  string `json:"mfaCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Username == "" || b.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "用户名/密码不能为空")
		return
	}
	// 真实凭据校验：查目录账号 + bcrypt 口令哈希（不再是"任意用户名 + baidi@123"）
	cred, found, err := s.store.Credential(r.Context(), b.Username)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load credential")
		return
	}
	if !found || !auth.VerifyPassword(cred.PassHash, b.Password) {
		s.auditAs(r, b.Username, "auth", "终端用户登录失败（账号或口令错误）", "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "用户名或密码错误"})
		return
	}
	// 账号状态门：禁用/锁定的目录账号口令对了也不放行（也不进 MFA 流程）
	if accountBlocked(cred.Status) {
		s.auditAs(r, cred.Account, "auth", "终端用户登录被拒（账号已"+statusZh[cred.Status]+"）", "deny")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "账号已被" + statusZh[cred.Status] + "，请联系管理员"})
		return
	}
	risky := strings.HasPrefix(cred.Account, "ext") || strings.Contains(cred.Account, "外包")
	if risky && b.MfaCode == "" {
		s.auditAs(r, cred.Account, "security", "终端用户登录触发自适应二次认证", "mfa")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "needMfa": true, "reason": "检测到未授信终端/异地登录，需短信二次认证"})
		return
	}
	if risky && b.MfaCode != "123456" {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "needMfa": true, "reason": "验证码错误（演示验证码：123456）"})
		return
	}
	s.auditAs(r, cred.Account, "auth", "终端用户登录成功", "ok")
	// 令牌 Name=账号（数据面网关按 claims.Name 做放行/封禁匹配，必须是规范账号，不能放显示名）；
	// 显示名单独经响应体 displayName 回给前端。
	tok := auth.Sign(s.secret, auth.Claims{Sub: cred.Account, Role: cred.Role, Name: cred.Account}, tokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "token": tok, "displayName": cred.Name})
}

// PortalTile 应用门户卡片。
type PortalTile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Addr        string `json:"addr"`
	Sensitivity string `json:"sensitivity"` // normal | high
	Accessible  bool   `json:"accessible"`  // false = 需申请
}

// handlePortalApps 返回当前用户可见的应用门户（复用 SQLite 中的已发布应用；高敏类需申请）。
func (s *Server) handlePortalApps(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.Apps(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load portal apps")
		return
	}
	tiles := []PortalTile{}
	for _, a := range b.Apps {
		if a.Status != "running" {
			continue
		}
		sens, acc := "normal", true
		if a.Category == "finance" {
			sens, acc = "high", false // 高敏应用默认需走自助申请审批
		}
		tiles = append(tiles, PortalTile{ID: a.ID, Name: a.Name, Mode: a.Mode, Addr: a.Addr, Sensitivity: sens, Accessible: acc})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"apps": tiles})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
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
	created, err := s.writer.CreateUser(r.Context(), u)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	s.audit(r, "admin", "新增用户「"+created.Name+"」("+created.Account+")", "ok")
	httpx.JSON(w, http.StatusCreated, created)
}

func (s *Server) handleSetUserStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
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
	if err := s.writer.SetUserStatus(r.Context(), id, body.Status); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to set user status")
		return
	}
	// 数据面联动：禁用/锁定 → 入封禁表（经网关策略轮询捎带撤窗+断隧道，同强制下线管道）；
	// 恢复启用 → 立即解除封禁（管理员显式信任动作，同时豁免残余的强制下线封禁）。
	// 新令牌来源由登录/knock-token 的账号状态门永久把守，限时封禁只负责掐掉存量在线。
	zh := statusZh[body.Status]
	detail := ""
	if u, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool { return du.ID == id }); err != nil {
		// 状态已落库但目录回查失败：数据面封禁没挂上，留痕告警。
		// 兜底：登录/knock-token 的账号状态门 fail-closed，该账号拿不到新令牌。
		if accountBlocked(body.Status) {
			s.audit(r, "security", "用户 "+id+" 置「"+zh+"」后目录回查失败，数据面即时封禁未生效（存量隧道待自然过期）", "fail")
		}
	} else if found {
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
	if !s.requireAdmin(w, r) {
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
	if err := s.writer.SetUserPassword(r.Context(), id, hash); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to set password")
		return
	}
	s.audit(r, "admin", "重置用户 "+id+" 的登录口令", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleChangePassword 当前登录用户自助改密（校验旧口令）。
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.FromContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "未认证")
		return
	}
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.New) < 6 {
		httpx.Error(w, http.StatusBadRequest, "新口令至少 6 位")
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
	if err := s.writer.SetUserPassword(r.Context(), cred.ID, hash); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to set password")
		return
	}
	s.audit(r, "auth", "自助修改登录口令", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
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
	// 真实凭据校验 + 要求 admin 角色（普通账号口令对也拿不到管理台）
	cred, found, err := s.store.Credential(r.Context(), b.Username)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load credential")
		return
	}
	if !found || !auth.VerifyPassword(cred.PassHash, b.Password) {
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
	s.auditAs(r, cred.Name, "auth", "管理员登录成功", "ok")
	// Name=账号（同门户：数据面身份匹配用规范账号）；显示名走 displayName。
	tok := auth.Sign(s.secret, auth.Claims{Sub: cred.Account, Role: "admin", Name: cred.Account}, tokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "token": tok, "displayName": cred.Name, "role": "admin"})
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
	c, ok := auth.FromContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "未认证")
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
	tok := auth.Sign(s.secret, auth.Claims{Sub: c.Sub, Role: c.Role, Name: c.Name, Jti: auth.RandJTI()}, knockTTL)
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
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	c, _ := auth.FromContext(r.Context())
	id := b.ID
	if id == "" {
		id = c.Sub
	}
	s.mu.Lock()
	s.gateways[id] = GatewayInfo{
		ID: id, Proxy: b.Proxy, SPA: b.SPA, LastSeen: time.Now().Unix(),
		Clients: b.Clients, Tunnels: b.Tunnels, Uptime: b.Uptime,
	}
	s.gwSess[id] = b.Sessions
	s.mu.Unlock()
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
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
	if b, err := s.store.Users(r.Context()); err == nil {
		until := now + int64(kickBanTTL.Seconds())
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
	httpx.JSON(w, http.StatusOK, map[string]any{"resources": rs, "revoked": revoked})
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

// handleResources 资源清单（管理台用）。
func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rs, err := s.store.Resources(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load resources")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"resources": rs})
}

// handleSaveResource 新增/修改一条受控资源（admin），落库后网关下次轮询即生效。
func (s *Server) handleSaveResource(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var res store.Resource
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil || res.ID == "" || res.Backend == "" {
		httpx.Error(w, http.StatusBadRequest, "id/backend 必填")
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
	if err := s.writer.SaveResource(r.Context(), res); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save resource")
		return
	}
	s.audit(r, "admin", "保存受控资源「"+res.ID+"」("+res.Backend+")", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "resource": res})
}

// handleDeleteResource 删除一条受控资源（admin）。
func (s *Server) handleDeleteResource(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
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
	if !s.requireAdmin(w, r) {
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
	if !s.requireAdmin(w, r) {
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
	if !s.requireAdmin(w, r) {
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

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.System(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load system")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
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

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
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
