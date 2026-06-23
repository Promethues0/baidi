// Package api 装配白帝控制中心的 HTTP 路由与模块处理器。
package api

import (
	"encoding/json"
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

// tokenTTL 会话令牌有效期；knockTTL 短时效一次性敲门令牌有效期。
const (
	tokenTTL = 8 * time.Hour
	knockTTL = 90 * time.Second
)

// Server 持有依赖（store 读 + writer 写 + JWT 密钥），按模块注册路由。
type Server struct {
	store    store.Store
	writer   store.Writer
	secret   []byte
	env      string
	mu       sync.Mutex
	gateways map[string]GatewayInfo // 已注册（在线）网关，按 id
}

// GatewayInfo 一台已注册数据面网关的运行信息。
type GatewayInfo struct {
	ID       string `json:"id"`
	Proxy    string `json:"proxy"`
	SPA      string `json:"spa"`
	LastSeen int64  `json:"lastSeen"`
}

// New 构造 Server。
func New(st store.Store, wr store.Writer, secret []byte, env string) *Server {
	return &Server{store: st, writer: wr, secret: secret, env: env, gateways: map[string]GatewayInfo{}}
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

	// ── 写操作（落 SQLite）──
	mux.HandleFunc("POST /api/v1/apps", s.handleCreateApp)                       // 发布应用
	mux.HandleFunc("POST /api/v1/approvals/{id}/decide", s.handleDecideApproval) // 设备绑定审批
	mux.HandleFunc("PUT /api/v1/policies/{node}", s.handleSavePolicy)            // 保存用户策略覆盖
	mux.HandleFunc("GET /api/v1/policies/{node}", s.handleGetPolicy)             // 读取用户策略覆盖
	mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)                     // 新增用户
	mux.HandleFunc("POST /api/v1/users/{id}/status", s.handleSetUserStatus)      // 禁用/启用/解锁

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
	if b.Password != "baidi@123" {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "用户名或密码错误（演示口令：baidi@123）"})
		return
	}
	risky := strings.HasPrefix(b.Username, "ext") || strings.Contains(b.Username, "外包")
	if risky && b.MfaCode == "" {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "needMfa": true, "reason": "检测到未授信终端/异地登录，需短信二次认证"})
		return
	}
	if risky && b.MfaCode != "123456" {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "needMfa": true, "reason": "验证码错误（演示验证码：123456）"})
		return
	}
	tok := auth.Sign(s.secret, auth.Claims{Sub: b.Username, Role: "user", Name: b.Username}, tokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "token": tok, "displayName": b.Username})
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
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil || u.Name == "" || u.Account == "" {
		httpx.Error(w, http.StatusBadRequest, "用户名/账号不能为空")
		return
	}
	created, err := s.writer.CreateUser(r.Context(), u)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to create user")
		return
	}
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
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "status": body.Status})
}

// handleAdminLogin 管理员登录（演示：admin / baidi@123）→ 签发 admin 角色 JWT。
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Username == "" || b.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "用户名/密码不能为空")
		return
	}
	if b.Username != "admin" || b.Password != "baidi@123" {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "reason": "用户名或密码错误（演示账号 admin / baidi@123）"})
		return
	}
	tok := auth.Sign(s.secret, auth.Claims{Sub: b.Username, Role: "admin", Name: "安全管理员"}, tokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "token": tok, "displayName": "安全管理员", "role": "admin"})
}

// handleMe 返回当前令牌身份。
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c, _ := auth.FromContext(r.Context())
	httpx.JSON(w, http.StatusOK, map[string]any{"sub": c.Sub, "role": c.Role, "name": c.Name, "exp": c.Exp})
}

// handleKnockToken 为已登录会话签发短时效一次性敲门令牌（带随机 jti）。
// 客户端用它敲门、网关按 jti 一次性放行，杜绝令牌被解出后主动重放（90s 内也仅一次）。
func (s *Server) handleKnockToken(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.FromContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "未认证")
		return
	}
	tok := auth.Sign(s.secret, auth.Claims{Sub: c.Sub, Role: c.Role, Name: c.Name, Jti: auth.RandJTI()}, knockTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"token": tok, "expires_in": int(knockTTL.Seconds())})
}

// handleGatewayRegister 记录一台数据面网关上线/心跳（网关用自签 gateway 令牌认证）。
func (s *Server) handleGatewayRegister(w http.ResponseWriter, r *http.Request) {
	if !s.requireGateway(w, r) {
		return
	}
	var b struct {
		ID    string `json:"id"`
		Proxy string `json:"proxy"`
		SPA   string `json:"spa"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	c, _ := auth.FromContext(r.Context())
	id := b.ID
	if id == "" {
		id = c.Sub
	}
	s.mu.Lock()
	s.gateways[id] = GatewayInfo{ID: id, Proxy: b.Proxy, SPA: b.SPA, LastSeen: time.Now().Unix()}
	s.mu.Unlock()
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleGatewayPolicy 网关拉取当前资源授权策略（替代静态 resources.json）。
func (s *Server) handleGatewayPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireGateway(w, r) {
		return
	}
	rs, err := s.store.Resources(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load resources")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"resources": rs})
}

// handleGateways 返回当前已注册（在线）的数据面网关清单（管理台用）。
func (s *Server) handleGateways(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.Lock()
	list := make([]GatewayInfo, 0, len(s.gateways))
	for _, g := range s.gateways {
		list = append(list, g)
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
	if err := s.writer.SaveResource(r.Context(), res); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save resource")
		return
	}
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
	httpx.JSON(w, http.StatusOK, ov)
}
