// Package api 装配白帝控制中心的 HTTP 路由与模块处理器。
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// Version 控制中心版本号。
const Version = "0.3.0"

// tokenTTL 令牌有效期。
const tokenTTL = 8 * time.Hour

// Server 持有依赖（store 读 + writer 写 + JWT 密钥），按模块注册路由。
type Server struct {
	store  store.Store
	writer store.Writer
	secret []byte
	env    string
}

// New 构造 Server。
func New(st store.Store, wr store.Writer, secret []byte, env string) *Server {
	return &Server{store: st, writer: wr, secret: secret, env: env}
}

// IsOpen 报告某路径是否免认证（登录/健康检查/门户登录）。供 auth 中间件使用。
func (s *Server) IsOpen(_ , path string) bool {
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
			"product": "白帝",
			"subtitle": "零信任访问控制系统",
			"component": "baidi-control · 控制中心",
			"version": Version,
			"env":     s.env,
		})
	})

	// 管理员登录 / 当前身份
	mux.HandleFunc("POST /api/v1/auth/login", s.handleAdminLogin)
	mux.HandleFunc("GET /api/v1/auth/me", s.handleMe)

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
