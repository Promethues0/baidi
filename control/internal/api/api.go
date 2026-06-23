// Package api 装配白帝控制中心的 HTTP 路由与模块处理器。
package api

import (
	"encoding/json"
	"net/http"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// Version 控制中心版本号。
const Version = "0.2.0"

// Server 持有依赖（store 读 + writer 写），按模块注册路由。
type Server struct {
	store  store.Store
	writer store.Writer
	env    string
}

// New 构造 Server。
func New(st store.Store, wr store.Writer, env string) *Server {
	return &Server{store: st, writer: wr, env: env}
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

	return mux
}

func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
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
