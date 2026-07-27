package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── JIT 即时访问申请：门户自助申请 + 管理台审批 + 时限授予 ──
// 授予的判定/到期完全在控制面（handleGatewayPolicy 出口现算），网关零改动被动消费。
// 到期回收走惰性：ActiveGrants 读时按 expires_at 过滤，网关下轮轮询即失去 allow（延迟上限≈一个 -poll 周期）。

// requireUser 校验上下文角色为 admin 或 user（拒 gateway）。
// 网关身份只服务数据面，绝不能走人机门户端点——否则宽权、长效的 gateway 令牌可伪造访问申请。
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (auth.Claims, bool) {
	c, ok := auth.FromContext(r.Context())
	if !ok || (c.Role != "admin" && c.Role != "user") {
		httpx.Error(w, http.StatusForbidden, "需要用户身份")
		return auth.Claims{}, false
	}
	return c, true
}

// resourceByID 按 id 点查受控资源（JIT 申请解析磁贴 → 真实资源用）。
func (s *Server) resourceByID(ctx context.Context, id string) (store.Resource, bool, error) {
	rs, err := s.store.Resources(ctx)
	if err != nil {
		return store.Resource{}, false, err
	}
	for _, r := range rs {
		if r.ID == id {
			return r, true, nil
		}
	}
	return store.Resource{}, false, nil
}

func orElse(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a
}

func fmtUnix(ts int64) string {
	if ts <= 0 {
		return "—"
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

// handlePortalCreateAccessRequest 终端用户对高敏应用发起自助访问申请。
// body {appId, reason, ttlMinutes}；服务端把磁贴解析成真实受控资源，校验其存在且基线受限。
func (s *Server) handlePortalCreateAccessRequest(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var b struct {
		AppID      string `json:"appId"`
		Reason     string `json:"reason"`
		TTLMinutes int    `json:"ttlMinutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&b); err != nil || strings.TrimSpace(b.Reason) == "" {
		httpx.Error(w, http.StatusBadRequest, "申请理由不能为空")
		return
	}
	if len(b.Reason) > 500 {
		httpx.Error(w, http.StatusBadRequest, "申请理由过长（≤500 字）")
		return
	}
	ttl := b.TTLMinutes
	if ttl <= 0 {
		ttl = 60 // 门户未指定时默认 1 小时
	}
	ttl = store.ClampGrantTTL(ttl)

	// 磁贴 → 真实资源：apps.resource_id 是权威映射（apps 与 resources 是两套 id 空间）。
	apps, err := s.store.Apps(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load apps")
		return
	}
	var app store.App
	found := false
	for _, a := range apps.Apps {
		if a.ID == b.AppID {
			app, found = a, true
			break
		}
	}
	if !found || app.ResourceID == "" {
		httpx.Error(w, http.StatusBadRequest, "该应用不支持自助申请")
		return
	}
	// 目标资源须存在且基线受限（AllowRoles/AllowUsers 非空）——否则本就全开，JIT 无意义（还会误把开放资源缩成仅授予人可访问）。
	res, exists, err := s.resourceByID(r.Context(), app.ResourceID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load resource")
		return
	}
	if !exists {
		httpx.Error(w, http.StatusBadRequest, "目标资源不存在")
		return
	}
	if len(res.AllowRoles) == 0 && len(res.AllowUsers) == 0 {
		httpx.Error(w, http.StatusBadRequest, "目标资源未设访问限制，无需申请")
		return
	}

	req := store.AccessRequest{
		User: normUser(c.Name), ResourceID: res.ID, ResourceName: res.Name,
		Reason: strings.TrimSpace(b.Reason), TTLMinutes: ttl,
	}
	created, err := s.writer.CreateAccessRequest(r.Context(), req)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateRequest) {
			httpx.Error(w, http.StatusConflict, "你已有待审批的申请或有效授予，请勿重复提交")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, "failed to create access request")
		return
	}
	s.audit(r, "access", "申请访问资源「"+res.Name+"」（期望 "+strconv.Itoa(ttl)+" 分钟）："+req.Reason, "ok")
	httpx.JSON(w, http.StatusCreated, created)
}

// handlePortalMyRequests 终端用户「我的申请」：本人全部申请单 + 当前有效授予（含剩余时长）。
func (s *Server) handlePortalMyRequests(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	user := normUser(c.Name)
	reqs, err := s.store.AccessRequestsFor(r.Context(), user)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load access requests")
		return
	}
	grants, _ := s.store.ActiveGrantsFor(r.Context(), user) // best-effort，读失败不阻断清单
	if grants == nil {
		grants = []store.JitGrant{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requests": reqs, "grants": grants})
}

// handleAccessRequests 管理台待审批申请队列（admin）。
func (s *Server) handleAccessRequests(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	reqs, err := s.store.AccessRequests(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load access requests")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requests": reqs})
}

// handleDecideAccessRequest 管理员审批处置（admin）。body {decision, reason, ttlMinutes?}。
// 通过时同事务内建时限授予并回填 grant_id；职责分离闸拒绝审批人==申请人；并发二次处置回 409。
func (s *Server) handleDecideAccessRequest(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	c, _ := auth.FromContext(r.Context())
	id := r.PathValue("id")
	var body struct {
		Decision   string `json:"decision"`
		Reason     string `json:"reason"`
		TTLMinutes int    `json:"ttlMinutes"` // 可覆盖申请时长；<=0 用申请单原值
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Decision != "approved" && body.Decision != "rejected") {
		httpx.Error(w, http.StatusBadRequest, "decision must be approved|rejected")
		return
	}
	req, grant, err := s.writer.DecideAccessRequest(r.Context(), id, body.Decision, body.Reason, normUser(c.Name), body.TTLMinutes)
	switch {
	case errors.Is(err, store.ErrRequestDecided):
		httpx.Error(w, http.StatusConflict, "该申请已被处置")
		return
	case errors.Is(err, store.ErrSelfApprove):
		httpx.Error(w, http.StatusForbidden, "不能审批自己提交的申请")
		return
	case err != nil:
		httpx.Error(w, http.StatusInternalServerError, "failed to decide access request")
		return
	}
	if body.Decision == "approved" {
		s.audit(r, "admin", "批准 "+req.User+" 访问「"+req.ResourceName+"」，授予至 "+fmtUnix(grant.ExpiresAt), "allow")
	} else {
		s.audit(r, "admin", "驳回 "+req.User+" 的访问申请 "+id+"："+orElse(body.Reason, "未说明"), "deny")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "decision": body.Decision, "grantId": grant.ID})
}

// handleJitGrants 现存授予清单（admin，访问审查 + 倒计时；到期授予在展示层已纠正为 expired）。
func (s *Server) handleJitGrants(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	grants, err := s.store.JitGrants(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load grants")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"grants": grants})
}

// handleRevokeGrant 管理员提前撤销一条授予（admin）。撤销后网关下轮轮询即失去 allow。
func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	g, err := s.writer.RevokeGrant(r.Context(), id, body.Reason)
	if errors.Is(err, store.ErrGrantInactive) {
		httpx.Error(w, http.StatusConflict, "授予不存在或已失效")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to revoke grant")
		return
	}
	s.audit(r, "security", "撤销 JIT 授予 "+g.ID+"（"+g.User+"@"+g.ResourceName+"）："+orElse(body.Reason, "管理员主动撤销"), "deny")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "grant": g})
}
