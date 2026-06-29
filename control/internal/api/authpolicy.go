package api

import (
	"encoding/json"
	"net/http"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 认证策略（PRD 第 7 章 FR-AUTH-12）──

// handleAuthPolicies 返回全部认证策略（前端按目录分组展示）。
func (s *Server) handleAuthPolicies(w http.ResponseWriter, r *http.Request) {
	pols, err := s.store.AuthPolicies(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth policies")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"policies": pols})
}

// handleSaveAuthPolicy 新增 / 修改一条认证策略（admin）。
func (s *Server) handleSaveAuthPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var p store.AuthPolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Name == "" || p.Directory == "" {
		httpx.Error(w, http.StatusBadRequest, "name/directory 必填")
		return
	}
	// 主认证是上线的必经闸门：PC 与移动端至少各有一种主认证方式，否则该端无法登录。
	if p.PC.Primary == "" || p.Mobile.Primary == "" {
		httpx.Error(w, http.StatusBadRequest, "PC 端与移动端均须配置主认证方式")
		return
	}
	saved, err := s.writer.SaveAuthPolicy(r.Context(), p)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save auth policy")
		return
	}
	s.audit(r, "admin", "保存认证策略「"+saved.Name+"」", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "policy": saved})
}

// handleDeleteAuthPolicy 删除一条认证策略（admin）；默认策略由 store 层拒绝删除。
func (s *Server) handleDeleteAuthPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.writer.DeleteAuthPolicy(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete auth policy")
		return
	}
	s.audit(r, "admin", "删除认证策略 "+id, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}
