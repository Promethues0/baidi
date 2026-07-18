package api

import (
	"encoding/json"
	"net/http"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 安全中心 · 基线 CRUD（风险引擎的规则源）──

var validDisposal = map[string]bool{"allow": true, "degrade": true, "block": true, "gray": true}
var validSeverity = map[string]bool{"high": true, "medium": true, "low": true}
var validCheckPlatform = map[string]bool{"Windows": true, "macOS": true, "Linux": true, "All": true}
var validBaselineType = map[string]bool{"onboarding": true, "app-protect": true}
var validBaselineStatus = map[string]bool{"enabled": true, "disabled": true}

// handleSaveBaseline 新增/修改一条安全基线（admin）。落库后风险引擎即用新规则评估后续上报。
func (s *Server) handleSaveBaseline(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var b store.BaselinePolicy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&b); err != nil || b.Name == "" {
		httpx.Error(w, http.StatusBadRequest, "基线名称不能为空")
		return
	}
	if !validBaselineType[b.Type] || !validDisposal[b.Disposal] || !validBaselineStatus[b.Status] {
		httpx.Error(w, http.StatusBadRequest, "type/disposal/status 取值非法")
		return
	}
	if len(b.Checks) > 64 {
		httpx.Error(w, http.StatusBadRequest, "检测项过多（≤64）")
		return
	}
	for _, c := range b.Checks {
		if c.Key == "" || c.Label == "" || !validCheckPlatform[c.Platform] || !validSeverity[c.Severity] {
			httpx.Error(w, http.StatusBadRequest, "检测项 key/label 必填，platform/severity 取值非法")
			return
		}
	}
	saved, err := s.writer.SaveBaseline(r.Context(), b)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save baseline")
		return
	}
	s.audit(r, "policy", "保存安全基线「"+saved.Name+"」（处置："+saved.Disposal+"）", "ok")
	s.warnIfNoEnabledBaseline(r)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "baseline": saved})
}

// warnIfNoEnabledBaseline 「无规则即放行」留痕：当前已无任何启用基线时落审计警示。
// best-effort（读失败不打扰主操作）。
func (s *Server) warnIfNoEnabledBaseline(r *http.Request) {
	bls, err := s.store.Baselines(r.Context())
	if err != nil {
		return
	}
	for _, b := range bls {
		if b.Status == "enabled" {
			return
		}
	}
	s.audit(r, "security", "已无启用的安全基线，风险引擎将对所有终端环境放行（无规则即放行）", "fail")
}

// handleDeleteBaseline 删除一条安全基线（admin）。
func (s *Server) handleDeleteBaseline(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.writer.DeleteBaseline(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete baseline")
		return
	}
	s.audit(r, "policy", "删除安全基线 "+id, "ok")
	s.warnIfNoEnabledBaseline(r)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}
