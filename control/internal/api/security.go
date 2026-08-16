package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 安全中心 · 基线 CRUD（风险引擎的规则源）──

// 四档处置全部可选，因为四档**都有执行方**（语义见 store.DisposalAllow 一组常量）：
// gray 记 observing 审计、degrade 摘除高敏资源、block 全断。
// 若将来加档位，先落实执行方再往这里加 —— 只能选不能执行的档位就是 config-only。
var validDisposal = map[string]bool{
	store.DisposalAllow: true, store.DisposalGray: true,
	store.DisposalDegrade: true, store.DisposalBlock: true,
}
var validSeverity = map[string]bool{"high": true, "medium": true, "low": true}
var validCheckPlatform = map[string]bool{"Windows": true, "macOS": true, "Linux": true, "All": true}
var validBaselineType = map[string]bool{"onboarding": true, "app-protect": true}
var validBaselineStatus = map[string]bool{"enabled": true, "disabled": true}

// handleSaveBaseline 新增/修改一条安全基线（admin）。落库后风险引擎即用新规则评估后续上报。
func (s *Server) handleSaveBaseline(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
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
	// 顶层 platforms 与上报 platform 精确匹配（risk.platformApplies）：存进 "macos"/"All" 这类
	// 枚举外取值的基线对任何上报都永不生效——静默失效比报错危险，入口拒绝。留空 = 适用全平台。
	for _, p := range b.Platforms {
		if !validReportPlatform[p] {
			httpx.Error(w, http.StatusBadRequest, "platforms 取值须为 Windows|macOS|Linux（留空=全平台）")
			return
		}
	}
	if len(b.Checks) > 64 {
		httpx.Error(w, http.StatusBadRequest, "检测项过多（≤64）")
		return
	}
	seen := map[string]bool{}
	for _, c := range b.Checks {
		if c.Key == "" || c.Label == "" || !validCheckPlatform[c.Platform] || !validSeverity[c.Severity] {
			httpx.Error(w, http.StatusBadRequest, "检测项 key/label 必填，platform/severity 取值非法")
			return
		}
		// ★key 必须是采集器真的会上报的那六个之一。
		//
		// 采集器不报的 key，risk.Evaluate 按「缺失即不合规」判该项失败（那是防选择性
		// 上报的正确设计），于是这条基线对该平台**全体终端**永远违规——而接入准入基线
		// 的默认处置是 block，等于一键给所有人拒发敲门令牌 + 撤窗断隧道。
		// 此前页面上唯一的「添加检测项」按钮 100% 产出这种 key（写死 'c-'+时间戳），
		// 保存那一刻零报错。方向比 platforms 拼错更坏：那个是永不生效（fail-open），
		// 这个是全员 fail-closed。判据与页面下拉同一份（store.CollectableChecks）。
		if _, ok := store.CheckSpecOf(c.Key); !ok {
			httpx.Error(w, http.StatusBadRequest,
				"检测项 key「"+c.Key+"」不是采集器会上报的项，该基线会对全平台终端永远判违规。"+
					"可选："+strings.Join(store.CollectableCheckKeys(), " / "))
			return
		}
		if seen[c.Key] {
			// 同一 key 配两遍：两条都会被判定一次，分数翻倍且理由重复出现，
			// 而管理员在页面上看到的是两行长得一样的检测项。
			httpx.Error(w, http.StatusBadRequest, "检测项 key「"+c.Key+"」重复")
			return
		}
		seen[c.Key] = true
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
	if !s.requirePerm(w, r, store.PermSecurity) {
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
