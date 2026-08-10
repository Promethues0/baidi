package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"baidi.dev/control/internal/authpolicy"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 认证策略（PRD 第 1 章 FR-INTRO-07/08、第 7 章 FR-AUTH-12）──
//
// 这一层只做两件事：给策略页下发「策略 + 能力声明」，以及在登录链路上**取数**、
// 把判定交给纯函数 internal/authpolicy.Evaluate。判定逻辑一行都不要写在这里——
// 写在这里就没法单测，也会与保存校验各自演化。

// handleAuthPolicies 返回全部认证策略 + 规则能力声明（前端按目录分组展示、按能力置灰）。
func (s *Server) handleAuthPolicies(w http.ResponseWriter, r *http.Request) {
	pols, err := s.store.AuthPolicies(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth policies")
		return
	}
	// 适用范围候选（组织含子树 / 用户组，账号已展开）与资源策略页同一个来源——
	// 管理员在策略页看到的"这条策略圈到几个人"，与判定时用的展开出自同一次计算。
	orgs, groups, oerr := s.subjectOptions(r.Context())
	if oerr != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load subjects")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"policies": pols,
		// ★能力声明必须由后端下发而不是前端自己写死：置灰与保存校验必须同源，
		// 否则前端放开一个后端会拒的开关（或反过来），管理员两头看不懂。
		"capabilities": authpolicy.Capabilities(),
		"orgs":         orgs,
		"groups":       groups,
	})
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
	// ★保存即校验：拦下所有"存进去也不会生效"的配置（冻结开关、空网段的可信网络、
	// 没绑定适用范围的非默认策略）。历史上这些形态能静默入库，于是页面配得好好的、
	// 登录行为一点没变。
	if err := authpolicy.Validate(p); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
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

// loginCtx 登录链路当场得知、判定又需要的上下文。
// Directory 只有登录链路知道（本地哈希命中 = local，外部源命中 = 该源 kind），
// DeviceID 由客户端随登录请求上报（浏览器登录为空 = 未知设备）。
type loginCtx struct {
	Directory string
	DeviceID  string
}

// stepUpDecision 组装决策输入并求值：本函数只负责取数与 fail-closed 处理。
//
// 返回 (决策, 是否可判)。**读不到判定材料时返回 ok=false**，调用方按 fail-closed 拒绝登录：
// 「查不到该不该要二次认证」与「不需要二次认证」是两回事，把前者当后者处理，
// 等于库一抖动就静默降级成单因素——而且没有任何人会发现。
func (s *Server) stepUpDecision(r *http.Request, cred store.Credential, lc loginCtx) (authpolicy.Decision, bool) {
	ctx := r.Context()
	pols, err := s.store.AuthPolicies(ctx)
	if err != nil {
		slog.Error("认证策略读取失败，登录按 fail-closed 处理", "账号", cred.Account, "err", err.Error())
		return authpolicy.Decision{}, false
	}
	ix, err := s.store.SubjectIndex(ctx)
	if err != nil {
		slog.Error("组织/用户组展开失败，登录按 fail-closed 处理", "账号", cred.Account, "err", err.Error())
		return authpolicy.Decision{}, false
	}
	in := authpolicy.Input{
		Account:    normUser(cred.Account),
		Directory:  lc.Directory,
		Now:        time.Now(),
		DeviceID:   lc.DeviceID,
		PwStrength: cred.PwStrength,
		Subjects:   ix,
	}
	if a, perr := netip.ParseAddr(s.clientIP(r)); perr == nil {
		in.ClientIP = a
	}
	// 授信终端豁免的判据：这台设备**以本账号**上报过 posture，且最新判定为 allow。
	// 读失败按"未知设备"处理（不给豁免）——豁免方向的 fail-closed。
	if lc.DeviceID != "" {
		if rep, found, perr := s.store.PostureReportFor(ctx, in.Account, lc.DeviceID); perr != nil {
			slog.Warn("终端报告读取失败，授信终端豁免按未知设备处理", "账号", cred.Account, "err", perr.Error())
		} else if found {
			in.DeviceKnown, in.DeviceVerdict = true, rep.Verdict
		}
	}
	return authpolicy.Evaluate(pols, in), true
}
