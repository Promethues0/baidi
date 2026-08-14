package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
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

// authDirectory 一个可被认证策略绑定的「用户目录」。
//
// ★Key 必须与登录链路给判定用的 Directory **同一取值域**：本地哈希命中 = "local"，
// 外部源命中 = 该认证源的 kind（ldap|ad|oidc，见 login_authsrc.go 的第三个返回值）。
// 控制台此前把这个下拉接在 GET /api/v1/authsrc 的演示种子上（恒定只有 local 与 ad），
// 于是管理员真配了一个 LDAP/OIDC 源之后：那批人登录时 Directory=ldap，
// authpolicy.Match 按目录先筛一刀就把全部策略筛掉了（连默认策略都没有），
// 而策略页上根本选不出 "ldap" 这一项——配不出、也修不了，且完全静默。
type authDirectory struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Configured 该目录下是否有已配置的认证源。false = 这个目录当前不会有人从这里登录
	// （例如存量策略绑的 ad，但 AD 源已删）——留着可选、但如实标注，不假装它在生效。
	Configured bool `json:"configured"`
	// Sources 落在该目录的认证源名（展示用，便于管理员认出"这条策略管的是哪个源"）。
	Sources []string `json:"sources"`
}

// dirZh 目录 key 的中文名。未知 key 原样回显（存量策略可能绑着已删源的 kind）。
var dirZh = map[string]string{
	"local": "本地用户目录", "ldap": "通用 LDAP", "ad": "Active Directory", "oidc": "OpenID Connect",
}

func dirLabel(key string) string {
	if zh, ok := dirZh[key]; ok {
		return zh
	}
	return key
}

// authDirectories 组装可绑定的用户目录清单：本地 ∪ 已配置认证源的 kind ∪ 存量策略已用的目录。
//
// 三个来源缺一不可：
//   - 本地恒有（本地哈希登录不依赖 auth_sources 表里有没有行）；
//   - 已配置源的 kind 是**唯一**能让新策略真命中的取值；
//   - 存量策略已用的目录必须保留，否则管理员一编辑就被自己的校验拒掉（种子里的
//     「AD 域 · 默认策略」在没有 AD 源时正是这种情况）。
//
// 下拉与保存校验共用这一份，与 capabilities 同一条纪律：前端能选的、后端就得能存。
func (s *Server) authDirectories(ctx context.Context, pols []store.AuthPolicy) ([]authDirectory, error) {
	idx := map[string]int{}
	out := []authDirectory{{Key: "local", Name: dirLabel("local"), Configured: true, Sources: []string{}}}
	idx["local"] = 0
	add := func(key string, configured bool, srcName string) {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return
		}
		i, ok := idx[key]
		if !ok {
			out = append(out, authDirectory{Key: key, Name: dirLabel(key), Sources: []string{}})
			i = len(out) - 1
			idx[key] = i
		}
		if configured {
			out[i].Configured = true
		}
		if srcName != "" {
			out[i].Sources = append(out[i].Sources, srcName)
		}
	}
	if as, ok := s.store.(authSourceStore); ok {
		recs, err := as.AuthSources(ctx)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			add(rec.Kind, true, rec.Name)
		}
	}
	for _, p := range pols {
		add(p.Directory, false, "")
	}
	return out, nil
}

// handleAuthPolicies 返回全部认证策略 + 规则能力声明（前端按目录分组展示、按能力置灰）。
func (s *Server) handleAuthPolicies(w http.ResponseWriter, r *http.Request) {
	pols, err := s.store.AuthPolicies(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth policies")
		return
	}
	dirs, err := s.authDirectories(r.Context(), pols)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth directories")
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
		// 二次认证方式的能力声明：真实现的（totp）可选，其余置灰并说明原因。
		"methods": authpolicy.SecondaryMethods(),
		// ★目录候选同样由后端下发：前端自己写死一份的话，真实认证源的 kind
		// （ldap/oidc）永远进不了下拉，而登录链路只按 kind 匹配。
		"directories": dirs,
		"orgs":        orgs,
		"groups":      groups,
	})
}

// handleSaveAuthPolicy 新增 / 修改一条认证策略（admin）。
func (s *Server) handleSaveAuthPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
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
	// 目录必须是登录链路真会给出的取值（本地 / 已配置源的 kind / 存量策略已用的目录）。
	// 拼错一个目录名，策略在库里好端端躺着而 Match 第一刀就把它筛掉——
	// 与"范围 id 拼错"同一族的静默失效。
	pols, err := s.store.AuthPolicies(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth policies")
		return
	}
	dirs, err := s.authDirectories(r.Context(), pols)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth directories")
		return
	}
	known := make([]string, 0, len(dirs))
	hit := false
	for _, d := range dirs {
		known = append(known, d.Key)
		if d.Key == strings.ToLower(strings.TrimSpace(p.Directory)) {
			hit = true
		}
	}
	if !hit {
		httpx.Error(w, http.StatusBadRequest, "用户目录「"+p.Directory+
			"」不存在（登录链路只会给出：本地目录与已配置认证源的类型，当前为 "+strings.Join(known, "/")+
			"）——绑了不存在的目录，这条策略永远匹配不到任何账号")
		return
	}
	// 适用范围引用的组织/用户组必须真实存在。★这条与 handleSaveResource 的
	// validateSubjects 是同一条纪律：拼错的 id 不静默入库——covers() 恒 false，
	// 策略页上"绑好了"、登录时一次都不命中，而且是**放松**方向（该二次认证的人没被要求）。
	if msg, err := s.validateSubjectRefs(r.Context(), p.ScopeOrgs, p.ScopeGroups); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to validate policy scope")
		return
	} else if msg != "" {
		httpx.Error(w, http.StatusBadRequest, msg)
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
	if !s.requirePerm(w, r, store.PermSecurity) {
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
	// 授信终端豁免的判据（两条同时成立）：
	//  ① 这台设备在本账号名下的设备台账里、且状态为 trusted（管理员批准过 / 自动绑定放过）；
	//  ② 它最新的 posture 判定为 allow。
	//
	// ★① 的口径与敲门准入闸 api.deviceAdmissionGate **同源**（都是 trusted_devices.status）。
	// 改造前这里只看 ②「曾上报过 posture」，于是任何终端上报一次就自动获得免二次认证资格，
	// 而管理员在终端管理页的批准/吊销对登录链路毫无影响——两处对"授信终端"给出两个答案，
	// 且都不报错。豁免是**削弱**认证强度的方向，两条判据里任何一条读失败都不给豁免。
	if lc.DeviceID != "" {
		dev, found, derr := s.store.DeviceByFingerprint(ctx, in.Account, lc.DeviceID)
		switch {
		case derr != nil:
			slog.Warn("设备台账读取失败，授信终端豁免按未知设备处理", "账号", cred.Account, "err", derr.Error())
		case found && dev.Status == store.DeviceStatusTrusted:
			if rep, ok, perr := s.store.PostureReportFor(ctx, in.Account, lc.DeviceID); perr != nil {
				slog.Warn("终端报告读取失败，授信终端豁免按未知设备处理", "账号", cred.Account, "err", perr.Error())
			} else if ok {
				in.DeviceKnown, in.DeviceVerdict = true, rep.Verdict
			}
		}
	}
	return authpolicy.Evaluate(pols, in), true
}
