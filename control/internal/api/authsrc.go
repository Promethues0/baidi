package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── 认证源接入 · 管理端点（全部 requireAdmin）──
//
//	GET    /api/v1/authsrc            列表（不含任何凭据原文）
//	POST   /api/v1/authsrc            新增 / 修改
//	DELETE /api/v1/authsrc/{id}       删除（连同凭据与身份绑定）
//	PUT    /api/v1/authsrc/{id}/secret  设置凭据（只写不读）
//	POST   /api/v1/authsrc/{id}/probe   连通性自检（控制台「测试连接」按钮）
//
// ★这一页此前是**纯内存种子**：6 条硬编码认证源，连「总部 AD 域 1160 用户」
// 这个数字都是凭空写的，「接入认证源 / 同步」按钮背后没有任何东西。

// authSrcWriter 是本文件需要的写能力（与 login_authsrc.go 的读接口分开，
// 让"能改配置"和"能读密文"是两组不同的能力）。
type authSrcWriter interface {
	authSourceStore
	AuthSourceByID(ctx context.Context, id string) (store.AuthSourceRec, bool, error)
	SaveAuthSource(ctx context.Context, rec store.AuthSourceRec) (store.AuthSourceRec, error)
	DeleteAuthSource(ctx context.Context, id string) error
	SaveAuthSourceSecret(ctx context.Context, sec store.AuthSourceSecret) error
}

func (s *Server) authSrcWriter(w http.ResponseWriter) (authSrcWriter, bool) {
	aw, ok := s.store.(authSrcWriter)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储实现不支持认证源")
		return nil, false
	}
	return aw, true
}

// handleAuthSources 认证源清单。
//
// ★响应里**永远不含**凭据原文，只有 hasSecret + 指纹前 8 位——
// 指纹的用途是让管理员核对"两端配的是不是同一把"，回显原文没有任何操作价值
// （配错了重设即可），只有泄露面。与 IPSec PSK 同款姿态。
func (s *Server) handleAuthSources(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	recs, err := aw.AuthSources(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth sources")
		return
	}
	// 顺带告诉前端哪些类型是真的实现了——控制台据此把未实现的选项置灰，
	// 而不是让它们看起来可选。
	supported := []string{}
	for _, k := range []authsrc.Kind{authsrc.KindLocal, authsrc.KindLDAP, authsrc.KindAD, authsrc.KindOIDC} {
		supported = append(supported, string(k))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sources": recs, "supportedKinds": supported})
}

// handleSaveAuthSource 新增 / 修改认证源。
func (s *Server) handleSaveAuthSource(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	var b struct {
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		Kind     string          `json:"kind"`
		Enabled  bool            `json:"enabled"`
		Priority int             `json:"priority"`
		Config   json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || strings.TrimSpace(b.Name) == "" {
		httpx.Error(w, http.StatusBadRequest, "name 必填")
		return
	}
	kind := authsrc.Kind(strings.TrimSpace(b.Kind))
	if !kind.Supported() {
		// ★装载期明确拒绝，而不是存下来再在登录时静默失败。
		// 「界面上能选、后端静默不生效」是本项目反复吃亏的形态。
		httpx.Error(w, http.StatusBadRequest,
			"认证源类型 "+b.Kind+" 本版本未实现（当前支持：local / ldap / ad / oidc）")
		return
	}
	if kind == authsrc.KindLocal && b.ID != "local" {
		httpx.Error(w, http.StatusBadRequest, "本地目录是内置认证源，不能再新建一条")
		return
	}
	cfg := "{}"
	if len(b.Config) > 0 {
		cfg = string(b.Config)
	}
	// ★准入设置入口校验（wave8 行动 10）：与 platforms 那道枚举校验同一条纪律。
	// 不校验的话，admitPolicy 填 "Approval"（大写 A）会被 NormalizeAdmitPolicy
	// 归成 auto——管理员在页面上看着「需要审批」，实际每个人照样自动建号进来，
	// 全程零报错。这是本项目最怕的那种"配了却不生效"。
	if kind != authsrc.KindLocal {
		var ac struct {
			AdmitPolicy    string   `json:"admitPolicy"`
			AllowedDomains []string `json:"allowedDomains"`
			AllowedGroups  []string `json:"allowedGroups"`
		}
		// ★解析不出对象时**跳过**这道校验，不拒绝保存：本函数下面那段
		// 「构造失败不拒绝保存（管理员可能正分几步填），但把原因带回去」是既定取舍，
		// 在这里改成硬拒会与它自相矛盾。配置真的不可用时，buildProvider 那条
		// warning 会说出来。这里只负责「配置是个对象、而 admitPolicy 填错了」这一种。
		if err := json.Unmarshal([]byte(cfg), &ac); err != nil {
			slog.Warn("认证源配置不是 JSON 对象，跳过准入设置校验（保存照常，可用性由 buildProvider 回警告）",
				"源", b.Name, "id", b.ID)
		} else if !store.ValidAdmitPolicy(ac.AdmitPolicy) {
			httpx.Error(w, http.StatusBadRequest,
				"admitPolicy 取值须为 auto（认证通过即建号）或 approval（首登需管理员批准），得到："+ac.AdmitPolicy)
			return
		} else {
			// 白名单清洗后写回：去空去重，免得一个多敲的空行让「配了却匹配不上」。
			ac.AllowedDomains = store.NormalizeAdmitList(ac.AllowedDomains)
			ac.AllowedGroups = store.NormalizeAdmitList(ac.AllowedGroups)
			if merged, merr := mergeAdmitCfg(cfg, ac.AdmitPolicy, ac.AllowedDomains, ac.AllowedGroups); merr == nil {
				cfg = merged
			}
		}
	}
	rec, err := aw.SaveAuthSource(r.Context(), store.AuthSourceRec{
		ID: b.ID, Name: b.Name, Kind: string(kind), Enabled: b.Enabled, Priority: b.Priority, Config: cfg,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save auth source")
		return
	}
	// ★保存即校验：配置写错了要当场知道，而不是等到有人登录不上才发现。
	// 构造失败不拒绝保存（管理员可能正分几步填），但把原因带回去。
	var warn string
	if kind != authsrc.KindLocal {
		if _, berr := s.buildProvider(r.Context(), rec); berr != nil {
			warn = "配置已保存，但当前还不可用：" + berr.Error()
		}
	}
	// FR-AUTH-10：接入一个用户目录后，系统要为它自动生成默认认证策略。
	// 不补的话，该目录的用户从此**不受任何二次认证约束**且全程无痕（见函数注释）。
	policyCreated, pwarn := s.ensureDirectoryDefaultPolicy(r.Context(), rec.Kind, rec.Name)
	if pwarn != "" {
		warn = strings.TrimSpace(warn + " " + pwarn)
	}
	s.audit(r, "admin", "保存认证源「"+rec.Name+"」（"+rec.Kind+"）", "ok")
	if policyCreated {
		// 自动生成的策略是一次真实的配置变更，必须单独留痕——管理员日后看到
		// 一条"没人建过"的策略时，要能在审计里查到它是何时因何而来。
		s.audit(r, "admin", "已为用户目录「"+dirLabel(rec.Kind)+"」自动生成默认认证策略"+
			"（接入认证源「"+rec.Name+"」触发；该策略未开启任何增强/豁免规则，请按需调整）", "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "source": rec, "warning": warn, "policyCreated": policyCreated,
	})
}

func (s *Server) handleDeleteAuthSource(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := aw.DeleteAuthSource(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	// ★删除会连同身份绑定一起清掉，所以要在审计里说清楚——
	// 那些外部用户下次登录会被重新建号，运维需要知道这是预期行为。
	s.audit(r, "admin", "删除认证源 "+id+"（连同其身份绑定）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleSetAuthSourceSecret 设置认证源凭据（LDAP bind 口令 / OIDC client_secret）。
//
// **只写不读**：没有任何端点能把它读回去。
func (s *Server) handleSetAuthSourceSecret(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	rec, found, err := aw.AuthSourceByID(r.Context(), id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth source")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "认证源不存在")
		return
	}
	var b struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if strings.TrimSpace(b.Secret) == "" {
		// ★空凭据必须拒绝。LDAP 里"有 DN + 空口令"会被许多目录当成**匿名 bind
		// 并返回成功**，于是"以为在用服务账号搜索、实际是匿名"——症状是部分用户
		// 查不到，而 bind 日志显示成功。宁可不让存。
		httpx.Error(w, http.StatusBadRequest, "凭据不能为空（空口令在 LDAP 上会退化成匿名 bind 并"+
			"看起来成功，这是经典的认证绕过）")
		return
	}
	box, err := secret.Default()
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "凭据主密钥不可用："+err.Error())
		return
	}
	// AAD 绑认证源 id：把某一行密文剪贴到另一条源上会直接解不开。
	nonce, cipher, err := box.Seal(rec.ID, []byte(b.Secret))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "凭据加密失败")
		return
	}
	fp := box.Fingerprint([]byte(b.Secret))[:8]
	if err := aw.SaveAuthSourceSecret(r.Context(), store.AuthSourceSecret{
		SourceID: rec.ID, Nonce: nonce, Cipher: cipher, Fingerprint: fp,
	}); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save secret")
		return
	}
	s.audit(r, "admin", "更新认证源「"+rec.Name+"」的凭据", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true,
		// 指纹供两端核对，绝不回显原文。
		"fingerprint": fp,
	})
}

// handleProbeAuthSource 连通性自检（控制台「测试连接」按钮的后端）。
//
// ★这个按钮此前是纯装饰。现在它真的去连目录 / 拉发现文档，
// 并把**真实**失败原因回给管理员——「配置写错了」和「网络不通」在这里能分开。
func (s *Server) handleProbeAuthSource(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	rec, found, err := aw.AuthSourceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth source")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "认证源不存在")
		return
	}
	if authsrc.Kind(rec.Kind) == authsrc.KindLocal {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "detail": "本地目录（SQLite）始终可用"})
		return
	}

	// 自检要有上界：目录不可达时 TCP 连接可能吊很久，让管理员盯着一个转圈的按钮
	// 等 30 秒毫无意义，也会占着一个 handler。
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	prov, err := s.buildProvider(ctx, rec)
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": err.Error()})
		return
	}
	type prober interface{ Probe(context.Context) error }
	p, okp := prov.(prober)
	if !okp {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": "该类型不支持连通性自检"})
		return
	}
	start := time.Now()
	if err := p.Probe(ctx); err != nil {
		s.audit(r, "admin", "测试认证源「"+rec.Name+"」连通性失败", "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": err.Error()})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "detail": "连接正常", "elapsedMs": time.Since(start).Milliseconds(),
	})
}

// ensureDirectoryDefaultPolicy 为某个用户目录补一条默认认证策略（若它一条都没有）。
//
// PRD FR-AUTH-10（P0）原文：「配置好认证服务器+用户目录后，系统自动为该用户目录生成
// 默认认证策略，作用于目录内所有用户」。store.AuthPolicy.IsDefault 的注释也早写着
// 「是否该目录的默认策略（**自动生成**，不可删除）」——功能声明在字段上，实现从没写过。
//
// ★不补的后果是一条彻底静默的降级：登录链路把 Directory 置成该源的 kind（ldap/oidc），
// 而 authpolicy.Match 第一刀就按目录筛——库里一条该目录的策略都没有 → Evaluate
// 返回零值 Decision → 二次认证要求为零，且 secondFactor 在零值分支两个 case 都不进，
// **审计里连「本次未要求二次认证」都没有**。三处都无异常：
//   ① 认证源保存回 200、连通性测试通过；
//   ② 认证策略页只按「已有策略」分组渲染，接了 LDAP 之后页面上根本不多出这一栏，
//      管理员看到的与接入前一模一样；
//   ③ 用户侧是一次完全正常的成功登录。
// 管理员在「本地目录 · 默认策略」里配好的规则对这批外部账号一条都不生效——
// 而外部目录的人恰恰是这些规则最想覆盖的对象。
//
// ★生成的策略**刻意不开任何增强/豁免规则**，与种子里 local 那条同一条纪律：
// 「种子的职责是给出可用的起点，不是替管理员做加严决策」。也就是说它的**判定行为
// 与"没有策略"完全一致**——这条修复真正改变的是**可见性**：策略页从此会出现这一栏，
// 管理员看得见、能编辑，而不是以为本地那条覆盖了所有人。
//
// best-effort：建不出来不阻断认证源保存（那会让一次读库抖动挡住整个接入配置），
// 但要把原因带回给管理员，而不是静默跳过。
func (s *Server) ensureDirectoryDefaultPolicy(ctx context.Context, kind, sourceName string) (created bool, warn string) {
	if kind == "" || kind == string(authsrc.KindLocal) {
		return false, "" // 本地目录的默认策略由种子给出
	}
	pols, err := s.store.AuthPolicies(ctx)
	if err != nil {
		return false, "未能检查该目录的认证策略（" + err.Error() + "）：请到「认证策略」页确认它是否已有默认策略"
	}
	for _, p := range pols {
		if strings.EqualFold(strings.TrimSpace(p.Directory), kind) {
			return false, "" // 已有（默认或自定义都算），不重复建
		}
	}
	zh := dirLabel(kind) // 复用认证策略页那份目录中文名，不另造第二份
	p := store.AuthPolicy{
		ID:        "ap-" + kind + "-default",
		Name:      zh + " · 默认策略",
		Directory: kind,
		IsDefault: true,
		Scope:     zh + " · 全体用户",
		Priority:  100,
		Enabled:   true,
		// 只列真实现的方式（同种子的纪律：冻结的 sms/radius/cert/http 不许出现）。
		Secondary:   []string{"totp"},
		ScopeOrgs:   []string{},
		ScopeGroups: []string{},
		Exempt:      store.ExemptRule{Networks: []string{}},
		Enhance:     store.EnhanceRule{WorkStart: "09:00", WorkEnd: "19:00", WorkDays: []int{1, 2, 3, 4, 5}},
	}
	if _, err := s.writer.SaveAuthPolicy(ctx, p); err != nil {
		return false, "未能为该目录自动生成默认认证策略（" + err.Error() + "）：" +
			"在补上之前，该目录的用户不受任何二次认证约束，请到「认证策略」页手动新增"
	}
	slog.Info("已为新接入的用户目录生成默认认证策略（FR-AUTH-10）",
		"目录", kind, "认证源", sourceName, "策略", p.ID)
	return true, ""
}
