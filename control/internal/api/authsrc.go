package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/authsrc/radiussrc"
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
	// ★清单只有 authsrc.SupportedKinds 一份：这里、保存拒绝文案、Kind.Supported 三处同源。
	supported := []string{}
	for _, k := range authsrc.SupportedKinds() {
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
			"认证源类型 "+b.Kind+" 本版本未实现（当前支持："+authsrc.SupportedKindsZh()+"）")
		return
	}
	// radiusWarn RADIUS 源打开了安全逃生舱时的当面告警（见 validateRadiusConfig）。
	var radiusWarn string
	if kind == authsrc.KindRADIUS {
		// RADIUS 专属入口校验。★与 IPSec peer 拒收 FQDN 同一条纪律：拒绝要说得出原因，
		// 且能在这里挡住的就不留到「第一个用户登录不上」那一刻。
		normalized, rwarn, rerr := validateRadiusConfig(b.Config)
		if rerr != nil {
			httpx.Error(w, http.StatusBadRequest, rerr.Error())
			return
		}
		b.Config = normalized
		radiusWarn = rwarn
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
	// 逃生舱告警排在最前：它是管理员**刚刚亲手放弃**的一层保护，不该跟在
	// 「还没填共享密钥」后面被读成同一类提示。
	warn := radiusWarn
	if kind != authsrc.KindLocal {
		if _, berr := s.buildProvider(r.Context(), rec); berr != nil {
			// ★拼接而不是覆盖：逃生舱告警与"当前不可用"是两件独立的事，
			// 覆盖会让「打开了逃生舱 + 还没填共享密钥」那一次保存把前者整句吃掉。
			warn = strings.TrimSpace(warn + " 配置已保存，但当前还不可用：" + berr.Error())
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
	start := time.Now()
	// ★能说清"用什么方法探到的"的源优先走 DetailedProber：RADIUS 的自检有两条路
	// （Status-Server / 回退到一次探测用 Access-Request），后者会在对面日志里留一条失败登录，
	// 控制台必须把是哪一种说给管理员，一句「连接正常」盖不住这个差别。
	if dp, okd := prov.(authsrc.DetailedProber); okd {
		rep, err := dp.ProbeDetail(ctx)
		if err != nil {
			s.audit(r, "admin", "测试认证源「"+rec.Name+"」连通性失败", "fail")
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": err.Error(), "method": rep.Method})
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{
			"ok": true, "detail": rep.Detail, "method": rep.Method, "elapsedMs": time.Since(start).Milliseconds(),
		})
		return
	}
	type prober interface{ Probe(context.Context) error }
	p, okp := prov.(prober)
	if !okp {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": "该类型不支持连通性自检"})
		return
	}
	if err := p.Probe(ctx); err != nil {
		s.audit(r, "admin", "测试认证源「"+rec.Name+"」连通性失败", "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": err.Error()})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "detail": "连接正常", "elapsedMs": time.Since(start).Milliseconds(),
	})
}

// radiusAllowMissingRespMAKey RADIUS 源配置里那个安全逃生舱的落库键名。
//
// ★名字刻意不叫 requireResponseAuthenticator：**Response Authenticator 正是 Blast-RADIUS
// 攻破的那层 MD5**，用它命名开关会被读成"要不要校验响应认证符"，与开关真正管的东西
// （应答里的 Message-Authenticator，HMAC-MD5 那层）差了一层。
// 同样刻意是**允许式**而不是要求式：JSON 里缺席 = false = 要求带 MA，安全那一侧就是零值——
// 用 requireXxx 的话存量库里没这个键的行在升级那一刻集体变成"不要求"，两边都不报错。
const radiusAllowMissingRespMAKey = "allowMissingResponseMessageAuthenticator"

// radiusWaiverWarning 打开逃生舱时回给管理员的当面告警（保存回执）。
const radiusWaiverWarning = "已打开「允许应答不带 Message-Authenticator」：该源会接受不携带 " +
	"Message-Authenticator 的 RADIUS 应答，等于放弃 Blast-RADIUS（CVE-2024-3596）缓解里唯一还站得住的那层 HMAC，" +
	"应答完整性只剩已被攻破的 MD5 Response Authenticator。只在确认该服务器确实不回这个属性时保持开启；" +
	"能在服务端开启应答侧 Message-Authenticator 的话，请关掉这个开关。"

// validateRadiusConfig RADIUS 源保存时的入口校验，返回归一后的 config JSON 与一句可选告警。
//
// 每一条都是「能在这里挡住就别留到登录那一刻」：
//   - host 必填、port 0（取 1812）或 1~65535；
//   - protocol / groupAttr 限枚举——填错的话 radiussrc.New 会拒，但那是「保存成功、
//     warning 里一句话」，而这里是 400，管理员不会把它当成"存好了"；
//   - **allowedDomains 必须为空**：RADIUS 应答里没有邮箱，准入闸的域白名单对它恒
//     fail-closed（AdmitFilter.Allow 的「认证源未返回邮箱」分支）——配上去的后果是该源
//     所有用户都进不来、而白名单看着完全正确。这正是本项目最怕的"配了却不生效"的反面：
//     "配了就全拒"，同样无报错。
//   - **allowedGroups 非空时 groupAttr 必填**：同一条理由。组属性留空 = radiussrc 不映射组
//     = Identity.Groups 恒空 = 组白名单对每个人都判「不属于任何允许的组」——保存 200、
//     零报错、谁都进不来。要么选一个组属性，要么清空允许的组。
//   - **retries 缺席归一成显式 1 落库**：DTO 用 *int 区分「缺席」与「显式 0」，落库那份
//     不该再留一个要靠读方约定去解释的空缺。
//   - **allowMissingResponseMessageAuthenticator 限布尔、归一成显式落库**，为真时回一句
//     告警（放弃了哪一层保护）。它是安全逃生舱，"填了个字符串 true 于是被当成 false"这种
//     静默归零在这里的方向是收紧的，但管理员会以为自己配上了，故一律 400 说清楚。
//
// ★归一用 **map 原样保留其余键**，绝不"解成 DTO 再重新 Marshal"：DTO 里没声明的配置键
// 会被那次保存整个抹掉——「改了 A 设置，B 设置莫名其妙没了」，两边都不报错。
// 同仓 mergeAdmitCfg 的注释早写死了这条纪律，这里此前恰好因为字段对齐才没出事，
// 是一颗已知会响的雷（DTO 与库里那份 config 的字段集，只要有一次没同步就炸）。
// 所以下面**只回写本函数真正修改过的键**。
//
// 共享密钥不在这里校验：它走独立的 secret 端点，保存那一刻可能还没来得及填；
// buildProvider 的 warning（「未配置共享密钥」）与登录时的「认证源不可用」都会点名它。
func validateRadiusConfig(raw json.RawMessage) (json.RawMessage, string, error) {
	if len(raw) == 0 {
		return nil, "", fmt.Errorf("RADIUS 源必须提供 config（host 必填）")
	}
	// ① 原文进 map：本函数没碰过的键（含将来新增的、以及别的入口写进去的）原样带过去。
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "", fmt.Errorf("RADIUS 配置不是合法 JSON 对象：%v", err)
	}
	if m == nil { // config 是字面量 null：当空对象处理，下面 host 必填那条会拦住它
		m = map[string]any{}
	}
	// ② DTO 只用来读本函数关心的那几个键（顺带把类型错的值挡在这里）。
	var c radiusConfigDTO
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, "", fmt.Errorf("RADIUS 配置字段类型不对：%v", err)
	}
	c.Host = strings.TrimSpace(c.Host)
	if c.Host == "" {
		return nil, "", fmt.Errorf("RADIUS 源的 host 必填（服务器主机名或 IP）")
	}
	if c.Port == 0 {
		c.Port = 1812
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, "", fmt.Errorf("RADIUS 端口 %d 超出 1~65535（认证口惯用 1812；1813 是计费口，不是认证口）", c.Port)
	}
	c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol))
	switch c.Protocol {
	case "":
		c.Protocol = string(radiussrc.ProtocolPAP)
	case string(radiussrc.ProtocolPAP), string(radiussrc.ProtocolCHAP):
	default:
		return nil, "", fmt.Errorf("RADIUS protocol 取值须为 pap 或 chap，得到：%s（EAP / MS-CHAPv2 本版本不做）", c.Protocol)
	}
	c.GroupAttr = strings.ToLower(strings.TrimSpace(c.GroupAttr))
	switch radiussrc.GroupAttr(c.GroupAttr) {
	case radiussrc.GroupAttrNone, radiussrc.GroupAttrClass, radiussrc.GroupAttrFilterID, radiussrc.GroupAttrReplyMessage:
	default:
		return nil, "", fmt.Errorf("RADIUS groupAttr 取值须为 class / filter-id / reply-message 或留空，得到：%s", c.GroupAttr)
	}
	if c.TimeoutMs < 0 || c.TimeoutMs > 30000 {
		return nil, "", fmt.Errorf("RADIUS timeoutMs 须在 0（取默认 3000）~30000 之间，得到：%d", c.TimeoutMs)
	}
	if c.Retries == nil {
		// 缺席 → 显式 1 落库（radiussrc 的默认值），落库那份不留空缺；显式 0 原样保留（只发一次）。
		one := 1
		c.Retries = &one
	}
	if *c.Retries < 0 || *c.Retries > 5 {
		return nil, "", fmt.Errorf("RADIUS retries 须在 0~5 之间，得到：%d", *c.Retries)
	}
	// 逃生舱：只认真正的布尔。缺席 = false = 要求应答带 Message-Authenticator。
	allowMissingMA := false
	if v, ok := m[radiusAllowMissingRespMAKey]; ok && v != nil {
		b, isBool := v.(bool)
		if !isBool {
			return nil, "", fmt.Errorf("RADIUS %s 须为布尔值 true / false，得到：%v", radiusAllowMissingRespMAKey, v)
		}
		allowMissingMA = b
	}
	if len(store.NormalizeAdmitList(c.AllowedDomains)) > 0 {
		return nil, "", fmt.Errorf("RADIUS 源不能配置「允许的邮箱域」：RADIUS 应答里没有邮箱，域白名单会让该源所有用户都被准入闸拒绝（fail-closed）。请清空后保存；按组限制请用「允许的组」+ 组属性映射")
	}
	if len(store.NormalizeAdmitList(c.AllowedGroups)) > 0 && c.GroupAttr == "" {
		// ★与上一条同一条理由：组属性留空 = 不映射组 = 每个人的组都是空 = 组白名单对谁都不过。
		// 放行等于保存一条谁都进不来的源，且保存 200、零报错。
		return nil, "", fmt.Errorf("RADIUS 源配置了「允许的组」但「组属性」为空：组属性留空时不从应答映射组，组白名单会让该源所有用户都被准入闸拒绝（fail-closed）。请在「组属性」里选 class / filter-id / reply-message 之一（须与服务端策略写入的属性一致），或清空「允许的组」")
	}
	// ③ 只回写本函数改过的键。其余（nasIdentifier / timeoutMs / 准入白名单 / 未来新增的键）原样留在 m 里。
	m["host"] = c.Host
	m["port"] = c.Port
	m["protocol"] = c.Protocol
	m["groupAttr"] = c.GroupAttr
	m["retries"] = *c.Retries
	m[radiusAllowMissingRespMAKey] = allowMissingMA
	out, err := json.Marshal(m)
	if err != nil {
		return nil, "", fmt.Errorf("RADIUS 配置序列化失败：%v", err)
	}
	warn := ""
	if allowMissingMA {
		warn = radiusWaiverWarning
	}
	return out, warn, nil
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
//
//	① 认证源保存回 200、连通性测试通过；
//	② 认证策略页只按「已有策略」分组渲染，接了 LDAP 之后页面上根本不多出这一栏，
//	   管理员看到的与接入前一模一样；
//	③ 用户侧是一次完全正常的成功登录。
//
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
