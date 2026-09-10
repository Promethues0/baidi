package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/authpolicy"
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/webauthnx"
)

// ── WebAuthn / passkey 二次认证 ──
//
// 取代硬编码演示验证码：口令通过后要求一次抗钓鱼的公钥断言。
//
// ★安全设计（对抗式复核的两条硬要求）：
//  1. 登录断言绝不是免认证入口。login/begin 只在 bcrypt 口令校验通过后签发，
//     challenge 绑定该账号（webauthn_challenges.account 非空）；login/finish 用
//     一次性 pre-auth 票据(mfaTicket)证明"口令那一步确实发生过"，并校验断言凭据
//     属于票据账号——否则任何持 passkey 者可跳过口令直接换会话令牌（名为 2FA 实为 passwordless）。
//  2. challenge 服务端生成、按值+类型单次消费、短 TTL；签名计数器单调校验在 store 层，
//     且对 signCount=0 的同步 passkey 跳过校验（否则误判克隆锁死 iCloud/Google passkey）。

// mfaTicketTTL 口令已验票据的有效期：够完成一次认证器交互，短到不留重放窗口。
const mfaTicketTTL = 3 * time.Minute

// webauthnEnabled 报告是否已配置 RP（未配则登录回落 legacy 演示路径）。
func (s *Server) webauthnEnabled() bool { return s.rp != nil }

// legacyDemoCode 未配置 WebAuthn 时的演示验证码（仅 dev/裸 IP 演示站回落路径使用）。
// 生产配置 BAIDI_WEBAUTHN_RPID/ORIGIN 后此路径不可达。
const legacyDemoCode = "123456"

// secondFactor 决定本次登录是否需要二次因子，并返回应直接回给客户端的响应。
// done=true 表示登录尚未完成（已产出 needWebauthn/needMfa 响应或拒绝），调用方直接回传。
//
// 判定顺序（顺序本身就是安全语义，别调换）：
//  1. 已注册 passkey 且 RP 已配置 → **无条件**要求 WebAuthn 断言（抗钓鱼，最强）；
//  2. 已确认 TOTP → **无条件**要求动态验证码（RFC 6238；裸 IP 部署下唯一的标准二因子）；
//  3. 否则按认证策略求值（internal/authpolicy）：命中增强条件且未被豁免 → 要求二次认证。
//     RP 已配置时要求先注册 passkey 或 TOTP（引导，不放行）；RP 未配置（裸 IP 演示站/dev）
//     且未注册 TOTP 时回落 legacy 演示验证码——注册 TOTP 后该回落对本账号不可达；
//  4. 其余 → 单因子口令放行。
//
// ★第 1 步排在策略之前，是「策略只能加强、不能削弱」这条语义的落点：
// 账号自己注册了 passkey，就没有任何一条豁免规则（可信网络 / 授信终端）能把它降级成单因素。
// 反过来若先算策略、命中豁免就直接放行，passkey 会变成"有时候要、有时候不要"，
// 而且这种削弱在日志里看不出来——authpolicy_test.go 有用例钉住这条顺序。
//
// ★零凭据不锁死：普通账号无 passkey 照常登录，登录后可去 /portal/security 注册——
// 避免"无 passkey→无法登录→无法进注册页"的 bootstrap 死锁。
func (s *Server) secondFactor(r *http.Request, cred store.Credential, lc loginCtx) (map[string]any, bool) {
	account := normUser(cred.Account)
	n := 0
	if s.webauthnEnabled() {
		if cnt, err := s.store.WebauthnCredentialCount(r.Context(), account); err == nil {
			n = cnt
		} else {
			// 读失败 fail-closed：不能因查不到凭据就跳过已启用账号的二次因子。
			s.auditAs(r, cred.Account, "auth", "二次认证前置查询失败，拒绝登录", "fail")
			return map[string]any{"ok": false, "reason": "二次认证服务暂不可用，请稍后重试"}, true
		}
	}
	if n > 0 {
		s.auditAs(r, cred.Account, "auth", "登录触发 passkey 二次认证（账号已注册 passkey）", "mfa")
		return map[string]any{
			"ok": false, "needWebauthn": true, "ticket": s.signMfaTicket(account, lc.Directory),
			"reason": "请用已注册的 passkey（Touch ID / Windows Hello / 安全密钥）完成二次认证",
		}, true
	}
	// TOTP 与 passkey 同款纪律：已确认即无条件强制，策略豁免碰不到它。
	// 排在 passkey 之后——两者都注册时用抗钓鱼的那个。
	trec, tfound, terr := s.store.TotpFor(r.Context(), account)
	if terr != nil {
		s.auditAs(r, cred.Account, "auth", "二次认证前置查询失败，拒绝登录", "fail")
		return map[string]any{"ok": false, "reason": "二次认证服务暂不可用，请稍后重试"}, true
	}
	if tfound && trec.Confirmed {
		s.auditAs(r, cred.Account, "auth", "登录触发 TOTP 二次认证（账号已启用动态验证码）", "mfa")
		return map[string]any{
			"ok": false, "needTotp": true, "ticket": s.signMfaTicket(account, lc.Directory),
			"reason": "请输入认证器 App 中的 6 位动态验证码",
		}, true
	}

	dec, ok := s.stepUpDecision(r, cred, lc)
	if !ok {
		// 判定材料读不到：不能把"不知道该不该要二次认证"当成"不需要"。
		s.auditAs(r, cred.Account, "auth", "认证策略判定材料读取失败，拒绝登录", "fail")
		return map[string]any{"ok": false, "reason": "认证策略暂不可用，请稍后重试"}, true
	}
	switch {
	case dec.RequireMFA:
		// 审计记的是已经发生的事实：这次登录因为哪条条件被抬到了二次认证。
		s.auditAs(r, cred.Account, "auth", dec.Summary(), "mfa")
		// ★这一步的判据是 authpolicy.Blocked，与**保存策略时**的防自锁闸
		// （api.guardAuthPolicyLockout）读同一个函数——闸算「保存后还有没有人进得来」，
		// 靠的就是这里对同一份决策的判定。各写一份的话，闸放行了而登录挡住了，两边都不报错。
		//
		// 分支内的两句文案分别对应 Blocked 的两个成因，措辞不同但结局一样：
		// 该账号既无 passkey 也无 TOTP，这次登录到此为止。
		if authpolicy.Blocked(dec, s.webauthnEnabled()) {
			why := "该账号尚未注册 passkey 或 TOTP"
			if !s.webauthnEnabled() {
				// ★RP 未配置（裸 IP 演示站）时 legacy 演示验证码本来是通的，
				// 是策略点名了方式才把它关掉——这是 AuthPolicy.Secondary 的**唯一执行语义**：
				// 「这条策略要求二次认证」不能由一个写死在代码里的 123456 来满足。
				why = "策略要求的二次认证方式为「" + strings.Join(methodLabels(dec.Methods), "、") +
					"」，而该账号尚未注册"
			}
			return map[string]any{
				"ok": false, "needEnroll": true,
				"reason": dec.Summary() + "；" + why + "。" + s.enrollDeadEndNote(),
			}, true
		}
		// 策略没声明方式（留空 = 不额外约束）且 RP 未配置：回落演示验证码，进得去。
		return s.legacySecondFactor(r, cred, dec)
	case dec.Exempted:
		// 豁免也是一次发生过的判定，必须留痕：否则"为什么这次没要二次认证"无从回答。
		s.auditAs(r, cred.Account, "auth", dec.Summary(), "ok")
	}
	return nil, false
}

// enrollDeadEndNote 「被策略抬到二次认证、却一个认证器都没注册」时给用户的补救路径。
//
// ★改造前这两条分支写的是「（可联系管理员协助录入）」和「请先在门户「安全设置」里绑定
// 后再登录」——两句指的都是**不存在的路**：
//   - 白帝没有任何「管理员代为录入认证器」的入口：/totp/enroll 与 webauthn 注册都走
//     requireUser，只能由本人在**已登录**状态下调；管理员那侧只有 ResetWebauthnCredentials，
//     那是清空，不是录入。
//   - 门户「安全设置」本身要先登录才进得去，而门户登录与管理台登录过的是**同一条**
//     认证策略（两处都按 directory 匹配、都调 secondFactor）——把人支到那里，
//     他会在同一堵墙上再撞一次，然后开始怀疑是自己口令记错了。
//
// 真实存在的出路只有两条，都写在这里。第二条之所以成立，是因为保存策略那一刻有
// guardAuthPolicyLockout 顶着：它保证「至少还有一名能登进来、且改得动这条策略的管理员」。
func (s *Server) enrollDeadEndNote() string {
	note := "注册入口在门户「安全设置」里、本身要求先登录，所以自助注册这条路现在走不通。" +
		"出路有二：① 若这条策略配了「可信网络 / 授信终端」豁免，换到符合条件的网络或终端登录，进去之后立刻注册；" +
		"② 请另一名仍能登录、且持「安全策略」权限的管理员，把你移出这条策略的适用范围、或关掉它的二次认证要求。" +
		"管理员无法代你录入认证器——passkey / TOTP 只能由本人在已登录状态下注册。"
	if !s.webauthnEnabled() {
		// 裸 IP 部署（演示站就是）下 passkey 根本注册不了：浏览器规范不允许把 IP 当
		// RP ID。不点名的话，用户会去查"为什么点了 passkey 没反应"。
		note += "（本部署未配置 WebAuthn RP，浏览器规范不允许裸 IP 作 RP ID，因此这里能注册的第二因子只有 TOTP。）"
	}
	return note
}

// legacySecondFactor 未配置 WebAuthn 时的演示验证码路径（仅演示环境可达）。
// reason 取自策略决策——此前这里写死"检测到未授信终端/异地登录"，那两件事当时根本没判过。
func (s *Server) legacySecondFactor(r *http.Request, cred store.Credential, dec authpolicy.Decision) (map[string]any, bool) {
	code := legacyMfaCode(r)
	if code == "" {
		s.auditAs(r, cred.Account, "auth", dec.Summary()+"（WebAuthn 未配置且未注册 TOTP，回落 legacy 演示验证码）", "mfa")
		return map[string]any{"ok": false, "needMfa": true,
			"reason": dec.Summary() + "，请输入演示验证码（登录后可在门户「安全设置」注册 TOTP 换成真动态码）"}, true
	}
	if code != legacyDemoCode {
		return map[string]any{"ok": false, "needMfa": true, "reason": "验证码错误（演示验证码：" + legacyDemoCode + "）"}, true
	}
	return nil, false
}

// legacyMfaCode 从 context 取 mfaCode（handlePortalLogin 解码请求体后存入，避免重复解码）。
func legacyMfaCode(r *http.Request) string {
	if v, ok := r.Context().Value(mfaCodeKey{}).(string); ok {
		return v
	}
	return ""
}

type mfaCodeKey struct{}

func withLegacyMfaCode(ctx context.Context, code string) context.Context {
	return context.WithValue(ctx, mfaCodeKey{}, code)
}

// signMfaTicket 签发"口令已验"的一次性短票据：role=mfa 使其无法当会话令牌用
// （requireAdmin/requireUser 都不认 mfa 角色），只能用来换取一次 WebAuthn 断言。
//
// dir 是**本回合第一因子来自哪个用户目录**（loginCtx.Directory：local / ldap / ad /
// oidc / radius），随票据带到第二回合去（见 auth.Claims.Dir 与 denyExternalMfaAdmin）。
// 它是**唯一**能把这件事告诉第二回合的通道：那两个 handler 拿票据换账号、重读 users 行、
// 按当下的 role 签完整令牌，天然不知道第一因子是谁验的。
func (s *Server) signMfaTicket(account, dir string) string {
	return s.keys.Sign(auth.Claims{
		Sub: account, Role: "mfa", Name: account, Jti: auth.RandJTI(), Dir: dir,
	}, mfaTicketTTL)
}

// verifyMfaTicket 校验票据并取回账号与第一因子目录；非 mfa 角色一律拒（防会话令牌当票据用）。
func (s *Server) verifyMfaTicket(tok string) (account, dir string, ok bool) {
	c, err := s.keys.Verify(tok)
	if err != nil || c.Role != "mfa" || c.Sub == "" {
		return "", "", false
	}
	return normUser(c.Sub), c.Dir, true
}

// denyExternalMfaAdmin 二次认证第二回合的**纵深闸**：本回合第一因子不是本地口令，
// 而重读出来的账号是管理员 → 一律不签任何令牌。写完响应返回 true（调用方直接 return）。
//
// ★它与「管理员的认证权不外包」是同一条纪律的第二层。第一层是**顺序**——
// externalSessionCredential 排在 secondFactor 之前，于是外部路径上的管理员根本拿不到
// mfa 票据。但顺序是一种"只要没人挪动它就成立"的保证，而两条腿各自看都自洽：
// 门户/OIDC 那边闸确实在；handleTotpLogin / handleWebauthnLoginFinish 这边则是按票据
// 重读 users 行、原样 Sign(Role: cred.Role)——它们从来不知道第一因子是谁验的。
// 顺序一旦被挪动（把闸下沉到签发处、加一道新闸插在中间、重构 secondFactor），
// 一名注册了 TOTP 的外部绑定管理员走一遍 IdP 就是一张 role=admin 的 8h 会话，
// 而**两处代码都不会报错**。带上 Dir 之后这一回合能独立复判，纵深不再依赖顺序。
//
// 三条判据上的取舍：
//   - **只对 role=admin 生效**：外部账号走 TOTP 二次认证是正常业务，不能拦。
//   - **dir 为空 = 不可判定 → 按外部处理（fail-closed）**。它只可能出现在"升级那一刻
//     尚在飞行的旧票据"上（3 分钟内自然消失），代价是那几个管理员重登一次；
//     反过来把空当成 local，等于给旧票据留一条绕过去的路。
//   - **读不到账号也拒**：与 externalSessionCredential 的 !found 同向。
//
// 拒绝不计入爆破锁定（外部那边的凭据是对的），审计与文案同经 denyAdminExternal 产出，
// 与门户口令 / OIDC 两条路上的那句逐字相同。
func (s *Server) denyExternalMfaAdmin(w http.ResponseWriter, r *http.Request, account, dir string) bool {
	if dir == string(authsrc.KindLocal) {
		// 本地口令那一回合：不读库、不判定，与改造前逐字同行为（绝大多数登录走这里）。
		return false
	}
	cred, found, err := s.store.Credential(r.Context(), account)
	if err != nil || !found {
		slog.Error("二次认证第二回合重读账号失败，拒绝签发令牌", "账号", account, "第一因子目录", dir, "找到", found, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "账号状态复查失败")
		return true
	}
	if cred.Role != "admin" {
		return false
	}
	via := "外部认证源（目录 " + dir + "）"
	if dir == "" {
		via = "外部认证源（目录不可判定）"
	}
	httpx.Error(w, http.StatusForbidden, s.denyAdminExternal(r, cred.Account, via))
	return true
}

// webauthnUserFor 按账号组装 go-webauthn User（含其已注册凭据）。
func (s *Server) webauthnUserFor(r *http.Request, account string) (webauthnUser, error) {
	key := normUser(account)
	cred, found, err := s.store.Credential(r.Context(), key)
	if err != nil {
		return webauthnUser{}, err
	}
	if !found {
		return webauthnUser{}, errNoSuchAccount
	}
	creds, err := s.store.WebauthnCredentialsFor(r.Context(), key)
	if err != nil {
		return webauthnUser{}, err
	}
	u, err := webauthnx.NewUser(cred.ID, cred.Account, cred.Name, creds)
	if err != nil {
		return webauthnUser{}, err
	}
	return webauthnUser{user: u, cred: cred, count: len(creds)}, nil
}

type webauthnUser struct {
	user  webauthn.User
	cred  store.Credential
	count int
}

var errNoSuchAccount = errors.New("账号不存在")

// handleWebauthnRegisterBegin 注册仪式第一回合（需登录）：出 CreationOptions + 落 challenge。
func (s *Server) handleWebauthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !s.webauthnEnabled() {
		httpx.Error(w, http.StatusServiceUnavailable, "服务端未配置 WebAuthn（需 BAIDI_WEBAUTHN_RPID/ORIGIN，且 RP ID 必须是域名或 localhost）")
		return
	}
	wu, err := s.webauthnUserFor(r, c.Name)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	opts, sess, err := s.rp.BeginRegistration(wu.user)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to begin registration")
		return
	}
	if err := s.saveChallenge(r, normUser(c.Name), "register", sess); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save challenge")
		return
	}
	s.audit(r, "security", "发起 passkey 注册", "ok")
	httpx.JSON(w, http.StatusOK, opts)
}

// handleWebauthnRegisterFinish 注册仪式第二回合（需登录）：校验 attestation 并落库凭据。
func (s *Server) handleWebauthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !s.webauthnEnabled() {
		httpx.Error(w, http.StatusServiceUnavailable, "服务端未配置 WebAuthn")
		return
	}
	account := normUser(c.Name)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体过大")
		return
	}
	// 客户端可带一个可读别名；其余字段是标准 attestation 响应，原样交给库解析。
	var meta struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(body, &meta)

	sess, err := s.consumeChallengeFromBody(r, body, "register")
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if sess.account != account {
		// challenge 归属账号必须与当前登录者一致，杜绝拿他人 challenge 给自己注册。
		httpx.Error(w, http.StatusForbidden, "挑战与当前账号不匹配")
		return
	}
	wu, err := s.webauthnUserFor(r, account)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	cred, err := s.rp.FinishRegistration(wu.user, sess.data, r)
	if err != nil {
		s.audit(r, "security", "passkey 注册失败："+err.Error(), "fail")
		httpx.Error(w, http.StatusBadRequest, "注册校验失败："+err.Error())
		return
	}
	cred.UserID, cred.Account, cred.Name = wu.cred.ID, account, strings.TrimSpace(meta.Name)
	saved, err := s.writer.SaveWebauthnCredential(r.Context(), cred)
	if errors.Is(err, store.ErrCredentialExists) {
		httpx.Error(w, http.StatusConflict, "该认证器已注册过")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save credential")
		return
	}
	s.audit(r, "security", "注册 passkey「"+saved.Name+"」成功", "ok")
	httpx.JSON(w, http.StatusCreated, saved)
}

// handleWebauthnLoginBegin 登录断言第一回合。
// ★不是免认证端点：必须带 mfaTicket（口令校验通过后签发），据此绑定账号并出 allowCredentials，
// 从根上避免"裸 username 探测某账号是否注册 passkey"的用户枚举面。
func (s *Server) handleWebauthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.webauthnEnabled() {
		httpx.Error(w, http.StatusServiceUnavailable, "服务端未配置 WebAuthn")
		return
	}
	var b struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&b); err != nil || b.Ticket == "" {
		httpx.Error(w, http.StatusBadRequest, "缺少认证票据")
		return
	}
	// begin 这一回合只出 allowCredentials、不签任何令牌，故不施加第一因子目录闸
	// （真正的闸在 finish 那一回合，见 denyExternalMfaAdmin）。
	account, _, ok := s.verifyMfaTicket(b.Ticket)
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "认证票据无效或已过期，请重新登录")
		return
	}
	wu, err := s.webauthnUserFor(r, account)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if wu.count == 0 {
		httpx.Error(w, http.StatusBadRequest, "该账号尚未注册 passkey")
		return
	}
	opts, sess, err := s.rp.BeginLogin(wu.user)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to begin login")
		return
	}
	if err := s.saveChallenge(r, account, "login", sess); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save challenge")
		return
	}
	httpx.JSON(w, http.StatusOK, opts)
}

// handleWebauthnLoginFinish 登录断言第二回合：校验断言 → 签发会话令牌。
// 三重绑定：票据证明口令已验、challenge 绑账号、断言凭据必须属于该账号。
func (s *Server) handleWebauthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !s.webauthnEnabled() {
		httpx.Error(w, http.StatusServiceUnavailable, "服务端未配置 WebAuthn")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体过大")
		return
	}
	var b struct {
		Ticket string `json:"ticket"`
	}
	_ = json.Unmarshal(body, &b)
	account, dir, ok := s.verifyMfaTicket(b.Ticket)
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "认证票据无效或已过期，请重新登录")
		return
	}
	// ★纵深：本回合第一因子不是本地口令、而这个账号是管理员 → 到此为止。
	// 排在断言校验之前——判定不需要那次断言，而"先验完再拒"会平白多一次认证器交互。
	if s.denyExternalMfaAdmin(w, r, account, dir) {
		return
	}
	// 防爆破锁：断言失败也计数，锁定可能在口令与断言两回合之间触发（含并行爆破），此处再拦一次。
	if s.loginGateLocked(w, r, account) {
		return
	}
	sess, err := s.consumeChallengeFromBody(r, body, "login")
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if sess.account != account {
		httpx.Error(w, http.StatusForbidden, "挑战与账号不匹配")
		return
	}
	wu, err := s.webauthnUserFor(r, account)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	// 账号状态门：口令那步已查过，这里再查一次，杜绝两回合之间被禁用仍能拿令牌。
	if accountBlocked(wu.cred.Status) {
		s.auditAs(r, account, "auth", "passkey 断言被拒（账号已"+statusZh[wu.cred.Status]+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "账号已被"+statusZh[wu.cred.Status])
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	credID, newCount, err := s.rp.FinishLogin(wu.user, sess.data, r)
	if err != nil {
		s.noteLoginFailure(r, account) // WebAuthn 断言失败同口令错误一样计入防爆破
		s.auditAs(r, account, "auth", "passkey 断言失败："+err.Error(), "fail")
		httpx.Error(w, http.StatusUnauthorized, "断言校验失败")
		return
	}
	if err := s.writer.UpdateSignCount(r.Context(), credID, newCount); err != nil {
		if errors.Is(err, store.ErrSignCountRegression) {
			s.auditAs(r, account, "security", "passkey 签名计数器倒退，疑似凭据克隆（credential "+credID+"）", "deny")
			httpx.Error(w, http.StatusUnauthorized, "认证器状态异常，请联系管理员")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, "failed to update credential")
		return
	}
	s.lockout.Success(account) // 二次认证走完才算成功登录，此刻清零失败计数
	// 首登强制改密：断言先走完（改密页必须在完整认证态之后），此处才降级令牌——
	// 顺序不能反，否则改密端点会向仅过口令、未过 2FA 的半程态开放。
	if wu.cred.MustChangePw {
		s.auditAs(r, account, "auth", "passkey 二次认证通过", "ok")
		s.mustChangeLogin(w, r, wu.cred)
		return
	}
	s.noteLoginSuccess(r.Context(), account)
	s.auditAs(r, account, "auth", "passkey 二次认证通过，登录成功", "ok")
	tok := s.keys.Sign(auth.Claims{Sub: wu.cred.Account, Role: wu.cred.Role, Name: wu.cred.Account, Jti: auth.RandJTI()}, tokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "token": tok, "displayName": wu.cred.Name, "role": wu.cred.Role,
	})
}

// handleWebauthnCredentials 列出我的 passkey（需登录）。
func (s *Server) handleWebauthnCredentials(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	creds, err := s.store.WebauthnCredentialsFor(r.Context(), normUser(c.Name))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load credentials")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"credentials": creds, "enabled": s.webauthnEnabled()})
}

// handleWebauthnDeleteCredential 删除我的一个 passkey（需登录，仅限本人；最后一个不许删）。
func (s *Server) handleWebauthnDeleteCredential(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	err := s.writer.DeleteWebauthnCredential(r.Context(), normUser(c.Name), id)
	switch {
	case errors.Is(err, store.ErrLastCredential):
		httpx.Error(w, http.StatusConflict, "不能删除最后一个 passkey（否则将无法完成二次认证）")
		return
	case errors.Is(err, store.ErrCredentialNotFound):
		httpx.Error(w, http.StatusNotFound, "凭据不存在")
		return
	case err != nil:
		httpx.Error(w, http.StatusInternalServerError, "failed to delete credential")
		return
	}
	s.audit(r, "security", "删除 passkey "+id, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// ── challenge 存取辅助 ──

type challengeSession struct {
	account string
	data    webauthn.SessionData
}

// saveChallenge 把库生成的 SessionData 落库（以 challenge 值为单次消费键）。
// 顺手清理过期行，避免匿名刷 begin 导致无界堆积（best-effort）。
func (s *Server) saveChallenge(r *http.Request, account, typ string, sess *webauthn.SessionData) error {
	raw, err := webauthnx.EncodeSession(sess)
	if err != nil {
		return err
	}
	_, _ = s.writer.PurgeExpiredChallenges(r.Context())
	_, err = s.writer.CreateWebauthnChallenge(r.Context(), store.WebauthnChallenge{
		Account: account, Challenge: webauthnx.ChallengeOf(sess), Type: typ, SessionData: raw,
	})
	return err
}

// consumeChallengeFromBody 从仪式响应体里取出 challenge（clientDataJSON 内），
// 按值+类型单次消费并还原 SessionData。消费失败即视为重放/过期。
func (s *Server) consumeChallengeFromBody(r *http.Request, body []byte, typ string) (challengeSession, error) {
	ch, err := challengeFromClientData(body)
	if err != nil {
		return challengeSession{}, errors.New("请求格式不正确")
	}
	rec, err := s.writer.ConsumeWebauthnChallenge(r.Context(), ch, typ)
	if err != nil {
		return challengeSession{}, store.ErrChallengeInvalid
	}
	data, err := webauthnx.DecodeSession(rec.SessionData)
	if err != nil {
		return challengeSession{}, store.ErrChallengeInvalid
	}
	return challengeSession{account: rec.Account, data: data}, nil
}

// challengeFromClientData 解出仪式响应里的 challenge（base64url）。
func challengeFromClientData(body []byte) (string, error) {
	var resp struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Response.ClientDataJSON == "" {
		return "", errors.New("missing clientDataJSON")
	}
	raw, err := base64.RawURLEncoding.DecodeString(resp.Response.ClientDataJSON)
	if err != nil {
		// 部分客户端可能带 padding
		raw, err = base64.URLEncoding.DecodeString(resp.Response.ClientDataJSON)
		if err != nil {
			return "", err
		}
	}
	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(raw, &cd); err != nil || cd.Challenge == "" {
		return "", errors.New("missing challenge")
	}
	return cd.Challenge, nil
}

// methodLabels 把方式 key 换成中文名（提示语里出现的是给人看的名字，不是 key）。
func methodLabels(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if mc, ok := authpolicy.MethodOf(k); ok {
			out = append(out, mc.Label)
			continue
		}
		out = append(out, k)
	}
	return out
}

// handleAdminResetPasskeys DELETE /api/v1/users/{id}/passkeys——管理员清空某账号的全部 passkey。
//
// ★与 handleAdminResetTotp **逐字对称**，而在此之前它不存在，于是 passkey 这一路
// 结构性地没有出口：
//
//	passkey 没有恢复码；`store.DeleteWebauthnCredential` 拒绝删最后一个
//	（那道守卫是为"别把自己锁在门外"设的，前提是本人还能登录）；
//	而 `api.secondFactor` 规定「已注册 passkey 即无条件强制断言，策略豁免碰不到它」。
//	三条合起来的后果是：认证器一丢，这个账号**永久登不进来**——本人删不掉，
//	管理员也没有任何端点可调，唯一出路是运维直接删库改行。
//	TOTP 那边早就把这条路判过死刑（"等于逼着每次事故都做一次 DB 手术"），
//	passkey 这半边只是没有一起做。
//
// 权限与重置口令、重置 TOTP 同一档：PermSecurity + 目标是管理员时须 admins 权。
// 清二因子是**削弱**目标账号防护的方向——能清 root 的 passkey 再重置其口令即全权接管。
func (s *Server) handleAdminResetPasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	u, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool { return du.ID == id })
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "用户不存在")
		return
	}
	if !s.guardAdminTarget(w, r, u, "重置 passkey 二次认证") {
		return
	}
	removed, err := s.writer.ResetWebauthnCredentials(r.Context(), u.Account)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "重置落库失败")
		return
	}
	if removed > 0 {
		s.audit(r, "security",
			"重置用户「"+u.Account+"」的 passkey 二次认证（清除 "+strconv.Itoa(removed)+
				" 个认证器，下次登录回到口令单因素，须本人重新注册）", "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
}
