package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"baidi.dev/control/internal/auth"
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

// riskyAccount 自适应二次认证的启发式：外包/未授信账号。
func riskyAccount(account string) bool {
	return strings.HasPrefix(account, "ext") || strings.Contains(account, "外包")
}

// secondFactor 决定本次登录是否需要二次因子，并返回应直接回给客户端的响应。
// done=true 表示登录尚未完成（已产出 needWebauthn/needMfa 响应或拒绝），调用方直接回传。
//
// 判定顺序：
//   - 已注册 passkey 且 RP 已配置 → 必须 WebAuthn 断言（抗钓鱼，最强）；
//   - 未注册 passkey 但属风险账号 → RP 已配置时要求先注册 passkey（引导，不放行）；
//     RP 未配置（裸 IP 演示站/dev）→ 回落 legacy 演示验证码，保证演示可用；
//   - 其余 → 单因子口令放行（与现状一致）。
//
// ★零凭据不锁死：普通账号无 passkey 照常登录，登录后可去 /portal/security 注册——
// 避免"无 passkey→无法登录→无法进注册页"的 bootstrap 死锁。
func (s *Server) secondFactor(r *http.Request, cred store.Credential) (map[string]any, bool) {
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
	switch {
	case n > 0:
		s.auditAs(r, cred.Account, "security", "登录触发 passkey 二次认证", "mfa")
		return map[string]any{
			"ok": false, "needWebauthn": true, "ticket": s.signMfaTicket(account),
			"reason": "请用已注册的 passkey（Touch ID / Windows Hello / 安全密钥）完成二次认证",
		}, true
	case riskyAccount(account) && s.webauthnEnabled():
		s.auditAs(r, cred.Account, "security", "风险账号未注册 passkey，登录被拒", "deny")
		return map[string]any{
			"ok": false, "needEnroll": true,
			"reason": "该账号为未授信/外包账号，须先注册 passkey 才能接入，请联系管理员协助录入",
		}, true
	case riskyAccount(account):
		// legacy 演示回落：RP 未配置（如裸 IP 演示站），保留演示验证码路径。
		return s.legacySecondFactor(r, cred)
	}
	return nil, false
}

// legacySecondFactor 未配置 WebAuthn 时的演示验证码路径（仅演示环境可达）。
func (s *Server) legacySecondFactor(r *http.Request, cred store.Credential) (map[string]any, bool) {
	code := legacyMfaCode(r)
	if code == "" {
		s.auditAs(r, cred.Account, "security", "终端用户登录触发自适应二次认证（legacy 演示码，WebAuthn 未配置）", "mfa")
		return map[string]any{"ok": false, "needMfa": true, "reason": "检测到未授信终端/异地登录，需短信二次认证"}, true
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
func (s *Server) signMfaTicket(account string) string {
	return s.keys.Sign(auth.Claims{Sub: account, Role: "mfa", Name: account, Jti: auth.RandJTI()}, mfaTicketTTL)
}

// verifyMfaTicket 校验票据并取回账号；非 mfa 角色一律拒（防会话令牌当票据用）。
func (s *Server) verifyMfaTicket(tok string) (string, bool) {
	c, err := s.keys.Verify(tok)
	if err != nil || c.Role != "mfa" || c.Sub == "" {
		return "", false
	}
	return normUser(c.Sub), true
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
	account, ok := s.verifyMfaTicket(b.Ticket)
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
	account, ok := s.verifyMfaTicket(b.Ticket)
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "认证票据无效或已过期，请重新登录")
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
