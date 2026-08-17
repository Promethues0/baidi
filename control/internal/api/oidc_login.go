package api

// OIDC 登录入口（wave7 行动 1：FR-AUTH-02/05）。
//
// ★回归背景：oidcsrc 协议客户端 30 条真密码学用例全绿、控制台配置页齐全、
// 「测试连接」真的探测——却没有任何用户能**经它登录**：authenticateExternal 只走
// PasswordAuthenticator，RedirectAuthenticator 那半从未被接进登录链路。
// config-only 静默失效的教科书案例（重扫清单 7 条同形缺口之首）。
//
// 流程（授权码 + PKCE，state/nonce/verifier 全部服务端保管）：
//
//	GET  /api/v1/auth/oidc/providers        已启用 OIDC 源的公开清单（登录页渲染按钮用）
//	GET  /api/v1/auth/oidc/{id}/authorize   生成 state/nonce/verifier → 302 到 IdP
//	GET  /api/v1/auth/oidc/{id}/callback    验 state（单次）→ Exchange → 绑定 → 二次因子
//	                                        → 302 回门户（带一次性交接票据，绝不带会话令牌）
//	POST /api/v1/auth/oidc/session          交接票据（60s、单次）→ 会话令牌
//
// 几条不许动的纪律：
//   - **会话令牌绝不进 URL**：8h 令牌进浏览器历史/代理日志等于白给。回调只带
//     60s 单次交接票据（Use=oidcgrant），由 SPA 用 POST 换真令牌。
//     交接票据被当 Bearer 用时，中间件的用途白名单直接 403（未知 Use 默认拒）。
//   - **二次因子不许被新入口绕过**：回调复用 secondFactor——已注册 passkey 的账号
//     照样被引去断言（经门户既有的 webauthn 流程），策略抬升的 needEnroll 照样拦。
//   - **只接门户，不接管理台**：外部账号 role 恒 user（BindExternalUser 的纪律），
//     管理台挂 OIDC 按钮只会让人登进去发现"无管理权限"——误导而无收益。
//   - state 单次使用、10 分钟过期、总量有上界：authorize 是免认证端点，
//     无上界的 pending 表就是一个免费的内存耗尽面。

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/authsrc/oidcsrc"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

const (
	// useOIDCGrant 交接票据的用途标记。刻意不进 auth 包的常量表：
	// 中间件的用途白名单对未知 Use **默认拒绝**，新用途不登记就天然进不了 API 面——
	// 这正是我们要的方向（它只该被 /auth/oidc/session 消费）。
	useOIDCGrant = "oidcgrant"
	// oidcGrantTTL 交接票据寿命：一次浏览器重定向 + 一次 XHR 的时间，再无别的用途。
	oidcGrantTTL = 60 * time.Second
	// oidcPendingTTL 授权往返的服务端会话寿命（用户在 IdP 页面上输码的时间）。
	oidcPendingTTL = 10 * time.Minute
	// oidcPendingCap pending 表上界。满了拒绝新的 authorize 而不是挤掉旧的——
	// 挤旧让攻击者能用洪水把正常用户进行中的登录顶掉（DoS 升级成登录必败）。
	oidcPendingCap = 2048
	// portalLoginPath 回调完成后浏览器落回的 SPA 路径（相对路径：与部署形态无关）。
	portalLoginPath = "/portal/login"
)

// oidcPending 一次进行中的授权往返。
type oidcPending struct {
	srcID    string
	nonce    string
	verifier string
	exp      int64
}

// oidcFlows state → 进行中会话，附带交接票据 jti 的单次消费登记。
// 内存态即可：控制面单实例（SQLite 单写者），重启丢 pending 的代价是用户重点一次登录。
type oidcFlows struct {
	mu      sync.Mutex
	pending map[string]oidcPending
	usedJTI map[string]int64 // jti → 过期时刻（懒清理）
}

func newOIDCFlows() *oidcFlows {
	return &oidcFlows{pending: map[string]oidcPending{}, usedJTI: map[string]int64{}}
}

func (f *oidcFlows) gcLocked(now int64) {
	for k, v := range f.pending {
		if v.exp <= now {
			delete(f.pending, k)
		}
	}
	for k, exp := range f.usedJTI {
		if exp <= now {
			delete(f.usedJTI, k)
		}
	}
}

// put 登记一次授权往返；表满返回 false（调用方回 503，别让洪水挤掉进行中的登录）。
func (f *oidcFlows) put(state string, p oidcPending) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().Unix()
	f.gcLocked(now)
	if len(f.pending) >= oidcPendingCap {
		return false
	}
	p.exp = now + int64(oidcPendingTTL.Seconds())
	f.pending[state] = p
	return true
}

// take 取出并删除（单次使用）。过期视为不存在。
func (f *oidcFlows) take(state string) (oidcPending, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().Unix()
	f.gcLocked(now)
	p, ok := f.pending[state]
	if !ok || p.exp <= now {
		return oidcPending{}, false
	}
	delete(f.pending, state)
	return p, true
}

// grantOnce 登记交接票据 jti 的首次消费；重复消费返回 false。
func (f *oidcFlows) grantOnce(jti string, ttl time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().Unix()
	f.gcLocked(now)
	if _, used := f.usedJTI[jti]; used {
		return false
	}
	f.usedJTI[jti] = now + int64(ttl.Seconds())
	return true
}

// oidcRedirectAuth 解析出某认证源的 RedirectAuthenticator。
// testRedirectAuth 是测试注入缝（照 baidi-ipsec 的 controlClient 先例：协议实现
// 已有 30 条真密码学用例，这里要测的是编排——state 单次性、重定向、票据交接）。
func (s *Server) oidcRedirectAuth(ctx context.Context, rec store.AuthSourceRec) (authsrc.RedirectAuthenticator, error) {
	if s.testRedirectAuth != nil {
		return s.testRedirectAuth(rec)
	}
	prov, err := s.buildProvider(ctx, rec)
	if err != nil {
		return nil, err
	}
	ra, ok := prov.(authsrc.RedirectAuthenticator)
	if !ok {
		return nil, errors.New("该认证源不支持重定向式登录")
	}
	return ra, nil
}

// oidcSourceByID 查一条**已启用**的 OIDC 源。
func (s *Server) oidcSourceByID(ctx context.Context, id string) (store.AuthSourceRec, bool) {
	as := s.authSrcStore()
	if as == nil {
		return store.AuthSourceRec{}, false
	}
	srcs, err := as.AuthSources(ctx)
	if err != nil {
		return store.AuthSourceRec{}, false
	}
	for _, rec := range srcs {
		if rec.ID == id && rec.Enabled && authsrc.Kind(rec.Kind) == authsrc.KindOIDC {
			return rec, true
		}
	}
	return store.AuthSourceRec{}, false
}

// handleOIDCProviders 已启用 OIDC 源的公开清单。
// 只回 id 与展示名：issuer/clientId/redirectUri 对未登录者是纯侦察情报。
func (s *Server) handleOIDCProviders(w http.ResponseWriter, r *http.Request) {
	type provider struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	out := []provider{}
	if as := s.authSrcStore(); as != nil {
		if srcs, err := as.AuthSources(r.Context()); err == nil {
			for _, rec := range srcs {
				if rec.Enabled && authsrc.Kind(rec.Kind) == authsrc.KindOIDC {
					out = append(out, provider{ID: rec.ID, Name: rec.Name})
				}
			}
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"providers": out})
}

// handleOIDCAuthorize 生成本次登录的 state/nonce/verifier，302 到 IdP 授权端点。
func (s *Server) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.oidcSourceByID(r.Context(), r.PathValue("id"))
	if !ok {
		httpx.Error(w, http.StatusNotFound, "认证源不存在或未启用")
		return
	}
	ra, err := s.oidcRedirectAuth(r.Context(), rec)
	if err != nil {
		slog.Warn("OIDC 授权入口不可用", "源", rec.Name, "err", err.Error())
		s.oidcFail(w, r, rec.Name, "认证源暂不可用，请稍后重试或联系管理员")
		return
	}
	state, err1 := oidcsrc.NewState()
	nonce, err2 := oidcsrc.NewNonce()
	verifier, err3 := oidcsrc.NewCodeVerifier()
	if err1 != nil || err2 != nil || err3 != nil {
		httpx.Error(w, http.StatusInternalServerError, "随机数生成失败")
		return
	}
	u, err := ra.AuthURL(state, nonce, verifier)
	if err != nil {
		slog.Warn("OIDC 授权地址构造失败", "源", rec.Name, "err", err.Error())
		s.oidcFail(w, r, rec.Name, "认证源暂不可用（授权地址构造失败），请联系管理员")
		return
	}
	if !s.oidcFlow.put(state, oidcPending{srcID: rec.ID, nonce: nonce, verifier: verifier}) {
		// 表满：如实 503。这是免认证端点，挤掉旧会话会让洪水把正常登录顶成必败。
		httpx.Error(w, http.StatusServiceUnavailable, "登录会话过多，请稍后重试")
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// handleOIDCCallback IdP 回调：验 state → 换码验令牌 → 绑定 → 二次因子 → 交接票据。
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.oidcSourceByID(r.Context(), r.PathValue("id"))
	if !ok {
		httpx.Error(w, http.StatusNotFound, "认证源不存在或未启用")
		return
	}
	q := r.URL.Query()
	// IdP 侧的显式拒绝（用户取消、consent 拒绝…）：如实转述，别包装成"密码错误"。
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if desc == "" {
			desc = e
		}
		s.auditAs(r, "-", "auth", "OIDC 登录被身份提供方拒绝（源 "+rec.Name+"）："+desc, "deny")
		s.oidcFail(w, r, rec.Name, "身份提供方拒绝了本次登录："+desc)
		return
	}
	state, code := q.Get("state"), q.Get("code")
	pend, ok := s.oidcFlow.take(state)
	if !ok || pend.srcID != rec.ID || code == "" {
		// state 对不上：过期、重放、或跨源混用。一律同一句话——区分开就是给攻击者的示波器。
		s.auditAs(r, "-", "auth", "OIDC 回调 state 校验失败（源 "+rec.Name+"）", "deny")
		s.oidcFail(w, r, rec.Name, "登录会话已过期或无效，请重新发起登录")
		return
	}
	ra, err := s.oidcRedirectAuth(r.Context(), rec)
	if err != nil {
		s.oidcFail(w, r, rec.Name, "认证源暂不可用，请稍后重试")
		return
	}
	ident, err := ra.Exchange(r.Context(), code, pend.verifier, pend.nonce)
	if err != nil {
		// 细节进日志（运维要看），给浏览器的只有结论——令牌校验失败的具体原因
		// （alg/aud/nonce…）对用户无用，对攻击者是调试信息。
		slog.Warn("OIDC 换码/验令牌失败", "源", rec.Name, "err", err.Error())
		s.auditAs(r, "-", "auth", "OIDC 令牌校验失败（源 "+rec.Name+"）", "deny")
		s.oidcFail(w, r, rec.Name, "登录校验失败，请重新发起登录")
		return
	}
	as := s.authSrcStore()
	if as == nil {
		s.oidcFail(w, r, rec.Name, "当前部署不支持外部认证源")
		return
	}
	// ★准入闸（wave8 行动 10）：与口令登录**同一个判定函数**，同样在 BindExternalUser
	// 之前。OIDC 这一侧尤其要紧——一个允许任意公有云账号完成授权码流的 IdP 配置，
	// 没有域/组白名单就等于对全互联网开放自动建号。
	_, bound, berr := as.UserBySubject(r.Context(), rec.ID, ident.Subject)
	if berr != nil {
		slog.Error("OIDC 绑定查询失败", "源", rec.Name, "err", berr.Error())
		s.oidcFail(w, r, rec.Name, "账号绑定失败，请联系管理员")
		return
	}
	if v := s.admitExternal(r.Context(), rec, ident, bound); !v.Allowed {
		if !v.Pending || v.NewTicket {
			s.auditAdmitDenied(r, rec, ident, v)
		}
		s.oidcFail(w, r, rec.Name, v.Reason)
		return
	}
	cred, err := as.BindExternalUser(r.Context(), rec.ID, store.ExternalIdentity{
		Subject: ident.Subject, Username: ident.Username,
		DisplayName: ident.DisplayName, Email: ident.Email, Groups: ident.Groups,
	})
	if err != nil {
		slog.Error("OIDC 外部身份绑定失败", "源", rec.Name, "subject", ident.Subject, "err", err.Error())
		s.oidcFail(w, r, rec.Name, "账号绑定失败，请联系管理员")
		return
	}
	if !bound {
		s.auditExtUserCreated(r, rec, ident, cred.Account)
	}
	if accountBlocked(cred.Status) {
		s.auditAs(r, cred.Account, "auth", "OIDC 登录被拒（账号已"+statusZh[cred.Status]+"，源 "+rec.Name+"）", "deny")
		s.oidcFail(w, r, rec.Name, "账号已被"+statusZh[cred.Status])
		return
	}
	// 二次因子：与口令登录**同一个判定函数**——已注册 passkey 强制断言、
	// 策略抬升照样生效，新入口不开旁路。
	if resp, done := s.secondFactor(r, cred, loginCtx{Directory: rec.Kind}); done {
		if need, _ := resp["needWebauthn"].(bool); need {
			// mfa 票据（3 分钟、role=mfa、只能换一次断言）经 URL 交给门户的既有
			// webauthn 流程。它与交接票据同级：短命、单用途、当 Bearer 必被拒。
			t, _ := resp["ticket"].(string)
			s.oidcRedirect(w, r, url.Values{"oidcTicket": {t}, "oidcSrc": {rec.Name}})
			return
		}
		// TOTP 同款：mfa 票据经 URL 交给门户的验证码输入框（oidcTotp 参数区分因子）。
		if need, _ := resp["needTotp"].(bool); need {
			t, _ := resp["ticket"].(string)
			s.oidcRedirect(w, r, url.Values{"oidcTotp": {t}, "oidcSrc": {rec.Name}})
			return
		}
		reason, _ := resp["reason"].(string)
		if reason == "" {
			reason = "登录被认证策略拦截"
		}
		s.oidcFail(w, r, rec.Name, reason)
		return
	}
	// 认证完成：签 60s 单次交接票据，绝不把 8h 会话令牌放进 URL。
	s.auditAs(r, cred.Account, "auth", "OIDC 认证通过（源 "+rec.Name+"），签发登录交接票据", "ok")
	grant := s.keys.Sign(auth.Claims{
		Sub: cred.Account, Role: cred.Role, Name: cred.Account,
		Jti: auth.RandJTI(), Use: useOIDCGrant,
	}, oidcGrantTTL)
	s.oidcRedirect(w, r, url.Values{"oidcGrant": {grant}})
}

// handleOIDCSession 交接票据 → 会话令牌（POST，票据在请求体不进 URL/日志）。
func (s *Server) handleOIDCSession(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&b); err != nil || b.Ticket == "" {
		httpx.Error(w, http.StatusBadRequest, "缺少交接票据")
		return
	}
	c, err := s.keys.Verify(b.Ticket)
	if err != nil || c.Use != useOIDCGrant || c.Sub == "" || c.Jti == "" {
		httpx.Error(w, http.StatusForbidden, "交接票据无效或已过期")
		return
	}
	if !s.oidcFlow.grantOnce(c.Jti, oidcGrantTTL) {
		// 单次性是硬闸：票据在 URL 里出现过（浏览器历史/代理日志），重放必须失败。
		s.auditAs(r, c.Sub, "auth", "OIDC 交接票据重放被拒", "deny")
		httpx.Error(w, http.StatusForbidden, "交接票据已被使用")
		return
	}
	// 60s 窗口内账号状态可能刚被改：复查，别让"禁用前最后一刻发起的登录"漏进来。
	if u, blocked, err := s.blockedDirAccount(r.Context(), c.Sub); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "账号状态复查失败")
		return
	} else if blocked {
		s.auditAs(r, c.Sub, "auth", "OIDC 登录被拒（换取会话时账号已"+statusZh[u.Status]+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "账号已被"+statusZh[u.Status])
		return
	}
	s.noteLoginSuccess(r.Context(), c.Sub)
	s.auditAs(r, c.Sub, "auth", "OIDC 登录成功", "ok")
	tok := s.keys.Sign(auth.Claims{Sub: c.Sub, Role: c.Role, Name: c.Name}, tokenTTL)
	display := c.Name
	if u, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool {
		return normUser(du.Account) == normUser(c.Sub)
	}); err == nil && found {
		display = u.Name
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "token": tok, "displayName": display, "role": c.Role})
}

// oidcFail 统一的失败收尾：302 回门户登录页并带上人话原因。
func (s *Server) oidcFail(w http.ResponseWriter, r *http.Request, srcName, msg string) {
	s.oidcRedirect(w, r, url.Values{"oidcError": {msg}, "oidcSrc": {srcName}})
}

func (s *Server) oidcRedirect(w http.ResponseWriter, r *http.Request, q url.Values) {
	http.Redirect(w, r, portalLoginPath+"?"+q.Encode(), http.StatusFound)
}
