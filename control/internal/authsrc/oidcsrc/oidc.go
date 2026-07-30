// Package oidcsrc 用标准库实现 OpenID Connect 的「授权码 + PKCE」登录，
// 是 authsrc.RedirectAuthenticator 的 OIDC 实现。
//
// # 为什么不引 OIDC 库
//
// OIDC 本体就是 HTTP + JSON + JWT 验签，没有任何需要复杂依赖的地方。而引库并不能
// 省掉审校验完整性的工夫——下面这些校验里**漏掉任何一条都是认证绕过**，引库之后
// 我们仍然得逐条确认库真的做了、且默认就开着：
//
//	· alg 白名单（拒 none、拒 HS*）      —— 见 idtoken.go 的 supportedAlgs
//	· iss / aud / azp / exp / iat / nbf   —— 见 checkClaims
//	· nonce 与会话一致                    —— 防重放的唯一手段
//	· state 与会话一致                    —— 防登录 CSRF（本包无从代劳，见 AuthURL）
//	· PKCE S256 推导正确                  —— 见 pkce.go
//	· 发现文档/JWKS 走 https，issuer 自洽  —— 见 discovery.go
//	· Subject 取 sub                      —— 见 identityFrom
//
// 自己写的好处是这些判据全部摆在明面上、可逐条打靶测试；坏处是要自己维护，
// 而这部分规范十年没变过，维护成本接近零。
//
// # 与项目内 internal/auth 的关系
//
// 刻意**不复用** internal/auth 的 JWT 代码：那套是白帝自己签自己验（HMAC / Ed25519，
// 密钥是我们自己的），信任模型是"对称的自证"；这里是**别人签、我们验**，密钥来自
// 对方的 JWKS，两者的密钥体系、算法集、校验项没有一处相同。硬凑到一起的结果会是
// 一个既要支持 HS256（我们自己的会话令牌）又要拒绝 HS256（外部 ID Token）的函数，
// 这种"同一份代码两套安全语义"正是算法混淆类漏洞的温床。
//
// # 调用方必须做的事
//
//	① 生成 state / nonce / codeVerifier（NewState/NewNonce/NewCodeVerifier）并**存进服务端会话**
//	② 跳转 AuthURL(state, nonce, codeVerifier)
//	③ 回调时先比对 state，再用 code + 会话里的 codeVerifier/nonce 调 Exchange
//
// ②③ 之间的 state 比对本包做不了（它不持有会话），漏掉即登录 CSRF：
// 攻击者把自己的授权码塞给受害者的浏览器，受害者会在不知情下登录到**攻击者的账号**，
// 之后在该账号里的一切操作（上传的文件、填的表单）都落在攻击者手里。
package oidcsrc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/authsrc"
)

// 默认值。全部可由 Config 覆盖。
const (
	defaultTimeout        = 10 * time.Second
	defaultClockSkew      = 2 * time.Minute
	defaultDiscoveryTTL   = 1 * time.Hour
	defaultJWKSTTL        = 1 * time.Hour
	defaultJWKSMinRefresh = 1 * time.Minute
	defaultMaxIDTokenAge  = 15 * time.Minute
	// maxBodyBytes 限制读取对端响应的字节数。对端是"别人家的服务"，
	// 不设上限的话一个恶意/故障的 IdP 能靠一条永不结束的响应把控制面内存吃干。
	maxBodyBytes = 1 << 20 // 1 MiB
)

// Config 一个 OIDC 认证源的配置。
type Config struct {
	// Issuer 签发者 URL，如 https://login.example.com/realms/corp。
	// 发现文档地址由它拼出（{issuer}/.well-known/openid-configuration）。
	Issuer string
	// ClientID 本应用在 IdP 上的客户端标识，同时是 ID Token 的 aud 期望值。
	ClientID string
	// ClientSecret 机密客户端的密钥。留空 = 公开客户端（纯 PKCE，不做客户端认证）。
	ClientSecret string
	// RedirectURI 回调地址，必须与 IdP 上登记的完全一致（含大小写与尾斜杠）。
	RedirectURI string
	// Scopes 申请的 scope。openid 会被强制补上（缺了它 IdP 根本不返回 ID Token，
	// 而错误通常只是一句 invalid_scope，指不到"少了 openid"）。
	Scopes []string

	// SigningAlgs 接受的 ID Token 签名算法，留空用 defaultAlgs。
	// **只能收窄不能扩宽**：不在内建表里的值会在 New 时报错（内建表刻意不含 HS*/none）。
	SigningAlgs []string

	// 属性映射。留空各取默认：preferred_username / name / email / groups。
	UsernameClaim    string
	DisplayNameClaim string
	EmailClaim       string
	GroupsClaim      string

	// UseUserInfo 是否调 UserInfo 端点补全属性。
	// 有些 IdP（如精简配置的 Keycloak）不把 groups/email 放进 ID Token，只在 UserInfo 里给。
	UseUserInfo bool

	// TokenAuthMethod 令牌端点的客户端认证方式：
	// 留空 = 自动（有 secret 时按发现文档挑 basic/post，无 secret 用 none）。
	// 可显式指定 client_secret_basic / client_secret_post / none。
	TokenAuthMethod string

	// AllowInsecureHTTP 允许 http 端点。**仅供本机联调**，生产禁用：
	// 明文下 JWKS 可被替换，所有验签都会用攻击者的公钥"验成功"。
	AllowInsecureHTTP bool

	ClockSkew      time.Duration // 时钟偏移容忍，默认 2 分钟
	MaxIDTokenAge  time.Duration // ID Token 允许的最大签发年龄，默认 15 分钟；0 由默认值填充，负数=不限
	DiscoveryTTL   time.Duration // 发现文档缓存 TTL，默认 1 小时
	JWKSTTL        time.Duration // JWKS 主动刷新周期，默认 1 小时
	JWKSMinRefresh time.Duration // kid 未命中时的最小重拉间隔，默认 1 分钟

	// HTTPClient 自定义 HTTP 客户端（测试注入 httptest 的 TLS 客户端，或生产注入企业代理/自签 CA）。
	HTTPClient *http.Client
	// Now 注入时钟，仅测试用。留空取 time.Now。
	Now func() time.Time
}

// Provider 一个 OIDC 认证源。并发安全，可长期持有（内部缓存发现文档与 JWKS）。
type Provider struct {
	cfg    Config
	algs   []string
	client *http.Client

	disc discoveryCache
	jwks jwksCache
}

// 编译期确认实现了契约接口——签名若与 authsrc 漂移，这行会先炸，而不是等到运行时。
var _ authsrc.RedirectAuthenticator = (*Provider)(nil)

// New 校验配置并构造 Provider。**不做任何网络访问**：控制台保存认证源配置时不该
// 因为 IdP 一时不可达就存不下来；连通性用 Probe 单独检查（对应「测试连接」按钮）。
func New(cfg Config) (*Provider, error) {
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.RedirectURI = strings.TrimSpace(cfg.RedirectURI)

	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURI == "" {
		return nil, errNotConfigured("OIDC 认证源缺少 issuer / client_id / redirect_uri")
	}
	p := &Provider{cfg: cfg}
	if err := p.checkHTTPS("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	if _, err := url.Parse(cfg.RedirectURI); err != nil {
		return nil, errNotConfigured("redirect_uri=%q 不是合法 URL", cfg.RedirectURI)
	}
	switch cfg.TokenAuthMethod {
	case "", "client_secret_basic", "client_secret_post", "none":
	default:
		return nil, errNotConfigured("不支持的令牌端点认证方式 %q", cfg.TokenAuthMethod)
	}

	// 算法白名单：配置项必须落在内建表内。
	// ★ 这一步是"配置只能收窄"的执行点。若允许配置写入任意算法名，运维在排障时
	// 一句"加上 HS256 试试"就能把算法混淆的大门重新打开——而它看起来只是改了个配置。
	p.algs = defaultAlgs
	if len(cfg.SigningAlgs) > 0 {
		for _, a := range cfg.SigningAlgs {
			if _, ok := supportedAlgs[a]; !ok {
				return nil, errNotConfigured("签名算法 %q 不被支持（对称算法 HS* 与 none 已被刻意排除）", a)
			}
		}
		p.algs = append([]string(nil), cfg.SigningAlgs...)
	}

	// 默认值填充
	if p.cfg.ClockSkew <= 0 {
		p.cfg.ClockSkew = defaultClockSkew
	}
	if p.cfg.MaxIDTokenAge == 0 {
		p.cfg.MaxIDTokenAge = defaultMaxIDTokenAge
	} else if p.cfg.MaxIDTokenAge < 0 {
		p.cfg.MaxIDTokenAge = 0 // 负数 = 显式关闭年龄上限
	}
	p.disc.ttl = orDur(cfg.DiscoveryTTL, defaultDiscoveryTTL)
	p.jwks.ttl = orDur(cfg.JWKSTTL, defaultJWKSTTL)
	// JWKSMinRefresh 允许显式设为 0（测试里要立刻自愈），故用 < 0 之外的判断：
	// 只有"完全没填"（零值）才套默认。这里用 -1 表示"不限流"不现实，故：
	// 零值 → 默认 1 分钟；负值 → 0（不限流，仅测试用）。
	switch {
	case cfg.JWKSMinRefresh == 0:
		p.jwks.minRefresh = defaultJWKSMinRefresh
	case cfg.JWKSMinRefresh < 0:
		p.jwks.minRefresh = 0
	default:
		p.jwks.minRefresh = cfg.JWKSMinRefresh
	}

	p.client = cfg.HTTPClient
	if p.client == nil {
		p.client = &http.Client{Timeout: defaultTimeout}
	}
	return p, nil
}

func (p *Provider) now() time.Time {
	if p.cfg.Now != nil {
		return p.cfg.Now()
	}
	return time.Now()
}

// AuthURL 构造授权端点跳转地址（response_type=code + PKCE S256）。
//
// 三个入参**都必须**由调用方随机生成并与服务端会话绑定：
//
//	state        —— 回调时调用方**必须**自行比对（本包不持有会话，代劳不了）。
//	                不比对 = 登录 CSRF：受害者会被静默登入攻击者的账号。
//	nonce        —— 原样传给 Exchange，由本包比对。不比对 = ID Token 可重放。
//	codeVerifier —— 原样传给 Exchange。挑战值在这里推导。
//
// 需要发现文档（拿授权端点），故可能触发一次网络请求；契约签名里没有 ctx，
// 这里用带超时的 Background——AuthURL 由 HTTP handler 同步调用，超时必须有界。
func (p *Provider) AuthURL(state, nonce, codeVerifier string) (string, error) {
	if strings.TrimSpace(state) == "" {
		return "", errNotConfigured("state 为空：登录 CSRF 防护依赖它，拒绝构造无 state 的授权地址")
	}
	if strings.TrimSpace(nonce) == "" {
		return "", errNotConfigured("nonce 为空：ID Token 重放防护依赖它，拒绝构造无 nonce 的授权地址")
	}
	if !validCodeVerifier(codeVerifier) {
		return "", errNotConfigured("code_verifier 不符合 RFC 7636（需 43~128 位 unreserved 字符），请用 NewCodeVerifier 生成")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	doc, err := p.discover(ctx)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", errNotConfigured("authorization_endpoint=%q 不是合法 URL", doc.AuthorizationEndpoint)
	}
	// 保留端点自带的查询串（部分 IdP 的授权地址天生带参数），只追加不覆盖。
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("scope", strings.Join(p.scopes(), " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", CodeChallengeS256(codeVerifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// scopes 返回最终 scope 列表，强制包含 openid。
func (p *Provider) scopes() []string {
	out := []string{"openid"}
	seen := map[string]bool{"openid": true}
	src := p.cfg.Scopes
	if len(src) == 0 {
		src = []string{"profile", "email"}
	}
	for _, s := range src {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Exchange 用授权码换令牌、校验 ID Token，并返回身份。
//
// nonce 与 codeVerifier 必须是本次登录会话在 AuthURL 时用的那一对。
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (authsrc.Identity, error) {
	var zero authsrc.Identity
	if strings.TrimSpace(code) == "" {
		return zero, errInvalidToken("授权码为空")
	}
	if !validCodeVerifier(codeVerifier) {
		return zero, errNotConfigured("code_verifier 不符合 RFC 7636：会话里没有正确保存 AuthURL 时生成的 verifier")
	}
	// ★ nonce 为空**必须硬失败**，不能"没给就跳过校验"。
	// "缺省即跳过"是这类校验最常见的死法：调用方某个分支忘了带 nonce，
	// 流程照样跑通、登录照样成功，防重放就此静默失效，而且没有任何迹象。
	if strings.TrimSpace(nonce) == "" {
		return zero, errNotConfigured("nonce 为空：本实现拒绝在无重放防护的情况下完成登录")
	}

	doc, err := p.discover(ctx)
	if err != nil {
		return zero, err
	}
	tok, err := p.tokenRequest(ctx, doc, code, codeVerifier)
	if err != nil {
		return zero, err
	}
	if tok.IDToken == "" {
		// 拿不到 ID Token 通常是 scope 少了 openid，或客户端在 IdP 上被配成了纯 OAuth2。
		return zero, errUnavailable("令牌端点未返回 id_token（请确认 scope 含 openid、且该客户端在 IdP 上启用了 OIDC）")
	}

	claims, all, err := p.verifyIDToken(ctx, tok.IDToken, nonce)
	if err != nil {
		return zero, err
	}
	id := p.identityFrom(claims.Sub, all)

	// UserInfo 只做**属性补全**，身份判定已经由 ID Token 完成。
	if p.cfg.UseUserInfo && doc.UserInfoEndpoint != "" && tok.AccessToken != "" {
		if ui, err := p.userInfo(ctx, doc.UserInfoEndpoint, tok.AccessToken); err == nil {
			// ★ sub 必须与 ID Token 一致，不一致要**硬失败**。
			// UserInfo 是拿 access token 取的，若 access token 与 ID Token 来自不同主体
			//（令牌替换、或我们自己把两次登录的令牌串了），补全出来的邮箱/组就会属于另一个人——
			// 结果是"以 A 的身份登录、却带着 B 的属性和组"，权限判定直接错乱。
			if s, _ := ui["sub"].(string); s != claims.Sub {
				return zero, errInvalidToken("UserInfo 的 sub 与 ID Token 不一致（疑似令牌替换）")
			}
			id = mergeIdentity(id, p.identityFrom(claims.Sub, ui))
		}
		// 取不到就算了：ID Token 已经足以确定身份，为了几个展示属性把登录整体判失败
		// 不成比例。真正不能容忍的是上面那条 sub 不一致——那是安全问题，不是可用性问题。
	}
	return id.Normalized(), nil
}

// Probe 连通性自检：强制重拉发现文档与 JWKS，并确认至少有一把可用公钥。
// 不校验任何用户凭据（契约要求），对应控制台「测试连接」。
func (p *Provider) Probe(ctx context.Context) error {
	doc, err := p.fetchDiscovery(ctx)
	if err != nil {
		return err
	}
	// 刷新缓存，让「测试连接」顺带把后续登录要用的东西预热好。
	p.disc.mu.Lock()
	p.disc.doc, p.disc.fetchedAt = doc, p.now()
	p.disc.mu.Unlock()

	keys, err := p.fetchJWKS(ctx)
	if err != nil {
		return err
	}
	p.jwks.mu.Lock()
	p.jwks.keys, p.jwks.fetchedAt = keys, p.now()
	p.jwks.mu.Unlock()

	// 我们接受的算法与 IdP 声称支持的算法必须有交集，否则「测试连接」通过、
	// 真登录时每一枚令牌都会被算法白名单拒掉——那种错法非常难归因。
	if len(doc.IDTokenSigningAlgValuesSupported) > 0 {
		ok := false
		for _, a := range doc.IDTokenSigningAlgValuesSupported {
			if p.algAllowed(a) {
				ok = true
				break
			}
		}
		if !ok {
			return errNotConfigured("IdP 声称的 ID Token 签名算法 %v 与本实现接受的 %v 无交集（注意对称算法 HS* 已被刻意排除）",
				doc.IDTokenSigningAlgValuesSupported, p.algs)
		}
	}
	return nil
}

// ── 令牌端点 ──────────────────────────────────────────────────────────────

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// oauthError 令牌端点的标准错误体（RFC 6749 §5.2）。
type oauthError struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

func (p *Provider) tokenRequest(ctx context.Context, doc *discoveryDoc, code, verifier string) (tokenResponse, error) {
	var out tokenResponse

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	// redirect_uri 必须与授权请求时**完全一致**，否则 IdP 回 invalid_grant。
	// 这是规范要求的绑定校验（防止授权码被换到另一个回调地址上）。
	form.Set("redirect_uri", p.cfg.RedirectURI)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("code_verifier", verifier)

	method := p.authMethod(doc)
	if method == "client_secret_post" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return out, errUnavailable("构造令牌请求失败：%v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if method == "client_secret_basic" {
		// ★ RFC 6749 §2.3.1 要求 basic 认证里的 id/secret 先做 **form-urlencode** 再拼。
		// 直接拼原文在 secret 含 '+' / '/' / 中文时会认证失败，而 IdP 只会回一句
		// invalid_client——看起来像"密钥填错了"，实际是编码问题，能耗掉一整天。
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return out, errUnavailable("请求令牌端点失败：%v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return out, errUnavailable("读取令牌端点响应失败：%v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return out, tokenErrorOf(resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, errUnavailable("令牌端点响应不是合法 JSON")
	}
	// token_type 规范上必须是 Bearer（大小写不敏感）。空值放行：确有 IdP 不下发该字段，
	// 而我们并不用它去调受保护资源，严格拒绝只会平添接不上的 IdP。
	if tt := strings.ToLower(strings.TrimSpace(out.TokenType)); tt != "" && tt != "bearer" {
		return out, errUnavailable("令牌端点返回了不支持的 token_type=%q", out.TokenType)
	}
	return out, nil
}

// authMethod 决定令牌端点的客户端认证方式。
func (p *Provider) authMethod(doc *discoveryDoc) string {
	if p.cfg.TokenAuthMethod != "" {
		return p.cfg.TokenAuthMethod
	}
	if p.cfg.ClientSecret == "" {
		return "none" // 公开客户端：安全性全靠 PKCE
	}
	// 发现文档明确只支持 post 时用 post，其余一律 basic（规范要求所有 IdP 都支持 basic）。
	if len(doc.TokenEndpointAuthMethodsSupported) > 0 &&
		!contains(doc.TokenEndpointAuthMethodsSupported, "client_secret_basic") &&
		contains(doc.TokenEndpointAuthMethodsSupported, "client_secret_post") {
		return "client_secret_post"
	}
	return "client_secret_basic"
}

// tokenErrorOf 把令牌端点的错误映射到 authsrc 的三类错误。
//
// ★ 这个映射就是契约里"三类错误必须区分"的落点，映射错了会直接误导排障方向：
//   - invalid_grant  → 凭据问题：授权码过期/被用过/**PKCE 校验失败**/redirect_uri 不符。
//     这是用户侧可重试的（重新点一次登录），不该报"认证源不可用"让运维去查网络。
//   - invalid_client → 配置问题：client_id/secret 不对。用户重试一万次也没用，
//     报成"用户名或密码错误"会让所有人往错的方向查。
//   - 5xx / 其他     → 源不可用。
func tokenErrorOf(status int, body []byte) error {
	var oe oauthError
	_ = json.Unmarshal(body, &oe) // 解不出就按空处理，下面按状态码兜底
	detail := strings.TrimSpace(oe.Desc)
	if detail == "" {
		detail = strings.TrimSpace(string(body))
	}
	if len(detail) > 300 { // 别把 IdP 的整页 HTML 错误页灌进日志
		detail = detail[:300] + "…"
	}

	switch oe.Err {
	case "invalid_grant":
		return fmt.Errorf("%w（授权码无效/已过期/已使用，或 PKCE 校验失败：%s）", authsrc.ErrInvalidCredentials, detail)
	case "invalid_client", "unauthorized_client", "invalid_request", "unsupported_grant_type", "invalid_scope":
		return errNotConfigured("令牌端点拒绝了本客户端配置（error=%s）：%s", oe.Err, detail)
	case "access_denied":
		// 用户在 IdP 页面上点了"拒绝"。这不是凭据错，但对调用方而言等价于"登录没成功"。
		return fmt.Errorf("%w（用户在身份提供方处拒绝了授权）", authsrc.ErrInvalidCredentials)
	}
	return errUnavailable("令牌端点返回 HTTP %d（error=%s）：%s", status, oe.Err, detail)
}

// ── UserInfo ─────────────────────────────────────────────────────────────

func (p *Provider) userInfo(ctx context.Context, endpoint, accessToken string) (map[string]any, error) {
	out := map[string]any{}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+accessToken)
	if err := p.getJSON(ctx, endpoint, hdr, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── 身份映射 ──────────────────────────────────────────────────────────────

// identityFrom 从声明集里取出身份。
//
// ★ Subject 恒取 sub，绝不取 email / preferred_username。
// 后两者在多数 IdP 上**可变**：用户改个邮箱、管理员改个登录名，账号映射就断了——
// 好一点的结果是"老用户登进来变成新用户"（历史权限与审计全部丢失），
// 坏的结果是这个被腾出来的旧邮箱/旧用户名被分配给了**另一个人**，
// 于是新人以老人的身份登了进来，而日志里一切正常。sub 是 IdP 承诺不变且不复用的。
func (p *Provider) identityFrom(sub string, claims map[string]any) authsrc.Identity {
	id := authsrc.Identity{Subject: sub}

	id.Username = strClaim(claims, orStr(p.cfg.UsernameClaim, "preferred_username"))
	if id.Username == "" && p.cfg.UsernameClaim == "" {
		// 只有在用默认映射时才做回退链；管理员显式指定了字段却取不到值，
		// 应当暴露成"用户名为空"而不是悄悄换个字段——否则配置错误永远发现不了。
		if e := strClaim(claims, "email"); e != "" {
			id.Username = e
		} else {
			id.Username = sub
		}
	}
	id.DisplayName = strClaim(claims, orStr(p.cfg.DisplayNameClaim, "name"))
	id.Email = strClaim(claims, orStr(p.cfg.EmailClaim, "email"))
	id.Groups = strsClaim(claims, orStr(p.cfg.GroupsClaim, "groups"))
	return id
}

// mergeIdentity 用 extra 补 base 里缺的字段（base 优先，因为它来自已验签的 ID Token）。
func mergeIdentity(base, extra authsrc.Identity) authsrc.Identity {
	if base.Username == "" || base.Username == base.Subject {
		if extra.Username != "" {
			base.Username = extra.Username
		}
	}
	if base.DisplayName == "" {
		base.DisplayName = extra.DisplayName
	}
	if base.Email == "" {
		base.Email = extra.Email
	}
	if len(base.Groups) == 0 {
		base.Groups = extra.Groups
	}
	return base
}

func strClaim(m map[string]any, key string) string {
	if key == "" {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case bool:
		return fmt.Sprintf("%t", v)
	case float64:
		// 有 IdP 把数字型 uid 直接当用户名下发。%v 会打成 1.234e+06，故按整数格式化。
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// strsClaim 取字符串数组型声明。兼容单值字符串（部分 IdP 只有一个组时不下发数组）。
func strsClaim(m map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	switch v := m[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, it := range v {
			if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{strings.TrimSpace(v)}
	}
	return nil
}

// ── HTTP 小工具 ───────────────────────────────────────────────────────────

// getJSON 发一个 GET 并解析 JSON 响应。所有对 IdP 的读取都走它，好处是限流、
// 状态码判断、body 上限只有一处实现，不会漏。
func (p *Provider) getJSON(ctx context.Context, rawURL string, hdr http.Header, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return errUnavailable("构造请求失败（%s）：%v", rawURL, err)
	}
	req.Header.Set("Accept", "application/json")
	for k, vals := range hdr {
		for _, val := range vals {
			req.Header.Add(k, val)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return errUnavailable("请求 %s 失败：%v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return errUnavailable("读取 %s 响应失败：%v", rawURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		return errUnavailable("%s 返回 HTTP %d", rawURL, resp.StatusCode)
	}
	// UserInfo 允许返回 application/jwt（签名的 UserInfo）。本实现不支持那种形态——
	// 与其把它当 JSON 解出一堆空字段（表现为"属性补全没生效"，无任何报错），
	// 不如明确报出来。ID Token 已经足以确定身份，缺的只是补全，故这条错误在
	// Exchange 里是被容忍的（见调用处）。
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err == nil && mt == "application/jwt" {
			return errUnavailable("%s 返回了签名形式的 application/jwt，本实现只支持 JSON 形式", rawURL)
		}
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errUnavailable("%s 响应不是合法 JSON", rawURL)
	}
	return nil
}

// ── 错误构造 ──────────────────────────────────────────────────────────────

// errInvalidToken 归入 ErrInvalidCredentials：从调用方视角，一枚过不了校验的 ID Token
// 与一个错的密码是同一类结果——本次登录不成立，且**不该**被呈现成"认证源故障"
// （那会让用户以为过一会儿重试就好，也会让运维去查根本没问题的网络）。
// 具体原因保留在错误文案里供日志归因，但不应原样回给终端用户。
func errInvalidToken(format string, a ...any) error {
	return fmt.Errorf("%w（%s）", authsrc.ErrInvalidCredentials, fmt.Sprintf(format, a...))
}

func errUnavailable(format string, a ...any) error {
	return fmt.Errorf("%w：%s", authsrc.ErrSourceUnavailable, fmt.Sprintf(format, a...))
}

func errNotConfigured(format string, a ...any) error {
	return fmt.Errorf("%w：%s", authsrc.ErrNotConfigured, fmt.Sprintf(format, a...))
}

func orStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
