package oidcsrc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// 进程内 mock OIDC 提供方：发现文档 + JWKS + 令牌端点 + UserInfo，
// 用**真实** RSA/EC 私钥签 ID Token。
//
// 为什么一定要做真实往返而不是打桩 verifyIDToken：本包的价值全在"每一条校验都真的成立"，
// 而打桩测试恰恰会把被测代码替换掉。只有让真令牌走完 发现→JWKS→换码→验签→校验声明
// 这条全链路，"alg=none 被拒""kid 轮换能自愈""PKCE 不匹配失败"这些断言才有意义。

// ── 共享测试密钥 ─────────────────────────────────────────────────────────
// RSA-2048 生成一次约上百毫秒，每个用例都生成会让整个包的测试慢一个量级，
// 故进程内只生成一次共享。rotatedRSA 专供"密钥轮换"用例。
var (
	keyOnce    sync.Once
	testRSA    *rsa.PrivateKey
	rotatedRSA *rsa.PrivateKey
	testEC     *ecdsa.PrivateKey
)

func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if testRSA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if rotatedRSA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if testEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
	})
	return testRSA, rotatedRSA, testEC
}

// ── mock 提供方 ──────────────────────────────────────────────────────────

type mockCode struct {
	challenge   string
	nonce       string
	redirectURI string
}

type mockIDP struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex

	rsaKey *rsa.PrivateKey
	rsaKid string
	ecKey  *ecdsa.PrivateKey
	ecKid  string

	clientID     string
	clientSecret string

	codes map[string]*mockCode

	jwksHits      int
	discoveryHits int

	// ── 测试钩子（全部通过 mu 保护，用例可在流程中途改）──
	signAlg        string         // RS256(默认) / ES256 / HS256 / none
	kidOverride    string         // 令牌头写死的 kid（用于制造"JWKS 里没有这把键"）
	claimOverride  map[string]any // 覆盖/追加 ID Token 声明
	dropClaims     []string       // 删除某些声明
	docIssuer      string         // 发现文档里的 issuer（默认 = srv.URL）
	pkceMethods    []string       // code_challenge_methods_supported（nil = 不下发该字段）
	signingAlgsAdv []string       // id_token_signing_alg_values_supported
	userinfo       map[string]any
	userinfoStatus int
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	rsaKey, _, ecKey := testKeys(t)
	m := &mockIDP{
		t:              t,
		rsaKey:         rsaKey,
		rsaKid:         "rsa-1",
		ecKey:          ecKey,
		ecKid:          "ec-1",
		clientID:       "baidi-console",
		clientSecret:   "s3cr3t+with/special",
		codes:          map[string]*mockCode{},
		signAlg:        "RS256",
		signingAlgsAdv: []string{"RS256", "ES256"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/userinfo", m.handleUserInfo)
	// TLS 服务端：本包硬性要求 https，用明文 httptest.NewServer 会被 checkHTTPS 挡掉，
	// 而那正是我们希望保留的行为，所以测试也得跑在真 TLS 上。
	m.srv = httptest.NewTLSServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockIDP) issuer() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.docIssuer != "" {
		return m.docIssuer
	}
	return m.srv.URL
}

// config 返回一份指向本 mock 的可用配置。
func (m *mockIDP) config() Config {
	return Config{
		Issuer:       m.srv.URL,
		ClientID:     m.clientID,
		ClientSecret: m.clientSecret,
		RedirectURI:  "https://console.example.com/api/v1/auth/oidc/callback",
		HTTPClient:   m.srv.Client(), // 信任 httptest 的自签 CA
		// 测试要能立刻观察轮换自愈，故关掉被动刷新限流（负值 = 不限流，见 New）。
		JWKSMinRefresh: -1,
	}
}

func (m *mockIDP) set(f func(*mockIDP)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

func (m *mockIDP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.discoveryHits++
	doc := map[string]any{
		"issuer":                                m.issuerLocked(),
		"authorization_endpoint":                m.srv.URL + "/authorize",
		"token_endpoint":                        m.srv.URL + "/token",
		"userinfo_endpoint":                     m.srv.URL + "/userinfo",
		"jwks_uri":                              m.srv.URL + "/jwks",
		"id_token_signing_alg_values_supported": m.signingAlgsAdv,
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	}
	if m.pkceMethods != nil {
		doc["code_challenge_methods_supported"] = m.pkceMethods
	}
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, doc)
}

func (m *mockIDP) issuerLocked() string {
	if m.docIssuer != "" {
		return m.docIssuer
	}
	return m.srv.URL
}

func (m *mockIDP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.jwksHits++
	keys := []map[string]any{
		rsaJWK(m.rsaKid, &m.rsaKey.PublicKey),
		ecJWK(m.ecKid, &m.ecKey.PublicKey),
	}
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// authorize 模拟"用户在 IdP 上完成登录并同意授权"这一步：
// 校验授权请求的各项参数，登记 code_challenge/nonce，返回授权码与回带的 state。
func (m *mockIDP) authorize(rawAuthURL string) (code, state string) {
	m.t.Helper()
	u, err := url.Parse(rawAuthURL)
	if err != nil {
		m.t.Fatalf("授权地址不是合法 URL：%v", err)
	}
	q := u.Query()
	if got := q.Get("response_type"); got != "code" {
		m.t.Fatalf("response_type=%q，期望 code", got)
	}
	if got := q.Get("client_id"); got != m.clientID {
		m.t.Fatalf("client_id=%q，期望 %q", got, m.clientID)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		m.t.Fatalf("code_challenge_method=%q，期望 S256（plain 等于没有 PKCE）", got)
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		m.t.Fatalf("scope=%q 缺少 openid", q.Get("scope"))
	}
	if q.Get("nonce") == "" || q.Get("state") == "" || q.Get("code_challenge") == "" {
		m.t.Fatalf("授权地址缺少 nonce/state/code_challenge：%s", u.RawQuery)
	}
	code = "code-" + q.Get("state")
	m.mu.Lock()
	m.codes[code] = &mockCode{
		challenge:   q.Get("code_challenge"),
		nonce:       q.Get("nonce"),
		redirectURI: q.Get("redirect_uri"),
	}
	m.mu.Unlock()
	return code, q.Get("state")
}

func (m *mockIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "表单解析失败")
		return
	}
	// 客户端认证：basic（值需 form-urldecode）或 post。
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
	}
	if id != m.clientID || secret != m.clientSecret {
		oauthErr(w, http.StatusUnauthorized, "invalid_client", "客户端认证失败")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}

	m.mu.Lock()
	c := m.codes[r.Form.Get("code")]
	delete(m.codes, r.Form.Get("code")) // 授权码一次性
	m.mu.Unlock()
	if c == nil {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "授权码无效或已使用")
		return
	}
	if c.redirectURI != r.Form.Get("redirect_uri") {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "redirect_uri 不一致")
		return
	}
	// 真做 PKCE 校验：S256(verifier) 必须等于登记的挑战。
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	idToken := m.signIDToken(c.nonce)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at-" + c.nonce,
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func (m *mockIDP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	body, status := m.userinfo, m.userinfoStatus
	m.mu.Unlock()
	if status != 0 && status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if body == nil {
		body = map[string]any{"sub": "u-1001"}
	}
	writeJSON(w, http.StatusOK, body)
}

// signIDToken 按当前 signAlg 签一枚 ID Token。
func (m *mockIDP) signIDToken(nonce string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	claims := map[string]any{
		"iss":                m.issuerLocked(),
		"sub":                "u-1001",
		"aud":                m.clientID,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"nonce":              nonce,
		"preferred_username": "zhangsan",
		"name":               "张三",
		"email":              "ZhangSan@Corp.Example",
		"groups":             []string{"研发中心", "运维组"},
	}
	for k, v := range m.claimOverride {
		claims[k] = v
	}
	for _, k := range m.dropClaims {
		delete(claims, k)
	}

	hdr := map[string]any{"typ": "JWT"}
	var (
		signer func(signingInput string) []byte
		alg    = m.signAlg
	)
	switch alg {
	case "none":
		hdr["alg"] = "none"
		signer = func(string) []byte { return nil }
	case "HS256":
		// ★ 攻击者视角：拿双方都知道的 client_secret 当 HMAC 密钥伪造 ID Token。
		hdr["alg"] = "HS256"
		hdr["kid"] = m.rsaKid
		signer = func(in string) []byte {
			mac := hmac.New(sha256.New, []byte(m.clientSecret))
			mac.Write([]byte(in))
			return mac.Sum(nil)
		}
	case "ES256":
		hdr["alg"] = "ES256"
		hdr["kid"] = m.ecKid
		signer = func(in string) []byte {
			sum := sha256.Sum256([]byte(in))
			r, s, err := ecdsa.Sign(rand.Reader, m.ecKey, sum[:])
			if err != nil {
				m.t.Fatalf("ES256 签名失败：%v", err)
			}
			out := make([]byte, 64)
			r.FillBytes(out[:32])
			s.FillBytes(out[32:])
			return out
		}
	default: // RS256
		hdr["alg"] = "RS256"
		hdr["kid"] = m.rsaKid
		signer = func(in string) []byte {
			sum := sha256.Sum256([]byte(in))
			sig, err := rsa.SignPKCS1v15(rand.Reader, m.rsaKey, crypto.SHA256, sum[:])
			if err != nil {
				m.t.Fatalf("RS256 签名失败：%v", err)
			}
			return sig
		}
	}
	if m.kidOverride != "" {
		hdr["kid"] = m.kidOverride
	}

	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	return in + "." + base64.RawURLEncoding.EncodeToString(signer(in))
}

// ── JWK 编码小工具 ───────────────────────────────────────────────────────

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(kid string, pub *ecdsa.PublicKey) map[string]any {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[string]any{
		"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]any{"error": code, "error_description": desc})
}
