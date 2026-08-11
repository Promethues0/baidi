package webproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/auth"
	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/spa"
)

// ── 测试脚手架：在**测试里**造一把控制面密钥并签票 ──
//
// ★签发逻辑只存在于测试文件中，生产代码（gateway/internal/auth）依然没有 Sign。
// 把它抽进被编译进二进制的包里，就等于给被保护方发了钥匙。
type ctrlKey struct {
	priv ed25519.PrivateKey
	kid  string
	pub  []byte // PEM
}

func newCtrlKey(t *testing.T) ctrlKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return ctrlKey{
		priv: priv,
		kid:  base64.RawURLEncoding.EncodeToString(sum[:8]),
		pub:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	}
}

func (k ctrlKey) sign(c auth.Claims, ttl time.Duration) string {
	b64u := base64.RawURLEncoding
	now := time.Now()
	c.Iat = now.Unix()
	c.Exp = now.Add(ttl).Unix()
	hj, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": k.kid})
	pj, _ := json.Marshal(c)
	body := b64u.EncodeToString(hj) + "." + b64u.EncodeToString(pj)
	return body + "." + b64u.EncodeToString(ed25519.Sign(k.priv, []byte(body)))
}

func (k ctrlKey) verifier(t *testing.T) *auth.Verifier {
	t.Helper()
	p := filepath.Join(t.TempDir(), "web.pub")
	if err := os.WriteFile(p, k.pub, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifier(p, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// harness 一整套进程内环境：假后端 + 注册表 + L7 代理。
type harness struct {
	key      ctrlKey
	reg      *resource.Registry
	al       *spa.Allowlist
	srv      *httptest.Server
	backend  *httptest.Server
	lastXFF  string
	lastHost string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{key: newCtrlKey(t)}
	h.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.lastXFF = r.Header.Get("X-Forwarded-For")
		h.lastHost = r.Host
		switch r.URL.Path {
		case "/redir":
			w.Header().Set("Location", "http://"+r.Host+"/login?next=1")
			w.Header().Add("Set-Cookie", "sid=abc; Path=/; HttpOnly")
			w.WriteHeader(http.StatusFound)
		default:
			_, _ = w.Write([]byte("BACKEND-OK " + r.URL.Path))
		}
	}))
	t.Cleanup(h.backend.Close)

	bu, _ := url.Parse(h.backend.URL)
	h.reg = resource.New("")
	h.reg.Replace([]resource.Resource{
		{ID: "oa", Backend: bu.Host, AllowRoles: []string{"user", "admin"}},
		{ID: "git", Backend: bu.Host, AllowRoles: []string{"user", "admin"}},
	})
	h.al = spa.NewAllowlist()

	key, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	ws, err := New(Config{
		Verifier: h.key.verifier(t), Registry: h.reg, Allow: h.al,
		SessionKey: key, SessionTTL: 10 * time.Minute, TicketMaxTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = httptest.NewServer(ws.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

// enter 走一次「票据换 Cookie」，返回 Cookie 值。
func (h *harness) enter(t *testing.T, user, role, res string) string {
	t.Helper()
	tok := h.key.sign(auth.Claims{Sub: user, Role: role, Name: user, Jti: "j-" + res + user,
		Use: auth.UseWeb, Res: res}, 30*time.Second)
	resp := h.get(t, entryPath+"?t="+url.QueryEscape(tok), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("换票应回 302，得 %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("会话 Cookie 必须 HttpOnly+Secure+SameSite=Lax，得 %+v", c)
			}
			if c.Path != AppPrefix(res) {
				t.Fatalf("Cookie Path 必须限定到本应用前缀，得 %q", c.Path)
			}
			return c.Value
		}
	}
	t.Fatal("换票成功却没有下发会话 Cookie")
	return ""
}

// get 发一个不自动跟随重定向、不自动带 Cookie 的请求（Cookie 手工给，
// 以便验证**服务端**的绑定校验，而不是浏览器的 Path 规则）。
func (h *harness) get(t *testing.T, path, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.Header.Set("Cookie", CookieName+"="+cookie)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// ① 没有票据、没有 Cookie 时，L7 端点不给任何业务内容。
func TestNoTicketNoAccess(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, "/app/oa/", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("裸访问应 401，得 %d", resp.StatusCode)
	}
	bad := h.get(t, entryPath+"?t=not-a-token", "")
	defer bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("伪造票据应 401，得 %d", bad.StatusCode)
	}
}

// ② 票据换 Cookie，③ 经代理拿到后端真实内容。
func TestTicketExchangeAndProxy(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	resp := h.get(t, "/app/oa/hello", ck)
	defer resp.Body.Close()
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "BACKEND-OK /hello") {
		t.Fatalf("应拿到后端真实内容，得 %d %q", resp.StatusCode, body)
	}
	if h.lastHost != strings.TrimPrefix(h.backend.URL, "http://") {
		t.Fatalf("出站 Host 应为后端地址，得 %q", h.lastHost)
	}
}

// ④ 一个应用的 Cookie 绝不能访问另一个应用——即使该用户对两个资源都有权限。
// 这条断言的重点是**绑定**本身，不是授权：git 的 ACL 与 oa 完全相同。
func TestCrossAppCookieRejected(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	// 先证明该用户确实能访问 git（否则下面的 403 可能只是"没权限"）
	ok := h.get(t, "/app/git/x", h.enter(t, "zhangsan", "user", "git"))
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("前置条件：该用户对 git 应有权限，得 %d", ok.StatusCode)
	}
	resp := h.get(t, "/app/git/x", ck) // 拿 oa 的 Cookie 去开 git
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("★跨应用复用会话必须 403，得 %d", resp.StatusCode)
	}
}

// ⑤ 逐请求鉴权：撤销授权后，**同一个 Cookie 的下一个请求**就被拒。
// 这是"不要只在建会话时判一次"的直接证据。
func TestPerRequestReauthorization(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	if resp := h.get(t, "/app/oa/", ck); resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("撤权前应可访问，得 %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	bu, _ := url.Parse(h.backend.URL)
	for name, mutate := range map[string]func(){
		"授权收回": func() {
			h.reg.Replace([]resource.Resource{{ID: "oa", Backend: bu.Host, AllowUsers: []string{"someone-else"}}})
		},
		"风险降权否决": func() {
			h.reg.Replace([]resource.Resource{{ID: "oa", Backend: bu.Host,
				AllowRoles: []string{"user"}, DenyUsers: []string{"zhangsan"}}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutate()
			resp := h.get(t, "/app/oa/", ck)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("★策略变更后同一 Cookie 的下一个请求必须被拒，得 %d", resp.StatusCode)
			}
		})
	}
}

// 强制下线（控制面下发的封禁名单）对 L7 同样生效——否则"已下线"的账号
// 换条路径照样进得来，而管理台显示他已被切断。
func TestForcedLogoutBlocksWebSession(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	h.al.DenyUser("zhangsan", time.Now().Add(5*time.Minute))
	resp := h.get(t, "/app/oa/", ck)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("强制下线后 L7 必须拒绝，得 %d", resp.StatusCode)
	}
}

// ⑥ 进站伪造的来源头必须被剥掉，后端看到的是真实对端。
func TestInboundForwardedHeadersAreStripped(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app/oa/x", nil)
	req.Header.Set("Cookie", CookieName+"="+ck)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("Forwarded", "for=1.2.3.4")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if strings.Contains(h.lastXFF, "1.2.3.4") {
		t.Fatalf("★进站 XFF 必须被剥掉，后端却看到 %q", h.lastXFF)
	}
	if h.lastXFF == "" {
		t.Fatal("剥掉之后必须按真实对端重写，不能什么都不给后端")
	}
}

// use 语义闸（这一侧）：敲门令牌不得换出 Web 会话。
// 另一侧（敲门路径拒 use=web）由 spa 包的用例守着，两条必须成对存在。
func TestKnockTokenRejectedOnWebPath(t *testing.T) {
	h := newHarness(t)
	for name, c := range map[string]auth.Claims{
		"敲门令牌":    {Sub: "u", Role: "user", Name: "u", Jti: "j", Use: auth.UseKnock, Res: "oa"},
		"会话令牌":    {Sub: "u", Role: "user", Name: "u"},
		"未绑定资源":   {Sub: "u", Role: "user", Name: "u", Jti: "j", Use: auth.UseWeb},
		"网关身份":    {Sub: "gw", Role: "gateway", Name: "gw", Jti: "j", Use: auth.UseWeb, Res: "oa"},
		"MFA半程票据": {Sub: "u", Role: "mfa", Name: "u", Jti: "j", Use: auth.UseWeb, Res: "oa"},
	} {
		t.Run(name, func(t *testing.T) {
			tok := h.key.sign(c, 30*time.Second)
			resp := h.get(t, entryPath+"?t="+url.QueryEscape(tok), "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s 不得换出 Web 会话，得 %d", name, resp.StatusCode)
			}
		})
	}
}

// 票据寿命上界是纵深防御：控制面若把 TTL 放大，数据面仍然拒。
func TestOverlongTicketRejected(t *testing.T) {
	h := newHarness(t)
	tok := h.key.sign(auth.Claims{Sub: "u", Role: "user", Name: "u", Jti: "j",
		Use: auth.UseWeb, Res: "oa"}, 8*time.Hour)
	resp := h.get(t, entryPath+"?t="+url.QueryEscape(tok), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("超长票据必须被拒，得 %d", resp.StatusCode)
	}
}

// 后端的绝对跳转与 Set-Cookie 作用域都要收进本应用前缀。
func TestBackendRedirectAndCookieScoped(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	resp := h.get(t, "/app/oa/redir", ck)
	defer resp.Body.Close()
	if got := resp.Header.Get("Location"); got != "/app/oa/login?next=1" {
		t.Fatalf("绝对跳转应改写回本应用前缀，得 %q", got)
	}
	sc := resp.Header.Get("Set-Cookie")
	if !strings.Contains(sc, "Path=/app/oa/") {
		t.Fatalf("后端 Cookie 的 Path 应收进本应用前缀（否则会被送给别的应用），得 %q", sc)
	}
}

// 根相对静态资源靠 Referer 兜底成一次同源 302——它只产生重定向，
// 重定向后的请求照样要过 Cookie 与逐请求鉴权。
func TestRootRelativeAssetRedirect(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/static/app.css", nil)
	req.Header.Set("Referer", h.srv.URL+"/app/oa/index.html")
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/app/oa/static/app.css" {
		t.Fatalf("根相对静态资源应 302 进应用前缀，得 %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// 重定向后没有 Cookie 依然进不去（302 本身不放行任何东西）
	after := h.get(t, "/app/oa/static/app.css", "")
	defer after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("兜底重定向不得放行未认证请求，得 %d", after.StatusCode)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	b := make([]byte, 4096)
	n, _ := resp.Body.Read(b)
	return string(b[:n])
}
