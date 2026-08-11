package webproxy

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	ws       *Server
	srv      *httptest.Server
	backend  *httptest.Server
	lastXFF  string
	lastHost string
	lastReq  *http.Request // 后端**实际收到**的那个请求（头部断言用）
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

// newHarnessWith 同上，但允许改装配参数（可信代理、对外主机名、网关 id…）。
func newHarnessWith(t *testing.T, tweak func(*Config)) *harness {
	t.Helper()
	h := &harness{key: newCtrlKey(t)}
	h.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.lastXFF = r.Header.Get("X-Forwarded-For")
		h.lastHost = r.Host
		h.lastReq = r.Clone(r.Context())
		switch r.URL.Path {
		case "/redir":
			w.Header().Set("Location", "http://"+r.Host+"/login?next=1")
			w.Header().Add("Set-Cookie", "sid=abc; Path=/; HttpOnly")
			w.WriteHeader(http.StatusFound)
		case "/hostcookie":
			// 现代框架很常见的形态（Django SESSION_COOKIE_NAME='__Host-sessionid' 等）
			w.Header().Add("Set-Cookie", "__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
			w.WriteHeader(http.StatusOK)
		case "/echo-cookie":
			_, _ = w.Write([]byte("COOKIE:" + r.Header.Get("Cookie")))
		case "/exact":
			// 长度**恰好等于**上界的响应体：cappedBody 的差一在这里暴露
			_, _ = w.Write(make([]byte, exactBodySize))
		case "/upgrade":
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			c, buf, err := hj.Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = buf.Flush()
			io.Copy(io.Discard, c) //nolint:errcheck // 保持连接直到某一端关闭
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
	cfg := Config{
		Verifier: h.key.verifier(t), Registry: h.reg, Allow: h.al,
		SessionKey: key, SessionTTL: 10 * time.Minute, TicketMaxTTL: time.Minute,
		GatewayID: "gw-a",
	}
	if tweak != nil {
		tweak(&cfg)
	}
	ws, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.ws = ws
	// ★与 Serve 装同一个 ConnContext：没有它，已升级连接进不了可切断台账，
	// handleAny 会（正确地）拒绝升级——测试环境也必须复现真实装配。
	srv := httptest.NewUnstartedServer(ws.Handler())
	srv.Config.ConnContext = ConnContext
	srv.Start()
	h.srv = srv
	t.Cleanup(h.srv.Close)
	return h
}

// exactBodySize 后端 /exact 的响应体长度，测试把 MaxBodyBytes 调到同一个值。
const exactBodySize = 4096

// jtiSeq 保证每次取票的 jti 唯一——票据现在是**真一次性**的，
// 复用 jti 会让第二次换票被去重挡掉（那正是我们想要的行为）。
var jtiSeq atomic.Int64

// ticket 签一张票（不换会话），供重放/绑定类断言直接拿原串用。
func (h *harness) ticket(user, role, res string) string {
	return h.key.sign(auth.Claims{Sub: user, Role: role, Name: user,
		Jti: fmt.Sprintf("j-%d", jtiSeq.Add(1)), Use: auth.UseWeb, Res: res}, 30*time.Second)
}

// enter 走一次「票据换 Cookie」，返回 Cookie 值。
func (h *harness) enter(t *testing.T, user, role, res string) string {
	t.Helper()
	tok := h.ticket(user, role, res)
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

// ★票据是**一次性**的：同一张票换第二次会话必须被拒。
//
// 退回旧实现（只检查 jti 非空、没有去重缓存）这条用例立刻红——那正是此前
// 控制面审计、文档、门户提示、前端注释四处都写着"60s 内一次性"而实际不成立的地方。
// 票据整串会进浏览器历史与前置 nginx 的 access.log，拿到即可重放。
func TestTicketIsSingleUse(t *testing.T) {
	h := newHarness(t)
	tok := h.ticket("zhangsan", "user", "oa")
	first := h.get(t, entryPath+"?t="+url.QueryEscape(tok), "")
	first.Body.Close()
	if first.StatusCode != http.StatusFound {
		t.Fatalf("首次换票应成功，得 %d", first.StatusCode)
	}
	for i := 0; i < 3; i++ {
		again := h.get(t, entryPath+"?t="+url.QueryEscape(tok), "")
		again.Body.Close()
		if again.StatusCode != http.StatusUnauthorized {
			t.Fatalf("★第 %d 次重放同一张票必须被拒，得 %d", i+2, again.StatusCode)
		}
		for _, c := range again.Cookies() {
			if c.Name == CookieName {
				t.Fatal("★重放被拒时绝不能下发会话 Cookie")
			}
		}
	}
}

// 票据绑定网关：去重缓存是每台网关自己的内存，票不带网关维度的话，
// 同一张票在每台装了 web 公钥的网关上都能各换一次会话——去重被台数整除掉。
func TestTicketBoundToGateway(t *testing.T) {
	h := newHarnessWith(t, func(c *Config) { c.GatewayID = "gw-a" })
	mine := h.key.sign(auth.Claims{Sub: "u", Role: "user", Name: "u", Jti: "j-gw-mine",
		Use: auth.UseWeb, Res: "oa", Gw: "gw-a"}, 30*time.Second)
	if resp := h.get(t, entryPath+"?t="+url.QueryEscape(mine), ""); resp.StatusCode != http.StatusFound {
		resp.Body.Close()
		t.Fatalf("绑定本网关的票应放行，得 %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}
	other := h.key.sign(auth.Claims{Sub: "u", Role: "user", Name: "u", Jti: "j-gw-other",
		Use: auth.UseWeb, Res: "oa", Gw: "gw-b"}, 30*time.Second)
	resp := h.get(t, entryPath+"?t="+url.QueryEscape(other), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("★绑定别台网关的票必须被拒，得 %d", resp.StatusCode)
	}
}

// 可信代理：只有来自白名单网段的请求，其 XFF / XFP 才被采信。
//
// 文档推荐的部署就是把七层绑在回环由前置 nginx 终结 HTTPS，没有这一半的话
// 后端看到的客户端 IP 恒为 nginx 自己、X-Forwarded-Proto 恒为 http。
func TestTrustedProxyForwardsRealClient(t *testing.T) {
	h := newHarnessWith(t, func(c *Config) {
		pfx, err := ParseTrustedProxies("127.0.0.1,::1")
		if err != nil {
			t.Fatal(err)
		}
		c.TrustedProxies = pfx
	})
	ck := h.enter(t, "zhangsan", "user", "oa")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app/oa/x", nil)
	req.Header.Set("Cookie", CookieName+"="+ck)
	// nginx 的典型形态：把客户端自称的那一段原样留在左边，自己追加真实对端在右边
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 203.0.113.7")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if h.lastXFF != "203.0.113.7" {
		t.Fatalf("★可信代理链上第一个不可信地址才是客户端，得 %q（9.9.9.9 是伪造段，回环是代理自己）", h.lastXFF)
	}
	if got := h.lastReq.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("★可信代理转发的 proto 必须采信，否则后端的 HTTPS 强制跳转会与 Location 改写咬成死循环，得 %q", got)
	}
}

// 反面：对端不在可信白名单时，进站的 XFF 一律不采信。
func TestUntrustedPeerForwardedIgnored(t *testing.T) {
	h := newHarness(t) // 未配 TrustedProxies
	ck := h.enter(t, "zhangsan", "user", "oa")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app/oa/x", nil)
	req.Header.Set("Cookie", CookieName+"="+ck)
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if strings.Contains(h.lastXFF, "9.9.9.9") {
		t.Fatalf("不可信对端的 XFF 必须被剥掉，后端却看到 %q", h.lastXFF)
	}
	if got := h.lastReq.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("不可信对端的 proto 不得采信（本监听是明文），得 %q", got)
	}
}

// ★Host header injection：Host 头是客户端完全可控的，绝不能当"真实值"下发。
// 后端（Django/Rails 一类）会用 X-Forwarded-Host 拼绝对 URL——比如找回密码链接。
func TestHostHeaderNotForwardedAsTruth(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app/oa/x", nil)
	req.Header.Set("Cookie", CookieName+"="+ck)
	req.Host = "evil.example.com"
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := h.lastReq.Header.Get("X-Forwarded-Host"); got != "" {
		t.Fatalf("★客户端可控的 Host 不得作为 X-Forwarded-Host 下发，得 %q", got)
	}
	// 显式配置了对外主机名时，下发的恒是配置值而不是客户端自称的那个
	h2 := newHarnessWith(t, func(c *Config) { c.ExternalHost = "oa.example.com" })
	ck2 := h2.enter(t, "zhangsan", "user", "oa")
	req2, _ := http.NewRequest(http.MethodGet, h2.srv.URL+"/app/oa/x", nil)
	req2.Header.Set("Cookie", CookieName+"="+ck2)
	req2.Host = "evil.example.com"
	resp2, err := (&http.Client{}).Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if got := h2.lastReq.Header.Get("X-Forwarded-Host"); got != "oa.example.com" {
		t.Fatalf("★配置了对外主机名时必须下发它，得 %q", got)
	}
}

// 网关自己的会话 Cookie 不得转发给后端：Cookie 不在 Go 的 hop-by-hop 剔除表里。
func TestOwnSessionCookieNotForwarded(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app/oa/echo-cookie", nil)
	req.Header.Set("Cookie", CookieName+"="+ck+"; biz=keep")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := h.lastReq.Header.Get("Cookie")
	if strings.Contains(got, CookieName) {
		t.Fatalf("★网关会话凭据不得白送给被保护应用，后端却收到 %q", got)
	}
	if !strings.Contains(got, "biz=keep") {
		t.Fatalf("业务自己的 Cookie 必须原样转发，得 %q", got)
	}
}

// `__Host-` 前缀的 Cookie：改 Path 会让浏览器整条丢弃（RFC 6265bis 要求 Path=/），
// 症状就是"登录成功后立刻又跳回登录页"。改名保住 Path 限定，出站再改回去。
func TestHostPrefixedCookieRoundTrip(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	resp := h.get(t, "/app/oa/hostcookie", ck)
	defer resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	if strings.Contains(sc, "__Host-") {
		t.Fatalf("★带 __Host- 前缀又改了 Path 的 Cookie 会被浏览器整条丢弃，得 %q", sc)
	}
	if !strings.Contains(sc, hostPrefixAlias+"sid=abc") || !strings.Contains(sc, "Path=/app/oa/") {
		t.Fatalf("应改名并收进本应用前缀，得 %q", sc)
	}
	// 浏览器把改名后的 Cookie 送回来时，后端要看到它原来的名字
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app/oa/echo-cookie", nil)
	req.Header.Set("Cookie", CookieName+"="+ck+"; "+hostPrefixAlias+"sid=abc")
	r2, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if got := h.lastReq.Header.Get("Cookie"); !strings.Contains(got, "__Host-sid=abc") {
		t.Fatalf("★出站必须把名字改回后端认识的形态，得 %q", got)
	}
}

// 响应体上界的边界：长度**恰好等于**上界的下载不该失败。
func TestBodyExactlyAtLimitSucceeds(t *testing.T) {
	h := newHarnessWith(t, func(c *Config) { c.MaxBodyBytes = exactBodySize })
	ck := h.enter(t, "zhangsan", "user", "oa")
	resp := h.get(t, "/app/oa/exact", ck)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("★长度恰好等于上界的响应体不该被判超限：%v", err)
	}
	if len(b) != exactBodySize {
		t.Fatalf("响应体应完整读到 %d 字节，得 %d", exactBodySize, len(b))
	}
}

// 跨应用同源请求（A 应用页面里 fetch B 应用）按 Referer 拦掉。
// 这是纵深不是隔离——真正的隔离要给每个应用配独立域名，边界写在 ARCHITECTURE 第七节。
func TestCrossAppSameOriginRequestRejected(t *testing.T) {
	h := newHarness(t)
	gitCk := h.enter(t, "zhangsan", "user", "git")
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app/git/secret", nil)
	req.Header.Set("Cookie", CookieName+"="+gitCk)
	req.Header.Set("Referer", h.srv.URL+"/app/oa/index.html") // 从 oa 的页面发起
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("★从另一个应用页面发起的带凭据请求必须被拒，得 %d", resp.StatusCode)
	}
	// 同应用内的 Referer 不受影响（否则整站静态资源全挂）
	req2, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/app/git/ok", nil)
	req2.Header.Set("Cookie", CookieName+"="+gitCk)
	req2.Header.Set("Referer", h.srv.URL+"/app/git/index.html")
	r2, err := cl.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("同应用内的请求不该被误伤，得 %d", r2.StatusCode)
	}
}

// ★已升级连接（WebSocket）必须能被强制下线切断，且逃不掉周期复查。
//
// 退回旧实现（modifyResponse 对 101 直接 return nil、没有任何台账）这条用例会挂在
// 读操作上直到超时：连接一直活着，而管理台与审计都显示该账号已被切断。
func TestUpgradedConnectionKilledOnForcedLogout(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")

	c, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /app/oa/upgrade HTTP/1.1\r\nHost: gw\r\nCookie: %s=%s\r\n"+
		"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n", CookieName, ck)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		t.Fatalf("升级应成功，得 %q（err=%v）", line, err)
	}
	for { // 把响应头读完，后面读到的就只可能是连接本身的状态了
		l, rerr := br.ReadString('\n')
		if rerr != nil {
			t.Fatalf("读 101 响应头失败：%v", rerr)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	// 台账里必须有它——否则"能切断"只是碰巧
	deadline := time.Now().Add(2 * time.Second)
	for h.ws.UpgradedCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.ws.UpgradedCount() != 1 {
		t.Fatalf("★已升级连接必须进可切断台账，当前 %d 条", h.ws.UpgradedCount())
	}

	if n := h.ws.KillUser("zhangsan"); n != 1 {
		t.Fatalf("★强制下线应切断 1 条七层长连接，得 %d", n)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("★连接被切断后不该还能读到数据")
	} else if os.IsTimeout(err) {
		t.Fatal("★连接仍然活着：强制下线对已升级连接没有执行方")
	}
}

// 拿不到底层连接时**拒绝**协议升级：放行一条谁也切不断的连接比拒绝它更糟。
func TestUpgradeRejectedWithoutConnTracking(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	// 这台 httptest 服务器刻意不装 ConnContext
	bare := httptest.NewServer(h.ws.Handler())
	defer bare.Close()
	req, _ := http.NewRequest(http.MethodGet, bare.URL+"/app/oa/upgrade", nil)
	req.Header.Set("Cookie", CookieName+"="+ck)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("★纳不进台账的升级请求必须被拒，得 %d", resp.StatusCode)
	}
}

// ★已升级连接逃不掉「逐请求鉴权」的等价物：撤权后周期复查必须把它切断。
//
// 这条与上一条的差别是执行路径：那条是管理员点强制下线（KillUser），这条是
// 授权自己变了（策略轮询把 DenyUsers 下发下来）——L4 那侧后者靠"下一个请求"，
// 长连接上没有下一个请求，只能靠复查。
func TestUpgradedConnectionKilledOnAuthorizationLoss(t *testing.T) {
	h := newHarnessWith(t, func(c *Config) { c.UpgradeRecheck = 50 * time.Millisecond })
	ck := h.enter(t, "zhangsan", "user", "oa")
	c, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /app/oa/upgrade HTTP/1.1\r\nHost: gw\r\nCookie: %s=%s\r\n"+
		"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n", CookieName, ck)
	br := bufio.NewReader(c)
	for {
		l, rerr := br.ReadString('\n')
		if rerr != nil {
			t.Fatalf("读 101 响应失败：%v", rerr)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	// 风险降权：控制面把该账号放进 DenyUsers（与逐请求那条用例同一个判据来源）
	bu, _ := url.Parse(h.backend.URL)
	h.reg.Replace([]resource.Resource{{ID: "oa", Backend: bu.Host,
		AllowRoles: []string{"user"}, DenyUsers: []string{"zhangsan"}}})

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("★撤权后不该还能读到数据")
	} else if os.IsTimeout(err) {
		t.Fatal("★撤权后连接仍活着：长连接上没有逐请求鉴权的等价执行方")
	}
}
