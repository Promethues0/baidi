package api

// OIDC 登录编排（wave7 行动 1）。协议实现（oidcsrc）另有 30 条真密码学用例；
// 这里换桩 RedirectAuthenticator 测**编排**：state 单次性、失败重定向、
// 交接票据的单次消费、以及"交接票据不是会话令牌"这条硬边界。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

// stubOIDC 桩认证源：AuthURL 回一个假地址，Exchange 按 code 决定成败。
type stubOIDC struct {
	identity authsrc.Identity
	// wantVerifier / wantNonce 记录 AuthURL 收到的值，Exchange 时校验编排真的
	// 把同一对传回来了——state 会话表串号的话这里当场翻脸。
	state, nonce, verifier string
}

func (f *stubOIDC) AuthURL(_ context.Context, state, nonce, codeVerifier string) (string, error) {
	f.state, f.nonce, f.verifier = state, nonce, codeVerifier
	return "https://idp.example/authorize?state=" + url.QueryEscape(state), nil
}
func (f *stubOIDC) Exchange(_ context.Context, code, codeVerifier, nonce string) (authsrc.Identity, error) {
	if code != "good-code" {
		return authsrc.Identity{}, authsrc.ErrInvalidCredentials
	}
	if codeVerifier != f.verifier || nonce != f.nonce {
		return authsrc.Identity{}, authsrc.ErrNotConfigured
	}
	return f.identity, nil
}
func (f *stubOIDC) Probe(context.Context) error { return nil }

// oidcFixture 建一个带已启用 OIDC 源 + 桩认证器的测试栈。
func oidcFixture(t *testing.T) (http.Handler, *Server, *stubOIDC) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "oidc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.SaveAuthSource(context.Background(), store.AuthSourceRec{
		ID: "oidc-1", Name: "公司 IdP", Kind: "oidc", Enabled: true,
		Config: `{"issuer":"https://idp.example","clientId":"baidi","redirectUri":"https://baidi.example/api/v1/auth/oidc/oidc-1/callback"}`,
	}); err != nil {
		t.Fatal(err)
	}
	stub := &stubOIDC{identity: authsrc.Identity{
		Subject: "idp|u-1001", Username: "ext.oidc.user", DisplayName: "外部用户一号",
	}}
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	s.testRedirectAuth = func(store.AuthSourceRec) (authsrc.RedirectAuthenticator, error) { return stub, nil }
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), s, stub
}

func getRaw(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestOIDCFullFlow(t *testing.T) {
	h, _, stub := oidcFixture(t)

	// providers 公开清单（未登录）。
	code, out := doJSON(t, h, "GET", "/api/v1/auth/oidc/providers", "", nil)
	if code != http.StatusOK {
		t.Fatalf("providers http %d", code)
	}
	pv := out["providers"].([]any)
	if len(pv) != 1 || mapOf(t, pv[0])["name"] != "公司 IdP" {
		t.Fatalf("应列出已启用 OIDC 源，实得 %v", pv)
	}

	// authorize → 302 到 IdP，state 已被服务端登记。
	rec := getRaw(t, h, "/api/v1/auth/oidc/oidc-1/authorize")
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://idp.example/authorize") {
		t.Fatalf("authorize 应 302 去 IdP，实得 %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if stub.state == "" || stub.nonce == "" || stub.verifier == "" {
		t.Fatal("state/nonce/verifier 应已生成并传给 AuthURL")
	}

	// callback（好码 + 正确 state）→ 302 回门户带 oidcGrant，8h 令牌绝不在 URL 里。
	rec = getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?state="+url.QueryEscape(stub.state)+"&code=good-code")
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, "/portal/login?") {
		t.Fatalf("callback 应 302 回门户，实得 %d %s", rec.Code, loc)
	}
	u, _ := url.Parse(loc)
	grant := u.Query().Get("oidcGrant")
	if grant == "" {
		t.Fatalf("应带交接票据，实得 %s", loc)
	}

	// ★交接票据不是会话令牌：拿它当 Bearer 调业务端点必须 403（中间件用途白名单）。
	if code, _ := doJSON(t, h, "GET", "/api/v1/portal/apps", grant, nil); code != http.StatusForbidden {
		t.Fatalf("交接票据当 Bearer 应 403，实得 %d", code)
	}

	// 交接票据 → 会话令牌。
	code, out = doJSON(t, h, "POST", "/api/v1/auth/oidc/session", "", map[string]any{"ticket": grant})
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("交接应成功，实得 %d %v", code, out)
	}
	tok, _ := out["token"].(string)
	if tok == "" || out["role"] != "user" {
		t.Fatalf("应发 user 会话令牌，实得 %v", out)
	}
	// 真令牌能调业务端点。
	if code, _ := doJSON(t, h, "GET", "/api/v1/portal/apps", tok, nil); code != http.StatusOK {
		t.Errorf("会话令牌应可用，实得 %d", code)
	}
	// ★单次性：同一张交接票据第二次兑换必须被拒。
	if code, _ := doJSON(t, h, "POST", "/api/v1/auth/oidc/session", "", map[string]any{"ticket": grant}); code != http.StatusForbidden {
		t.Error("交接票据重放应 403")
	}
	// ★state 单次性：同一 state 再回调必须失败（重定向带 oidcError）。
	rec = getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?state="+url.QueryEscape(stub.state)+"&code=good-code")
	if !strings.Contains(rec.Header().Get("Location"), "oidcError") {
		t.Errorf("state 重放应失败，实得 %s", rec.Header().Get("Location"))
	}
}

func TestOIDCCallbackRejections(t *testing.T) {
	h, _, stub := oidcFixture(t)

	// 未登记的 state。
	rec := getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?state=forged&code=good-code")
	if !strings.Contains(rec.Header().Get("Location"), "oidcError") {
		t.Errorf("伪造 state 应失败：%s", rec.Header().Get("Location"))
	}
	// IdP 显式拒绝：如实转述，且不消耗 state。
	getRaw(t, h, "/api/v1/auth/oidc/oidc-1/authorize")
	rec = getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?error=access_denied&error_description=用户取消")
	if !strings.Contains(rec.Header().Get("Location"), url.QueryEscape("用户取消")) {
		t.Errorf("IdP 拒绝应转述原因：%s", rec.Header().Get("Location"))
	}
	// 坏授权码：Exchange 失败 → oidcError，不落任何绑定。
	rec = getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?state="+url.QueryEscape(stub.state)+"&code=bad-code")
	if !strings.Contains(rec.Header().Get("Location"), "oidcError") {
		t.Errorf("坏授权码应失败：%s", rec.Header().Get("Location"))
	}
	// 未启用/不存在的源。
	if rec := getRaw(t, h, "/api/v1/auth/oidc/nope/authorize"); rec.Code != http.StatusNotFound {
		t.Errorf("未知源应 404，实得 %d", rec.Code)
	}
}

// 外部账号 role 恒 user：即便 IdP 声称管理员，交接出来的也只能是 user 会话。
func TestOIDCNeverGrantsAdmin(t *testing.T) {
	h, _, stub := oidcFixture(t)
	stub.identity.Username = "admin" // 撞本地管理员用户名
	stub.identity.Groups = []string{"Domain Admins"}

	getRaw(t, h, "/api/v1/auth/oidc/oidc-1/authorize")
	rec := getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?state="+url.QueryEscape(stub.state)+"&code=good-code")
	u, _ := url.Parse(rec.Header().Get("Location"))
	grant := u.Query().Get("oidcGrant")
	if grant == "" {
		t.Fatalf("callback 未发交接票据：%s", rec.Header().Get("Location"))
	}
	code, out := doJSON(t, h, "POST", "/api/v1/auth/oidc/session", "", map[string]any{"ticket": grant})
	if code != http.StatusOK {
		t.Fatalf("交接失败 %d %v", code, out)
	}
	if out["role"] != "user" {
		t.Fatalf("外部账号 role 必须恒 user（Subject 绑定 + 撞名加后缀的既有纪律），实得 %v", out["role"])
	}
	// 且拿不到管理端点。
	tok := out["token"].(string)
	if code, _ := doJSON(t, h, "GET", "/api/v1/users", tok, nil); code != http.StatusForbidden {
		t.Error("OIDC 登录的账号不得进管理面")
	}
}
