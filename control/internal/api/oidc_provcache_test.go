package api

// OIDC Provider 跨请求复用（wave9）。此前每个 HTTP 请求都新建一个 Provider，
// 于是 oidcsrc 内部的 discoveryCache / jwksCache 跨请求恒不命中——不只是多打几次
// 网，两处「拉不动就用旧值」的降级分支与 minRefresh 防拉取风暴限流一并被架空。

import (
	"context"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/store"
)

func provCacheServer(t *testing.T) (*Server, *store.SQLiteStore) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "provcache.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, st, testKeys, "test", t.TempDir(), nil, nil, true), st
}

func oidcRec(id, issuer string) store.AuthSourceRec {
	return store.AuthSourceRec{
		ID: id, Name: "公司 IdP", Kind: "oidc", Enabled: true,
		Config: `{"issuer":"` + issuer + `","clientId":"baidi",` +
			`"redirectUri":"https://baidi.example/api/v1/auth/oidc/` + id + `/callback"}`,
	}
}

// 同一份配置 + 同一份凭据 → 跨请求必须拿到**同一个** Provider。
func TestOIDCProvider跨请求复用(t *testing.T) {
	s, st := provCacheServer(t)
	ctx := context.Background()
	rec := oidcRec("oidc-1", "https://idp.example")
	if _, err := st.SaveAuthSource(ctx, rec); err != nil {
		t.Fatal(err)
	}

	a, err := s.oidcProviderFor(ctx, rec)
	if err != nil {
		t.Fatalf("首次构造失败：%v", err)
	}
	b, err := s.oidcProviderFor(ctx, rec)
	if err != nil {
		t.Fatalf("二次构造失败：%v", err)
	}
	if a != b {
		t.Fatal("每次都新建 Provider：discoveryCache/jwksCache 跨请求恒不命中，" +
			"两处「拉不动就用旧值」的降级分支永远进不去，minRefresh 防拉取风暴限流也跨不了请求")
	}
}

// 改配置（issuer）后必须重建——否则「改了配置不生效」。
func TestOIDCProvider配置变更后重建(t *testing.T) {
	s, st := provCacheServer(t)
	ctx := context.Background()
	rec := oidcRec("oidc-1", "https://old.example")
	if _, err := st.SaveAuthSource(ctx, rec); err != nil {
		t.Fatal(err)
	}
	a, _ := s.oidcProviderFor(ctx, rec)

	rec2 := oidcRec("oidc-1", "https://new.example")
	if _, err := st.SaveAuthSource(ctx, rec2); err != nil {
		t.Fatal(err)
	}
	b, err := s.oidcProviderFor(ctx, rec2)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("改了 issuer 却仍在用旧 Provider——管理员在页面上改完保存，登录还是打到旧 IdP")
	}
}

// 轮换 client_secret 后必须重建。指纹只吃密文与 nonce，不解密——
// 每次保存都重新加密，nonce 必然不同。
func TestOIDCProvider凭据轮换后重建(t *testing.T) {
	s, st := provCacheServer(t)
	ctx := context.Background()
	rec := oidcRec("oidc-1", "https://idp.example")
	if _, err := st.SaveAuthSource(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuthSourceSecret(ctx, store.AuthSourceSecret{
		SourceID: "oidc-1", Nonce: []byte("nonce-old-12"), Cipher: []byte("cipher-old"), Fingerprint: "aaaaaaaa",
	}); err != nil {
		t.Fatal(err)
	}
	fp1 := s.oidcConfigFingerprint(ctx, rec)

	if err := st.SaveAuthSourceSecret(ctx, store.AuthSourceSecret{
		SourceID: "oidc-1", Nonce: []byte("nonce-new-99"), Cipher: []byte("cipher-new"), Fingerprint: "bbbbbbbb",
	}); err != nil {
		t.Fatal(err)
	}
	fp2 := s.oidcConfigFingerprint(ctx, rec)

	if fp1 == "" || fp2 == "" {
		t.Fatalf("指纹不该为空：%q / %q", fp1, fp2)
	}
	if fp1 == fp2 {
		t.Fatal("轮换凭据后指纹没变——旧 client_secret 会一直被用下去")
	}
}

// 指纹算不出来时**不入缓存**：存一个算不准失效判据的条目，
// 等于把「改了配置不生效」变成常态。
func TestOIDCProvider指纹算不出时不缓存(t *testing.T) {
	s, _ := provCacheServer(t)
	ctx := context.Background()
	rec := oidcRec("oidc-1", "https://idp.example")

	// 没有 authSrcStore 的场景由 oidcConfigFingerprint 内部兜住；这里直接验
	// 「空指纹不入表」这条：手工塞一个空指纹的条目不应被命中。
	s.oidcProv.mu.Lock()
	s.oidcProv.m = map[string]oidcProvEntry{"oidc-1": {fp: "", ra: nil}}
	s.oidcProv.mu.Unlock()

	got, err := s.oidcProviderFor(ctx, rec)
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	if got == nil {
		t.Fatal("空指纹的缓存条目被命中了，返回了 nil Provider")
	}
}
