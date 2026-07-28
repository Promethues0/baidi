package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

func openTestSQLite(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// gwServer 构造一台按 compat 开关装配的控制面（不起真实监听）。
func gwServer(t *testing.T, plaintextCompat bool) http.Handler {
	t.Helper()
	st := openTestSQLite(t)
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, plaintextCompat)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes())
}

// gwSelfSignedToken 模拟网关用共享密钥自签的 role=gateway 令牌（阶段 2 之前的机器身份）。
func gwSelfSignedToken() string {
	return testKeys.Sign(auth.Claims{Sub: "gateway:gw-1", Role: "gateway", Name: "gw-1"}, tokenTTL)
}

func getWithToken(h http.Handler, path, tok string) int {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// 迁移期（compat=true）：网关仍可用自签 role=gateway 令牌走明文口，升级不断线。
func TestGatewayRoutesPlaintextCompatOn(t *testing.T) {
	h := gwServer(t, true)
	if code := getWithToken(h, "/api/v1/gateways/policy", gwSelfSignedToken()); code != http.StatusOK {
		t.Fatalf("迁移期网关令牌应可拉策略，得 %d", code)
	}
}

// ★收口态（compat=false）：网关接口从明文口整体摘除，只剩 mTLS 一条路。
// 这是阶段 2 的核心性质——不是「换个角色判断」，而是旧路根本不存在。
func TestGatewayRoutesRemovedWhenCompatOff(t *testing.T) {
	h := gwServer(t, false)
	for _, p := range []string{"/api/v1/gateways/policy", "/api/v1/gateways/register"} {
		if code := getWithToken(h, p, gwSelfSignedToken()); code == http.StatusOK {
			t.Fatalf("收口后 %s 不应在明文口可用，得 %d", p, code)
		}
	}
}

// ★admin 令牌也调不到网关接口：admin 兜底已从 requireGateway 移除。
// 留着它的话，「机器身份走 mTLS」只是多一条路而没关掉旧路。
func TestGatewayRoutesRejectAdminToken(t *testing.T) {
	h := gwServer(t, true) // 即便在最宽松的迁移期
	adminTok := testKeys.Sign(auth.Claims{Sub: "admin", Role: "admin", Name: "admin"}, tokenTTL)
	if code := getWithToken(h, "/api/v1/gateways/policy", adminTok); code != http.StatusForbidden {
		t.Fatalf("admin 令牌不应能调网关接口，得 %d", code)
	}
}

// 普通用户令牌当然更不行。
func TestGatewayRoutesRejectUserToken(t *testing.T) {
	h := gwServer(t, true)
	userTok := testKeys.Sign(auth.Claims{Sub: "li.fang", Role: "user", Name: "li.fang"}, tokenTTL)
	if code := getWithToken(h, "/api/v1/gateways/policy", userTok); code != http.StatusForbidden {
		t.Fatalf("普通用户令牌不应能调网关接口，得 %d", code)
	}
}

// 证书白名单：签发→可信；吊销→立刻不可信（mTLS 握手回调据此拒绝）。
func TestGatewayCertTrustLifecycle(t *testing.T) {
	st := openTestSQLite(t)
	ctx := t.Context()
	const fp = "abc123fingerprint"

	if _, ok, _ := st.GatewayCertTrusted(ctx, fp); ok {
		t.Fatal("未登记的指纹不应可信")
	}
	if err := st.SaveGatewayCert(ctx, store.GatewayCert{Fingerprint: fp, GatewayID: "gw-1", NotAfter: "2099-01-01 00:00:00"}); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := st.GatewayCertTrusted(ctx, fp)
	if err != nil || !ok || rec.GatewayID != "gw-1" {
		t.Fatalf("登记后应可信: %+v %v %v", rec, ok, err)
	}
	if err := st.RevokeGatewayCert(ctx, fp, "验证吊销"); err != nil {
		t.Fatalf("吊销应成功: %v", err)
	}
	rec, ok, _ = st.GatewayCertTrusted(ctx, fp)
	if ok || !rec.Revoked {
		t.Fatalf("吊销后必须不可信: %+v ok=%v", rec, ok)
	}
	// 重复吊销 → 明确错误，不静默成功
	if err := st.RevokeGatewayCert(ctx, fp, "再吊销"); err == nil {
		t.Fatal("重复吊销应报错")
	}
}
