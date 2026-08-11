package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/pki"
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

// ★吊销证书必须**当场**把这台网关从下发给终端的落点清单里摘掉。
//
// 退回旧实现（只写库、不动内存台账）这条立刻红：被吊销的网关会永远留在剖面里、
// 连隧道指纹一起下发——客户端钉扎照样通过、界面显示「已建立 · 证书钉扎」，
// 每轮还主动给它发一次有效敲门令牌，首选落点一抖业务流量就流进那台失陷机器。
// 吊销此前只切断了「网关→控制面」这一半。
func TestRevokeGatewayCertDropsEndpointFromProfile(t *testing.T) {
	st := openTestSQLite(t)
	ca, err := pki.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("建 CA: %v", err)
	}
	s := New(st, st, testKeys, "test", t.TempDir(), nil, ca, true)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	// 给 gw-b 签一张证书，并让它注册上线（带隧道指纹）
	code, out := doJSON(t, h, "POST", "/api/v1/pki/gateway-certs", adminToken(),
		map[string]string{"gatewayId": "gw-b"})
	if code != http.StatusCreated {
		t.Fatalf("签发证书应 201，得 %d %v", code, out)
	}
	fp, _ := out["fingerprint"].(string)
	regGateway(s, "gw-a", "10.0.0.1", 0, "aa")
	regGateway(s, "gw-b", "10.0.0.2", 0, "bb")
	if ids := gatewayIDs(mustProfileGateways(s)); len(ids) != 2 {
		t.Fatalf("前置条件：两台网关都该在落点清单里，得 %v", ids)
	}

	code, out = doJSON(t, h, "POST", "/api/v1/pki/gateway-certs/"+fp+"/revoke", adminToken(),
		map[string]string{"reason": "机器失陷"})
	if code != http.StatusOK {
		t.Fatalf("吊销应 200，得 %d %v", code, out)
	}
	if out["endpointDropped"] != true {
		t.Fatalf("吊销响应应报告已摘除落点，得 %v", out)
	}
	list := mustProfileGateways(s)
	for _, g := range list {
		if g.ID == "gw-b" {
			t.Fatalf("★被吊销的网关仍在落点清单里（还带着指纹 %q）：%v", g.TunnelPin, gatewayIDs(list))
		}
	}
	if ids := gatewayIDs(list); len(ids) != 1 || ids[0] != "gw-a" {
		t.Fatalf("只该剩 gw-a，得 %v", ids)
	}
}

// mustProfileGateways 取当前落点清单（忽略告警）。
func mustProfileGateways(s *Server) []ProfileGateway {
	list, _ := s.profileGateways()
	return list
}

// ★`standby-` 是保留命名空间：HTTP 签发端点不得签出温备节点身份。
//
// CN 前缀是温备同步端点的唯一分权判据，签得出 CN=standby-x 的证书，就等于
// 持 PermSystem 的系统管理员能拉走整套信任材料（CA 私钥 + 三把签名私钥 + 整个库）。
// 备机证书的正路是主机上的离线 CLI。
func TestIssueGatewayCertRejectsReservedStandbyPrefix(t *testing.T) {
	st := openTestSQLite(t)
	ca, err := pki.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("建 CA: %v", err)
	}
	s := New(st, st, testKeys, "test", t.TempDir(), nil, ca, true)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	for _, id := range []string{"standby-1", "standby-evil"} {
		if code, out := doJSON(t, h, "POST", "/api/v1/pki/gateway-certs", adminToken(),
			map[string]string{"gatewayId": id}); code != http.StatusBadRequest {
			t.Fatalf("★%s 必须被拒（凭它能拉走整套信任材料），得 %d %v", id, code, out)
		}
	}
	// 反面：组网网关的 ipsec- 前缀本来就走这条路，不能误伤
	if code, _ := doJSON(t, h, "POST", "/api/v1/pki/gateway-certs", adminToken(),
		map[string]string{"gatewayId": "ipsec-a"}); code != http.StatusCreated {
		t.Fatalf("ipsec- 前缀不该被误伤，得 %d", code)
	}
	// 也不该误伤形近的普通 id
	if code, _ := doJSON(t, h, "POST", "/api/v1/pki/gateway-certs", adminToken(),
		map[string]string{"gatewayId": "xstandby-1"}); code != http.StatusCreated {
		t.Fatalf("非前缀命中的 id 不该被拒，得 %d", code)
	}
}
