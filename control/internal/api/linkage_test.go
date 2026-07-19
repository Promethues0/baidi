package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// 账号禁用/锁定 × 接入封禁联动：
// 禁用/锁定的目录账号应被拒绝门户登录、拒发敲门令牌；
// 管理员禁用/锁定动作应触发数据面封禁（经网关策略下发撤窗断隧道），恢复启用则立即解除。
//
// 种子目录：u2 li.fang(active) / u4 zhao.min(locked) / u5 ext.zhou(disabled)

var testSecret = []byte("test-secret")

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testSecret, "test", t.TempDir())
	return auth.Middleware(testSecret, s.IsOpen)(s.Routes())
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func portalLogin(t *testing.T, h http.Handler, user, mfa string) map[string]any {
	t.Helper()
	body := map[string]string{"username": user, "password": "baidi@123"}
	if mfa != "" {
		body["mfaCode"] = mfa
	}
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", body)
	if code != http.StatusOK {
		t.Fatalf("portal login http %d, want 200", code)
	}
	return out
}

func userToken(name string) string {
	return auth.Sign(testSecret, auth.Claims{Sub: name, Role: "user", Name: name}, tokenTTL)
}

func adminToken() string {
	return auth.Sign(testSecret, auth.Claims{Sub: "admin", Role: "admin", Name: "安全管理员"}, tokenTTL)
}

func gatewayToken() string {
	return auth.Sign(testSecret, auth.Claims{Sub: "gw-test", Role: "gateway", Name: "gw-test"}, tokenTTL)
}

// revokedUsers 拉一次网关策略，返回 revoked 名单里的账号集合。
func revokedUsers(t *testing.T, h http.Handler) map[string]bool {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("gateways/policy http %d, want 200", code)
	}
	users := map[string]bool{}
	if arr, ok := out["revoked"].([]any); ok {
		for _, it := range arr {
			if m, ok := it.(map[string]any); ok {
				if u, ok := m["user"].(string); ok {
					users[u] = true
				}
			}
		}
	}
	return users
}

// 门户登录走真实凭据校验：正确口令过、错误口令拒、目录中不存在的账号拒
//（不再是"任意用户名 + baidi@123"）。
func TestPortalLoginVerifiesRealCredentials(t *testing.T) {
	h := newTestServer(t)

	// 种子用户 li.fang 正确口令
	if out := portalLogin(t, h, "li.fang", ""); !out["ok"].(bool) {
		t.Fatalf("li.fang 正确口令应过: %v", out)
	}
	// 错误口令
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{"username": "li.fang", "password": "wrong-pw"})
	if code != http.StatusOK || out["ok"] == true {
		t.Fatalf("错误口令应被拒: %v", out)
	}
	// 目录中不存在的账号（旧逻辑会放行任意用户名）
	code, out = doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{"username": "ghost.user", "password": "baidi@123"})
	if code != http.StatusOK || out["ok"] == true {
		t.Fatalf("不存在账号应被拒（不再任意用户名放行）: %v", out)
	}
}

// 管理员登录走真实凭据校验且要求 admin 角色：普通账号即便口令对也拿不到 admin。
func TestAdminLoginRequiresAdminRole(t *testing.T) {
	h := newTestServer(t)

	// admin 正确口令 → admin 角色
	code, out := doJSON(t, h, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "baidi@123"})
	if code != http.StatusOK || out["ok"] != true || out["role"] != "admin" {
		t.Fatalf("admin 登录应过且 role=admin: %v", out)
	}
	// 普通用户 li.fang 走管理员登录口 → 拒（角色不足）
	code, out = doJSON(t, h, "POST", "/api/v1/auth/login", "", map[string]string{"username": "li.fang", "password": "baidi@123"})
	if code != http.StatusOK || out["ok"] == true {
		t.Fatalf("普通账号不应能从管理员口登录: %v", out)
	}
	// admin 错误口令 → 拒
	code, out = doJSON(t, h, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "nope"})
	if code != http.StatusOK || out["ok"] == true {
		t.Fatalf("admin 错误口令应拒: %v", out)
	}
}

// 管理员重置他人口令：旧口令失效、新口令生效（真实改密）。
func TestAdminResetsUserPassword(t *testing.T) {
	h := newTestServer(t)
	admin := adminToken()

	// 重置 u2(li.fang) 口令
	code, _ := doJSON(t, h, "POST", "/api/v1/users/u2/password", admin, map[string]string{"password": "Reset-9x!"})
	if code != http.StatusOK {
		t.Fatalf("重置口令 http %d, want 200", code)
	}
	// 新口令登录成功
	if !mustLogin(t, h, "li.fang", "Reset-9x!") {
		t.Fatal("新口令应能登录")
	}
	// 旧口令失效
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{"username": "li.fang", "password": "baidi@123"})
	if code != http.StatusOK || out["ok"] == true {
		t.Fatalf("旧口令应失效: %v", out)
	}
	// 非 admin 不能重置他人口令
	code, _ = doJSON(t, h, "POST", "/api/v1/users/u2/password", userToken("li.fang"), map[string]string{"password": "x"})
	if code != http.StatusForbidden {
		t.Fatalf("非 admin 重置口令应 403, 得到 %d", code)
	}
}

func mustLogin(t *testing.T, h http.Handler, user, pw string) bool {
	t.Helper()
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{"username": user, "password": pw})
	return code == http.StatusOK && out["ok"] == true
}

func TestPortalLoginRefusesDisabledAndLockedAccounts(t *testing.T) {
	h := newTestServer(t)

	// disabled 账号（ext.zhou 会触发 MFA，带对验证码直达最终判定）
	out := portalLogin(t, h, "ext.zhou", "123456")
	if ok, _ := out["ok"].(bool); ok {
		t.Fatalf("disabled account ext.zhou logged in: %v", out)
	}

	// locked 账号
	out = portalLogin(t, h, "zhao.min", "")
	if ok, _ := out["ok"].(bool); ok {
		t.Fatalf("locked account zhao.min logged in: %v", out)
	}

	// active 账号不受影响（回归护栏）
	out = portalLogin(t, h, "li.fang", "")
	if ok, _ := out["ok"].(bool); !ok {
		t.Fatalf("active account li.fang refused: %v", out)
	}
}

func TestKnockTokenDeniedForBlockedAccounts(t *testing.T) {
	h := newTestServer(t)

	for _, name := range []string{"ext.zhou", "zhao.min", " EXT.ZHOU "} { // 含变体：换大小写/加空格不可绕过
		code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", userToken(name), nil)
		if code != http.StatusForbidden {
			t.Errorf("knock-token for %q http %d, want 403", name, code)
		}
	}

	// active 账号照常拿令牌
	code, out := doJSON(t, h, "POST", "/api/v1/knock-token", userToken("li.fang"), nil)
	if code != http.StatusOK || out["token"] == "" {
		t.Fatalf("knock-token for li.fang http %d out %v, want 200+token", code, out)
	}
}

// 会话令牌回退洞：目录中 disabled/locked 账号即便没有被显式踢下线，
// 网关策略的 revoked 名单也应持续包含它们（滚动续期），
// 否则 5min 限时封禁到期后，其 8h 会话令牌可直连网关重新放行。
func TestGatewayPolicyIncludesDisabledDirectoryAccounts(t *testing.T) {
	h := newTestServer(t)
	now := time.Now().Unix()

	rev := policyRevoked(t, h)
	// 种子：zhao.min(locked) / ext.zhou(disabled) 应在名单里，且 until 在未来（滚动）
	for _, u := range []string{"zhao.min", "ext.zhou"} {
		until, ok := rev[u]
		if !ok {
			t.Errorf("disabled/locked 账号 %q 未进网关 revoked 名单", u)
			continue
		}
		if until <= now {
			t.Errorf("%q 的 until=%d 未来化失败（now=%d）", u, until, now)
		}
	}
	// active 账号未被踢，不应出现
	if _, ok := rev["li.fang"]; ok {
		t.Errorf("active 账号 li.fang 不该出现在 revoked 名单")
	}
}

// policyRevoked 拉一次网关策略，返回 revoked 名单 账号→until。
func policyRevoked(t *testing.T, h http.Handler) map[string]int64 {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("gateways/policy http %d", code)
	}
	m := map[string]int64{}
	if arr, ok := out["revoked"].([]any); ok {
		for _, it := range arr {
			if r, ok := it.(map[string]any); ok {
				u, _ := r["user"].(string)
				until, _ := r["until"].(float64)
				m[u] = int64(until)
			}
		}
	}
	return m
}

func TestDisableUserRevokesDataPlaneAndEnableLifts(t *testing.T) {
	h := newTestServer(t)
	admin := adminToken()

	// 禁用 u2 li.fang → 网关策略 revoked 名单出现该账号（数据面撤窗断隧道）
	code, _ := doJSON(t, h, "POST", "/api/v1/users/u2/status", admin, map[string]string{"status": "disabled"})
	if code != http.StatusOK {
		t.Fatalf("set status disabled http %d, want 200", code)
	}
	if !revokedUsers(t, h)["li.fang"] {
		t.Fatalf("li.fang not in gateway revoked list after disable")
	}
	// 禁用期间拒发敲门令牌
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", userToken("li.fang"), nil); code != http.StatusForbidden {
		t.Fatalf("knock-token during disabled http %d, want 403", code)
	}

	// 恢复启用 → 封禁立即解除 + 敲门令牌恢复
	code, _ = doJSON(t, h, "POST", "/api/v1/users/u2/status", admin, map[string]string{"status": "active"})
	if code != http.StatusOK {
		t.Fatalf("set status active http %d, want 200", code)
	}
	if revokedUsers(t, h)["li.fang"] {
		t.Fatalf("li.fang still in gateway revoked list after re-enable")
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", userToken("li.fang"), nil); code != http.StatusOK {
		t.Fatalf("knock-token after re-enable http %d, want 200", code)
	}
}
