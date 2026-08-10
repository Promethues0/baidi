package api

import (
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
)

// 首次登录强制改密（FR-DEPLOY-09）全流程：
// 管理员新建用户 → 该账号登录只拿到受限令牌（mustChangePassword）→ 受限令牌调业务端点
// 与 /knock-token 均 403、只放行改密与查身份 → 改密成功清标志 → 新口令登录拿正常会话。
func TestMustChangePasswordFlow(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	// 管理员新建用户：置首登改密
	code, _ := doJSON(t, h, "POST", "/api/v1/users", adm, map[string]any{
		"name": "新员工", "account": "xin.yuangong", "org": "研发部", "orgKey": "dev",
		"roles": []string{"研发"}, "password": "init-pw-01",
	})
	if code != http.StatusCreated {
		t.Fatalf("新建用户应 201, got %d", code)
	}

	// 登录：口令对，但只发受限令牌 + mustChangePassword:true
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{
		"username": "xin.yuangong", "password": "init-pw-01"})
	if code != http.StatusOK || out["ok"] != true || out["mustChangePassword"] != true {
		t.Fatalf("首登应 ok+mustChangePassword: %d %v", code, out)
	}
	limited, _ := out["token"].(string)
	if limited == "" {
		t.Fatal("首登应发受限令牌")
	}
	// 令牌确实带 pwreset 声明且短时效（≤15min）
	c, err := testKeys.Verify(limited)
	if err != nil || c.Use != auth.UsePwReset {
		t.Fatalf("受限令牌应 Use=pwreset: %v %+v", err, c)
	}
	if ttl := c.Exp - c.Iat; ttl > 15*60 {
		t.Fatalf("受限令牌 TTL 应 ≤15min, got %ds", ttl)
	}

	// 受限令牌：业务端点 403（消息指向改密）
	for _, ep := range []struct{ method, path string }{
		{"GET", "/api/v1/portal/apps"},
		{"GET", "/api/v1/client/profile"},
		{"POST", "/api/v1/knock-token"}, // 受限态绝不能拿到能触达数据面的令牌
	} {
		rec, body := doRaw(t, h, ep.method, ep.path, limited)
		if rec != http.StatusForbidden || !strings.Contains(body, "须先修改初始口令") {
			t.Fatalf("受限令牌调 %s %s 应 403 须先修改初始口令: %d %s", ep.method, ep.path, rec, body)
		}
	}
	// 放行面：GET /auth/me 可用
	if code, me := doJSON(t, h, "GET", "/api/v1/auth/me", limited, nil); code != http.StatusOK || me["sub"] != "xin.yuangong" {
		t.Fatalf("受限令牌应可查身份: %d %v", code, me)
	}

	// 改密后端校验：短于 8 位 400；与旧口令相同 400
	if code, _ := doJSON(t, h, "POST", "/api/v1/auth/password", limited,
		map[string]string{"old": "init-pw-01", "new": "short7c"}); code != http.StatusBadRequest {
		t.Fatalf("新口令 <8 位应 400, got %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/auth/password", limited,
		map[string]string{"old": "init-pw-01", "new": "init-pw-01"}); code != http.StatusBadRequest {
		t.Fatalf("新旧口令相同应 400, got %d", code)
	}

	// 改密成功 → 标志清零
	if code, out := doJSON(t, h, "POST", "/api/v1/auth/password", limited,
		map[string]string{"old": "init-pw-01", "new": "My-Real-Pw-9"}); code != http.StatusOK || out["ok"] != true {
		t.Fatalf("改密应成功: %d %v", code, out)
	}

	// 新口令登录：正常会话令牌（无 mustChangePassword），业务端点可用
	code, out = doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{
		"username": "xin.yuangong", "password": "My-Real-Pw-9"})
	if code != http.StatusOK || out["ok"] != true || out["mustChangePassword"] == true {
		t.Fatalf("改密后登录应发正常会话: %d %v", code, out)
	}
	sess, _ := out["token"].(string)
	if c, err := testKeys.Verify(sess); err != nil || c.Use != "" {
		t.Fatalf("会话令牌不应带 use 声明: %v %+v", err, c)
	}
	if code, _ := doJSON(t, h, "GET", "/api/v1/portal/apps", sess, nil); code != http.StatusOK {
		t.Fatalf("正常会话应能调业务端点, got %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", sess, nil); code != http.StatusOK {
		t.Fatalf("正常会话应能取敲门令牌, got %d", code)
	}
}

// 管理员重置口令 → 标志置位：种子账号 li.fang 原本正常登录，重置后降级为受限令牌；
// 管理台登录口（/auth/login）同样只发受限令牌。
func TestResetPasswordSetsMustChange(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	// 种子账号默认正常登录（回填 0，演示流程不被打碎）
	if out := portalLogin(t, h, "li.fang", ""); out["ok"] != true || out["mustChangePassword"] == true {
		t.Fatalf("种子账号默认应正常登录: %v", out)
	}

	// 管理员重置口令（li.fang 种子 id=u2）
	if code, _ := doJSON(t, h, "POST", "/api/v1/users/u2/password", adm,
		map[string]string{"password": "reset-pw-02"}); code != http.StatusOK {
		t.Fatalf("重置口令应 200, got %d", code)
	}

	// 重置后登录：受限令牌
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{
		"username": "li.fang", "password": "reset-pw-02"})
	if code != http.StatusOK || out["mustChangePassword"] != true {
		t.Fatalf("重置后首登应 mustChangePassword: %d %v", code, out)
	}

	// admin 重置自己 → 管理台登录口同样降级
	if code, _ := doJSON(t, h, "POST", "/api/v1/users/u-admin/password", adm,
		map[string]string{"password": "admin-reset-3"}); code != http.StatusOK {
		t.Fatalf("重置 admin 口令应 200, got %d", code)
	}
	code, out = doJSON(t, h, "POST", "/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": "admin-reset-3"})
	if code != http.StatusOK || out["mustChangePassword"] != true {
		t.Fatalf("管理台登录口也应降级为受限令牌: %d %v", code, out)
	}
	limited, _ := out["token"].(string)
	// 受限令牌带 admin 角色也调不了管理端点（中间件先于 requireAdmin 拦截）
	if code, _ := doJSON(t, h, "GET", "/api/v1/users", limited, nil); code != http.StatusForbidden {
		t.Fatalf("admin 受限令牌调管理端点应 403, got %d", code)
	}
}

// doRaw 同 doJSON 但返回原始响应体（断言错误消息用）。
func doRaw(t *testing.T, h http.Handler, method, path, token string) (int, string) {
	t.Helper()
	code, out := doJSON(t, h, method, path, token, nil)
	// doJSON 已解析 JSON；错误消息在 error.message
	if e, ok := out["error"].(map[string]any); ok {
		if m, ok := e["message"].(string); ok {
			return code, m
		}
	}
	return code, ""
}
