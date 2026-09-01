package api

import (
	"net/http"
	"testing"

	"baidi.dev/control/internal/auth"
)

// GET /api/v1/auth/me 的身份下发回归。
//
// 这是控制台顶栏与「按权限收敛写操作」的唯一数据源。此前它只回 sub/role/name/exp，
// 于是前端把身份写死成「安全管理员 / security-admin」——而种子 admin 的**显示名**
// 恰好就是"安全管理员"、**角色**却是超管，两者在页面上完全同形。
//
// 四向断言，缺一条都能让一个坏实现全绿：
//   ① 超管拿到 root/`*`；② 审计管理员拿到 audit（且**不含** security）；
//   ③ 受限改密令牌拿得到身份但**拿不到** adminRole；④ 普通用户没有 adminRole。

// meRole 取 /auth/me 里的 adminRole 对象（缺席则第二个返回值为 false）。
func meRole(t *testing.T, h http.Handler, token string) (map[string]any, bool, map[string]any) {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/auth/me", token, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /auth/me http %d, want 200: %v", code, out)
	}
	role, ok := out["adminRole"].(map[string]any)
	return role, ok, out
}

// permsOf 把 adminRole.perms 摊成集合。
func permsOf(role map[string]any) map[string]bool {
	set := map[string]bool{}
	arr, _ := role["perms"].([]any)
	for _, p := range arr {
		if s, ok := p.(string); ok {
			set[s] = true
		}
	}
	return set
}

func TestMeCarriesLiveAdminRole(t *testing.T) {
	h := newTestServer(t)

	// ① 种子 admin：回填为超管，权限键是 `*`
	role, ok, out := meRole(t, h, adminToken())
	if !ok {
		t.Fatalf("超管的 /auth/me 应带 adminRole: %v", out)
	}
	if role["key"] != "root" || role["power"] != "root" {
		t.Fatalf("种子 admin 应是超管 root，got key=%v power=%v", role["key"], role["power"])
	}
	if !permsOf(role)["*"] {
		t.Fatalf("超管权限键应含 *，got %v", role["perms"])
	}
	// 显示名与账号是两回事：令牌里的 Name 是账号，页面要显示的名字得从库里取。
	if out["displayName"] != "安全管理员" {
		t.Fatalf("应下发库里的显示名「安全管理员」，got %v", out["displayName"])
	}
	if out["sub"] != "admin" {
		t.Fatalf("sub 应是账号 admin，got %v", out["sub"])
	}

	// ② 审计管理员：只有 audit，且**不含** security——这正是前端要据以收敛写操作的判据。
	audTok := makeAdmin(t, h, "aud.me", "audit")
	role, ok, _ = meRole(t, h, audTok)
	if !ok {
		t.Fatal("审计管理员的 /auth/me 应带 adminRole")
	}
	if role["key"] != "audit" {
		t.Fatalf("角色键应为 audit，got %v", role["key"])
	}
	perms := permsOf(role)
	if !perms["audit"] {
		t.Fatalf("审计管理员应持 audit 权，got %v", role["perms"])
	}
	if perms["security"] || perms["system"] || perms["*"] {
		t.Fatalf("审计管理员不该持 security/system/*，got %v", role["perms"])
	}

	// ③ 角色现算：把审计管理员改成系统管理员，**同一张旧令牌**下一次拉身份就要变。
	//    角色若塞在令牌里，这里会在 8h 内一直回 audit，而执行方早已按 system 判。
	if code, out := doJSON(t, h, "PUT", "/api/v1/admins/aud.me/role", adminToken(),
		map[string]any{"roleKey": "system"}); code != http.StatusOK {
		t.Fatalf("改角色 http %d: %v", code, out)
	}
	role, _, _ = meRole(t, h, audTok)
	if role["key"] != "system" {
		t.Fatalf("角色必须现算：改判后旧令牌应看到 system，got %v", role["key"])
	}
}

// 受限改密令牌（首登强制改密态）拿得到身份，但拿不到权限清单。
// 它在 auth.pwResetAllowed 里对 /auth/me 是放行的，而那是一个连自己口令
// 都还没换的半程态，不该拿到"你在这套系统里能做什么"的完整答案。
func TestMeWithholdsRoleFromPwResetToken(t *testing.T) {
	h := newTestServer(t)
	limited := testKeys.Sign(auth.Claims{
		Sub: "admin", Role: "admin", Name: "admin", Use: auth.UsePwReset,
	}, tokenTTL)

	code, out := doJSON(t, h, "GET", "/api/v1/auth/me", limited, nil)
	if code != http.StatusOK {
		t.Fatalf("受限令牌应能查身份: http %d", code)
	}
	if out["sub"] != "admin" {
		t.Fatalf("身份仍应下发，got %v", out["sub"])
	}
	if _, has := out["adminRole"]; has {
		t.Fatalf("受限改密令牌不该拿到 adminRole: %v", out["adminRole"])
	}
}

// 普通用户（门户身份）没有管理员角色——不是「空权限」，是**缺席**。
func TestMeHasNoAdminRoleForUser(t *testing.T) {
	h := newTestServer(t)
	if _, has, out := meRole(t, h, userToken("li.fang")); has {
		t.Fatalf("普通用户不该有 adminRole: %v", out["adminRole"])
	}
}
