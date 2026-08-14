package api

// 闲置账号治理（wave7 行动 8②）。钉三条硬边界：批量锁定不是分权后门
// （安全管理员照样锁不动管理员）、防自锁在批量里同样生效（最后一名超管锁不掉）、
// 锁定即真实生效（被锁账号登录被拒 + 数据面进封禁名单）。

import (
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
)

func TestIdleListAndBatchLock(t *testing.T) {
	h := newTestServer(t)

	// 识别：种子里 4 个 active 超 30 天（zhang.wei 是管理员）
	code, out := doJSON(t, h, "GET", "/api/v1/users/idle?days=30", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("idle list http %d", code)
	}
	accts, _ := out["accounts"].([]any)
	byAcct := map[string]map[string]any{}
	for _, raw := range accts {
		m := raw.(map[string]any)
		byAcct[m["account"].(string)] = m
	}
	if len(byAcct) != 4 || byAcct["zhang.wei"] == nil || byAcct["li.fang"] == nil {
		t.Fatalf("30 天阈值应命中 4 个，实得 %v", byAcct)
	}
	if byAcct["zhang.wei"]["isAdmin"] != true {
		t.Fatal("zhang.wei 应标 isAdmin")
	}
	// 普通用户读不到清单
	if code, _ := doJSON(t, h, "GET", "/api/v1/users/idle", userToken("li.fang"), nil); code != http.StatusForbidden {
		t.Fatal("非管理员应 403")
	}

	// 批量锁定（root 调用）：普通账号锁上；已锁定/不存在的如实跳过
	liID := byAcct["li.fang"]["id"].(string)
	code, out = doJSON(t, h, "POST", "/api/v1/users/idle/lock", adminToken(),
		map[string]any{"ids": []string{liID, "u4", "no-such"}})
	if code != http.StatusOK {
		t.Fatalf("batch lock http %d %v", code, out)
	}
	locked, _ := out["locked"].([]any)
	if len(locked) != 1 || locked[0] != "li.fang" {
		t.Fatalf("应只锁上 li.fang，实得 %v", locked)
	}
	skipped, _ := out["skipped"].([]any)
	if len(skipped) != 2 {
		t.Fatalf("u4（已锁定）与 no-such 应被跳过，实得 %v", skipped)
	}
	// 锁定真实生效：登录被拒
	_, lo := doJSON(t, h, "POST", "/api/v1/portal/login", "",
		map[string]string{"username": "li.fang", "password": "baidi@123"})
	if lo["token"] != nil || !strings.Contains(lo["reason"].(string), "锁定") {
		t.Fatalf("被锁账号应拒登录，实得 %v", lo)
	}
}

// 分权与防自锁在批量路径同样生效。
func TestIdleLockGuards(t *testing.T) {
	h := newTestServer(t)

	// root 建一个 security 角色的管理员
	_, atok := doJSON(t, h, "POST", "/api/v1/auth/login", "",
		map[string]string{"username": "admin", "password": "baidi@123"})
	rootTok, _ := atok["token"].(string)
	if code, _ := doJSON(t, h, "POST", "/api/v1/admins", rootTok,
		map[string]string{"account": "sec.op", "name": "安全专员", "roleKey": "security", "password": "baidi@123456"}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatal("建 security 管理员失败")
	}
	secTok := testKeys.Sign(auth.Claims{Sub: "sec.op", Role: "admin", Name: "sec.op"}, tokenTTL)

	// security 管理员批量锁定含管理员目标（zhang.wei=u1）→ 该目标被跳过（越权），普通目标照锁
	code, out := doJSON(t, h, "POST", "/api/v1/users/idle/lock", secTok,
		map[string]any{"ids": []string{"u1", "u3"}})
	if code != http.StatusOK {
		t.Fatalf("http %d %v", code, out)
	}
	locked, _ := out["locked"].([]any)
	skipped, _ := out["skipped"].([]any)
	if len(locked) != 1 || locked[0] != "wang.qiang" {
		t.Fatalf("普通目标应锁上，实得 %v", locked)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].(map[string]any)["reason"].(string), "管理员") {
		t.Fatalf("管理员目标应因越权被跳过，实得 %v", skipped)
	}

	// root 批量锁定全部管理员：防自锁保住最后一名可登录超管
	_, dir := doJSON(t, h, "GET", "/api/v1/users", rootTok, nil)
	adminIDs := []string{}
	for _, raw := range dir["users"].([]any) {
		m := raw.(map[string]any)
		if m["role"] == "admin" {
			adminIDs = append(adminIDs, m["id"].(string))
		}
	}
	if len(adminIDs) < 2 {
		t.Fatalf("种子应有至少两个管理员，实得 %v", adminIDs)
	}
	code, out = doJSON(t, h, "POST", "/api/v1/users/idle/lock", rootTok, map[string]any{"ids": adminIDs})
	if code != http.StatusOK {
		t.Fatalf("http %d", code)
	}
	skipped, _ = out["skipped"].([]any)
	selfLocked := false
	for _, raw := range skipped {
		if strings.Contains(raw.(map[string]any)["reason"].(string), "最后一名") {
			selfLocked = true
		}
	}
	if !selfLocked {
		t.Fatalf("最后一名超管应被防自锁拦下，实得 locked=%v skipped=%v", out["locked"], skipped)
	}
	// root 自己仍然登录得进（没把自己锁死）
	if _, lo := doJSON(t, h, "POST", "/api/v1/auth/login", "",
		map[string]string{"username": "admin", "password": "baidi@123"}); lo["token"] == nil {
		t.Fatalf("防自锁后 root 应仍可登录，实得 %v", lo)
	}
}
