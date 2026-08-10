package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// 登录防爆破主流程：配置真实生效 → 连续 5 次错口令后第 6 次被拒（正确口令也拒）→
// 锁定写审计 + 用户态势叠加 → admin 列锁/解锁（非 admin 403）→ 解锁后立即可登录。
func TestLoginLockoutFlow(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	// 先关 IP 维度：httptest 所有请求同源 IP，不关会先触发 IP 锁、盖住账号锁的断言——
	// 这次 PUT 同时就是「配置有真实消费方」的证明。
	cfg := map[string]any{"threshold": 5, "windowSec": 600, "durationSec": 900, "ipEnabled": false, "accountEnabled": true}
	if code, out := doJSON(t, h, "PUT", "/api/v1/security/lockout-config", adm, cfg); code != http.StatusOK {
		t.Fatalf("保存配置应 200: %d %v", code, out)
	}
	// GET 回读生效值
	if code, out := doJSON(t, h, "GET", "/api/v1/security/lockout-config", adm, nil); code != http.StatusOK ||
		out["threshold"].(float64) != 5 || out["ipEnabled"].(bool) != false {
		t.Fatalf("配置回读: %d %v", code, out)
	}

	wrong := map[string]string{"username": "li.fang", "password": "wrong-pw"}
	right := map[string]string{"username": "li.fang", "password": "baidi@123"}
	for i := 0; i < 5; i++ {
		code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", wrong)
		if code != http.StatusOK || out["ok"] == true {
			t.Fatalf("第 %d 次错口令应 200+ok=false: %d %v", i+1, code, out)
		}
	}
	// 第 6 次：错口令 403；锁定期内正确口令也 403；管理台入口同样被拦
	if code, _ := doJSON(t, h, "POST", "/api/v1/portal/login", "", wrong); code != http.StatusForbidden {
		t.Fatalf("锁定后错口令应 403, got %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/portal/login", "", right); code != http.StatusForbidden {
		t.Fatalf("锁定期内正确口令也应 403, got %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/auth/login", "", right); code != http.StatusForbidden {
		t.Fatalf("管理台登录口同样应查锁 403, got %d", code)
	}

	// 锁定触发写了审计（category=security）
	_, ab := doJSON(t, h, "GET", "/api/v1/audit", adm, nil)
	foundAudit := false
	for _, it := range ab["logs"].([]any) {
		m := it.(map[string]any)
		if strings.Contains(m["event"].(string), "触发登录防爆破锁定") && m["category"] == "security" {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatal("锁定触发应写 security 审计")
	}

	// 用户态势叠加：li.fang 目录状态仍 active（不在受关注清单）→ 合成 bruteLocked 行 + locked 桶计数
	_, us := doJSON(t, h, "GET", "/api/v1/userstate", adm, nil)
	foundItem := false
	for _, it := range us["items"].([]any) {
		m := it.(map[string]any)
		if m["account"] == "li.fang" && m["bruteLocked"] == true && m["state"] == "locked" {
			foundItem = true
		}
	}
	if !foundItem {
		t.Fatalf("用户态势应叠加爆破锁定行: %v", us["items"])
	}

	// admin 列锁：恰 1 条账号锁；非 admin 全部 403
	code, lo := doJSON(t, h, "GET", "/api/v1/security/lockouts", adm, nil)
	arr := lo["lockouts"].([]any)
	if code != http.StatusOK || len(arr) != 1 {
		t.Fatalf("应列出 1 条锁定: %d %v", code, lo)
	}
	if m := arr[0].(map[string]any); m["kind"] != "account" || m["key"] != "li.fang" {
		t.Fatalf("锁定条目: %v", m)
	}
	utok := userToken("zhang.san")
	if code, _ := doJSON(t, h, "GET", "/api/v1/security/lockouts", utok, nil); code != http.StatusForbidden {
		t.Fatalf("user 列锁应 403, got %d", code)
	}
	unlockBody := map[string]string{"kind": "account", "key": "li.fang"}
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/lockouts/unlock", utok, unlockBody); code != http.StatusForbidden {
		t.Fatalf("user 解锁应 403, got %d", code)
	}
	if code, _ := doJSON(t, h, "PUT", "/api/v1/security/lockout-config", utok, cfg); code != http.StatusForbidden {
		t.Fatalf("user 改配置应 403, got %d", code)
	}
	// 非法 kind 400
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/lockouts/unlock", adm, map[string]string{"kind": "mac", "key": "x"}); code != http.StatusBadRequest {
		t.Fatalf("非法 kind 应 400, got %d", code)
	}

	// 解锁 → 立即可登录；重复解锁 404
	if code, out := doJSON(t, h, "POST", "/api/v1/security/lockouts/unlock", adm, unlockBody); code != http.StatusOK {
		t.Fatalf("解锁应 200: %d %v", code, out)
	}
	if out := portalLogin(t, h, "li.fang", ""); out["ok"] != true {
		t.Fatalf("解锁后应立即可登录: %v", out)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/lockouts/unlock", adm, unlockBody); code != http.StatusNotFound {
		t.Fatalf("重复解锁应 404, got %d", code)
	}
}

// 成功登录清零账号计数：4 错 + 1 成 + 4 错不触发锁（若不清零，累计第 5 次就锁了）。
func TestLockoutCounterResetOnSuccess(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()
	cfg := map[string]any{"threshold": 5, "windowSec": 600, "durationSec": 900, "ipEnabled": false, "accountEnabled": true}
	if code, _ := doJSON(t, h, "PUT", "/api/v1/security/lockout-config", adm, cfg); code != http.StatusOK {
		t.Fatal("保存配置失败")
	}
	wrong := map[string]string{"username": "li.fang", "password": "wrong-pw"}
	for i := 0; i < 4; i++ {
		doJSON(t, h, "POST", "/api/v1/portal/login", "", wrong)
	}
	if out := portalLogin(t, h, "li.fang", ""); out["ok"] != true {
		t.Fatalf("4 次失败后正确口令应过: %v", out)
	}
	for i := 0; i < 4; i++ {
		code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", wrong)
		if code != http.StatusOK || out["ok"] == true {
			t.Fatalf("成功后计数应清零，第 %d 次失败不应触发锁: %d %v", i+1, code, out)
		}
	}
	if out := portalLogin(t, h, "li.fang", ""); out["ok"] != true {
		t.Fatalf("仍应可登录: %v", out)
	}
}

// IP 维度（默认开启）：同一源 IP 换着账号爆破，5 次即锁整个 IP——
// 之后连正确口令的存在账号也被拦；解锁 IP 后恢复。
func TestIPLockoutAcrossAccounts(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()
	for i := 0; i < 5; i++ {
		body := map[string]string{"username": fmt.Sprintf("ghost%d", i), "password": "x"}
		if code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", body); code != http.StatusOK || out["ok"] == true {
			t.Fatalf("第 %d 次: %d %v", i+1, code, out)
		}
	}
	right := map[string]string{"username": "li.fang", "password": "baidi@123"}
	if code, _ := doJSON(t, h, "POST", "/api/v1/portal/login", "", right); code != http.StatusForbidden {
		t.Fatalf("IP 锁后任意账号应 403, got %d", code)
	}
	// httptest 默认 RemoteAddr 192.0.2.1（不在信任代理网段，XFF 不采信）
	_, lo := doJSON(t, h, "GET", "/api/v1/security/lockouts", adm, nil)
	foundIP := false
	for _, it := range lo["lockouts"].([]any) {
		m := it.(map[string]any)
		if m["kind"] == "ip" && m["key"] == "192.0.2.1" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("应有 192.0.2.1 的 IP 锁: %v", lo)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/lockouts/unlock", adm, map[string]string{"kind": "ip", "key": "192.0.2.1"}); code != http.StatusOK {
		t.Fatal("解 IP 锁失败")
	}
	if out := portalLogin(t, h, "li.fang", ""); out["ok"] != true {
		t.Fatalf("解 IP 锁后应可登录: %v", out)
	}
}

// brokenAuthSrcStore 让外部认证源查询直接故障（模拟目录挂了）。
type brokenAuthSrcStore struct{ *store.SQLiteStore }

func (b *brokenAuthSrcStore) AuthSources(context.Context) ([]store.AuthSourceRec, error) {
	return nil, errors.New("外部目录不可用")
}

// 认证源故障不计数：故障 ≠ 密码错误（login_authsrc.go 既有约定），用户什么都没做错，
// 连续多次也不该把他锁出去。
func TestAuthSourceFailureNotCounted(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(&brokenAuthSrcStore{st}, st, testKeys, "test", t.TempDir(), nil, nil, true)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	wrong := map[string]string{"username": "li.fang", "password": "wrong-pw"}
	for i := 0; i < 6; i++ {
		code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", wrong)
		if code != http.StatusOK || out["ok"] == true {
			t.Fatalf("第 %d 次: %d %v", i+1, code, out)
		}
		if reason, _ := out["reason"].(string); !strings.Contains(reason, "认证服务暂时不可用") {
			t.Fatalf("认证源故障应回服务不可用而非密码错误: %v", out)
		}
	}
	// 6 次「失败」后既无账号锁也无 IP 锁：正确口令直接成功
	if out := portalLogin(t, h, "li.fang", ""); out["ok"] != true {
		t.Fatalf("认证源故障不该累计锁定: %v", out)
	}
	_, lo := doJSON(t, h, "GET", "/api/v1/security/lockouts", adminToken(), nil)
	if arr := lo["lockouts"].([]any); len(arr) != 0 {
		t.Fatalf("不应有任何锁定: %v", arr)
	}
}
