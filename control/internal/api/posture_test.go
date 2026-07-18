package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// 基线 CRUD：admin 可保存/删除；非法枚举 400；非 admin 403。
func TestBaselineCRUD(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	body := map[string]any{"name": "外包收紧基线", "type": "onboarding", "disposal": "block", "status": "enabled",
		"platforms": []string{"macOS"},
		"checks":    []map[string]string{{"key": "disk_encrypted", "label": "磁盘已加密", "platform": "All", "severity": "high"}}}
	code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adm, body)
	if code != http.StatusOK {
		t.Fatalf("save http %d: %v", code, out)
	}
	id := out["baseline"].(map[string]any)["id"].(string)
	if id == "" {
		t.Fatal("应生成 id")
	}

	// GET /security 反映新基线（3 条 = 2 种子 + 1 新建）
	code, sec := doJSON(t, h, "GET", "/api/v1/security", adm, nil)
	if code != http.StatusOK || len(sec["baselines"].([]any)) != 3 {
		t.Fatalf("security 应 3 条基线: %v", sec["baselines"])
	}

	// 非法 disposal 400
	bad := map[string]any{"name": "x", "type": "onboarding", "disposal": "nuke", "status": "enabled"}
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/baselines", adm, bad); code != http.StatusBadRequest {
		t.Fatalf("非法 disposal 应 400, got %d", code)
	}
	// 非 admin 403
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/baselines", userToken("li.fang"), body); code != http.StatusForbidden {
		t.Fatalf("user 保存基线应 403, got %d", code)
	}
	// 删除
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/security/baselines/"+id, adm, nil); code != http.StatusOK {
		t.Fatalf("delete 应 200, got %d", code)
	}
	_, sec = doJSON(t, h, "GET", "/api/v1/security", adm, nil)
	if len(sec["baselines"].([]any)) != 2 {
		t.Fatal("删后应回 2 条")
	}
}

// goodPosture / badPosture 上报体 helper（bad = 磁盘未加密 → 接入准入基线 block）。
func posturePayload(diskOK bool) map[string]any {
	return map[string]any{"device": "DEV-A", "platform": "macOS", "os": "macOS 14.4", "clientVersion": "0.1.0",
		"checks": []map[string]any{
			{"key": "disk_encrypted", "label": "磁盘已加密", "ok": diskOK, "value": "x"},
			{"key": "sys_integrity", "label": "系统完整性保护开启", "ok": true, "value": "enabled"},
			{"key": "firewall_on", "label": "系统防火墙启用", "ok": true, "value": "enabled"},
			{"key": "os_version", "label": "系统版本合规", "ok": true, "value": "14.4"},
			{"key": "edr_online", "label": "EDR 终端防护在线", "ok": true, "value": "falcond"},
			{"key": "client_version", "label": "客户端为最新版本", "ok": true, "value": "0.1.0"},
		}}
}
func goodPosture() map[string]any { return posturePayload(true) }
func badPosture() map[string]any  { return posturePayload(false) }

// 上报→评估落库→verdict 回传；gateway 角色拒；非 admin 读 403；输入校验。
func TestPostureReportAndList(t *testing.T) {
	h := newTestServer(t)
	tok := userToken("li.fang")

	code, out := doJSON(t, h, "POST", "/api/v1/posture", tok, goodPosture())
	if code != http.StatusOK || out["verdict"] != "allow" {
		t.Fatalf("合规上报应 allow: %d %v", code, out)
	}
	code, out = doJSON(t, h, "POST", "/api/v1/posture", tok, badPosture())
	if code != http.StatusOK || out["verdict"] != "block" || out["level"] != "high" {
		t.Fatalf("磁盘未加密应 block/high: %v", out)
	}

	// admin 读清单；user 读 403；gateway 上报 403
	code, list := doJSON(t, h, "GET", "/api/v1/posture", adminToken(), nil)
	if code != http.StatusOK || len(list["reports"].([]any)) != 1 {
		t.Fatalf("清单应 1 行: %d %v", code, list)
	}
	if code, _ := doJSON(t, h, "GET", "/api/v1/posture", tok, nil); code != http.StatusForbidden {
		t.Fatalf("user 读清单应 403, got %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/posture", gatewayToken(), goodPosture()); code != http.StatusForbidden {
		t.Fatalf("gateway 角色上报应 403, got %d", code)
	}
	// 校验：device 缺失 400、检查数超限 400
	if code, _ := doJSON(t, h, "POST", "/api/v1/posture", tok, map[string]any{"platform": "macOS"}); code != http.StatusBadRequest {
		t.Fatalf("缺 device 应 400, got %d", code)
	}
	many := make([]map[string]any, 33)
	for i := range many {
		many[i] = map[string]any{"key": "k", "label": "l", "ok": true}
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/posture", tok, map[string]any{"device": "D", "platform": "macOS", "checks": many}); code != http.StatusBadRequest {
		t.Fatalf("检查超 32 应 400, got %d", code)
	}
}

// 持续验证闭环：坏报告 → 拒发敲门令牌 + 网关策略并入撤销名单 → 合规报告 → 双双解除。
func TestPostureBlockClosesLoop(t *testing.T) {
	h := newTestServer(t)
	tok := userToken("li.fang")

	// 初始：可拿令牌、不在撤销名单
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusOK {
		t.Fatalf("初始应可拿令牌, got %d", code)
	}
	if revokedUsers(t, h)["li.fang"] {
		t.Fatal("初始不应在撤销名单")
	}
	// 坏报告（磁盘未加密 → block）
	if code, out := doJSON(t, h, "POST", "/api/v1/posture", tok, badPosture()); code != 200 || out["verdict"] != "block" {
		t.Fatalf("坏报告应 block: %v", out)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusForbidden {
		t.Fatalf("block 后应 403, got %d", code)
	}
	if !revokedUsers(t, h)["li.fang"] {
		t.Fatal("block 用户应并入网关撤销名单（堵 8h 会话令牌直连洞）")
	}
	// 合规报告 → 恢复
	if code, out := doJSON(t, h, "POST", "/api/v1/posture", tok, goodPosture()); code != 200 || out["verdict"] != "allow" {
		t.Fatalf("合规报告应 allow: %v", out)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusOK {
		t.Fatalf("恢复后应可拿令牌, got %d", code)
	}
	if revokedUsers(t, h)["li.fang"] {
		t.Fatal("恢复后应移出撤销名单")
	}
}

// strict 模式：无新鲜报告拒发令牌；observe（默认）放行（上面闭环用例已覆盖默认放行）。
func TestPostureStrictMode(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testSecret, "test")
	s.postureStrict = true
	h := auth.Middleware(testSecret, s.IsOpen)(s.Routes())
	tok := userToken("li.fang")

	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusForbidden {
		t.Fatalf("strict 缺报应 403, got %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/posture", tok, goodPosture()); code != 200 {
		t.Fatal("上报失败")
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusOK {
		t.Fatalf("strict 有新鲜合规报告应 200, got %d", code)
	}
}
