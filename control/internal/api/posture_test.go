package api

import (
	"net/http"
	"testing"
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
