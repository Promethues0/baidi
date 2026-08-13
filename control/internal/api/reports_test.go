package api

// 运营报表的权限与参数面。聚合数学在 store 层测；这里钉三权分立与参数纪律。

import (
	"net/http"
	"testing"
)

func TestOpsReportPermissions(t *testing.T) {
	h := newTestServer(t)

	// 审计管理员读得到；root 也读得到。
	audTok := makeAdmin(t, h, "aud.report", "audit")
	if code, out := doJSON(t, h, "GET", "/api/v1/audit/report", audTok, nil); code != http.StatusOK {
		t.Fatalf("审计管理员读报表应 200，实得 %d %v", code, out)
	}
	if code, _ := doJSON(t, h, "GET", "/api/v1/audit/report", adminToken(), nil); code != http.StatusOK {
		t.Fatalf("root 读报表应 200，实得 %d", code)
	}
	// ★安全/系统管理员读不到：报表是聚合过的审计正文，聚合并不脱敏。
	// 给 security 开这个口，三权分立里"安全管理员读不到审计"就只剩字面成立。
	for _, power := range []string{"security", "system"} {
		tok := makeAdmin(t, h, power+".noreport", power)
		if code, _ := doJSON(t, h, "GET", "/api/v1/audit/report", tok, nil); code != http.StatusForbidden {
			t.Errorf("%s 管理员读报表应 403，实得 %d", power, code)
		}
	}
	// 普通用户 403。
	if code, _ := doJSON(t, h, "GET", "/api/v1/audit/report", userTokenFor("zhang.wei"), nil); code != http.StatusForbidden {
		t.Error("普通用户读报表应 403")
	}
}

func TestOpsReportDaysValidation(t *testing.T) {
	h := newTestServer(t)
	// 拼错的窗口明确 400，不静默回落（一个静默换掉的窗口会让人对着 7 天的表讨论"这个月"）。
	if code, _ := doJSON(t, h, "GET", "/api/v1/audit/report?days=90", adminToken(), nil); code != http.StatusBadRequest {
		t.Error("days=90 应 400")
	}
	code, out := doJSON(t, h, "GET", "/api/v1/audit/report?days=7", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("days=7 应 200，实得 %d %v", code, out)
	}
	if daily, _ := out["daily"].([]any); len(daily) != 7 {
		t.Errorf("7 天窗口应回 7 行（零日补全），实得 %d", len(out["daily"].([]any)))
	}
	// 告警段固定三档（前端按档渲染，缺档就是 undefined 渲染错）。
	al := mapOf(t, out["alerts"])
	if sv, _ := al["bySeverity"].([]any); len(sv) != 3 {
		t.Errorf("bySeverity 应固定三档，实得 %v", al["bySeverity"])
	}
}
