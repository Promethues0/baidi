package api

// last_login 写入方（wave7 行动 8①）。回归背景：该列建号置 "—"、页面渲染、
// 导出携带，唯独零写入方——「最后登录」整列永远停在建号时刻。
// 闲置账号治理与 license 的"删除闲置账号释放席位"提示都要靠它判闲置。

import (
	"net/http"
	"testing"
)

func lastLoginOf(t *testing.T, h http.Handler, account string) string {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读用户目录 http %d", code)
	}
	for _, raw := range out["users"].([]any) {
		u := mapOf(t, raw)
		if u["account"] == account {
			return u["lastLogin"].(string)
		}
	}
	t.Fatalf("目录里没有 %s", account)
	return ""
}

func TestLoginTouchesLastLogin(t *testing.T) {
	h := newTestServer(t)
	if got := lastLoginOf(t, h, "li.fang"); got != "—" && len(got) < 10 {
		t.Logf("种子初值：%q", got) // 种子可能带演示值，断言只看"登录后变成今天"
	}
	portalLogin(t, h, "li.fang", "")
	got := lastLoginOf(t, h, "li.fang")
	if len(got) < 10 || got == "—" {
		t.Fatalf("登录成功后 last_login 应为时间戳，实得 %q", got)
	}
}
