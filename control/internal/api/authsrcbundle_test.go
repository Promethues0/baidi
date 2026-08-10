package api

// 认证源页顶部聚合（GET /api/v1/authsrc）的脱种子回归。
// 这一页此前最误导：下半截读真实配置，上半截还渲染 6 条硬编码源与「1160 用户」。

import (
	"net/http"
	"testing"
)

// 认证源聚合与 /authsrc/sources 读同一批库行，权限必须同档：
// 低一档就是给"接了哪些外部目录、各接进来多少人"开了条侧门。
func TestAuthSrcBundleRequiresAdmin(t *testing.T) {
	h := newTestServer(t)
	if code, _ := doJSON(t, h, "GET", "/api/v1/authsrc", userToken("li.fang"), nil); code != http.StatusForbidden {
		t.Errorf("普通用户读认证源聚合应 403，得到 %d", code)
	}
	code, out := doJSON(t, h, "GET", "/api/v1/authsrc", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("管理员读认证源聚合 http %d：%v", code, out)
	}
	srcs, _ := out["sources"].([]any)
	if len(srcs) != 1 {
		t.Fatalf("全新库应只有回填出的 local 一条，实得 %v", srcs)
	}
	src := mapOf(t, srcs[0])
	if src["key"] != "local" {
		t.Errorf("应为本地目录，实得 %+v", src)
	}
	if src["boundAccounts"].(float64) <= 0 {
		t.Errorf("本地目录应计出种子账号数，实得 %v", src["boundAccounts"])
	}
	// 编造的字段不许复活：status 恒 online、users 是凭空数字、primary 无对应概念。
	for _, k := range []string{"status", "users", "primary"} {
		if _, ok := src[k]; ok {
			t.Errorf("字段 %s 没有真实来源，不该出现在响应里", k)
		}
	}
	// 「自适应规则」不再由后端下发（真实生效的是认证策略，前端那套是明确标注的沙盘）。
	if _, ok := out["rules"]; ok {
		t.Error("rules 是与登录判定无关的第二套编造规则，不该再出现在响应里")
	}
}
