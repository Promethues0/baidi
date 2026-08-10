package api

// 在线用户（GET /api/v1/online）的脱种子回归：
// 无网关上报时曾回退 10 条演示会话，现在是空态——安全读数宁可空着也不编。

import (
	"net/http"
	"testing"
)

// 无网关上报时，在线用户必须是空态且仍标 source=live——
// 「无人在线」与「10 条编造的会话」传达的安全含义完全相反。
func TestOnlineHasNoDemoFallback(t *testing.T) {
	h := newTestServer(t)

	code, out := doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读在线会话 http %d：%v", code, out)
	}
	sessions, _ := out["sessions"].([]any)
	if len(sessions) != 0 {
		t.Fatalf("没有网关上报，在线会话必须为空，实得 %v", sessions)
	}
	if out["source"] != "live" {
		t.Errorf("端点只有一个数据源（网关上报），source 应恒为 live，实得 %v", out["source"])
	}
}

// 演示种子里那些会话 id 已不存在：对它们发起"强制下线"必须 404，
// 而不是给一个虚构账号落一条处置审计、再把它写进封禁表挡住同名真人。
func TestKickRejectsUnknownSession(t *testing.T) {
	h := newTestServer(t)
	if code, out := doJSON(t, h, "POST", "/api/v1/online/s-1001/kick", adminToken(),
		map[string]any{"reason": "测试"}); code != http.StatusNotFound {
		t.Errorf("下线不存在的会话应 404，得到 %d %v", code, out)
	}
}

// 有真实上报时，在线会话按网关上报聚合，并可就近处置。
func TestOnlineListsGatewayReportedSessions(t *testing.T) {
	h, _ := gwReceiptServer(t)
	body := `{"id":"gw-1","proxy":":18443","spa":":18201",
	          "sessions":[{"ip":"10.0.0.9","user":"li.fang","role":"user","since":1754800000}]}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}
	code, out := doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读在线会话 http %d：%v", code, out)
	}
	sessions, _ := out["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("应列出网关上报的这一条会话，实得 %v", sessions)
	}
	se := mapOf(t, sessions[0])
	if se["account"] != "li.fang" || se["ip"] != "10.0.0.9" || se["gateway"] != "gw-1" {
		t.Errorf("会话字段必须来自网关上报，实得 %+v", se)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/online/"+se["id"].(string)+"/kick", adminToken(),
		map[string]any{"reason": "测试处置"}); code != http.StatusOK {
		t.Fatalf("下线真实会话应 200，得到 %d %v", code, out)
	}
}
