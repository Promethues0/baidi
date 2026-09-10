package api

// 网关与隐身页（GET /api/v1/gateway）的脱种子回归。
//
// 这一页此前整页是 Memory 里的「华东/华南出口」四台主备节点（带负载条），
// 后端种子与前端 MOCK 两边都假、严丝合缝。下面的用例把空态与真实态都钉死，
// 并禁止那三个没有真实来源的维度（区域 / 主备角色 / 负载百分比）复活。

import (
	"net/http"
	"strings"
	"testing"
)

// 无网关注册时：网关页必须是**空态**，不能凭空长出区域拓扑。
func TestGatewayPageEmptyWithoutRegistration(t *testing.T) {
	h := newTestServer(t)

	code, out := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读网关页 http %d：%v", code, out)
	}
	nodes, _ := out["nodes"].([]any)
	if len(nodes) != 0 {
		t.Fatalf("一台网关都没注册，节点列表必须为空，实得 %v", nodes)
	}
	if out["total"].(float64) != 0 || out["online"].(float64) != 0 {
		t.Errorf("注册数/在线数应均为 0，实得 total=%v online=%v", out["total"], out["online"])
	}
	// 敲门令牌 TTL 是控制面自身的真实常量，任何时候都该有值（页面据此说明敲门口径）。
	if out["knockTokenTtlSec"].(float64) <= 0 {
		t.Errorf("敲门令牌 TTL 应为控制面真实常量，实得 %v", out["knockTokenTtlSec"])
	}
	if out["onlineWindowSec"].(float64) <= 0 {
		t.Errorf("在线判定窗口应下发给前端（否则'在线'二字没有判据），实得 %v", out["onlineWindowSec"])
	}
	// 编造的区域拓扑不许以任何形式复活。
	if _, ok := out["zones"]; ok {
		t.Error("区域拓扑（zones）没有真实来源，不该再出现在响应里")
	}
}

// 注册一次心跳后：节点列表的每一项都必须等于网关自报的那份，不做任何美化。
func TestGatewayPageReflectsRegisteredHeartbeat(t *testing.T) {
	h, _ := gwReceiptServer(t)
	body := `{"id":"gw-page-1","proxy":":18443","spa":":18201","clients":3,"tunnels":2,
	          "uptime":600,"version":"v1.2.3",
	          "sessions":[{"ip":"10.0.0.9","user":"li.fang","role":"user","since":1754800000}]}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}

	code, out := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读网关页 http %d：%v", code, out)
	}
	nodes, _ := out["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("应恰好列出这一台注册网关，实得 %v", nodes)
	}
	n := mapOf(t, nodes[0])
	if n["id"] != "gw-page-1" || n["proxy"] != ":18443" || n["spa"] != ":18201" {
		t.Errorf("落点必须是网关自报的那份，实得 %+v", n)
	}
	if n["version"] != "v1.2.3" {
		t.Errorf("版本必须来自心跳，实得 %v", n["version"])
	}
	if n["online"] != true {
		t.Error("刚上报的心跳应判为在线")
	}
	if n["clients"].(float64) != 3 || n["tunnels"].(float64) != 2 || n["sessions"].(float64) != 1 {
		t.Errorf("计数必须来自心跳，实得 clients=%v tunnels=%v sessions=%v", n["clients"], n["tunnels"], n["sessions"])
	}
	// 无真实来源的维度不许回来：区域、主备角色、负载百分比。
	for _, k := range []string{"zone", "role", "loadPct"} {
		if _, ok := n[k]; ok {
			t.Errorf("字段 %s 没有真实来源（无区域概念/无选主/无负载采集），不该出现", k)
		}
	}
	if out["total"].(float64) != 1 || out["online"].(float64) != 1 || out["sessions"].(float64) != 1 {
		t.Errorf("汇总计数应与节点一致，实得 %+v", out)
	}
}

// 网关落点属敏感拓扑：普通用户读不到（与 GET /api/v1/gateways 同档）。
func TestGatewayPageRequiresAdmin(t *testing.T) {
	h := newTestServer(t)
	if code, _ := doJSON(t, h, "GET", "/api/v1/gateway", userToken("li.fang"), nil); code != http.StatusForbidden {
		t.Errorf("普通用户读网关页应 403，得到 %d", code)
	}
}

// ── wave11 行动 3：L4 隧道身份姿态的三态必须在网关页上分得开 ──
//
// ★三种姿态在页面上长得一样是最坏的结果：一台停在旧信任模型上的网关（按源 IP 定身份）
// 与一台已收口的网关如果都不出告警，管理员永远不会去升级它——而在它上面，
// 同一出口下任意主机在放行窗内直连隧道口就继承别人的授权。
func TestGatewayPageTunnelIDPosture(t *testing.T) {
	warn := func(t *testing.T, body string) []string {
		t.Helper()
		h, _ := gwReceiptServer(t)
		if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
			t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
		}
		code, out := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
		if code != http.StatusOK {
			t.Fatalf("读网关页 http %d：%v", code, out)
		}
		arr, _ := out["tunnelIdWarnings"].([]any)
		got := make([]string, 0, len(arr))
		for _, v := range arr {
			got = append(got, v.(string))
		}
		return got
	}

	// ① 已收口（明确 true）：不出告警——这一页不为正常态加噪声。
	if got := warn(t, `{"id":"gw-strict","proxy":":18443","spa":":18201","tunnelIdStrict":true}`); len(got) != 0 {
		t.Errorf("严格模式开着时不该出告警，实得 %v", got)
	}
	// ② 逃生舱开着（明确 false）：必须点名网关并说清风险与关回的路。
	got := warn(t, `{"id":"gw-loose","proxy":":18443","spa":":18201","tunnelIdStrict":false}`)
	if len(got) != 1 || !strings.Contains(got[0], "gw-loose") {
		t.Fatalf("逃生舱开着必须逐台点名告警，实得 %v", got)
	}
	for _, want := range []string{"源 IP", "继承"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("告警要说清后果（含 %q），实得：%s", want, got[0])
		}
	}
	// ③ 旧网关根本不报（字段缺席）：**不可判定**，同样要出一条——
	// 静默通过等于替一台按旧模型在跑的网关背书。
	got = warn(t, `{"id":"gw-old","proxy":":18443","spa":":18201"}`)
	if len(got) != 1 || !strings.Contains(got[0], "gw-old") || !strings.Contains(got[0], "无从判断") {
		t.Fatalf("旧网关不上报姿态时应如实报「不可判定」，实得 %v", got)
	}
}
