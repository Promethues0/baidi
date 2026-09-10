package api

import (
	"net/http"
	"strings"
	"testing"
)

// ── DNAT 自伤闸的入口侧（wave11 行动 13-①）与 DNAT 敞口（13-②）──

// natErrMsg 取错误信封里的中文原话。
func natErrMsg(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	m, _ := e["message"].(string)
	return m
}

// natRegister 让 gw-test 报一次心跳（可指定监听端口与 NAT/隐身运行态）。
func natRegister(t *testing.T, h http.Handler, extra map[string]any) {
	t.Helper()
	body := map[string]any{
		"id": "gw-test", "proxy": "127.0.0.1:18443", "spa": "127.0.0.1:18201",
		"ifaces": []map[string]any{
			{"name": "eth2", "addrs": []string{"5.5.10.102/16"}, "up": true},
			{"name": "eth3", "addrs": []string{"155.155.10.102/16"}, "up": true},
		},
	}
	for k, v := range extra {
		body[k] = v
	}
	code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), body)
	if code != http.StatusOK {
		t.Fatalf("网关注册 http %d", code)
	}
}

// natDnatBody 一条正常的发布规则（公网 9443 → 内网 5.5.20.30:8080）。
func natDnatBody() map[string]any {
	return map[string]any{
		"name": "发布 OA", "type": "dnat", "gatewayId": "gw-test",
		"srcIface": "eth3", "srcAddr": "0.0.0.0/0",
		"dstIface": "eth2", "dstAddr": "155.155.10.102", "protocol": "tcp",
		"dstPort": 9443, "translatedAddr": "5.5.20.30", "translatedPort": 8080,
		"enabled": true,
	}
}

// 把网关自己的隧道口 DNAT 发布出去：入口必须**拒绝**而不是挂一条告警。
// 改造前这条 200 OK、规则照灌 prerouting，页面上一个字都看不出来
// （NATWarnSPA 是常量字符串，它并不知道这条规则做了什么）。
func TestSelfPublishDnatRejectedAtEntry(t *testing.T) {
	h := newTestServer(t)
	natRegister(t, h, nil)
	natTypeIfaces(t, h)

	p := natDnatBody()
	p["translatedAddr"], p["translatedPort"] = "127.0.0.1", 18443
	code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), p)
	if code != http.StatusBadRequest {
		t.Fatalf("自伤 DNAT 应被入口拒绝，实得 http %d %v", code, out)
	}
	msg := natErrMsg(out)
	// 照 parsePeer 拒收 FQDN 的先例：拒绝要说得出**原因**，笼统的「格式不对」
	// 会让人反复换写法试。
	for _, want := range []string{"18443", "零信任隧道口"} {
		if !strings.Contains(msg, want) {
			t.Errorf("拒绝文案要点名端口与用途，缺「%s」：%s", want, msg)
		}
	}

	_, list := doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	if ps, _ := list["policies"].([]any); len(ps) != 0 {
		t.Fatalf("被拒的策略一条都不该落库，实际 %d 条", len(ps))
	}
}

// 判据必须取自**网关心跳里自报的监听端口**，不是写死的 18443/18201/18444。
// 写死的话，一台把 -proxy 换到 29443 的网关上，这道闸保护的就是别人。
func TestSelfPublishGateFollowsHeartbeatPorts(t *testing.T) {
	h := newTestServer(t)
	natRegister(t, h, map[string]any{"proxy": "127.0.0.1:29443"})
	natTypeIfaces(t, h)

	// 这台网关并不监听 18443，把它发布出去是正常业务。
	ok := natDnatBody()
	ok["translatedAddr"], ok["translatedPort"] = "5.5.20.30", 18443
	if code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), ok); code != http.StatusOK {
		t.Fatalf("网关没监听 18443 时不该被拒，实得 http %d %v", code, out)
	}

	// 29443 才是它真正的隧道口。
	bad := natDnatBody()
	bad["name"] = "自伤"
	bad["translatedAddr"], bad["translatedPort"] = "127.0.0.1", 29443
	code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), bad)
	if code != http.StatusBadRequest {
		t.Fatalf("换过端口后 29443 才是隧道口，应被拒，实得 http %d %v", code, out)
	}
	if !strings.Contains(natErrMsg(out), "29443") {
		t.Errorf("拒绝文案要点名网关**实际**监听的那个端口：%s", natErrMsg(out))
	}
}

// ② 「攻击面 = 0」的前提集补上 DNAT 发布的端口。
//
// 一条已灌进内核的 DNAT 本身就是在网关的公网地址上开一个端口，而 SPA 隐身
// 只写在 filter 表上、与 nat 表无关。此前网关页那段断言的前提集里只有七层 Web 口。
func TestGatewayPageCountsDnatExposure(t *testing.T) {
	h := newTestServer(t)
	natRegister(t, h, nil)
	natTypeIfaces(t, h)

	// 没有任何 DNAT 时：确定的零 + 已判定（不是"不可判定"）。
	_, page := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if page["natKnown"] != true {
		t.Fatalf("读得到策略表就该判定为已知，实得 natKnown=%v", page["natKnown"])
	}
	if n, _ := page["natExposed"].(float64); n != 0 {
		t.Fatalf("没有 DNAT 时敞口应为 0，实得 %v", n)
	}

	if code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), natDnatBody()); code != http.StatusOK {
		t.Fatalf("建 DNAT http %d %v", code, out)
	}

	// 网关还没上报 NAT 运行态：**判不出来**规则在没在内核里——既不算敞口，
	// 也不能拿去支撑「攻击面 = 0」。
	_, page = doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if n, _ := page["natExposed"].(float64); n != 0 {
		t.Fatalf("未上报运行态时不该算成已敞开，实得 %v", n)
	}
	if u, _ := page["natUnknown"].([]any); len(u) != 1 {
		t.Fatalf("未上报运行态应单列成不可判定，实得 %v", page["natUnknown"])
	}

	// 网关明确说「我没带 -nat 启动」：规则一条都不会进内核，这不是敞口。
	natRegister(t, h, map[string]any{"nat": map[string]any{"enabled": false}})
	_, page = doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if n, _ := page["natExposed"].(float64); n != 0 {
		t.Fatalf("网关没开 -nat 时规则不在内核里，不该算敞口，实得 %v", n)
	}
	if u, _ := page["natUnknown"].([]any); len(u) != 0 {
		t.Fatalf("网关明确说了没开，这是确定结论不是不可判定，实得 %v", page["natUnknown"])
	}

	// 网关回报已灌入内核：这才是真敞口，必须点名端点并顶出一条告警。
	natRegister(t, h, map[string]any{
		"nat": map[string]any{"enabled": true, "backend": "nftables", "applied": 1}})
	_, page = doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if n, _ := page["natExposed"].(float64); n != 1 {
		t.Fatalf("已灌入内核的 DNAT 应计入敞口，实得 %v", n)
	}
	eps, _ := page["natEndpoints"].([]any)
	if len(eps) != 1 || !strings.Contains(eps[0].(string), "155.155.10.102:9443") {
		t.Fatalf("敞口要点名到端点，实得 %v", page["natEndpoints"])
	}
	warns, _ := page["stealthWarnings"].([]any)
	hit := false
	for _, w := range warns {
		if s, _ := w.(string); strings.Contains(s, "不受 SPA 隐身保护") && strings.Contains(s, "DNAT") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("DNAT 敞口必须顶到页面告警上（文案由后端下发），实得 %v", warns)
	}
}

// 端到端：DNAT 敞口真的能把「攻击面 = 0」那句断言按下去。
//
// 前置把内核态隐身与七层口两条前提都做成"好"的，让这条用例只在**第三条前提**
// 上有区分度——否则它在改造前也会是绿的（那时两条老前提本来就不满足）。
func TestDnatExposureBreaksStealthClaim(t *testing.T) {
	h := newTestServer(t)
	// 内核态隐身实测生效（规则集在、保护的端口与自报隧道口一致）+ 地址转换已灌入内核。
	beat := func() {
		natRegister(t, h, map[string]any{
			"stealth": map[string]any{
				"wanted": true, "backend": "nftables(Linux)", "root": true,
				"ruleset": true, "guardedPort": 18443, "detail": "test",
			},
			"nat": map[string]any{"enabled": true, "backend": "nftables", "applied": 1},
		})
	}
	beat()
	natTypeIfaces(t, h)

	// 一条 DNAT 都没有：三条前提齐，断言成立。
	_, page := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if page["stealthClaimOk"] != true {
		t.Fatalf("隐身实测生效、无七层口、无 DNAT 时应给出「攻击面 = 0」，实得 %v（stealth=%v）",
			page["stealthClaimOk"], page["stealth"])
	}

	// 加一条已灌进内核的 DNAT：它在网关的公网地址上开着一个端口，断言不再成立。
	if code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), natDnatBody()); code != http.StatusOK {
		t.Fatalf("建 DNAT http %d %v", code, out)
	}
	beat() // 再报一次心跳，运行态不变
	_, page = doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if page["stealthClaimOk"] != false {
		t.Fatalf("有 DNAT 在公网上开着端口时不该再说「攻击面 = 0」，实得 %v", page["stealthClaimOk"])
	}
}
