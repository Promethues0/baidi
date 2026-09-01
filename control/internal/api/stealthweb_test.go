package api

import (
	"strings"
	"testing"
)

// 「攻击面 = 0」这句正向安全断言必须把**已知敞着的**七层 Web 代理口算进去
// （PRD FR-SEC-SPA-02/05/12）。
//
// ★缺陷原样：allArmed 只看内核态隐身回执，而 L7 监听口**不受 SPA 隐身保护**
// （CLAUDE.md 端口表逐字写着，发布向导与网关启动日志也都告警过）——
// 内核态隐身只护住敲门口与隧道口。于是一台开着 `-web` 且 nft 规则装好的网关，
// 隐身页会同时显示「端口扫描全程超时，无任何端口可探测」与「攻击面 = 0」，
// 而 nmap 对着 18444 一扫一个准。这是这一页唯一一句正向安全断言。
func TestGatewayBundleReportsWebExposure(t *testing.T) {
	h, srv := newTestServerWithSrv(t)

	// 一台在线网关，开着 L7。
	srv.mu.Lock()
	srv.gateways["gw-web"] = GatewayInfo{
		Proxy: ":18443", SPA: ":18201", LastSeen: nowUnix(),
		Web: "0.0.0.0:18444", WebTLS: false,
	}
	srv.mu.Unlock()

	_, out := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if n, _ := out["webExposed"].(float64); int(n) != 1 {
		t.Fatalf("应报出 1 台敞着 L7 口的在线网关，got %v", out["webExposed"])
	}
	eps, _ := out["webEndpoints"].([]any)
	if len(eps) != 1 || !strings.Contains(eps[0].(string), "18444") {
		t.Fatalf("应点名是哪台、哪个口，got %v", out["webEndpoints"])
	}
	// 告警文案必须说清「不受 SPA 隐身保护」——只报个数字，页面无从知道该怎么讲。
	warns, _ := out["stealthWarnings"].([]any)
	hit := false
	for _, w := range warns {
		if strings.Contains(w.(string), "不受 SPA 隐身保护") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("敞着 L7 口时必须出一条说清「不受 SPA 隐身保护」的告警，got %v", out["stealthWarnings"])
	}

	// 反向：没开 L7 的网关不该被算进去（否则这条告警会变成常驻噪声）。
	srv.mu.Lock()
	delete(srv.gateways, "gw-web")
	srv.gateways["gw-plain"] = GatewayInfo{Proxy: ":18443", SPA: ":18201", LastSeen: nowUnix()}
	srv.mu.Unlock()
	_, out = doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if n, _ := out["webExposed"].(float64); int(n) != 0 {
		t.Fatalf("没开 -web 的网关不该计入敞口，got %v", out["webExposed"])
	}

	// 离线网关的上报是陈旧读数，同样不计入。
	srv.mu.Lock()
	srv.gateways["gw-stale"] = GatewayInfo{
		Proxy: ":18443", SPA: ":18201", LastSeen: nowUnix() - 99999, Web: "0.0.0.0:18444",
	}
	srv.mu.Unlock()
	_, out = doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if n, _ := out["webExposed"].(float64); int(n) != 0 {
		t.Fatalf("离线网关的 L7 上报是陈旧读数，不该计入，got %v", out["webExposed"])
	}
}
