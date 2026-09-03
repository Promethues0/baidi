package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// ── 网关对外接入地址（wave8 行动 4，PRD FR-SCEN-08/17）──
//
// 改造前剖面里的落点主机名是从网关自报的**监听地址**反推的，而网关默认监听
// ':18201'（不带 host）→ 必然落进全局兜底 127.0.0.1，而 deploy 全程不设那个环境变量。
// 两个后果都完全静默：
//   ① 客户端拨号超时，控制台显示在线、剖面 warnings 一条不报；
//   ② 多台网关共用同一兜底 host → 客户端「切到落点 2/3」拨的还是同一台机器，
//      故障转移在页面上可见、在网络上不存在。
//
// ★既有的 failover_test.go 所有用例都给显式 host（`SPA: host+":18201"`），
// 兜底折叠这条路径此前**零测试覆盖**——这也是它能一直活着的原因。

// regGateway 让一台网关注册上来。spa 传 ":18201" 即复刻默认配置（不带 host）。
func regGatewayHB(t *testing.T, f *isoFixture, id, spa string) {
	t.Helper()
	code, out := doJSON(t, f.h, "POST", "/api/v1/gateways/register", gatewayToken(),
		map[string]any{"id": id, "proxy": ":18443", "spa": spa, "version": "v0.5.0"})
	if code != http.StatusOK {
		t.Fatalf("网关 %s 注册 http %d: %v", id, code, out)
	}
}

// profileEndpoints 拉一次剖面，返回落点清单与 warnings。
func profileEndpoints(t *testing.T, f *isoFixture) (hosts []string, ids []string, warns []string) {
	t.Helper()
	code, out := doJSON(t, f.h, "GET", "/api/v1/client/profile", userToken("li.fang"), nil)
	if code != http.StatusOK {
		t.Fatalf("client/profile http %d: %v", code, out)
	}
	arr, _ := out["gateways"].([]any)
	for _, it := range arr {
		g, _ := it.(map[string]any)
		hosts = append(hosts, asStr(g["host"]))
		ids = append(ids, asStr(g["id"]))
	}
	return hosts, ids, strSlice(out["warnings"])
}

func setAccess(t *testing.T, f *isoFixture, id, lan, wan string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, f.h, "PUT", "/api/v1/gateway/"+id+"/access", adminToken(),
		map[string]any{"lanHost": lan, "wanHost": wan})
}

// ★核心用例①：默认配置（网关 bind ':18201'）下落点会折叠成兜底地址——
// 这本身改不了（控制面确实不知道网关对外是什么地址），但**必须当面说**。
// 改造前这里一条 warning 都没有，客户端拨 127.0.0.1 超时而控制台一切正常。
func TestGatewayAccess_未登记地址必须告警而不是静默兜底(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-1", ":18201") // 复刻 install-remote.sh 装出来的默认形态

	hosts, _, warns := profileEndpoints(t, f)
	if len(hosts) != 1 {
		t.Fatalf("应有一个落点，实得 %v", hosts)
	}
	if hosts[0] != "127.0.0.1" {
		t.Fatalf("前提变了：默认配置下应落进兜底 127.0.0.1，实得 %q", hosts[0])
	}
	joined := strings.Join(warns, " | ")
	if !strings.Contains(joined, "gw-1") || !strings.Contains(joined, "对外接入地址") {
		t.Fatalf("★必须点名这台网关没登记地址（否则客户端拨号超时而控制台一切正常），实得 warnings=%v", warns)
	}
	// 回环地址还要单独说一句：它比「没登记」更确定地不通。
	if !strings.Contains(joined, "回环") {
		t.Fatalf("落点是回环地址时必须单独指出，实得 %v", warns)
	}
}

// ★核心用例②：多台网关共用同一兜底 host —— 故障转移在页面上可见、在网络上不存在。
func TestGatewayAccess_多落点同址必须点破故障转移是假的(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-a", ":18201")
	regGatewayHB(t, f, "gw-b", ":18201")

	hosts, ids, warns := profileEndpoints(t, f)
	if len(hosts) != 2 {
		t.Fatalf("应有两个落点，实得 %v", hosts)
	}
	if hosts[0] != hosts[1] {
		t.Fatalf("前提变了：两台默认配置的网关应折叠到同一 host，实得 %v", hosts)
	}
	joined := strings.Join(warns, " | ")
	if !strings.Contains(joined, "落点地址相同") {
		t.Fatalf("★必须点破「切换落点拨的还是同一台机器」，实得 warnings=%v（落点 %v/%v）", warns, ids, hosts)
	}
	for _, id := range []string{"gw-a", "gw-b"} {
		if !strings.Contains(joined, id) {
			t.Fatalf("告警应点名涉及的网关（缺 %s）：%v", id, warns)
		}
	}
}

// 登记地址后：落点用登记值，且上面两条告警都消失。
func TestGatewayAccess_登记后落点用真实地址且告警消失(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-a", ":18201")
	regGatewayHB(t, f, "gw-b", ":18201")
	if code, out := setAccess(t, f, "gw-a", "", "gw-a.example.com"); code != http.StatusOK {
		t.Fatalf("登记 gw-a http %d: %v", code, out)
	}
	if code, out := setAccess(t, f, "gw-b", "", "gw-b.example.com"); code != http.StatusOK {
		t.Fatalf("登记 gw-b http %d: %v", code, out)
	}
	hosts, _, warns := profileEndpoints(t, f)
	want := map[string]bool{"gw-a.example.com": true, "gw-b.example.com": true}
	for _, h := range hosts {
		if !want[h] {
			t.Fatalf("落点应用登记地址，实得 %v", hosts)
		}
	}
	joined := strings.Join(warns, " | ")
	for _, bad := range []string{"对外接入地址", "回环", "落点地址相同"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("登记之后不该再报「%s」：%v", bad, warns)
		}
	}
}

// PRD FR-SCEN-17 的两栏：都登记时各下发一个落点，**内网在前**且顺序确定。
// 顺序不确定的话，客户端每次拉剖面都可能换首选地址，表现为隧道莫名重连。
func TestGatewayAccess_内外网两栏各下发一个落点且内网在前(t *testing.T) {
	f := newIsoFixture(t)
	// ★用多台网关，不是一台。sort.Slice 不是稳定排序：元素少时它退化成插入排序、
	// 恰好保住 append 顺序，于是「比较器里有没有 kind 这一维」根本看不出来
	// （第一版用一台网关，把比较器改成恒 false 也照样绿）。元素多到触发 pdqsort
	// 才会真的重排等价元素，这一维才被验到。
	const n = 8
	want := make([]string, 0, n*2)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("gw-%02d", i)
		regGatewayHB(t, f, id, ":18201")
		lan, wan := fmt.Sprintf("10.0.%d.9", i), fmt.Sprintf("%s.example.com", id)
		if code, out := setAccess(t, f, id, lan, wan); code != http.StatusOK {
			t.Fatalf("登记 %s http %d: %v", id, code, out)
		}
		want = append(want, lan, wan) // 期望序：id 字典序，同 id 内网在前
	}
	for round := 0; round < 3; round++ { // 多拉几次：确定性不能靠 map 迭代运气
		hosts, ids, _ := profileEndpoints(t, f)
		if len(hosts) != n*2 {
			t.Fatalf("第 %d 轮：应有 %d 个落点，实得 %d 个 %v", round+1, n*2, len(hosts), hosts)
		}
		for i := range want {
			if hosts[i] != want[i] {
				t.Fatalf("第 %d 轮落点第 %d 位应为 %q（id 字典序 + 同网关内网在前），实得 %q\n完整序：%v",
					round+1, i, want[i], hosts[i], hosts)
			}
		}
		// 同一台网关的两个落点 id 相同——它们确实是同一台机器的两个地址
		if ids[0] != ids[1] || ids[0] != "gw-00" {
			t.Fatalf("同一网关的两个落点 id 应一致：%v", ids[:2])
		}
	}
	// 单数字段恒等于 gateways[0]（存量终端只读它，这条纪律不许破）
	code, out := doJSON(t, f.h, "GET", "/api/v1/client/profile", userToken("li.fang"), nil)
	if code != http.StatusOK {
		t.Fatalf("profile http %d", code)
	}
	g, _ := out["gateway"].(map[string]any)
	if asStr(g["host"]) != want[0] {
		t.Fatalf("单数 gateway 字段必须等于 gateways[0]，实得 %v", g["host"])
	}
}

// 网关显式 bind 了地址时用自报值——它至少是个真实地址，比全局兜底可信，且不该报警。
func TestGatewayAccess_网关显式bind地址时沿用自报值(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-1", "203.0.113.9:18201")
	hosts, _, warns := profileEndpoints(t, f)
	if len(hosts) != 1 || hosts[0] != "203.0.113.9" {
		t.Fatalf("应沿用自报地址，实得 %v", hosts)
	}
	if j := strings.Join(warns, " | "); strings.Contains(j, "对外接入地址") {
		t.Fatalf("自报了真实地址就不该报「未登记」：%v", warns)
	}
}

// 入口校验：带端口 / 带协议 / 回环 / 通配 一律当面拒绝。
// ★回环那条尤其重要——它正是旧兜底的默认值，不拦的话管理员会照着旧行为抄一遍。
func TestGatewayAccess_入口拒绝必然连不通的地址(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-1", ":18201")
	for _, tc := range []struct{ host, why string }{
		{"127.0.0.1", "回环地址只有网关本机连得上"},
		{"::1", "IPv6 回环同理"},
		{"0.0.0.0", "通配监听地址不是客户端能连的地址"},
		// ★以下四条是 silent-2 / security-2 补的：改造前它们全都 200 OK 存了下来，
		// 而客户端与浏览器都会把它们解析到回环——剖面照发、门户「访问」按钮照亮，
		// 只有七层入口那一处（判据里多认了 localhost）说不可达，同一份配置两种结论。
		{"localhost", "localhost 就是回环，只是 net.ParseIP 认不出来"},
		{"localhost.", "带根点的 FQDN 写法是同一个名字"},
		{"127.1", "inet_aton 短写，浏览器与 C 库会展开成 127.0.0.1"},
		{"2130706433", "同上的整数写法"},
		{"gw.example.com:18201", "端口的权威来源是网关自报的监听地址，不能有第二份"},
		{"https://gw.example.com", "只填主机名或 IP"},
		{"gw example.com", "含空格"},
	} {
		code, out := setAccess(t, f, "gw-1", "", tc.host)
		if code != http.StatusBadRequest {
			t.Fatalf("%q 应被拒（%s），实得 http %d: %v", tc.host, tc.why, code, out)
		}
	}
	// 合法值要收下
	for _, ok := range []string{"gw.example.com", "203.0.113.9", "gw-1.corp.internal"} {
		if code, out := setAccess(t, f, "gw-1", "", ok); code != http.StatusOK {
			t.Fatalf("%q 应被接受，实得 http %d: %v", ok, code, out)
		}
	}
}

// 剖面告警②的判据也得认出 localhost（silent-2）：网关自报 `-spa localhost:18201` 时
// 落点就是 localhost，它和 127.0.0.1 一样只有本机连得上。
// 把 endpointWarnings 的判据改回 net.ParseIP().IsLoopback()，这条会红（一条告警都不报）。
func TestGatewayAccess_落点是localhost也要报回环(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-1", "localhost:18201")
	hosts, _, warns := profileEndpoints(t, f)
	if len(hosts) == 0 || hosts[0] != "localhost" {
		t.Fatalf("前提变了：网关显式 bind localhost 时落点应沿用自报 host，实得 %v", hosts)
	}
	if !strings.Contains(strings.Join(warns, " | "), "回环") {
		t.Fatalf("★落点是 localhost 时必须与 127.0.0.1 同样报回环告警，实得 %v", warns)
	}
}

// 给一个没注册过的网关登记地址要 404：页面只列注册过的网关，
// 静默收下会让管理员以为自己配好了，而那条记录永远不会出现在任何地方。
func TestGatewayAccess_未注册网关拒绝登记(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-1", ":18201")
	if code, out := setAccess(t, f, "gw-typo", "", "gw.example.com"); code != http.StatusNotFound {
		t.Fatalf("未注册的 id 应 404，实得 http %d: %v", code, out)
	}
}

// 撤销登记（两栏都清空）后回到「未登记」态，告警重新出现。
func TestGatewayAccess_撤销登记后告警回来(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-1", ":18201")
	if code, _ := setAccess(t, f, "gw-1", "", "gw.example.com"); code != http.StatusOK {
		t.Fatal("登记失败")
	}
	if _, _, w := profileEndpoints(t, f); strings.Contains(strings.Join(w, "|"), "对外接入地址") {
		t.Fatal("前置失败：登记后不该有该告警")
	}
	if code, _ := setAccess(t, f, "gw-1", "", ""); code != http.StatusOK {
		t.Fatal("撤销失败")
	}
	hosts, _, warns := profileEndpoints(t, f)
	if hosts[0] != "127.0.0.1" {
		t.Fatalf("撤销后应退回兜底，实得 %v", hosts)
	}
	if !strings.Contains(strings.Join(warns, " | "), "对外接入地址") {
		t.Fatalf("撤销后告警必须回来，实得 %v", warns)
	}
}

// 网关页要带出登记值与「有没有登记」——页面得能显示、也得能提示没填。
func TestGatewayPage_带出接入地址与未登记标记(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-1", ":18201")
	node := func() map[string]any {
		code, out := doJSON(t, f.h, "GET", "/api/v1/gateway", adminToken(), nil)
		if code != http.StatusOK {
			t.Fatalf("GET /gateway http %d", code)
		}
		arr, _ := out["nodes"].([]any)
		for _, it := range arr {
			if n, _ := it.(map[string]any); asStr(n["id"]) == "gw-1" {
				return n
			}
		}
		t.Fatal("网关页里没有 gw-1")
		return nil
	}
	if n := node(); n["accessConfigured"] == true {
		t.Fatalf("未登记时应为 false：%v", n)
	}
	if code, _ := setAccess(t, f, "gw-1", "10.0.0.9", "gw.example.com"); code != http.StatusOK {
		t.Fatal("登记失败")
	}
	n := node()
	if n["accessConfigured"] != true || asStr(n["lanHost"]) != "10.0.0.9" || asStr(n["wanHost"]) != "gw.example.com" {
		t.Fatalf("网关页没带出登记值：%v", n)
	}
}

// 权限：登记接入地址归 PermSystem（改错它等于让全体终端连不上）。
func TestGatewayAccess_写权限归系统管理员(t *testing.T) {
	f := newIsoFixture(t)
	regGatewayHB(t, f, "gw-1", ":18201")
	if code, _ := doJSON(t, f.h, "PUT", "/api/v1/gateway/gw-1/access", userToken("li.fang"),
		map[string]any{"wanHost": "gw.example.com"}); code != http.StatusForbidden {
		t.Fatalf("普通用户应 403，实得 %d", code)
	}
	if code, _ := doJSON(t, f.h, "PUT", "/api/v1/gateway/gw-1/access", adminTokenFor("sec.admin"),
		map[string]any{"wanHost": "gw.example.com"}); code == http.StatusOK {
		t.Fatal("安全管理员不该能改接入地址（那是网络部署配置，归 PermSystem）")
	}
}
