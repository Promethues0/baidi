package api

// 网关多活与客户端故障转移（PRD FR-ARCH-03/04、第 19 章多数据中心）的回归防线。
//
// 改造前剖面结构上**只装得下一个落点**（ProfileGateway 单数），buildProfile 把所有
// 客户端导向「心跳最新鲜的那一台」：一台网关挂掉 = 全部终端断，哪怕另有网关在线。
// 下面的用例逐条钉住新契约里最容易做错、且做错之后毫无报错的几件事：
//
//	① 排序确定性（错了 = 客户端每次拉剖面换落点，表现为隧道莫名重连）
//	② 离线网关排末尾但仍下发（错了 = 控制面抖一下就让客户端丢掉可用落点）
//	③ 指纹逐网关（错了 = 切过去必然握手失败，被误判成第二台网关也坏了）
//	④ 旧客户端只读单数 gateway 仍可用（错了 = 升级控制面那一刻存量终端集体掉线）
//	⑤ 在线判定与 GET /api/v1/gateway 同源（错了 = 控制台绿灯、终端当它离线）

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
)

// newFailoverServer 同时交出 *Server（直接摆布网关注册表，好构造心跳时间）与
// http.Handler（走真实端点，验证跨端点同构）。两者是同一个 Server 实例。
func newFailoverServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	st := openTestSQLite(t)
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	return s, auth.Middleware(testKeys, s.IsOpen)(s.Routes())
}

// regGateway 往注册表里放一台网关。lastSeenAgo 为距今多久收到过心跳。
//
// ★这里直接写内存注册表而不是发注册报文，是因为要构造「心跳已超时」这种时间态——
// 注册端点永远把 lastSeen 记成 now。字段名对不上的风险由
// TestProfileGateways_PinIsPerGateway 那条走真实报文的用例兜住。
func regGateway(s *Server, id, host string, lastSeenAgo time.Duration, fp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gateways[id] = GatewayInfo{
		ID: id, SPA: host + ":18201", Proxy: host + ":18443",
		LastSeen: time.Now().Add(-lastSeenAgo).Unix(),
	}
	s.gwTunnelFP[id] = fp
}

func gatewayIDs(list []ProfileGateway) []string {
	out := make([]string, 0, len(list))
	for _, g := range list {
		out = append(out, g.ID)
	}
	return out
}

// ① + ② 排序确定性 + 离线排末尾但仍下发。
func TestProfileGateways_DeterministicOrderOfflineLast(t *testing.T) {
	s, _ := newFailoverServer(t)
	// 刻意让「心跳最新鲜」与「id 字典序」相反：若排序偷偷按心跳新鲜度做，
	// gw-c 会窜到最前面，这条用例立刻失败。
	regGateway(s, "gw-c", "10.0.0.3", 1*time.Second, "cc")
	regGateway(s, "gw-a", "10.0.0.1", 30*time.Second, "aa")
	regGateway(s, "gw-b", "10.0.0.2", 60*time.Second, "bb")
	regGateway(s, "gw-dead", "10.0.0.9", 10*time.Minute, "dd") // 心跳早超窗

	want := []string{"gw-a", "gw-b", "gw-c", "gw-dead"}
	for i := 0; i < 20; i++ {
		got, _ := s.profileGateways()
		ids := gatewayIDs(got)
		if len(ids) != len(want) {
			t.Fatalf("落点条数应为 %d（离线网关也要下发），实得 %v", len(want), ids)
		}
		for k := range want {
			if ids[k] != want[k] {
				t.Fatalf("第 %d 轮排序不符：期望 %v，实得 %v（顺序抖动 = 客户端每次换落点 = 隧道莫名重连）", i, want, ids)
			}
		}
	}

	got, _ := s.profileGateways()
	for _, g := range got[:3] {
		if !g.Online {
			t.Fatalf("%s 心跳新鲜却被标离线", g.ID)
		}
	}
	last := got[len(got)-1]
	if last.ID != "gw-dead" || last.Online {
		t.Fatalf("离线网关须排末尾且标 online=false，实得 %+v", last)
	}
	// ★仍然下发，且地址完整：不下发的话，控制面自己抖一下（心跳窗口边缘）
	// 就会让客户端丢掉一个其实可达的落点。
	if last.Host == "" || last.SPAPort == "" || last.ProxyPort == "" {
		t.Fatalf("离线落点的地址也必须完整下发，实得 %+v", last)
	}
}

// ③ 指纹逐网关：走**真实注册报文**（字段名 tunnelFp 对不上是这类改动最常见的失败形态）。
func TestProfileGateways_PinIsPerGateway(t *testing.T) {
	s, h := newFailoverServer(t)
	const fpA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const fpB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct{ id, fp string }{{"gw-a", fpA}, {"gw-b", fpB}} {
		body := `{"id":"` + tc.id + `","proxy":"10.0.0.1:18443","spa":"10.0.0.1:18201","tunnelFp":"` + tc.fp + `"}`
		if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
			t.Fatalf("注册 %s 返回 %d：%s", tc.id, w.Code, w.Body.String())
		}
	}
	byID := map[string]ProfileGateway{}
	list, _ := s.profileGateways()
	for _, g := range list {
		byID[g.ID] = g
	}
	if byID["gw-a"].TunnelPin != fpA || byID["gw-b"].TunnelPin != fpB {
		t.Fatalf("每个落点必须带**自己**那台网关的指纹，实得 a=%q b=%q", byID["gw-a"].TunnelPin, byID["gw-b"].TunnelPin)
	}
	if byID["gw-a"].TunnelPin == byID["gw-b"].TunnelPin {
		t.Fatal("两台网关共用一个指纹：故障转移到第二台时钉扎必然失败（症状是「切过去就连不上」）")
	}
}

// 备用落点缺指纹要单独说清楚：它与「首选落点此刻就在裸奔」的紧急程度不同。
func TestProfileGateways_SpareWithoutPinWarnsSeparately(t *testing.T) {
	s, _ := newFailoverServer(t)
	regGateway(s, "gw-a", "10.0.0.1", time.Second, "aa")
	regGateway(s, "gw-b", "10.0.0.2", time.Second, "") // 备用落点没上报指纹

	_, warns := s.profileGateways()
	var hit bool
	for _, w := range warns {
		if strings.Contains(w, "备用落点") && strings.Contains(w, "gw-b") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("备用落点缺指纹须点名告警，实得 %v", warns)
	}
}

// ④ 旧客户端只读单数 gateway：它必须恒等于清单首项，且自身完整可用。
func TestBuildProfile_LegacyClientReadsSingularGateway(t *testing.T) {
	s, _ := newFailoverServer(t)
	regGateway(s, "gw-a", "10.0.0.1", time.Second, "aa")
	regGateway(s, "gw-b", "10.0.0.2", time.Second, "bb")

	apps, res := profileFixture()
	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)
	if p.Gateway.ID != p.Gateways[0].ID || p.Gateway.Host != p.Gateways[0].Host ||
		p.Gateway.TunnelPin != p.Gateways[0].TunnelPin || p.Gateway.Online != p.Gateways[0].Online {
		t.Fatalf("单数字段必须恒等于清单首项，实得 %+v vs %+v", p.Gateway, p.Gateways[0])
	}
	// 序列化后旧客户端仍能拿到完整的 gateway 对象（少一个字段就是"升级后连不上"）。
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("序列化剖面失败：%v", err)
	}
	var wire struct {
		Gateway struct {
			Host, SpaPort, ProxyPort, TunnelPin string
			Online                              bool
		} `json:"gateway"`
		Gateways []struct {
			ID string `json:"id"`
		} `json:"gateways"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("反序列化失败：%v", err)
	}
	if wire.Gateway.Host == "" || wire.Gateway.SpaPort == "" || wire.Gateway.ProxyPort == "" || !wire.Gateway.Online {
		t.Fatalf("线上 JSON 的 gateway 字段须完整（旧客户端只读这一个），实得 %+v", wire.Gateway)
	}
	// ⑤' 新客户端读列表：两台都在，顺序确定。
	if len(wire.Gateways) != 2 || wire.Gateways[0].ID != "gw-a" || wire.Gateways[1].ID != "gw-b" {
		t.Fatalf("新客户端须读到两个落点且顺序确定，实得 %+v", wire.Gateways)
	}
}

// ⑤ 同构：剖面里的在线判定与 GET /api/v1/gateway 必须逐台同真同假。
//
// 两处各写一遍窗口的后果是"控制台说在线、客户端剖面把它当离线备用"——两边都不报错，
// 而运维会照着控制台的绿灯去排查一条终端根本没在用的链路。
func TestGatewayOnlineIsomorphic_ProfileVsGatewayPage(t *testing.T) {
	s, h := newFailoverServer(t)
	window := gatewayOnlineWindow
	// 刻意贴着窗口边缘取值：判据只要差一点（比如一处用 <、一处用 <=，或窗口值不同），
	// 这两台里必有一台在两个出口上给出相反的答案。
	regGateway(s, "gw-inside", "10.0.0.1", window-5*time.Second, "aa")
	regGateway(s, "gw-outside", "10.0.0.2", window+5*time.Second, "bb")

	profileOnline := map[string]bool{}
	list, _ := s.profileGateways()
	for _, g := range list {
		profileOnline[g.ID] = g.Online
	}

	code, out := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读网关页 http %d：%v", code, out)
	}
	nodes, _ := out["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("网关页应列出两台，实得 %v", nodes)
	}
	for _, n := range nodes {
		m := mapOf(t, n)
		id, _ := m["id"].(string)
		pageOnline, _ := m["online"].(bool)
		if got, ok := profileOnline[id]; !ok || got != pageOnline {
			t.Fatalf("%s 在线判定不同源：网关页=%v 客户端剖面=%v", id, pageOnline, got)
		}
	}
	if !profileOnline["gw-inside"] || profileOnline["gw-outside"] {
		t.Fatalf("窗口内应在线、窗口外应离线，实得 %v", profileOnline)
	}
}

// 全部网关心跳超时：落点照常下发（不清空），但要如实说明控制面视角已看不到心跳。
func TestProfileGateways_AllStaleStillDelivered(t *testing.T) {
	s, _ := newFailoverServer(t)
	regGateway(s, "gw-a", "10.0.0.1", 10*time.Minute, "aa")
	regGateway(s, "gw-b", "10.0.0.2", 10*time.Minute, "bb")

	list, warns := s.profileGateways()
	if len(list) != 2 {
		t.Fatalf("心跳全超时也要照常下发落点，实得 %d 条", len(list))
	}
	var hit bool
	for _, w := range warns {
		if strings.Contains(w, "心跳全部超时") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("全部超时须带出告警（否则「连不上」没有归因），实得 %v", warns)
	}
}

// 落点集合与授权无关：换个用户拉剖面，落点清单必须一模一样。
// （落点是网络拓扑，授权收缩的是 resmap/routes/apps，两者混在一起会让
//
//	「降权」顺带砍掉容灾余量，而那完全不是降权的语义。）
func TestProfileGateways_IndependentOfUser(t *testing.T) {
	s, _ := newFailoverServer(t)
	regGateway(s, "gw-a", "10.0.0.1", time.Second, "aa")
	regGateway(s, "gw-b", "10.0.0.2", time.Second, "bb")
	apps, res := profileFixture()

	admin := s.buildProfile(context.Background(), "admin", "admin", apps, res)
	user := s.buildProfile(context.Background(), "li.fang", "user", apps, res)
	if len(admin.Gateways) != len(user.Gateways) {
		t.Fatalf("落点清单不该随用户变化：admin %d 条 / user %d 条", len(admin.Gateways), len(user.Gateways))
	}
	for i := range admin.Gateways {
		if admin.Gateways[i].ID != user.Gateways[i].ID {
			t.Fatalf("第 %d 个落点不一致：%s vs %s", i, admin.Gateways[i].ID, user.Gateways[i].ID)
		}
	}
}
