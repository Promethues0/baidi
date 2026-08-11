package dataplane

// 网关多活 / 客户端故障转移的回归防线（PRD FR-ARCH-03/04）。
//
// 这条链路最阴的失败形态不是"切不过去"，而是**切过去了却连不上**：两台网关的隧道证书
// 各自自签，指纹只要取错一份，故障转移就永远在钉扎那一步失败——而现场看到的是
// "备用网关也坏了"。所以下面每条用例都用**两张不同的自签证书**跑真 TLS 握手。

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// deadAddr 一个格式合法但确定拨不通的本地地址（1 号端口是特权端口，测试机上不会有服务）。
// 用它模拟"首选网关挂了"。
const deadAddr = "127.0.0.1:1"

// 单落点三件套必须继续可用：移动端绑定与手工起的 baidi-tun 都还在走这条路，
// 去掉的话它们会拿到空清单，一条流都拨不出去。
func TestEndpoints_FallsBackToSingleTriple(t *testing.T) {
	cfg := &Config{SpaAddr: "1.2.3.4:18201", ProxyAddr: "1.2.3.4:18443", TunnelPin: "abcd"}
	eps := cfg.endpoints()
	if len(eps) != 1 {
		t.Fatalf("单落点配置应产出一个落点，实得 %d", len(eps))
	}
	if eps[0].SPAAddr != cfg.SpaAddr || eps[0].ProxyAddr != cfg.ProxyAddr || eps[0].Pin != cfg.TunnelPin {
		t.Fatalf("三件套未原样搬进落点：%+v", eps[0])
	}
	// 有清单时三件套不再被读取（否则会出现"清单里是 A、实际拨的是 B"）。
	cfg.Endpoints = []Endpoint{{ID: "gw-a", SPAAddr: "10.0.0.1:18201", ProxyAddr: "10.0.0.1:18443"}}
	if got := cfg.endpoints(); len(got) != 1 || got[0].ID != "gw-a" {
		t.Fatalf("有清单时应以清单为准，实得 %+v", got)
	}
}

// 地址残缺的落点必须在启动期就被拒——留着它只会在故障转移那一刻白耗一轮拨号超时。
func TestValidateEndpoints_RejectsIncomplete(t *testing.T) {
	if err := validateEndpoints(nil); err == nil {
		t.Fatal("空清单必须被拒")
	}
	if err := validateEndpoints([]Endpoint{{ID: "gw-a", SPAAddr: "1.2.3.4:18201"}}); err == nil {
		t.Fatal("缺隧道地址必须被拒")
	}
	if err := validateEndpoints([]Endpoint{{ID: "gw-a", ProxyAddr: "1.2.3.4:18443"}}); err == nil {
		t.Fatal("缺敲门地址必须被拒（敲不了门就永远拨不通，网关对未敲门者隐身）")
	}
}

func TestPicker_PromoteRecordsReason(t *testing.T) {
	p := newPicker([]Endpoint{{ID: "gw-a", ProxyAddr: "a:1"}, {ID: "gw-b", ProxyAddr: "b:1"}})
	idx, total, label, addr, reason := p.status()
	if idx != 1 || total != 2 || label != "gw-a" || addr != "a:1" || reason == "" {
		t.Fatalf("初始状态应是首选落点且带原因，实得 %d/%d %s %s %q", idx, total, label, addr, reason)
	}
	if p.promote(0, "不该发生") {
		t.Fatal("提升到当前落点应返回 false（否则每条流都会刷一条'切换'日志）")
	}
	if !p.promote(1, "gw-a 拨号失败") {
		t.Fatal("提升到另一落点应返回 true")
	}
	idx, _, label, _, reason = p.status()
	if idx != 2 || label != "gw-b" || !strings.Contains(reason, "gw-a") {
		t.Fatalf("切换后状态应指向 gw-b 并记下原因，实得 %d %s %q", idx, label, reason)
	}
}

// 首选落点拨不通时切到下一个，并且**粘住**：后续每条流直接去新落点，
// 不再每次都先撞一遍死网关（5s 超时 × 每条流 = 用户眼里的"接入后什么都打不开"）。
func TestDialTunnel_FailsOverAndSticks(t *testing.T) {
	certB, pinB := selfSigned(t, "gw-b")
	liveAddr := serveTLS(t, certB)

	tl := newTunneler(&Config{Endpoints: []Endpoint{
		{ID: "gw-a", SPAAddr: deadAddr, ProxyAddr: deadAddr, Pin: pinB}, // 死掉的首选
		{ID: "gw-b", SPAAddr: liveAddr, ProxyAddr: liveAddr, Pin: pinB},
	}})

	conn, ep, err := tl.dialTunnel("10.99.0.11:8080")
	if err != nil {
		t.Fatalf("首选落点死了应切到备用，实得错误：%v", err)
	}
	conn.Close()
	if ep.ID != "gw-b" {
		t.Fatalf("应落到 gw-b，实得 %s", ep.ID)
	}
	idx, _, label, _, reason := tl.pick.status()
	if idx != 2 || label != "gw-b" {
		t.Fatalf("切换后当前落点应变为第 2 个，实得 %d %s", idx, label)
	}
	if !strings.Contains(reason, "gw-a") {
		t.Fatalf("切换原因须点名是哪个落点失败了（否则「我明明连着但很慢」无从排查），实得 %q", reason)
	}
	// 粘住：下一条流不再从死掉的 gw-a 起拨。
	conn2, ep2, err := tl.dialTunnel("10.99.0.12:22")
	if err != nil {
		t.Fatalf("第二条流应直接落到已切换的落点，实得 %v", err)
	}
	conn2.Close()
	if ep2.ID != "gw-b" {
		t.Fatalf("第二条流应仍在 gw-b，实得 %s", ep2.ID)
	}
}

// 指纹逐落点：备用落点带的是**它自己**那张证书的指纹才连得上。
// 共用一份（这里用首选那台的指纹去连备用那台）必须失败——这正是
// 「切过去就连不上」被误判成"第二台网关也坏了"的根因。
func TestDialTunnel_PinIsPerEndpoint(t *testing.T) {
	certA, pinA := selfSigned(t, "gw-a")
	certB, pinB := selfSigned(t, "gw-b")
	addrA := serveTLS(t, certA)
	addrB := serveTLS(t, certB)

	// ① 备用落点带自己的指纹 → 切过去连得上。
	ok := newTunneler(&Config{Endpoints: []Endpoint{
		{ID: "gw-a", SPAAddr: deadAddr, ProxyAddr: deadAddr, Pin: pinA},
		{ID: "gw-b", SPAAddr: addrB, ProxyAddr: addrB, Pin: pinB},
	}})
	conn, ep, err := ok.dialTunnel("10.99.0.11:8080")
	if err != nil {
		t.Fatalf("备用落点带自己的指纹应连得上，实得 %v", err)
	}
	conn.Close()
	if ep.ID != "gw-b" {
		t.Fatalf("应落到 gw-b，实得 %s", ep.ID)
	}

	// ② 备用落点错配成首选那台的指纹 → 必须握手失败（钉扎不许被绕过）。
	bad := newTunneler(&Config{Endpoints: []Endpoint{
		{ID: "gw-a", SPAAddr: deadAddr, ProxyAddr: deadAddr, Pin: pinA},
		{ID: "gw-b", SPAAddr: addrB, ProxyAddr: addrB, Pin: pinA}, // 指纹取错
	}})
	if c, _, err := bad.dialTunnel("10.99.0.11:8080"); err == nil {
		c.Close()
		t.Fatal("指纹取错时必须拒绝握手，否则钉扎形同虚设")
	}

	// ③ 首选落点活着时压根不该动备用（顺序即优先级，终端不重排）。
	pri := newTunneler(&Config{Endpoints: []Endpoint{
		{ID: "gw-a", SPAAddr: addrA, ProxyAddr: addrA, Pin: pinA},
		{ID: "gw-b", SPAAddr: addrB, ProxyAddr: addrB, Pin: pinB},
	}})
	conn3, ep3, err := pri.dialTunnel("10.99.0.11:8080")
	if err != nil {
		t.Fatalf("首选落点可用时应直接连它，实得 %v", err)
	}
	conn3.Close()
	if ep3.ID != "gw-a" {
		t.Fatalf("首选落点可用时不该切换，实得 %s", ep3.ID)
	}
}

// 全部落点都拨不通：报**首选**那次的错误（后面几台多半只是次生现象），
// 且当前落点不变——没有任何一个落点被"提升"过。
func TestDialTunnel_AllDown(t *testing.T) {
	tl := newTunneler(&Config{Endpoints: []Endpoint{
		{ID: "gw-a", SPAAddr: deadAddr, ProxyAddr: deadAddr},
		{ID: "gw-b", SPAAddr: deadAddr, ProxyAddr: deadAddr},
	}})
	if c, _, err := tl.dialTunnel("10.99.0.11:8080"); err == nil {
		c.Close()
		t.Fatal("全部落点不可达时必须报错")
	}
	if idx, _, label, _, _ := tl.pick.status(); idx != 1 || label != "gw-a" {
		t.Fatalf("全都拨不通时不该改变当前落点，实得 %d %s", idx, label)
	}
}

// 每轮保活必须敲**全部**落点。
//
// ★只敲当前那个的话，备用落点始终对本机隐身，故障转移那一刻只会得到一次拨号超时——
// "有备用落点"就退化成"多等 5 秒再失败"，而这在单元测试之外几乎无法被发现
// （平时一切正常，只有真出故障那次才暴露）。
//
// 同时验证**逐落点各取一张令牌**：jti 去重是每台网关各自做的，同一封包发两处等于
// 让链路上截获它的人能拿去给自己的源 IP 开一扇窗，一次性语义就没了。
func TestKnock_ReachesEveryEndpointWithItsOwnToken(t *testing.T) {
	var issued atomic.Int64
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := issued.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"tok-` + string(rune('0'+n)) + `"}`))
	}))
	defer control.Close()

	// 两个真实 UDP 监听，分别代表两个网关的敲门口。
	socks := make([]net.PacketConn, 2)
	for i := range socks {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		defer pc.Close()
		socks[i] = pc
	}

	tl := newTunneler(&Config{Control: control.URL, Token: "sess", Endpoints: []Endpoint{
		{ID: "gw-a", SPAAddr: socks[0].LocalAddr().String(), ProxyAddr: deadAddr},
		{ID: "gw-b", SPAAddr: socks[1].LocalAddr().String(), ProxyAddr: deadAddr},
	}})
	tl.knock()

	seen := map[string]bool{}
	for i, pc := range socks {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("第 %d 个落点没有收到敲门包（备用落点会始终隐身，故障转移必然失败）：%v", i+1, err)
		}
		// 比的是信封里那张**令牌**，不是整包：Seal 每次都掺随机 nonce，
		// 比整包的话即使复用同一张令牌两个包也长得不一样，这条断言就废了。
		var env struct {
			T string `json:"t"`
		}
		if err := json.Unmarshal(buf[:n], &env); err != nil || env.T == "" {
			t.Fatalf("第 %d 个落点收到的不是敲门信封：%q", i+1, string(buf[:n]))
		}
		if seen[env.T] {
			t.Fatalf("两个落点收到了**同一张**敲门令牌（%s）：一次性语义没了，截获者可拿它给自己的源 IP 开窗", env.T)
		}
		seen[env.T] = true
	}
	if got := issued.Load(); got != 2 {
		t.Fatalf("应逐落点各取一张令牌（共 2 张），实得 %d", got)
	}
}
