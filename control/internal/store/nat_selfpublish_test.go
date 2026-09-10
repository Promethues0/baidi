package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ── DNAT 自伤闸（wave11 行动 13-①）──
//
// 这一组用例的共同点：**被拒的那些配置在改造前全部 200 OK**，规则照样灌进 prerouting，
// 页面上一个字都看不出来。所以每条都同时断言「拒了」与「拒的理由说得出是哪个口」——
// 只断言 error != nil 的话，把文案换成一句「参数不合法」也照样绿。

// natGateIfaces 与 natSeedIfaces 同形，但直接给纯函数用（不必起库）。
func natGateIfaces() []GatewayIface {
	return []GatewayIface{
		{GatewayID: "gw-1", Name: "eth2", Type: IfaceLAN, Addrs: []string{"5.5.10.102/16"}},
		{GatewayID: "gw-1", Name: "eth3", Type: IfaceWAN, Addrs: []string{"155.155.10.102/16"}},
	}
}

// dnatGateFixture 一条**正常**的发布规则：公网口 9443 → 内网业务 5.5.20.30:8080。
// 它不碰网关自己的任何监听口，是这一组用例的「不该被拦」基线。
func dnatGateFixture() NATPolicy {
	return NATPolicy{
		Name: "发布 OA", Type: NATDnat, GatewayID: "gw-1",
		SrcIface: "eth3", SrcAddr: "0.0.0.0/0",
		DstIface: "eth2", DstAddr: "155.155.10.102", Protocol: NATProtoTCP,
		DstPort: 9443, TranslatedAddr: "5.5.20.30", TranslatedPort: 8080, Enabled: true,
	}
}

func natNorm(t *testing.T, p NATPolicy, l NATListen) (NATPolicy, error) {
	t.Helper()
	return normNATPolicy(p, natGateIfaces(), l)
}

// 基线：正常发布规则不许被这道闸误伤。一道会误伤的闸最后一定被人整个关掉，
// 所以它排在第一条。
func TestOrdinaryDnatNotRejectedBySelfPublishGate(t *testing.T) {
	if _, err := natNorm(t, dnatGateFixture(), natTestListen()); err != nil {
		t.Fatalf("正常发布规则不该被拒：%v", err)
	}
}

// 甲：转换后目的 = 网关自己的隧道口。改造前这条 200 OK，等于用地址转换
// 给零信任接入面在另一个公网端口上再开一扇门，而控制面对这扇门一无所知。
func TestDnatToOwnTunnelPortRejected(t *testing.T) {
	p := dnatGateFixture()
	p.TranslatedAddr, p.TranslatedPort = "5.5.10.102", 18443 // 网关自己的 LAN 地址 + 隧道口
	_, err := natNorm(t, p, natTestListen())
	if !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("发布网关自己的隧道口应被拒，实际 err=%v", err)
	}
	for _, want := range []string{"18443", "零信任隧道口", "转换后目的"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("拒绝文案要点名是哪个口、哪一侧，缺「%s」：%v", want, err)
		}
	}
}

// 回环同样是「网关自己」：DNAT 到 127.0.0.1 的自伤形态与 LAN 地址完全一样。
func TestDnatToLoopbackTunnelPortRejected(t *testing.T) {
	p := dnatGateFixture()
	p.TranslatedAddr, p.TranslatedPort = "127.0.0.1", 18443
	if _, err := natNorm(t, p, natTestListen()); !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("DNAT 到回环上的隧道口应被拒，实际 %v", err)
	}
}

// 乙：对外发布端 = 网关自己的监听口。prerouting 的 dstnat 排在**路由决策之前**，
// 命中的报文被整条改道走掉，本机服务再也收不到——而网关到控制面的心跳是出向的，
// 照常在线：控制台全绿、客户端只是拨号超时。
func TestDnatHijackingOwnListenPortRejected(t *testing.T) {
	p := dnatGateFixture()
	p.DstPort = 18443 // 在网关自己的 WAN 地址上，把隧道口发布给别人
	_, err := natNorm(t, p, natTestListen())
	if !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("在网关自身地址上占用隧道口应被拒，实际 err=%v", err)
	}
	for _, want := range []string{"对外发布端", "路由决策之前", "拨号超时"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("拒绝文案缺「%s」：%v", want, err)
		}
	}
}

// ★变异守卫：把 natSelfPublish 从 normNATPolicy 的**末尾**挪到 checkPort 之前，
// 这条会绿而其余仍红——因为「发布端口 = 隧道口、转换端口留空」这条最省事的写法
// 正是靠归一那两行补出 TranslatedPort 的。实跑确认过。
func TestSelfPublishGateSeesDefaultedTranslatedPort(t *testing.T) {
	p := dnatGateFixture()
	p.DstAddr = "155.155.10.200" // 不是网关自己的地址，排除掉乙那一侧
	p.DstPort = 18443
	p.TranslatedAddr = "5.5.10.102" // 网关自己
	p.TranslatedPort = 0            // 留空 = 与发布端口相同，由归一补成 18443
	if _, err := natNorm(t, p, natTestListen()); !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("转换端口留空时闸必须看到补出来的 18443，实际 %v", err)
	}
}

// 协议维度：SPA 敲门口是 UDP。同号的 TCP 端口与它不是一回事，拦下来就是误伤。
func TestSelfPublishGateRespectsProtocol(t *testing.T) {
	base := dnatGateFixture()
	base.TranslatedAddr = "5.5.10.102"
	base.TranslatedPort = 18201

	tcp := base
	tcp.Protocol = NATProtoTCP
	if _, err := natNorm(t, tcp, natTestListen()); err != nil {
		t.Fatalf("TCP/18201 与 UDP 敲门口不是一回事，不该被拒：%v", err)
	}

	udp := base
	udp.Protocol = NATProtoUDP
	if _, err := natNorm(t, udp, natTestListen()); !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("UDP/18201 正是敲门口，应被拒，实际 %v", err)
	}

	// protocol=all 在 nft 里展开成 `meta l4proto { tcp, udp } th dport N`，两种都命中。
	all := base
	all.Protocol = NATProtoAll
	if _, err := natNorm(t, all, natTestListen()); !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("protocol=all 覆盖 udp，应被拒，实际 %v", err)
	}
}

// ICMP 没有端口概念，任何端口比对对它都不成立——拦下来只会让人莫名其妙。
func TestSelfPublishGateSkipsIcmp(t *testing.T) {
	p := dnatGateFixture()
	p.Protocol = NATProtoICMP
	p.DstPort, p.TranslatedPort = 0, 0
	p.TranslatedAddr = "5.5.10.102"
	if _, err := natNorm(t, p, natTestListen()); err != nil {
		t.Fatalf("ICMP 转发到网关自身不涉及端口，不该被这道闸拒：%v", err)
	}
}

// ★这道闸的判据必须取自**网关自报**的监听端口，不是写死的 18443/18201/18444。
// 写死的话，一台把 -proxy 换到 29443 的网关上，闸会同时犯两个方向的错：
// 放过真正把隧道口发布出去的那条，又拦下一条正常发布 18443 业务的规则。
func TestSelfPublishGateUsesReportedPortsNotConstants(t *testing.T) {
	moved := NATListen{Reported: true, Proxy: "0.0.0.0:29443", SPA: "0.0.0.0:29201"}

	hit := dnatGateFixture()
	hit.TranslatedAddr, hit.TranslatedPort = "5.5.10.102", 29443
	if _, err := natNorm(t, hit, moved); !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("换过端口后 29443 才是隧道口，应被拒，实际 %v", err)
	}
	if !strings.Contains(hit.Name, "OA") { // 夹具没被改坏
		t.Fatal("夹具异常")
	}

	miss := dnatGateFixture()
	miss.TranslatedAddr, miss.TranslatedPort = "5.5.10.102", 18443
	if _, err := natNorm(t, miss, moved); err != nil {
		t.Fatalf("这台网关并不监听 18443，发布它是正常业务，不该被拒：%v", err)
	}
}

// 七层口只在网关**真的报了** -web 时才算它自己的口。
// 网关明说没开七层却硬塞一个 18444 进来，等于拦下一条正常规则、
// 而拒绝理由指向一个这台机器上根本不存在的监听口。
func TestWebPortCountedOnlyWhenReported(t *testing.T) {
	p := dnatGateFixture()
	p.TranslatedAddr, p.TranslatedPort = "5.5.10.102", 18444

	if _, err := natNorm(t, p, natTestListen()); err != nil { // 快照里 Web 为空
		t.Fatalf("网关没开七层时 18444 只是普通端口，不该被拒：%v", err)
	}

	withWeb := natTestListen()
	withWeb.Web = "0.0.0.0:18444"
	_, err := natNorm(t, p, withWeb)
	if !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("网关开着七层时 18444 是它自己的口，应被拒，实际 %v", err)
	}
	if !strings.Contains(err.Error(), "七层 Web 代理口") {
		t.Errorf("拒绝文案要点名七层口：%v", err)
	}
}

// 网关没上报过监听地址（从未心跳，或控制面刚重启）时**保守判**，
// 并且必须当面说清这是按出厂默认端口猜的——少了这句，一个换过端口的部署
// 会收到一句方向完全错误的拒绝，且没有任何线索指向「等一次心跳再试」。
func TestUnreportedListenFallsBackConservatively(t *testing.T) {
	p := dnatGateFixture()
	p.TranslatedAddr, p.TranslatedPort = "5.5.10.102", 18443
	_, err := natNorm(t, p, NATListen{}) // Reported=false
	if !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("判不出监听端口时应保守拒绝，实际 %v", err)
	}
	for _, want := range []string{"保守判定", "gw-1", "18443/tcp", "18201/udp", "18444/tcp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("兜底判定必须当面说明，缺「%s」：%v", want, err)
		}
	}
}

// 上报了、但连隧道口都解析不出来时，这份快照整体不可信——同样退守默认值。
// 只按「Reported 为真」就采信，会让一份坏快照静默关掉整道闸。
func TestGarbledListenTreatedAsUnreported(t *testing.T) {
	p := dnatGateFixture()
	p.TranslatedAddr, p.TranslatedPort = "5.5.10.102", 18443
	bad := NATListen{Reported: true, Proxy: "不是地址", SPA: ""}
	_, err := natNorm(t, p, bad)
	if !errors.Is(err, ErrNATSelfPublish) || !strings.Contains(err.Error(), "保守判定") {
		t.Fatalf("坏快照应退守默认端口并说明，实际 %v", err)
	}
}

// SNAT 不走这道闸：源地址被改写导致隧道回包丢失（FR-NAT-13）由数据面的
// natfw.Exempt 排除规则兜住，判据同样是网关自己知道的端口。
func TestSnatUntouchedBySelfPublishGate(t *testing.T) {
	if err := natSelfPublish(snatFixture(), NATListen{}, natGateIfaces()); err != nil {
		t.Fatalf("SNAT 不该被 DNAT 自伤闸拒：%v", err)
	}
}

// 端到端：闸真的接在保存路径上（纯函数测得再全，没接上也是零）。
func TestSaveNATPolicyRejectsSelfPublish(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	natSeedIfaces(t, s)

	p := dnatGateFixture()
	p.TranslatedAddr, p.TranslatedPort = "5.5.10.102", 18443
	if _, err := s.SaveNATPolicy(ctx, p, natTestListen()); !errors.Is(err, ErrNATSelfPublish) {
		t.Fatalf("保存路径必须拦住自伤 DNAT，实际 %v", err)
	}
	ps, err := s.NATPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Fatalf("被拒的策略一行都不该落库，实际 %d 条", len(ps))
	}
}
