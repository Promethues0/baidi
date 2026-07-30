package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/cplane"
	"baidi.dev/gateway/internal/ipsec"
)

// TestTwoNodesEstablishTunnel 起**两个真实实例**，让它们经回环 UDP 完整协商一次。
//
// # 这条测试守的是什么
//
// 装配错误只在"两端真的要通信"时才现形，任何单元测试都替代不了：
//
//   - IKE 状态机若收的是原始 Transport 而不是 Backend 分出来的 IKE 支路，
//     它会和入向泵抢同一个接收队列（见 lateTransport 的说明）；
//   - Protector 若不是同一个实例，握手全绿但一个包都不通；
//   - lateTransport 若在 set 之前就被 Run 读走，报文会静默丢失。
//
// # 断言的是"只有真协商才可能成立的性质"
//
// 不能只断言 state==up——那正是旧实现（toggle 一下就显示 up）能做到的事。
// 这里断言 **SPI 交叉相等**：本端入向 SPI == 对端出向 SPI，两个方向都要。
// 这一对值是两个独立实例各自随机生成、经报文交换才对得上的，单端伪造不出来。
//
// 无 root：IKE/NAT-T 端口传 0 由内核分配高位端口，数据面用进程内 netstack。
func TestTwoNodesEstablishTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("-short：跳过需要真实 UDP 协商的装配测试")
	}

	cpA, cpB := newFakeControl(), newFakeControl()
	a, err := assemble(nodeOptions{
		GatewayID: "ipsec-a", Listen: "127.0.0.1",
		Datapath: "netstack", TUNAddr: "10.20.0.1/16",
		Control: cpA, Log: quietLog(),
	})
	if err != nil {
		t.Fatalf("装配 A 失败：%v", err)
	}
	defer a.close()
	b, err := assemble(nodeOptions{
		GatewayID: "ipsec-b", Listen: "127.0.0.1",
		Datapath: "netstack", TUNAddr: "10.40.0.1/16",
		Control: cpB, Log: quietLog(),
	})
	if err != nil {
		t.Fatalf("装配 B 失败：%v", err)
	}
	defer b.close()

	// 落点在装配之后才知道（端口 0 = 内核分配），所以站点配置到这里才拼得出来。
	// ★peer 必须写对端**实际绑定**的 IKE 端口：写 500 的话两端谁也找不到谁，
	// 而现象只是"一直 connecting"。
	psk := []byte("baidi-ipsec-test-psk-0123456789") // ≥20 字节，避免走进弱 PSK 告警分支
	cpA.sites = []cplane.IpsecSiteDTO{peerSite("site-x", "ipsec-a", b.udp.LocalIKE().String(),
		"10.20.0.0/16", "10.40.0.0/16", "a.baidi", "b.baidi")}
	cpA.psk["site-x"], cpA.pskVer["site-x"] = psk, 1
	cpB.sites = []cplane.IpsecSiteDTO{peerSite("site-x", "ipsec-b", a.udp.LocalIKE().String(),
		"10.40.0.0/16", "10.20.0.0/16", "b.baidi", "a.baidi")}
	cpB.psk["site-x"], cpB.pskVer["site-x"] = psk, 1

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.engine.Run(ctx)
	go b.engine.Run(ctx)

	a.sy.round(ctx)
	b.sy.round(ctx)

	// ★两端都启用了这条站点，于是两端**几乎同时**发起 IKE_SA_INIT，各自又都尽责地
	// 响应了对方——短暂存在两条完整可用的 IKE SA 是正常的，由 collapseDuplicates
	// 按两端算得出同一结果的判据收敛到一条。所以这里要等的是"收敛完成"，
	// 而不是"某一端 up 了"：只等 up 会在收敛前就断言，得到一对不交叉的 SPI。
	sa, sb := waitConverged(t, ctx, a, b)

	// ★交叉相等是"真的协商过"最硬的可视证据：这一对值是两个独立实例各自随机生成、
	// 经报文交换才对得上的，单端伪造不出来。
	if sa.ChildSPIIn == 0 || sa.ChildSPIOut == 0 {
		t.Fatalf("A 侧 Child SPI 为零：in=%#x out=%#x", sa.ChildSPIIn, sa.ChildSPIOut)
	}
	if sa.IKESPIi == "" || sa.IKESPIr == "" {
		t.Errorf("IKE SPI 为空：%q / %q", sa.IKESPIi, sa.IKESPIr)
	}
	if sa.NegotiatedProposal == "" {
		t.Error("协商结果为空：控制台上「配的是 A、谈出来是 B」那一格会没东西可比")
	}
	// 两端谈出来的必须是同一套算法：不同就意味着两边各自"成功"了一次不同的协商。
	if sa.NegotiatedProposal != sb.NegotiatedProposal {
		t.Errorf("两端协商结果不同：A=%q B=%q", sa.NegotiatedProposal, sb.NegotiatedProposal)
	}
	if sa.IKESPIi != sb.IKESPIi || sa.IKESPIr != sb.IKESPIr {
		t.Errorf("两端看到的 IKE SPI 对不上：A=%s/%s B=%s/%s", sa.IKESPIi, sa.IKESPIr, sb.IKESPIi, sb.IKESPIr)
	}

	// 回报链路也要真的走通：状态必须经 syncer 落到（假的）控制面上。
	a.sy.report(ctx)
	got := lastState(t, cpA, "site-x")
	if got.State != ipsec.StateUp {
		t.Errorf("回报给控制面的状态是 %q，期望 up", got.State)
	}
	if got.ChildSPIIn != sa.ChildSPIIn {
		t.Errorf("回报的 SPI 与本地实测不一致：%#x vs %#x", got.ChildSPIIn, sa.ChildSPIIn)
	}
}

// waitConverged 轮询到两端都 up 且 SPI 两个方向都交叉相等（同时发起后的收敛完成）。
func waitConverged(t *testing.T, ctx context.Context, a, b *node) (ipsec.SiteState, ipsec.SiteState) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var sa, sb ipsec.SiteState
	for time.Now().Before(deadline) {
		sa, sb = stateOf(t, ctx, a, "A"), stateOf(t, ctx, b, "B")
		if sa.State == ipsec.StateUp && sb.State == ipsec.StateUp &&
			sa.ChildSPIIn != 0 && sa.ChildSPIIn == sb.ChildSPIOut && sb.ChildSPIIn == sa.ChildSPIOut {
			return sa, sb
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 失败时必须把两端的状态与 LastError 一起带出来——「一直 connecting」本身不含任何信息。
	t.Fatalf("20s 内两端没有收敛到同一条 SA：\n  A state=%q spi(in/out)=%#x/%#x lastError=%q\n  B state=%q spi(in/out)=%#x/%#x lastError=%q",
		sa.State, sa.ChildSPIIn, sa.ChildSPIOut, sa.LastError,
		sb.State, sb.ChildSPIIn, sb.ChildSPIOut, sb.LastError)
	return sa, sb
}

func stateOf(t *testing.T, ctx context.Context, n *node, who string) ipsec.SiteState {
	t.Helper()
	sts, err := n.backend.States(ctx)
	if err != nil {
		t.Fatalf("%s 读状态失败：%v", who, err)
	}
	for _, st := range sts {
		if st.SiteID == "site-x" {
			return st
		}
	}
	return ipsec.SiteState{}
}

func peerSite(id, gw, peer, local, remote, localID, remoteID string) cplane.IpsecSiteDTO {
	return cplane.IpsecSiteDTO{
		ID: id, Name: id, GatewayID: gw, Enabled: true,
		Peer: peer, LocalSubnet: local, RemoteSubnet: remote,
		LocalID: localID, RemoteID: remoteID,
		Auth: "psk", Suite: "standard",
		Phase1:     cplane.IpsecPhaseDTO{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		Phase2:     cplane.IpsecPhaseDTO{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		PFS:        true,
		PSKVersion: 1,
	}
}

// 装配期的拒绝：这些都是"起来了却静默不工作"的前置条件，必须当场拒。
func TestAssembleRejects(t *testing.T) {
	base := func() nodeOptions {
		return nodeOptions{
			GatewayID: "ipsec-a", Listen: "127.0.0.1",
			Datapath: "netstack", TUNAddr: "10.20.0.1/16",
			Control: newFakeControl(), Log: quietLog(),
		}
	}
	cases := []struct {
		name string
		want string
		mut  func(*nodeOptions)
	}{
		{"IKE 与 NAT-T 同端口", "不能相同", func(o *nodeOptions) { o.IKEPort, o.NATTPort = 14500, 14500 }},
		{"端口越界", "端口越界", func(o *nodeOptions) { o.IKEPort = 70000 }},
		{"绑定地址非法", "不是合法 IP", func(o *nodeOptions) { o.Listen = "不是地址" }},
		{"数据面类型未知", "无法识别", func(o *nodeOptions) { o.Datapath = "xfrm" }},
		// netstack 模式下地址必须带前缀长度：前缀长度决定哪些地址算同网段直连，
		// 少了它协议栈会把该走隧道的目的地当成直连邻居。
		{"netstack 缺前缀长度", "前缀长度", func(o *nodeOptions) { o.TUNAddr = "10.20.0.1" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := base()
			c.mut(&o)
			n, err := assemble(o)
			if err == nil {
				n.close()
				t.Fatalf("应当拒绝装配（%s）", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误信息里应含 %q，实际：%v", c.want, err)
			}
		})
	}
}
