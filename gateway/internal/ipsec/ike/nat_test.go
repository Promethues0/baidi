package ike

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// NAT-T 的测试。
//
// ★这一组用例覆盖的错误有一个共同特征：**只在 NAT 路径上炸，非 NAT 环境永远发现不了**。
// 因为非 NAT 时两个检测哈希天然相等，判定逻辑写反、哈希算法选错、marker 混进签名字节，
// 统统不会有任何表现。所以必须专门造一个 NAT 环境来跑。

// ── 检测哈希本身 ──

func TestNATDetectHashShapeAndSensitivity(t *testing.T) {
	spii := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	spir := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
	base := netip.MustParseAddrPort("203.0.113.5:500")

	h := natDetectHash(spii, spir, base)
	// ★固定 20 字节 = SHA-1，与协商出的 PRF 无关。
	// 用 SHA-256 会算出 32 字节，对端按 20 字节比对必然不等 → 双方都判定
	// "对端在 NAT 后" → 双双切 4500 → 居然还能通，于是这个错误会一直潜伏到
	// 与第三方设备互通时才爆发。
	if len(h) != 20 {
		t.Fatalf("NAT 检测哈希应为 20 字节（SHA-1，与协商的 PRF 无关），实际 %d", len(h))
	}
	if !bytes.Equal(h, natDetectHash(spii, spir, base)) {
		t.Fatal("同样的输入必须算出同样的哈希")
	}

	// 四个输入分量各自都必须参与计算——漏掉任何一个，NAT 检测都会在某些
	// 场景下给出错误结论（例如只改端口的 NAPT 就检测不出来）。
	spii2 := spii
	spii2[0]++
	spir2 := spir
	spir2[7]++
	for name, other := range map[string][]byte{
		"SPIi": natDetectHash(spii2, spir, base),
		"SPIr": natDetectHash(spii, spir2, base),
		"IP":   natDetectHash(spii, spir, netip.MustParseAddrPort("203.0.113.6:500")),
		"端口":   natDetectHash(spii, spir, netip.MustParseAddrPort("203.0.113.5:4500")),
	} {
		if bytes.Equal(h, other) {
			t.Fatalf("%s 没有参与 NAT 检测哈希的计算", name)
		}
	}

	// IPv4-mapped IPv6 必须与纯 IPv4 算出同一个值：netip 里 ::ffff:a.b.c.d 的
	// As16() 是 16 字节，不 Unmap 就会与对端按 4 字节算出的哈希对不上。
	mapped := netip.AddrPortFrom(netip.AddrFrom16(base.Addr().As16()), base.Port())
	if !bytes.Equal(h, natDetectHash(spii, spir, mapped)) {
		t.Fatal("IPv4-mapped IPv6 地址应先 Unmap 再参与哈希")
	}
}

// ── 交叉比对逻辑 ──

func TestDetectNATIsCrossCompared(t *testing.T) {
	spii := [8]byte{0xaa}
	claimedSrc := netip.MustParseAddrPort("10.0.0.1:500") // 发送方自认为的源
	claimedDst := netip.MustParseAddrPort("10.0.0.2:500") // 发送方自认为的目的
	natedSrc := netip.MustParseAddrPort("198.51.100.7:33333")

	build := func(ps []Payload) *Message {
		raw, err := Encode(Header{SPIi: spii, Version: Version, ExchangeType: ExchangeIKESAInit}, ps)
		if err != nil {
			t.Fatalf("编码失败: %v", err)
		}
		m, err := Decode(raw)
		if err != nil {
			t.Fatalf("解码失败: %v", err)
		}
		return m
	}
	m := build(natNotifies(spii, [8]byte{}, claimedSrc, claimedDst))

	// ① 完全没有 NAT：实测地址与声明一致。
	peer, local, present := detectNAT(m, claimedSrc, claimedDst)
	if !present || peer || local {
		t.Fatalf("无 NAT 时不应判定任何一侧在 NAT 后（peer=%v local=%v present=%v）", peer, local, present)
	}

	// ② 对端在 NAT 后：我看到的源地址与它声明的不一样。
	peer, local, _ = detectNAT(m, natedSrc, claimedDst)
	if !peer || local {
		t.Fatalf("对端源地址被改写时应判定**对端**在 NAT 后（peer=%v local=%v）——"+
			"这里写反的话，非 NAT 环境下一切正常，只有真到 NAT 场景才炸", peer, local)
	}

	// ③ 本端在 NAT 后：对端声明的目的地址不是我实际收包的地址。
	peer, local, _ = detectNAT(m, claimedSrc, netip.MustParseAddrPort("192.168.1.9:500"))
	if peer || !local {
		t.Fatalf("目的地址对不上时应判定**本端**在 NAT 后（peer=%v local=%v）", peer, local)
	}

	// ④ ★对端根本没发 NAT 通知：必须两条都是 false，且 present=false。
	// 把"没发"当成"不匹配"，会让所有不支持 NAT-T 的对端被误判成 NAT 后并被切到
	// 4500 端口——而它根本没监听 4500，隧道就此消失。
	m2 := build([]Payload{&NoncePayload{Nonce: make([]byte, 32)}})
	peer, local, present = detectNAT(m2, natedSrc, claimedDst)
	if present || peer || local {
		t.Fatalf("对端没发 NAT 通知时必须一律判 false（peer=%v local=%v present=%v）", peer, local, present)
	}
}

// ── 端口切换：applyNAT ──

func TestApplyNATSwitchesPortsOnlyWhenNeeded(t *testing.T) {
	natLocal := netip.MustParseAddrPort("10.0.0.1:4500")

	// 无 NAT：一切不动，继续走 500。
	sa := newIKESA("s", true, time.Now())
	sa.Local = netip.MustParseAddrPort("10.0.0.1:500")
	sa.Peer = netip.MustParseAddrPort("10.0.0.2:500")
	sa.applyNAT(false, false, natLocal, 0)
	if sa.Local.Port() != 500 || sa.Peer.Port() != 500 {
		t.Fatalf("无 NAT 时不该切换端口，实际 local=%s peer=%s", sa.Local, sa.Peer)
	}

	// 本端在 NAT 后、对端不在：两侧都切 4500。
	sa = newIKESA("s", true, time.Now())
	sa.Local = netip.MustParseAddrPort("10.0.0.1:500")
	sa.Peer = netip.MustParseAddrPort("10.0.0.2:500")
	sa.applyNAT(false, true, natLocal, 0)
	if sa.Local != natLocal || sa.Peer.Port() != 4500 {
		t.Fatalf("检测到 NAT 后两侧都应切到 4500，实际 local=%s peer=%s", sa.Local, sa.Peer)
	}

	// ★发起方：对端在 NAT 后也必须切到**对端的封装口**，不能保留实测到的源端口。
	//
	// 那个源端口（33333）是 NAT 为对端的 **IKE 口(500)** 建立的映射——IKE_SA_INIT
	// 就是从 500 发出的。而对端从 IKE_AUTH 起改用封装口收发，保留 33333 等于把
	// IKE_AUTH 发进一个对端已经不再监听的映射。更糟的是本端此时已从 4500 发出
	// （Transport 会加 non-ESP marker），而 500 那侧按设计不剥 marker——
	// 收端解析失败后静默丢弃，协商停在 IKE_AUTH 且两端都不报错。
	sa = newIKESA("s", true, time.Now()) // true = 本端是发起方
	sa.Local = netip.MustParseAddrPort("10.0.0.1:500")
	sa.Peer = netip.MustParseAddrPort("198.51.100.7:33333")
	sa.applyNAT(true, false, natLocal, 0)
	if sa.Peer.Port() != 4500 {
		t.Fatalf("发起方应切到对端封装口 4500（对称假设），实际 %s", sa.Peer)
	}
	if sa.Local != natLocal {
		t.Fatalf("本端仍应切到 4500，实际 %s", sa.Local)
	}

	// 发起方 + 对端封装口非标准：必须用配置的 PeerNATPort，而不是对称假设。
	sa = newIKESA("s", true, time.Now())
	sa.Local = netip.MustParseAddrPort("10.0.0.1:500")
	sa.Peer = netip.MustParseAddrPort("198.51.100.7:33333")
	sa.applyNAT(true, false, natLocal, 15501)
	if sa.Peer.Port() != 15501 {
		t.Fatalf("配了 PeerNATPort 时应切到它，实际 %s", sa.Peer)
	}

	// ★响应方：保留实测到的映射端口。
	// 响应方观测到的源端口就是对端 NAT 映射出来的那个，硬改成 4500 会送到
	// NAT 设备上一个根本不存在的映射，全部黑洞。对端随后从自己的封装口发来
	// IKE_AUTH 时，onAuthRequest 会用实测地址覆盖（responder.go 的 sa.Peer = d.Remote）。
	sa = newIKESA("s", false, time.Now()) // false = 本端是响应方
	sa.Local = netip.MustParseAddrPort("10.0.0.1:500")
	sa.Peer = netip.MustParseAddrPort("198.51.100.7:33333")
	sa.applyNAT(true, false, natLocal, 0)
	if sa.Peer.Port() != 33333 {
		t.Fatalf("响应方应保留实测到的映射端口，实际 %s", sa.Peer)
	}

	// 双向 NAT（两个分支各自在 NAT 后、靠端口转发互通，是常见的企业组网形态）：
	// 发起方仍须切到对端封装口。不区分角色时两端都保留对方的 IKE 口，
	// 于是双方的 IKE_AUTH 都发给了对方不再监听的端口——隧道永远建不起来。
	sa = newIKESA("s", true, time.Now())
	sa.Local = netip.MustParseAddrPort("10.0.0.1:500")
	sa.Peer = netip.MustParseAddrPort("198.51.100.7:33333")
	sa.applyNAT(true, true, natLocal, 0)
	if sa.Peer.Port() != 4500 || sa.Local != natLocal {
		t.Fatalf("双向 NAT 下发起方两侧都应切到封装口，实际 local=%s peer=%s", sa.Local, sa.Peer)
	}

	// 没配 4500 落点时宁可不切：切到一个不存在的端口会让隧道彻底消失。
	sa = newIKESA("s", true, time.Now())
	sa.Local = netip.MustParseAddrPort("10.0.0.1:500")
	sa.Peer = netip.MustParseAddrPort("10.0.0.2:500")
	sa.applyNAT(true, true, netip.AddrPort{}, 0)
	if sa.Local.Port() != 500 {
		t.Fatalf("未配置 4500 落点时不该切换，实际 %s", sa.Local)
	}
	if !sa.PeerNATed || !sa.LocalNATed {
		t.Fatal("即便不切端口，NAT 判定也要记录下来（回报与 keepalive 都靠它）")
	}
}

// ── 端到端：一台网关在 NAT 后，完整握手必须成功 ──

// natMulti 把多个 MemTransport（500 / 4500）合成一个 ipsec.Transport。
//
// 生产实现（WP-E 的 transport_udp.go）同样是"一个 Transport 背后两个 socket"，
// 且 non-ESP marker 的加减完全由它独占——★上层永远看不到 marker，
// 这正是 RealMessage1/2 天然不含 marker 的原因（auth.go 第 2 条约束）。
type natMulti struct {
	subs map[netip.AddrPort]*ipsec.MemTransport
	any  *ipsec.MemTransport
	in   chan ipsec.Datagram
	done chan struct{}
	once sync.Once
}

func newNATMulti(ts ...*ipsec.MemTransport) *natMulti {
	m := &natMulti{
		subs: make(map[netip.AddrPort]*ipsec.MemTransport, len(ts)),
		in:   make(chan ipsec.Datagram, 64),
		done: make(chan struct{}),
	}
	for _, t := range ts {
		m.subs[t.Local()] = t
		if m.any == nil {
			m.any = t
		}
		go func(t *ipsec.MemTransport) {
			for {
				d, err := t.Recv()
				if err != nil {
					return
				}
				select {
				case m.in <- d:
				case <-m.done:
					return
				}
			}
		}(t)
	}
	return m
}

func (m *natMulti) Send(d ipsec.Datagram) error {
	t := m.subs[d.Local]
	if t == nil {
		t = m.any
	}
	return t.Send(d)
}

func (m *natMulti) Recv() (ipsec.Datagram, error) {
	select {
	case d := <-m.in:
		return d, nil
	case <-m.done:
		return ipsec.Datagram{}, ipsec.ErrClosed
	}
}

func (m *natMulti) Close() error {
	m.once.Do(func() {
		close(m.done)
		for _, t := range m.subs {
			_ = t.Close()
		}
	})
	return nil
}

// natRecord 抓包（含 Kind，keepalive 断言要用）。
type natRecord struct {
	mu   sync.Mutex
	pkts []ipsec.Datagram
}

func (r *natRecord) add(d ipsec.Datagram) {
	r.mu.Lock()
	r.pkts = append(r.pkts, ipsec.Datagram{
		Kind: d.Kind, Local: d.Local, Remote: d.Remote,
		Payload: append([]byte(nil), d.Payload...),
	})
	r.mu.Unlock()
}

func (r *natRecord) snapshot() []ipsec.Datagram {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ipsec.Datagram(nil), r.pkts...)
}

func TestNATTraversalCompletesHandshakeAndSwitchesTo4500(t *testing.T) {
	var (
		aIKE = netip.MustParseAddrPort("10.0.0.1:500")
		aNAT = netip.MustParseAddrPort("10.0.0.1:4500")
		bIKE = netip.MustParseAddrPort("10.0.0.2:500")
		bNAT = netip.MustParseAddrPort("10.0.0.2:4500")
		// A 在 NAT 后，公网映射：500→1500，4500→14500。
		pubIKE = netip.MustParseAddrPort("198.51.100.7:1500")
		pubNAT = netip.MustParseAddrPort("198.51.100.7:14500")
	)

	rec := &natRecord{}
	clk := newRKClock()

	cfgA := hsSiteA("baidi-ipsec-psk")
	cfgB := hsSiteB("baidi-ipsec-psk")
	// ★B 只知道 A 的**公网**地址——这正是 NAT 场景的定义。
	// findSiteByPeer 只比 IP 不比端口，否则 NAT 随机分配的源端口必然匹配不上，
	// 症状是"NAT 后的对端永远连不进来"，而日志里连一条记录都没有（静默丢包）。
	cfgB.Peer = netip.MustParseAddrPort("198.51.100.7:500")

	f := hsSetupWith(t, cfgA, cfgB, clk.now,
		func(n *ipsec.MemNet) (ipsec.Transport, ipsec.Transport, netip.AddrPort, netip.AddrPort, netip.AddrPort, netip.AddrPort) {
			mk := func(ap netip.AddrPort) *ipsec.MemTransport {
				tr, err := n.Bind(ap)
				if err != nil {
					t.Fatalf("绑定 %s 失败: %v", ap, err)
				}
				return tr
			}
			ta := newNATMulti(mk(aIKE), mk(aNAT))
			tb := newNATMulti(mk(bIKE), mk(bNAT))

			// NAT 设备：改写 A 出去的源地址，以及回程包的目的地址。
			n.SetFilter(func(d ipsec.Datagram) (ipsec.Datagram, bool) {
				switch d.Local {
				case aIKE:
					d.Local = pubIKE
				case aNAT:
					d.Local = pubNAT
				}
				switch d.Remote {
				case pubIKE:
					d.Remote = aIKE
				case pubNAT:
					d.Remote = aNAT
				}
				rec.add(d)
				return d, true
			})
			return ta, tb, aIKE, bIKE, aNAT, bNAT
		})

	hsWait(t, "NAT 环境下两端都建立成功", func() bool { return hsUp(f.a, "site-1") && hsUp(f.b, "site-1") })

	saA, saB := hsPrimarySA(f.a, "site-1"), hsPrimarySA(f.b, "site-1")

	// ── 判定方向必须正确（写反的话非 NAT 环境一切正常）──
	if !saA.LocalNATed || saA.PeerNATed {
		t.Fatalf("A 侧应判定「本端在 NAT 后、对端不在」，实际 local=%v peer=%v", saA.LocalNATed, saA.PeerNATed)
	}
	if saB.LocalNATed || !saB.PeerNATed {
		t.Fatalf("B 侧应判定「对端在 NAT 后、本端不在」，实际 local=%v peer=%v", saB.LocalNATed, saB.PeerNATed)
	}

	// ── IKE_AUTH 起切 4500 ──
	if saA.Local != aNAT {
		t.Fatalf("A 侧应从 IKE_AUTH 起改用 4500，实际本端落点 %s", saA.Local)
	}
	if saB.Local != bNAT {
		t.Fatalf("B 侧应从 IKE_AUTH 起改用 4500，实际本端落点 %s", saB.Local)
	}
	// B 发往 A 的地址必须是**实测到的 NAT 映射**，不是配置里的 198.51.100.7:500。
	if saB.Peer != pubNAT {
		t.Fatalf("B 应把对端地址更新为实测到的 NAT 映射 %s，实际 %s", pubNAT, saB.Peer)
	}

	// ── ★IKE_SA_INIT 那一轮必须还在 500 上 ──
	// 提前切的后果：响应从 4500 发出并被 Transport 加上 4 字节 non-ESP marker，
	// 而对端还在 500 上按裸 IKE 报文解析——第一个字节就是 0，解析失败且静默丢包。
	pkts := rec.snapshot()
	if len(pkts) < 4 {
		t.Fatalf("抓到 %d 条报文，握手至少 4 条", len(pkts))
	}
	for i := 0; i < 2; i++ {
		if pkts[i].Local.Port() == 4500 || pkts[i].Remote.Port() == 4500 {
			t.Fatalf("第 %d 条（IKE_SA_INIT）走了 4500：%s→%s；切换必须从 IKE_AUTH 开始",
				i+1, pkts[i].Local, pkts[i].Remote)
		}
	}
	for i := 2; i < 4; i++ {
		if pkts[i].Local.Port() != 4500 && pkts[i].Local.Port() != 14500 {
			t.Fatalf("第 %d 条（IKE_AUTH）没有走 4500：%s→%s", i+1, pkts[i].Local, pkts[i].Remote)
		}
	}

	// ── ★AUTH 成功本身就证明了签名字节串不含 non-ESP marker ──
	// marker 由 Transport 独占，从未进入 Engine；这里再正面验证一次
	// RealMessage1 确实是从 SPIi 第一字节开始的裸 IKE 报文。
	if !bytes.HasPrefix(saA.initMsgRaw, saA.SPIi[:]) {
		t.Fatal("RealMessage1 没有从 SPIi 第一字节开始——多半是 4 字节 non-ESP marker 混进了签名字节串")
	}
	if bytes.HasPrefix(saA.initMsgRaw, []byte{0, 0, 0, 0}) {
		t.Fatal("RealMessage1 以 4 个零字节开头，那正是 non-ESP marker 的形态")
	}
	if hdr, err := ParseHeader(saA.initMsgRaw); err != nil || hdr.ExchangeType != ExchangeIKESAInit {
		t.Fatalf("RealMessage1 应能直接按 IKE 头解析：%v / %v", err, hdr.ExchangeType)
	}
	if !bytes.Equal(saA.initMsgRaw, saB.initMsgRaw) || !bytes.Equal(saA.respMsgRaw, saB.respMsgRaw) {
		t.Fatal("两端缓存的 RealMessage1/2 必须逐字节相同，否则 AUTH 只能靠运气对上")
	}

	// 密钥仍然要两端一致（NAT 不该影响任何密码学计算）。
	if !bytes.Equal(saA.Keys.SKei, saB.Keys.SKei) || !bytes.Equal(saA.Keys.SKd, saB.Keys.SKd) {
		t.Fatal("NAT 环境下两端 IKE 密钥不一致")
	}

	// ── NAT keepalive ──
	before := len(rec.snapshot())
	clk.advance(natKeepaliveInterval + time.Second)
	f.a.runTimers()
	var ka *ipsec.Datagram
	for i, d := range rec.snapshot() {
		if i >= before && d.Kind == ipsec.KindKeepalive {
			ka = &rec.snapshot()[i]
			break
		}
	}
	if ka == nil {
		// ★不发 keepalive 的症状极具迷惑性：隧道建好后能跑，空闲一两分钟后单向不通
		//（NAT 映射老化，对端发来的包没有回程条目），本端一发包又立刻恢复——
		// 看起来像"网络时好时坏"。
		t.Fatal("本端在 NAT 后时必须定期发 NAT keepalive")
	}
	if len(ka.Payload) != 1 || ka.Payload[0] != 0xFF {
		t.Fatalf("NAT keepalive 必须是单字节 0xFF，实际 %x", ka.Payload)
	}

	// B 不在 NAT 后，不该发 keepalive（白白烧对端的 CPU 与流量）。
	beforeB := len(rec.snapshot())
	clk.advance(natKeepaliveInterval + time.Second)
	f.b.runTimers()
	for i, d := range rec.snapshot() {
		if i >= beforeB && d.Kind == ipsec.KindKeepalive && d.Local.Addr() == bIKE.Addr() {
			t.Fatal("不在 NAT 后的一端不应发 keepalive")
		}
	}
}

// 双向 NAT + 非标准封装口：两端各自在 NAT 后，且对端的封装口不是 4500。
//
// ★两个分支各自在 NAT 后、靠端口转发互通是常见的企业组网形态。它一次性压住
// 本轮线上暴露的两个缺陷：
//
//	① applyNAT 不区分发起方/响应方 → 发起方保留对端的 IKE 口，IKE_AUTH 发进
//	   一个对方已不再监听的端口；
//	② applyNAT 之后 onSAInitResponse 里那句 `sa.Peer = d.Remote` 连**端口**一起
//	   覆盖 → 把刚切好的封装口冲回成 IKE_SA_INIT 响应的源端口。
//
// 两者症状完全一样且都不报错：协商停在 IKE_AUTH，而日志里「对端落点」还显示着
// 正确的值（那条日志打在覆盖之前），照着日志排查会一直看错方向。
func TestBidirectionalNATWithNonStandardEncapPorts(t *testing.T) {
	var (
		aIKE = netip.MustParseAddrPort("10.0.0.1:500")
		aNAT = netip.MustParseAddrPort("10.0.0.1:4500")
		// B 用非标准封装口（如与既有 IPSec 共存时被迫改的端口）。
		bIKE = netip.MustParseAddrPort("10.0.0.2:15500")
		bNAT = netip.MustParseAddrPort("10.0.0.2:15501")
		// 两端各自的公网映射。
		pubAIKE = netip.MustParseAddrPort("198.51.100.7:1500")
		pubANAT = netip.MustParseAddrPort("198.51.100.7:14500")
		pubBIKE = netip.MustParseAddrPort("198.51.100.8:25500")
		pubBNAT = netip.MustParseAddrPort("198.51.100.8:25501")
	)

	clk := newRKClock()
	cfgA := hsSiteA("baidi-ipsec-psk")
	cfgB := hsSiteB("baidi-ipsec-psk")
	// 每一端只知道对方的**公网**落点。
	cfgA.Peer, cfgB.Peer = pubBIKE, pubAIKE
	// 对端封装口只能靠显式配置表达——IKEv2 没有通告它的机制（RFC 3948 定死 4500）。
	cfgA.PeerNATPort, cfgB.PeerNATPort = pubBNAT.Port(), pubANAT.Port()

	f := hsSetupWith(t, cfgA, cfgB, clk.now,
		func(n *ipsec.MemNet) (ipsec.Transport, ipsec.Transport, netip.AddrPort, netip.AddrPort, netip.AddrPort, netip.AddrPort) {
			mk := func(ap netip.AddrPort) *ipsec.MemTransport {
				tr, err := n.Bind(ap)
				if err != nil {
					t.Fatalf("绑定 %s 失败: %v", ap, err)
				}
				return tr
			}
			ta := newNATMulti(mk(aIKE), mk(aNAT))
			tb := newNATMulti(mk(bIKE), mk(bNAT))
			// 两台 NAT 设备：出方向改源、回程改目的，两端对称。
			out := map[netip.AddrPort]netip.AddrPort{
				aIKE: pubAIKE, aNAT: pubANAT, bIKE: pubBIKE, bNAT: pubBNAT,
			}
			back := map[netip.AddrPort]netip.AddrPort{
				pubAIKE: aIKE, pubANAT: aNAT, pubBIKE: bIKE, pubBNAT: bNAT,
			}
			n.SetFilter(func(d ipsec.Datagram) (ipsec.Datagram, bool) {
				if v, ok := out[d.Local]; ok {
					d.Local = v
				}
				if v, ok := back[d.Remote]; ok {
					d.Remote = v
				}
				return d, true
			})
			return ta, tb, aIKE, bIKE, aNAT, bNAT
		})

	hsWait(t, "双向 NAT + 非标准封装口下握手完成", func() bool { return hsUp(f.a, "site-1") && hsUp(f.b, "site-1") })

	saA, saB := hsPrimarySA(f.a, "site-1"), hsPrimarySA(f.b, "site-1")
	if !saA.PeerNATed || !saA.LocalNATed || !saB.PeerNATed || !saB.LocalNATed {
		t.Fatalf("双向 NAT 下两端都应判定双侧在 NAT 后，实际 A(peer=%v local=%v) B(peer=%v local=%v)",
			saA.PeerNATed, saA.LocalNATed, saB.PeerNATed, saB.LocalNATed)
	}
	if saA.Local != aNAT || saB.Local != bNAT {
		t.Fatalf("两端都应从 IKE_AUTH 起切到各自的封装口，实际 A=%s B=%s", saA.Local, saB.Local)
	}
	// ★发起方必须发往对端的**封装口**映射，而不是它的 IKE 口映射。
	if saA.Peer != pubBNAT {
		t.Fatalf("发起方 A 应发往对端封装口映射 %s，实际 %s（发到 IKE 口的话对端不剥 marker，静默丢弃）",
			pubBNAT, saA.Peer)
	}
}
