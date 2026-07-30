package ike

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// 本文件是「真的协商了」的证据。
//
// 正例（两端跑通握手）本身说明不了什么——一个 `return nil` 也能让状态变成 up。
// 有说服力的是下面四组断言：
//
//	① **两端各自独立导出的密钥逐字节相等**。这是 Diffie-Hellman 的定义性质：
//	   双方从未交换过密钥本身，却算出同一串字节。假实现伪造不出来——除非它
//	   把密钥明文发过去，而 ② 恰好把这条路堵死了。
//	② **这些密钥字节从未出现在任何一条抓到的报文里**（全报文逐条扫描）。
//	③ **报文序列符合 RFC**（Exchange Type 34/34/35/35），且 IKE_AUTH 里的身份
//	   在明文中不可见——证明 SK 载荷真的加密了，而不是"加密"了个寂寞。
//	④ **反例三连**：PSK 改一位 → AUTHENTICATION_FAILED；套件不相交 →
//	   NO_PROPOSAL_CHOSEN；网段对不上 → TS_UNACCEPTABLE 且 **IKE SA 仍存活**。
//	   没有反例，正例毫无意义。

// ── 测试用的假数据面 ──

// hsProtector 记录 IKE 推下来的 Child SA 参数。
// 它不做任何加解密——本文件要验证的是**协商**，加解密由 esp 包的 KAT 测试守着。
type hsProtector struct {
	mu   sync.Mutex
	live map[uint32]ipsec.ChildSAParams
}

func newHSProtector() *hsProtector {
	return &hsProtector{live: make(map[uint32]ipsec.ChildSAParams)}
}

func (p *hsProtector) Install(x ipsec.ChildSAParams) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.live[x.InSPI] = x
	return nil
}

func (p *hsProtector) Remove(inSPI uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.live, inSPI)
	return nil
}

func (p *hsProtector) Counters(uint32) ipsec.Counters { return ipsec.Counters{} }

// count 已装载的 Child SA 条数。
// ★必须走锁：装载发生在引擎的事件循环 goroutine 里，测试直接读 map 长度
// 是一条真实的数据竞争（只是不一定每次都被 -race 抓到）。
func (p *hsProtector) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.live)
}

func (p *hsProtector) Protect([]byte) ([]byte, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, ipsec.ErrNoPolicy
}

func (p *hsProtector) Unprotect([]byte, netip.AddrPort) ([]byte, error) { return nil, ipsec.ErrNoSA }

// only 返回唯一一条在册的 Child SA。多于一条说明退休逻辑没生效，直接失败。
func (p *hsProtector) only(t *testing.T) ipsec.ChildSAParams {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.live) != 1 {
		t.Fatalf("期望恰好 1 条已装载的 Child SA，实际 %d 条", len(p.live))
	}
	for _, v := range p.live {
		return v
	}
	return ipsec.ChildSAParams{}
}

// ── 报文抓包 ──

type hsPacket struct {
	from, to netip.AddrPort
	payload  []byte
}

type hsCapture struct {
	mu   sync.Mutex
	pkts []hsPacket
}

func (c *hsCapture) filter(d ipsec.Datagram) (ipsec.Datagram, bool) {
	c.mu.Lock()
	c.pkts = append(c.pkts, hsPacket{
		from: d.Local, to: d.Remote,
		payload: append([]byte(nil), d.Payload...),
	})
	c.mu.Unlock()
	return d, true
}

func (c *hsCapture) snapshot() []hsPacket {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]hsPacket(nil), c.pkts...)
}

// ── 装配 ──

var (
	hsAddrA = netip.MustParseAddrPort("10.0.0.1:500")
	hsAddrB = netip.MustParseAddrPort("10.0.0.2:500")
)

// hsSiteA / hsSiteB 一对互为对端的站点配置。
//
// ★两端的 LocalSubnet/RemoteSubnet 是**交叉**的，LocalID/RemoteID 也是。
// 这个交叉正是 responder 侧最容易写反的地方（见 acceptChildFromAuth 的注释），
// 所以测试里必须用两个不同的网段，用同一个网段会让写反也能过。
func hsSiteA(psk string) ipsec.SiteConfig {
	return ipsec.SiteConfig{
		ID: "site-1", Name: "成都", GatewayID: "gw-a", Enabled: true,
		Peer:         hsAddrB,
		LocalSubnet:  netip.MustParsePrefix("10.20.0.0/16"),
		RemoteSubnet: netip.MustParsePrefix("10.60.0.0/16"),
		LocalID:      "gw-a.baidi", RemoteID: "gw-b.baidi",
		Auth: "psk", Suite: SuiteStandard,
		Phase1: ipsec.Phase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		Phase2: ipsec.Phase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		PSK:    []byte(psk),
	}
}

func hsSiteB(psk string) ipsec.SiteConfig {
	c := hsSiteA(psk)
	c.GatewayID = "gw-b"
	c.Peer = hsAddrA
	c.LocalSubnet = netip.MustParsePrefix("10.60.0.0/16")
	c.RemoteSubnet = netip.MustParsePrefix("10.20.0.0/16")
	c.LocalID, c.RemoteID = "gw-b.baidi", "gw-a.baidi"
	return c
}

type hsFixture struct {
	net    *ipsec.MemNet
	cap    *hsCapture
	a, b   *Engine
	pa, pb *hsProtector
}

// hsSetup 起两台引擎，A 作为发起方，B 作为响应方。
//
// ★两端的 Tick 都设成 1 小时：定时器由测试**手工**驱动（a.runTimers()），
// 于是"谁先发起"完全确定，也不会有 sleep。真实部署里 B 也会在自己的 tick 上
// 发起协商，那条路径由 TestSimultaneousInitiationConvergesToOneSA 单独覆盖。
func hsSetup(t *testing.T, cfgA, cfgB ipsec.SiteConfig) *hsFixture {
	t.Helper()
	return hsSetupWith(t, cfgA, cfgB, nil, nil)
}

// hsLogger `go test -v` 时把两端的 debug 日志打到 stderr。
//
// ★这不是装饰：协商失败的根因几乎总在"两端各自算了什么"里，而两端的日志必须
// 并排看才有意义（SignedOctetsDigest 就是为此设计的）。
func hsLogger() *slog.Logger {
	if !testing.Verbose() {
		return nil
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// hsSetupWith 是通用装配：可注入时钟（rekey/DPD 测试用）与自定义 Transport（NAT 测试用）。
//
// clock 为 nil 时用真实时钟；mkTransport 为 nil 时各绑一个 500 端口。
func hsSetupWith(
	t *testing.T,
	cfgA, cfgB ipsec.SiteConfig,
	clock func() time.Time,
	mkTransport func(n *ipsec.MemNet) (ta, tb ipsec.Transport, localA, localB, natA, natB netip.AddrPort),
) *hsFixture {
	t.Helper()
	net := ipsec.NewMemNet()
	cap := &hsCapture{}
	net.SetFilter(cap.filter)

	var (
		ta, tb                     ipsec.Transport
		localA, localB, natA, natB netip.AddrPort
	)
	if mkTransport != nil {
		ta, tb, localA, localB, natA, natB = mkTransport(net)
	} else {
		var err error
		if ta, err = net.Bind(hsAddrA); err != nil {
			t.Fatalf("绑定 A 失败: %v", err)
		}
		if tb, err = net.Bind(hsAddrB); err != nil {
			t.Fatalf("绑定 B 失败: %v", err)
		}
		localA, localB = hsAddrA, hsAddrB
	}

	log := hsLogger()
	pa, pb := newHSProtector(), newHSProtector()
	a := NewEngine(EngineOptions{Transport: ta, Protector: pa, LocalIKE: localA, LocalNAT: natA, Tick: time.Hour, Log: log, Now: clock})
	b := NewEngine(EngineOptions{Transport: tb, Protector: pb, LocalIKE: localB, LocalNAT: natB, Tick: time.Hour, Log: log, Now: clock})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ta.Close()
		_ = tb.Close()
	})
	go func() { _ = a.Run(ctx) }()
	go func() { _ = b.Run(ctx) }()

	if err := b.AddSite(cfgB); err != nil {
		t.Fatalf("B 装载站点失败: %v", err)
	}
	if err := a.AddSite(cfgA); err != nil {
		t.Fatalf("A 装载站点失败: %v", err)
	}
	a.runTimers() // 只有 A 主动发起
	return &hsFixture{net: net, cap: cap, a: a, b: b, pa: pa, pb: pb}
}

// hsWait 轮询等待条件成立。用轮询而不是 sleep 固定时长：
// 前者在快机器上瞬间返回，在慢机器上也不会假失败。
func hsWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

// hsState 取某个站点当前的对外状态。
func hsState(e *Engine, id string) ipsec.SiteState {
	for _, st := range e.States() {
		if st.SiteID == id {
			return st
		}
	}
	return ipsec.SiteState{}
}

// hsPrimarySA 取某站点当前承载流量的 IKE SA（测试与实现同包，可以直接看内部状态）。
func hsPrimarySA(e *Engine, id string) *IKESA {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sites[id]
	if s == nil {
		return nil
	}
	return s.primary()
}

func hsUp(e *Engine, id string) bool { return hsState(e, id).State == ipsec.StateUp }

// ── ① 正例：完整握手 + 密钥交叉相等 ──

func TestHandshakeDerivesIdenticalKeysOnBothEnds(t *testing.T) {
	f := hsSetup(t, hsSiteA("baidi-ipsec-psk"), hsSiteB("baidi-ipsec-psk"))

	hsWait(t, "两端站点都变成 up", func() bool { return hsUp(f.a, "site-1") && hsUp(f.b, "site-1") })

	saA, saB := hsPrimarySA(f.a, "site-1"), hsPrimarySA(f.b, "site-1")
	if saA == nil || saB == nil {
		t.Fatal("两端应各有一条已建立的 IKE SA")
	}

	// ── 角色与 SPI ──
	if !saA.LocalIsInit || saB.LocalIsInit {
		t.Fatalf("原始角色错误：A 应为发起方（实际 %v），B 应为响应方（实际 %v）", saA.LocalIsInit, saB.LocalIsInit)
	}
	if saA.SPIi != saB.SPIi || saA.SPIr != saB.SPIr {
		t.Fatalf("两端的 IKE SPI 不一致：A=%s/%s B=%s/%s",
			spiHex(saA.SPIi), spiHex(saA.SPIr), spiHex(saB.SPIi), spiHex(saB.SPIr))
	}

	// ── ★核心断言：七段 IKE 密钥逐字节相等 ──
	//
	// 两端从未交换过任何一段密钥（② 会证明这一点），却算出同一串字节——
	// 这只可能来自一次真实的 Diffie-Hellman + prf+ 派生。
	for _, kv := range []struct {
		name string
		a, b []byte
	}{
		{"SK_d", saA.Keys.SKd, saB.Keys.SKd},
		{"SK_ei", saA.Keys.SKei, saB.Keys.SKei},
		{"SK_er", saA.Keys.SKer, saB.Keys.SKer},
		{"SK_ai", saA.Keys.SKai, saB.Keys.SKai},
		{"SK_ar", saA.Keys.SKar, saB.Keys.SKar},
		{"SK_pi", saA.Keys.SKpi, saB.Keys.SKpi},
		{"SK_pr", saA.Keys.SKpr, saB.Keys.SKpr},
	} {
		if !bytes.Equal(kv.a, kv.b) {
			t.Fatalf("%s 两端不一致：A=%x B=%x", kv.name, kv.a, kv.b)
		}
	}
	if len(saA.Keys.SKei) != 36 {
		t.Fatalf("AES256-GCM 的 SK_ei 应为 36 字节（32 密钥 + 4 salt），实际 %d", len(saA.Keys.SKei))
	}
	if saA.Keys.SKai != nil || saA.Keys.SKar != nil {
		t.Fatalf("combined 模式下不应派生 SK_ai/SK_ar，实际 %d/%d 字节", len(saA.Keys.SKai), len(saA.Keys.SKar))
	}

	// ── ★KEYMAT：出向 = 对端入向，逐字节 ──
	//
	// 这一条同时守住了两件事：KEYMAT 切片顺序（encr_i‖integ_i‖encr_r‖integ_r）
	// 与方向选取（LocalIsInit 决定取哪一半）。任一写反都会让下面四行里的某一行炸。
	ca, cb := f.pa.only(t), f.pb.only(t)
	if ca.InSPI != cb.OutSPI || ca.OutSPI != cb.InSPI {
		t.Fatalf("Child SA 的 SPI 没有交叉相等：A(in=%08x out=%08x) B(in=%08x out=%08x)",
			ca.InSPI, ca.OutSPI, cb.InSPI, cb.OutSPI)
	}
	if ca.InSPI <= 255 || cb.InSPI <= 255 {
		t.Fatalf("ESP SPI 落进了保留区（≤255）：A=%08x B=%08x", ca.InSPI, cb.InSPI)
	}
	if !bytes.Equal(ca.OutEncrKey, cb.InEncrKey) {
		t.Fatalf("A 的出向加密密钥与 B 的入向不一致：%x vs %x", ca.OutEncrKey, cb.InEncrKey)
	}
	if !bytes.Equal(ca.InEncrKey, cb.OutEncrKey) {
		t.Fatalf("A 的入向加密密钥与 B 的出向不一致：%x vs %x", ca.InEncrKey, cb.OutEncrKey)
	}
	if bytes.Equal(ca.OutEncrKey, ca.InEncrKey) {
		t.Fatal("两个方向用了同一把 ESP 密钥——KEYMAT 切片必然写错了")
	}
	if ca.EncrID != EncrAESGCM16 || ca.KeyBits != 256 || ca.IntegID != IntegNone {
		t.Fatalf("Child SA 算法码点不对：encr=%d keyBits=%d integ=%d", ca.EncrID, ca.KeyBits, ca.IntegID)
	}
	if ca.LocalTS.String() != "10.20.0.0/16" || ca.RemoteTS.String() != "10.60.0.0/16" {
		t.Fatalf("A 侧 Child SA 的网段方向写反了：local=%s remote=%s", ca.LocalTS, ca.RemoteTS)
	}
	if cb.LocalTS.String() != "10.60.0.0/16" || cb.RemoteTS.String() != "10.20.0.0/16" {
		t.Fatalf("B 侧 Child SA 的网段方向写反了：local=%s remote=%s", cb.LocalTS, cb.RemoteTS)
	}

	// ── 对外状态：SPI 是"真协商过"最硬的可视证据 ──
	stA, stB := hsState(f.a, "site-1"), hsState(f.b, "site-1")
	if stA.IKESPIi == "" || stA.IKESPIi != stB.IKESPIi || stA.IKESPIr != stB.IKESPIr {
		t.Fatalf("回报的 IKE SPI 两端对不上：A=%s/%s B=%s/%s", stA.IKESPIi, stA.IKESPIr, stB.IKESPIi, stB.IKESPIr)
	}
	if stA.ChildSPIIn != stB.ChildSPIOut || stA.ChildSPIOut != stB.ChildSPIIn {
		t.Fatal("回报的 Child SPI 没有交叉相等")
	}
	// 协商结果必须是**真实算法名**，不是 suite 标签——"配的是 A、谈出来 B"要一眼可见。
	if !strings.Contains(stA.NegotiatedProposal, "AES256-GCM16") ||
		!strings.Contains(stA.NegotiatedProposal, "ECP256") {
		t.Fatalf("协商结果文案没有给出真实算法：%q", stA.NegotiatedProposal)
	}
	if stA.LastError != "" {
		t.Fatalf("成功路径不该留下错误：%q", stA.LastError)
	}

	// ── ② 密钥字节绝不能出现在任何一条报文里 ──
	hsAssertSecretsNeverOnWire(t, f.cap.snapshot(), map[string][]byte{
		"SK_d":     saA.Keys.SKd,
		"SK_ei":    saA.Keys.SKei,
		"SK_er":    saA.Keys.SKer,
		"SK_pi":    saA.Keys.SKpi,
		"SK_pr":    saA.Keys.SKpr,
		"ESP 出向密钥": ca.OutEncrKey,
		"ESP 入向密钥": ca.InEncrKey,
		"PSK":      []byte("baidi-ipsec-psk"),
	})

	// ── ③ 报文序列与"身份确实被加密了" ──
	hsAssertWireShape(t, f.cap.snapshot())
}

// hsAssertSecretsNeverOnWire 逐条报文扫描，任何一段密钥出现即失败。
//
// ★逐条扫而不是把所有报文拼起来扫：拼接会在边界处造出现实中不存在的字节序列，
// 制造假失败。反过来漏检的风险不存在——密钥不可能被拆成两半分两个包发。
func hsAssertSecretsNeverOnWire(t *testing.T, pkts []hsPacket, secrets map[string][]byte) {
	t.Helper()
	if len(pkts) < 4 {
		t.Fatalf("抓到的报文只有 %d 条，握手至少 4 条", len(pkts))
	}
	for name, sec := range secrets {
		if len(sec) == 0 {
			continue
		}
		for i, p := range pkts {
			if bytes.Contains(p.payload, sec) {
				t.Fatalf("第 %d 条报文（%s→%s，%d 字节）里出现了 %s 的明文字节——密钥泄漏到线上了",
					i+1, p.from, p.to, len(p.payload), name)
			}
		}
	}
}

// hsAssertWireShape 断言报文序列符合 RFC，且 IKE_AUTH 的身份不可见。
func hsAssertWireShape(t *testing.T, pkts []hsPacket) {
	t.Helper()
	want := []ExchangeType{ExchangeIKESAInit, ExchangeIKESAInit, ExchangeIKEAuth, ExchangeIKEAuth}
	if len(pkts) < len(want) {
		t.Fatalf("报文条数 %d 少于握手所需的 %d", len(pkts), len(want))
	}
	for i, et := range want {
		hdr, err := ParseHeader(pkts[i].payload)
		if err != nil {
			t.Fatalf("第 %d 条报文头解析失败: %v", i+1, err)
		}
		if hdr.ExchangeType != et {
			t.Fatalf("第 %d 条报文的交换类型是 %s（%d），应为 %s（%d）",
				i+1, hdr.ExchangeType, uint8(hdr.ExchangeType), et, uint8(et))
		}
		if hdr.Version != Version {
			t.Fatalf("第 %d 条报文的版本字节是 %#x，应为 %#x", i+1, hdr.Version, Version)
		}
	}
	// Message ID：SA_INIT 两条都是 0，IKE_AUTH 两条都是 1。
	for i, wantMID := range []uint32{0, 0, 1, 1} {
		hdr, _ := ParseHeader(pkts[i].payload)
		if hdr.MessageID != wantMID {
			t.Fatalf("第 %d 条报文的 Message ID 是 %d，应为 %d", i+1, hdr.MessageID, wantMID)
		}
	}
	// I 位：前三条由发起方发（含它发的 AUTH 请求）为 1，B 的两条响应为 0。
	for i, fromInit := range []bool{true, false, true, false} {
		hdr, _ := ParseHeader(pkts[i].payload)
		if hdr.FromInitiator() != fromInit {
			t.Fatalf("第 %d 条报文的 I 位是 %v，应为 %v（I 位描述的是该 SA 的**原始**发起方）",
				i+1, hdr.FromInitiator(), fromInit)
		}
	}
	// ★IKE_AUTH 里的身份必须被 SK 加密：明文中出现即说明 SK 载荷形同虚设。
	for i := 2; i < 4; i++ {
		for _, id := range []string{"gw-a.baidi", "gw-b.baidi"} {
			if bytes.Contains(pkts[i].payload, []byte(id)) {
				t.Fatalf("第 %d 条报文（IKE_AUTH）的明文里能看到身份 %q——SK 载荷没有真正加密", i+1, id)
			}
		}
	}
	// 反过来，IKE_SA_INIT 是明文交换，SA/KE/Nonce 一定在里面；
	// 若连它都"看起来像密文"，说明上面那条断言其实什么都没验到。
	m, err := Decode(pkts[0].payload)
	if err != nil {
		t.Fatalf("IKE_SA_INIT 请求应能被明文解析: %v", err)
	}
	if m.Find(PayloadSA) == nil || m.Find(PayloadKE) == nil || m.Find(PayloadNonce) == nil {
		t.Fatal("IKE_SA_INIT 请求里应能明文看到 SA/KE/Nonce 三个载荷")
	}
	if m.Find(PayloadSK) != nil {
		t.Fatal("IKE_SA_INIT 不应含 SK 载荷（此时密钥还没派生出来）")
	}
	if n := m.FindNotify(NotifyNATDetectionSourceIP); n == nil || len(n.Data) != 20 {
		t.Fatalf("IKE_SA_INIT 应带 20 字节（SHA-1）的 NAT_DETECTION_SOURCE_IP，实际 %v", n)
	}
}

// ── ④ 反例一：PSK 改一位 → AUTHENTICATION_FAILED ──

func TestHandshakeRejectsMismatchedPSK(t *testing.T) {
	// 只差一个字符。★这正是最需要测的形态：差一位与差一百位在密码学上等价，
	// 但"只差一位"能同时验证 PSK 真的参与了计算，而不是被当成了可有可无的装饰。
	f := hsSetup(t, hsSiteA("baidi-ipsec-psk"), hsSiteB("baidi-ipsec-psX"))

	hsWait(t, "A 侧站点被判 failed", func() bool { return hsState(f.a, "site-1").State == ipsec.StateFailed })

	stA := hsState(f.a, "site-1")
	if !strings.Contains(stA.LastError, "AUTHENTICATION_FAILED") {
		t.Fatalf("A 侧失败原因应点明 AUTHENTICATION_FAILED，实际：%q", stA.LastError)
	}
	stB := hsState(f.b, "site-1")
	if stB.State != ipsec.StateFailed {
		t.Fatalf("B 侧也应判 failed，实际 %s", stB.State)
	}
	// ★失败原因必须能直接指导排障：只写"认证失败"三个字等于没写。
	if !strings.Contains(stB.LastError, "PSK") {
		t.Fatalf("B 侧失败原因应指向 PSK，实际：%q", stB.LastError)
	}
	if f.pa.count() != 0 || f.pb.count() != 0 {
		t.Fatal("认证失败时不得装载任何 Child SA")
	}
	// 认证失败后 IKE SA 必须被拆掉（与 TS 失败那条路径相反，见下一个用例）。
	if sa := hsPrimarySA(f.a, "site-1"); sa != nil {
		t.Fatal("认证失败后 A 侧不应还留着已建立的 IKE SA")
	}
}

// ── ④ 反例二：套件不相交 → NO_PROPOSAL_CHOSEN ──

func TestHandshakeRejectsDisjointProposal(t *testing.T) {
	cfgA := hsSiteA("baidi-ipsec-psk")
	cfgB := hsSiteB("baidi-ipsec-psk")
	// B 只接受 AES256-CBC，A 只提 AES256-GCM。
	cfgB.Phase1 = ipsec.Phase{Enc: "AES256-CBC", Hash: "SHA256", DH: "group19"}
	f := hsSetup(t, cfgA, cfgB)

	hsWait(t, "A 侧站点被判 failed", func() bool { return hsState(f.a, "site-1").State == ipsec.StateFailed })

	stA := hsState(f.a, "site-1")
	if !strings.Contains(stA.LastError, "NO_PROPOSAL_CHOSEN") {
		t.Fatalf("A 侧失败原因应点明 NO_PROPOSAL_CHOSEN，实际：%q", stA.LastError)
	}
	// ★B 侧的错误信息必须同时包含"对端提了什么"与"本端要什么"——
	// 只回一个码点，两端管理员各改各的配置能耗掉一整天。
	stB := hsState(f.b, "site-1")
	if !strings.Contains(stB.LastError, "AES256-CBC") || !strings.Contains(stB.LastError, "ENCR") {
		t.Fatalf("B 侧失败原因应同时给出本端要求与对端提案，实际：%q", stB.LastError)
	}
	// 拒绝提案时不建立任何状态（half-open 配额不能被这种请求消耗）。
	f.b.mu.Lock()
	half := f.b.halfOpen.total
	f.b.mu.Unlock()
	if half != 0 {
		t.Fatalf("提案被拒时不应占用 half-open 配额，实际 %d", half)
	}
}

// ── ④ 反例三：网段对不上 → TS_UNACCEPTABLE，且 IKE SA 必须存活 ──

func TestHandshakeRejectsMismatchedTrafficSelectors(t *testing.T) {
	cfgA := hsSiteA("baidi-ipsec-psk")
	cfgB := hsSiteB("baidi-ipsec-psk")
	cfgB.LocalSubnet = netip.MustParsePrefix("10.70.0.0/16") // A 要的是 10.60.0.0/16
	f := hsSetup(t, cfgA, cfgB)

	hsWait(t, "A 侧站点被判 failed", func() bool { return hsState(f.a, "site-1").State == ipsec.StateFailed })

	stA := hsState(f.a, "site-1")
	if !strings.Contains(stA.LastError, "TS_UNACCEPTABLE") {
		t.Fatalf("A 侧失败原因应点明 TS_UNACCEPTABLE，实际：%q", stA.LastError)
	}
	stB := hsState(f.b, "site-1")
	if !strings.Contains(stB.LastError, "10.70.0.0/16") || !strings.Contains(stB.LastError, "10.60.0.0") {
		t.Fatalf("B 侧失败原因应把两侧实际网段都打出来，实际：%q", stB.LastError)
	}

	// ★核心：认证成功、只是 Child SA 谈不拢 → **IKE SA 必须存活**。
	// 拆掉它对端会以为整条连接没了并立刻重连，两端陷入"建了拆、拆了建"的循环，
	// 而真正的根因（网段配错）一次都不会被人看到。
	hsWait(t, "两端 IKE SA 都保持存活", func() bool {
		saA, saB := hsAnySA(f.a, "site-1"), hsAnySA(f.b, "site-1")
		return saA != nil && saA.State == SAEstablished && saB != nil && saB.State == SAEstablished
	})
	if f.pa.count() != 0 || f.pb.count() != 0 {
		t.Fatal("TS 谈不拢时不得装载 Child SA")
	}
}

// hsAnySA 取该站点下第一条非 Dead 的 IKE SA（primary 要求非退休，这里更宽松）。
func hsAnySA(e *Engine, id string) *IKESA {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sites[id]
	if s == nil {
		return nil
	}
	for _, sa := range s.sas {
		if sa.State != SADead {
			return sa
		}
	}
	return nil
}

// ── 国密私有码点走同一条链路 ──
//
// 不是为了"支持国密"这个卖点，而是为了守住套件参数化：
// 一旦有人把 AES 硬编码进状态机，这条用例会立刻变红。
func TestHandshakeWithGMSuite(t *testing.T) {
	cfgA := hsSiteA("baidi-ipsec-psk")
	cfgA.Suite = SuiteGM
	cfgA.Phase1 = ipsec.Phase{Enc: "SM4-GCM", Hash: "SM3", DH: "sm2p256"}
	cfgA.Phase2 = cfgA.Phase1
	cfgB := hsSiteB("baidi-ipsec-psk")
	cfgB.Suite = SuiteGM
	cfgB.Phase1 = cfgA.Phase1
	cfgB.Phase2 = cfgA.Phase1

	f := hsSetup(t, cfgA, cfgB)
	hsWait(t, "国密套件下两端都 up", func() bool { return hsUp(f.a, "site-1") && hsUp(f.b, "site-1") })

	saA, saB := hsPrimarySA(f.a, "site-1"), hsPrimarySA(f.b, "site-1")
	if !bytes.Equal(saA.Keys.SKei, saB.Keys.SKei) {
		t.Fatal("国密套件下两端 SK_ei 不一致")
	}
	if len(saA.Keys.SKei) != 20 {
		t.Fatalf("SM4-GCM 的 SK_ei 应为 20 字节（16 密钥 + 4 salt），实际 %d", len(saA.Keys.SKei))
	}
	st := hsState(f.a, "site-1")
	if !strings.Contains(st.NegotiatedProposal, "SM4-GCM16") || !strings.Contains(st.NegotiatedProposal, "SM2P256") {
		t.Fatalf("协商结果应显示真实的国密算法名，实际：%q", st.NegotiatedProposal)
	}
	hsAssertSecretsNeverOnWire(t, f.cap.snapshot(), map[string][]byte{
		"SK_ei": saA.Keys.SKei, "SK_d": saA.Keys.SKd,
	})
}

// ── 私有码点必须被 suite=standard 挡住 ──

func TestAddSiteRejectsPrivateCodepointsUnderStandardSuite(t *testing.T) {
	e := NewEngine(EngineOptions{Transport: nil, Tick: time.Hour})
	cfg := hsSiteA("psk")
	cfg.Suite = SuiteStandard
	cfg.Phase1 = ipsec.Phase{Enc: "SM4-GCM", Hash: "SM3", DH: "sm2p256"}
	err := e.AddSite(cfg)
	if err == nil {
		t.Fatal("suite=standard 下不应放行私有码点")
	}
	var ce *ipsec.ConfigError
	if !asConfigError(err, &ce) {
		t.Fatalf("装载期拒绝必须是 *ipsec.ConfigError（这样才能原样回报控制面），实际 %T: %v", err, err)
	}
	if !strings.Contains(ce.Reason, "phase1.enc") || !strings.Contains(ce.Reason, "SM4-GCM") {
		t.Fatalf("拒绝原因必须带上字段名与用户填的原值，实际：%q", ce.Reason)
	}
}

// asConfigError 是 errors.As 的一层包装，避免测试文件为一次断言引入 errors 包。
func asConfigError(err error, dst **ipsec.ConfigError) bool {
	for err != nil {
		if ce, ok := err.(*ipsec.ConfigError); ok {
			*dst = ce
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ── 空 PSK 必须在装载期就被拒 ──

func TestAddSiteRejectsEmptyPSK(t *testing.T) {
	e := NewEngine(EngineOptions{Tick: time.Hour})
	cfg := hsSiteA("")
	cfg.PSK = nil
	err := e.AddSite(cfg)
	if err == nil {
		t.Fatal("空 PSK 必须被拒——空 PSK 能协商成功，会建立一条没有任何认证的隧道")
	}
	if !strings.Contains(err.Error(), "PSK") {
		t.Fatalf("拒绝原因应点明 PSK，实际：%v", err)
	}
}

// ── 重传：响应方必须原样回放，绝不重算 ──

func TestResponderReplaysCachedResponseByteForByte(t *testing.T) {
	f := hsSetup(t, hsSiteA("baidi-ipsec-psk"), hsSiteB("baidi-ipsec-psk"))
	hsWait(t, "握手完成", func() bool { return hsUp(f.a, "site-1") && hsUp(f.b, "site-1") })

	pkts := f.cap.snapshot()
	authResp := pkts[3].payload // B 发出的 IKE_AUTH 响应

	// 把 A 的 IKE_AUTH 请求原样再发一次（模拟 A 侧重传）。
	f.b.handle(ipsec.Datagram{
		Kind: ipsec.KindIKE, Local: hsAddrB, Remote: hsAddrA,
		Payload: append([]byte(nil), pkts[2].payload...),
	})

	all := f.cap.snapshot()
	if len(all) <= len(pkts) {
		t.Fatal("重复请求必须触发一条响应（回放），实际一条都没发")
	}
	replay := all[len(all)-1].payload
	// ★逐字节相等是这条用例的全部意义：只要 B 重新加密一次，GCM 的显式 nonce
	// 就会变（甚至可能被复用），字节必然不同。相等 = 真的走了缓存回放。
	if !bytes.Equal(replay, authResp) {
		t.Fatalf("回放的响应与原响应不是同一串字节（长度 %d vs %d）——说明 B 重新计算了响应，"+
			"这会复用/推进 GCM 的显式 nonce，属灾难性错误", len(replay), len(authResp))
	}
	// 回放不得产生第二条 Child SA。
	if f.pb.count() != 1 {
		t.Fatalf("回放不应改变 SA 表，实际 B 侧有 %d 条 Child SA", f.pb.count())
	}
}

// ── 优雅拆除：RemoveSite 要让对端也把 SA 拆掉 ──

func TestRemoveSiteTearsDownBothEnds(t *testing.T) {
	f := hsSetup(t, hsSiteA("baidi-ipsec-psk"), hsSiteB("baidi-ipsec-psk"))
	hsWait(t, "握手完成", func() bool { return hsUp(f.a, "site-1") && hsUp(f.b, "site-1") })

	if err := f.a.RemoveSite("site-1"); err != nil {
		t.Fatalf("RemoveSite 失败: %v", err)
	}
	// ★对端必须**被通知**而不是靠 DPD 熬过 30 秒——那 30 秒里它会一直往一条
	// 没人接收的隧道里灌业务流量。
	hsWait(t, "B 侧收到 D(IKE) 后拆掉 SA", func() bool {
		return hsAnySA(f.b, "site-1") == nil && f.pb.count() == 0
	})
	if f.pa.count() != 0 {
		t.Fatal("A 侧应已摘掉全部 Child SA")
	}
}

// ── 站点未启用时不得发起任何协商 ──

func TestDisabledSiteNeverInitiates(t *testing.T) {
	cfgA := hsSiteA("baidi-ipsec-psk")
	cfgA.Enabled = false
	f := hsSetup(t, cfgA, hsSiteB("baidi-ipsec-psk"))
	f.a.runTimers()
	f.a.runTimers()

	if st := hsState(f.a, "site-1"); st.State != ipsec.StateDown {
		t.Fatalf("未启用的站点状态应为 down（管理意图），实际 %s", st.State)
	}
	if n := len(f.cap.snapshot()); n != 0 {
		t.Fatalf("未启用的站点不该发出任何报文，实际发了 %d 条", n)
	}
}

// ── 同一份配置重复下发不得拆隧道 ──
//
// 控制面是 15 秒一次的全量声明式同步：不做指纹比对的话，
// 每一轮都会把所有隧道拆了重建，症状是"隧道每 15 秒断一次"。
func TestReapplySameConfigKeepsTunnel(t *testing.T) {
	cfg := hsSiteA("baidi-ipsec-psk")
	f := hsSetup(t, cfg, hsSiteB("baidi-ipsec-psk"))
	hsWait(t, "握手完成", func() bool { return hsUp(f.a, "site-1") })

	before := hsPrimarySA(f.a, "site-1")
	for i := 0; i < 3; i++ {
		if err := f.a.AddSite(cfg); err != nil {
			t.Fatalf("重复下发同一配置失败: %v", err)
		}
	}
	after := hsPrimarySA(f.a, "site-1")
	if before != after {
		t.Fatal("重复下发同一份配置不应重建 IKE SA")
	}
	if !hsUp(f.a, "site-1") {
		t.Fatalf("重复下发后站点应仍为 up，实际 %s", hsState(f.a, "site-1").State)
	}
}

// ── 扫描流量：来自未配置对端的 IKE_SA_INIT 必须静默丢弃 ──

func TestUnknownPeerIsSilentlyDropped(t *testing.T) {
	f := hsSetup(t, hsSiteA("baidi-ipsec-psk"), hsSiteB("baidi-ipsec-psk"))
	hsWait(t, "握手完成", func() bool { return hsUp(f.b, "site-1") })
	base := len(f.cap.snapshot())

	stray := netip.MustParseAddrPort("203.0.113.9:500")
	pkts := f.cap.snapshot()
	f.b.handle(ipsec.Datagram{
		Kind: ipsec.KindIKE, Local: hsAddrB, Remote: stray,
		Payload: append([]byte(nil), pkts[0].payload...),
	})
	// ★一个字节都不能回。UDP 500 是网关上唯一不受 SPA 保护的端口，
	// 对未知源回任何东西都等于把自己变成反射放大器。
	if n := len(f.cap.snapshot()); n != base {
		t.Fatalf("对未配置对端的报文回了 %d 条响应，必须静默丢弃", n-base)
	}
}

// ── ESP 报文必须转给数据面，而不是被 Engine 吞掉 ──

func TestESPDatagramsAreHandedToDataplane(t *testing.T) {
	got := make(chan ipsec.Datagram, 1)
	e := NewEngine(EngineOptions{
		Tick:  time.Hour,
		OnESP: func(d ipsec.Datagram) { got <- d },
	})
	want := ipsec.Datagram{Kind: ipsec.KindESP, Payload: []byte{0xde, 0xad, 0xbe, 0xef}}
	e.handle(want)
	select {
	case d := <-got:
		if !bytes.Equal(d.Payload, want.Payload) {
			t.Fatal("转出去的 ESP 报文内容不对")
		}
	default:
		// Transport 只有一个读者（IKE 与 ESP 共用一条 socket 是 NAT 穿越的硬要求），
		// 所以 Engine 必须把 ESP 报文转给数据面；吞掉的症状是"隧道建好了但业务不通"。
		t.Fatal("ESP 报文没有被转给数据面回调")
	}
	// keepalive 则应被直接丢弃，不打扰数据面。
	e.handle(ipsec.Datagram{Kind: ipsec.KindKeepalive, Payload: []byte{0xFF}})
	select {
	case d := <-got:
		t.Fatalf("NAT keepalive 不该转给数据面，收到 %v", d)
	default:
	}
}

// ── 两端同时发起：必须收敛到一条 IKE SA ──
//
// 真实部署里两台网关都配了这条站点、都有自己的定时器，几乎必然出现"几乎同时
// 发出 IKE_SA_INIT，又都尽责地响应了对方"的局面，结果是两条完整可用的 IKE SA。
// ★收敛判据必须是**两端算出来完全一样**的东西（这里用 SPIi‖SPIr 的字典序），
// 否则各留各的，隧道会在两条 SA 之间反复抖动，而两端日志都显示"已建立"。
func TestSimultaneousInitiationConvergesToOneSA(t *testing.T) {
	f := hsSetup(t, hsSiteA("baidi-ipsec-psk"), hsSiteB("baidi-ipsec-psk"))
	f.b.runTimers() // B 也发起（hsSetup 里 A 已经发过了）

	hsWait(t, "两端收敛到同一条 IKE SA", func() bool {
		f.a.runTimers()
		f.b.runTimers()
		sa, sb := hsPrimarySA(f.a, "site-1"), hsPrimarySA(f.b, "site-1")
		if sa == nil || sb == nil {
			return false
		}
		f.a.mu.Lock()
		na := len(f.a.sites["site-1"].sas)
		f.a.mu.Unlock()
		f.b.mu.Lock()
		nb := len(f.b.sites["site-1"].sas)
		f.b.mu.Unlock()
		return na == 1 && nb == 1 && sa.SPIi == sb.SPIi && sa.SPIr == sb.SPIr
	})

	sa, sb := hsPrimarySA(f.a, "site-1"), hsPrimarySA(f.b, "site-1")
	// 角色必须互补：一端是原始发起方，另一端就是响应方。
	if sa.LocalIsInit == sb.LocalIsInit {
		t.Fatalf("收敛后两端的原始角色相同（都为 %v）——密钥方向会全反", sa.LocalIsInit)
	}
	if !bytes.Equal(sa.Keys.SKei, sb.Keys.SKei) {
		t.Fatal("收敛后两端密钥不一致")
	}
	if f.pa.count() != 1 || f.pb.count() != 1 {
		t.Fatalf("收敛后每端应恰好留一条 Child SA，实际 A=%d B=%d", f.pa.count(), f.pb.count())
	}
	ca, cb := f.pa.only(t), f.pb.only(t)
	if ca.InSPI != cb.OutSPI || ca.OutSPI != cb.InSPI {
		t.Fatal("收敛后留下的 Child SA 不是同一条（SPI 没有交叉相等）")
	}
	if !hsUp(f.a, "site-1") || !hsUp(f.b, "site-1") {
		t.Fatal("收敛后两端都应为 up")
	}
}

// hsDump 供排障时打印抓到的报文序列（正常路径不调用，留着是因为
// 这类测试一旦红了，第一件想做的事就是看报文序列）。
func hsDump(pkts []hsPacket) string {
	var b strings.Builder
	for i, p := range pkts {
		hdr, err := ParseHeader(p.payload)
		if err != nil {
			fmt.Fprintf(&b, "%d) %s→%s 无法解析(%d字节)\n", i+1, p.from, p.to, len(p.payload))
			continue
		}
		fmt.Fprintf(&b, "%d) %s→%s %s mid=%d I=%v R=%v %d字节\n",
			i+1, p.from, p.to, hdr.ExchangeType, hdr.MessageID,
			hdr.FromInitiator(), !hdr.IsRequest(), len(p.payload))
	}
	return b.String()
}

var _ = hsDump
