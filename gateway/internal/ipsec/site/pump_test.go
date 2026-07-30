package site

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/esp"
)

// 本文件把两条泵、ESP 引擎、内存 UDP 网、内存数据面串成一条**完整的数据通路**，
// 然后问四个问题：
//
//	① 明文包从 A 侧内网进去，能不能原样从 B 侧内网出来；
//	② 线上跑的到底是不是密文（全偏移扫描金丝雀）；
//	③ 密文被改一个 bit，会不会被当作明文投递出去；
//	④ 目的地址不在任何站点网段内时，包是被丢弃还是被明文放行。
//
// ★③和④才是这套测试的价值所在。①单独看毫无意义——一个把 Protect/Unprotect
// 都实现成恒等变换的"加密"也能让①全绿。没有反例的正例等于没测。
//
// 辅助一律加 pmt 前缀（pump test）。

const (
	pmtSiteID = "site-ab"
	// 金丝雀：出现在明文里、且绝不可能出现在密文里的一段字节。
	pmtCanary = "BAIDI-ESP-CANARY-6f3a1c9d-DO-NOT-LEAK"
)

var (
	pmtAddrA = netip.MustParseAddrPort("192.0.2.1:4500")
	pmtAddrB = netip.MustParseAddrPort("192.0.2.2:4500")
	pmtNetA  = netip.MustParsePrefix("10.71.0.0/16")
	pmtNetB  = netip.MustParsePrefix("10.72.0.0/16")
)

// pmtKeys 一对方向密钥。AES-256-GCM 的密钥是 36 字节：32 密钥 + **末尾 4 字节 salt**。
func pmtKeys(seed byte) []byte {
	k := make([]byte, 36)
	for i := range k {
		k[i] = seed ^ byte(i*7+3)
	}
	return k
}

// pmtChildSA 造一对**镜像**的 Child SA 参数。
//
// ★镜像关系是这类测试最容易写错的地方：A 的出向密钥必须等于 B 的入向密钥，
// A 的 InSPI 必须等于 B 的 OutSPI。写反了两端都不报错，只是永远解不开——
// 而现象与"加密算法写错"完全一样。
func pmtChildSA(local, remote netip.Prefix, localAddr, peerAddr netip.AddrPort,
	inSPI, outSPI uint32, inKey, outKey []byte) ipsec.ChildSAParams {
	return ipsec.ChildSAParams{
		SiteID:     pmtSiteID,
		InSPI:      inSPI,
		OutSPI:     outSPI,
		EncrID:     20, // ENCR_AES_GCM_16
		KeyBits:    256,
		IntegID:    0, // combined mode：INTEG 必须是 NONE
		OutEncrKey: outKey,
		InEncrKey:  inKey,
		LocalTS:    local,
		RemoteTS:   remote,
		Local:      localAddr,
		Peer:       peerAddr,
		CreatedAt:  time.Now(),
		HardExpire: time.Now().Add(time.Hour),
	}
}

// pmtIPv4 造一个结构合法的 IPv4 包（协议号取 253，RFC 3692 的实验用值）。
func pmtIPv4(src, dst netip.Addr, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45 // 版本 4，IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64  // TTL
	pkt[9] = 253 // 实验/测试用协议号
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	copy(pkt[20:], payload)
	return pkt
}

// pmtRig 一整套对拨环境。
type pmtRig struct {
	netw         *ipsec.MemNet
	backA, backB *GoBackend
	protA, protB *esp.Engine
	hostA, hostB ipsec.Datapath // 测试扮演的"受保护网络里的主机"
	trA, trB     ipsec.Transport

	mu     sync.Mutex
	onWire [][]byte // 线上跑过的每一个 ESP 载荷（用于金丝雀扫描）
	tamper func([]byte)
}

func pmtSetup(t *testing.T) *pmtRig {
	t.Helper()
	r := &pmtRig{netw: ipsec.NewMemNet()}

	// 中间人：抄下每一个上线的报文，并允许按需篡改。
	r.netw.SetFilter(func(d ipsec.Datagram) (ipsec.Datagram, bool) {
		r.mu.Lock()
		r.onWire = append(r.onWire, append([]byte(nil), d.Payload...))
		tp := r.tamper
		r.mu.Unlock()
		if tp != nil {
			cp := append([]byte(nil), d.Payload...)
			tp(cp)
			d.Payload = cp
		}
		return d, true
	})

	var err error
	if r.trA, err = r.netw.Bind(pmtAddrA); err != nil {
		t.Fatalf("绑定 A 失败：%v", err)
	}
	if r.trB, err = r.netw.Bind(pmtAddrB); err != nil {
		t.Fatalf("绑定 B 失败：%v", err)
	}

	dpA, hostA := ipsec.NewPairDatapath(1400)
	dpB, hostB := ipsec.NewPairDatapath(1400)
	r.hostA, r.hostB = hostA, hostB

	r.protA = esp.New(bktLog(), time.Now)
	r.protB = esp.New(bktLog(), time.Now)

	kAB, kBA := pmtKeys(0x11), pmtKeys(0x22)
	// A：出向用 kAB（B 用它做入向），入向用 kBA。
	if err := r.protA.Install(pmtChildSA(pmtNetA, pmtNetB, pmtAddrA, pmtAddrB, 0x0000A001, 0x0000B001, kBA, kAB)); err != nil {
		t.Fatalf("A 装载 SA 失败：%v", err)
	}
	// B：镜像。
	if err := r.protB.Install(pmtChildSA(pmtNetB, pmtNetA, pmtAddrB, pmtAddrA, 0x0000B001, 0x0000A001, kAB, kBA)); err != nil {
		t.Fatalf("B 装载 SA 失败：%v", err)
	}

	r.backA = pmtBackend(t, "gw-a", r.trA, dpA, r.protA)
	r.backB = pmtBackend(t, "gw-b", r.trB, dpB, r.protB)

	t.Cleanup(func() {
		_ = r.backA.Close()
		_ = r.backB.Close()
		_ = hostA.Close()
		_ = hostB.Close()
		_ = r.trA.Close()
		_ = r.trB.Close()
	})
	return r
}

func pmtBackend(t *testing.T, gw string, tr ipsec.Transport, dp ipsec.Datapath, prot ipsec.Protector) *GoBackend {
	t.Helper()
	b, err := NewBackend(BackendOptions{
		GatewayID: gw, Transport: tr, Datapath: dp,
		IKE: newBktIKE(), Protector: prot, Log: bktLog(),
	})
	if err != nil {
		t.Fatalf("组装 %s 的 Backend 失败：%v", gw, err)
	}
	return b
}

func (r *pmtRig) wire() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.onWire))
	copy(out, r.onWire)
	return out
}

func (r *pmtRig) setTamper(f func([]byte)) {
	r.mu.Lock()
	r.tamper = f
	r.mu.Unlock()
}

// pmtExpect 期望在 dp 上读到一个包。
func pmtExpect(t *testing.T, dp ipsec.Datapath, d time.Duration) ([]byte, bool) {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 65535)
		n, err := dp.ReadOutbound(buf)
		ch <- res{buf[:n], err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, false
		}
		return r.b, true
	case <-time.After(d):
		return nil, false
	}
}

// ① + ②：明文包过隧道原样送达，且线上跑的是密文。
func TestPumpRoundTripAndCiphertext(t *testing.T) {
	r := pmtSetup(t)

	plain := pmtIPv4(netip.MustParseAddr("10.71.0.5"), netip.MustParseAddr("10.72.0.9"),
		[]byte(pmtCanary+"：这段明文只应出现在两端内网，绝不该出现在链路上"))
	if err := r.hostA.WriteInbound(plain); err != nil {
		t.Fatalf("注入明文包失败：%v", err)
	}

	got, ok := pmtExpect(t, r.hostB, 3*time.Second)
	if !ok {
		t.Fatalf("B 侧内网没有收到包（隧道没通）")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("送达的包与原包不一致：\n原包 % x\n实得 % x", plain, got)
	}

	// ★全偏移扫描：只要线上任何一个报文的任何一个偏移出现了金丝雀，
	// 就说明这段明文根本没被加密（或只加密了一部分——"只加密了头部"是很常见的写法错误）。
	wire := r.wire()
	if len(wire) == 0 {
		t.Fatalf("链路上一个报文都没有：包没有经过 Transport")
	}
	for i, p := range wire {
		if bytes.Contains(p, []byte(pmtCanary)) {
			t.Fatalf("★第 %d 个上线报文里出现了明文金丝雀，流量根本没被加密：% x", i, p)
		}
	}
	// 顺带确认线上的确是 ESP 形态（首 4 字节 = 对端期望的 SPI）。
	if len(wire[0]) < 8 || binary.BigEndian.Uint32(wire[0][:4]) != 0x0000B001 {
		t.Errorf("线上报文不像 ESP：前 8 字节 % x", wire[0][:min(8, len(wire[0]))])
	}
}

// ③ 反例：密文被翻一个 bit，绝不能有任何东西被投递进内网。
//
// ★没有这一条，一个"解密时不校验 ICV、直接吐出解出来的字节"的实现照样能通过①。
func TestPumpRejectsTamperedCiphertext(t *testing.T) {
	r := pmtSetup(t)
	r.setTamper(func(p []byte) {
		if len(p) > 16 {
			p[len(p)/2] ^= 0x01 // 翻中间一个 bit
		}
	})

	plain := pmtIPv4(netip.MustParseAddr("10.71.0.5"), netip.MustParseAddr("10.72.0.9"),
		[]byte("这段内容不该抵达对端"))
	if err := r.hostA.WriteInbound(plain); err != nil {
		t.Fatalf("注入失败：%v", err)
	}
	if got, ok := pmtExpect(t, r.hostB, 800*time.Millisecond); ok {
		t.Fatalf("★被篡改的报文竟然被投递进了内网（% x）——说明解封没有校验完整性", got)
	}
	if d := r.protB.SiteDrops(pmtSiteID); d.Auth == 0 {
		t.Errorf("完整性校验失败必须计数，实得 %+v", d)
	}
}

// ④ 反例：目的地址不在任何站点的 remoteSubnet 内。
//
// ★这是 CLAUDE.md 里 `-route` 那条事故的形态：包必须被**丢弃并计数**，
// 绝不能明文原样发出去。若线上出现了一个含明文的报文，就等于业务流量从旁路走了。
func TestPumpDropsPacketWithoutPolicy(t *testing.T) {
	r := pmtSetup(t)

	plain := pmtIPv4(netip.MustParseAddr("10.71.0.5"), netip.MustParseAddr("10.99.0.9"),
		[]byte(pmtCanary+"：目的地址不在任何站点网段内"))
	if err := r.hostA.WriteInbound(plain); err != nil {
		t.Fatalf("注入失败：%v", err)
	}
	// 给泵一点时间去处理（它要么丢弃，要么——错误地——发出去）。
	time.Sleep(300 * time.Millisecond)

	for i, p := range r.wire() {
		if bytes.Contains(p, []byte(pmtCanary)) {
			t.Fatalf("★无匹配策略的包被明文放行了（第 %d 个上线报文）：% x", i, p)
		}
	}
	if n := r.backA.NoPolicyDrops(); n == 0 {
		t.Errorf("★无匹配策略的丢弃必须计数——这是「流量本该进隧道却没走隧道」的唯一可见信号")
	}
	if _, ok := pmtExpect(t, r.hostB, 300*time.Millisecond); ok {
		t.Errorf("不该有任何东西抵达 B 侧")
	}
}

// 双向都要通：只测单向的话，"密钥方向写反"这类错误有一半概率测不出来。
func TestPumpBidirectional(t *testing.T) {
	r := pmtSetup(t)

	a2b := pmtIPv4(netip.MustParseAddr("10.71.0.5"), netip.MustParseAddr("10.72.0.9"), []byte("A→B"))
	if err := r.hostA.WriteInbound(a2b); err != nil {
		t.Fatal(err)
	}
	if got, ok := pmtExpect(t, r.hostB, 3*time.Second); !ok || !bytes.Equal(got, a2b) {
		t.Fatalf("A→B 方向不通（ok=%v）", ok)
	}

	b2a := pmtIPv4(netip.MustParseAddr("10.72.0.9"), netip.MustParseAddr("10.71.0.5"), []byte("B→A"))
	if err := r.hostB.WriteInbound(b2a); err != nil {
		t.Fatal(err)
	}
	if got, ok := pmtExpect(t, r.hostA, 3*time.Second); !ok || !bytes.Equal(got, b2a) {
		t.Fatalf("B→A 方向不通（ok=%v）", ok)
	}
}

// 收到 ESP 报文后必须回调 IKE.Touch：有数据在流就不必再发 DPD 探活。
// ★漏掉它的后果不是"多发几个包"，而是数据面繁忙时 DPD 误判对端失联、
// 把一条活得好好的隧道拆掉。
func TestPumpTouchesIKEOnInbound(t *testing.T) {
	r := pmtSetup(t)
	fake := r.backB.ike.(*bktIKE)

	plain := pmtIPv4(netip.MustParseAddr("10.71.0.5"), netip.MustParseAddr("10.72.0.9"), []byte("x"))
	if err := r.hostA.WriteInbound(plain); err != nil {
		t.Fatal(err)
	}
	if _, ok := pmtExpect(t, r.hostB, 3*time.Second); !ok {
		t.Fatalf("包没送达")
	}
	fake.mu.Lock()
	touched := append([]uint32(nil), fake.touched...)
	fake.mu.Unlock()
	if len(touched) == 0 {
		t.Fatalf("入向泵没有回调 IKE.Touch")
	}
	if touched[0] != 0x0000B001 {
		t.Errorf("Touch 应带上本端入向 SPI（B 的 InSPI=0x0000B001），实得 0x%08x", touched[0])
	}
}

// 分流器必须把 IKE 与 ESP 分开：两个消费者共读一条队列时会互相吞包，
// 表现为「握手偶尔卡住、流量偶尔丢包」，低负载下几乎不复现。
func TestDemuxSeparatesIKEAndESP(t *testing.T) {
	r := pmtSetup(t)

	// 从 A 侧伪造一个 IKE 报文发给 B：它必须出现在 B 的 IKE 支路上，
	// 而不该被入向泵吃掉。
	ikeMsg := bytes.Repeat([]byte{0xC3}, 40)
	if err := r.trA.Send(ipsec.Datagram{Kind: ipsec.KindIKE, Remote: pmtAddrB, Payload: ikeMsg}); err != nil {
		t.Fatalf("发送失败：%v", err)
	}
	ch := make(chan ipsec.Datagram, 1)
	go func() {
		if d, err := r.backB.IKETransport().Recv(); err == nil {
			ch <- d
		}
	}()
	select {
	case d := <-ch:
		if !bytes.Equal(d.Payload, ikeMsg) {
			t.Errorf("IKE 支路收到的载荷不符：% x", d.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("IKE 报文没有出现在 IKE 支路上（多半被入向泵吞掉了）")
	}

	// keepalive 由分流器直接丢弃，但要计数。
	if err := r.trA.Send(ipsec.Datagram{Kind: ipsec.KindKeepalive, Remote: pmtAddrB}); err != nil {
		t.Fatalf("发送失败：%v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ka := r.backB.TransportStats(); ka > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("收到的 NAT keepalive 没有被计数")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
