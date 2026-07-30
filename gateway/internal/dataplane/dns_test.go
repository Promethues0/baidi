package dataplane

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// ── 测试脚手架：手写 DNS 线上字节 ──
//
// 刻意不用 dnsReply.bytes() 反过来造期望值——那样测的是"编码器和它自己一致"，
// 而不是"编码器符合线上格式"。期望字节全部手工拼，改错一位就会红。

// encodeName 把 "oa.corp.internal" 编成线上 QNAME（保留大小写，用于验证回显）。
func encodeName(name string) []byte {
	var out []byte
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			out = append(out, byte(len(l)))
			out = append(out, l...)
		}
	}
	return append(out, 0)
}

// buildQuery 组装一条标准查询（RD=1，QDCOUNT=1）。
func buildQuery(id uint16, name string, qtype, qclass uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	msg = append(msg, encodeName(name)...)
	return append(msg, byte(qtype>>8), byte(qtype), byte(qclass>>8), byte(qclass))
}

func testResponder() *dnsResponder {
	return newDNSResponder(map[string]string{
		"oa.corp.internal":  "10.20.1.10",
		"OA2.Corp.Internal": "10.99.0.14", // 大小写 + 后面单独测尾点
		"db.corp.internal.": "10.20.1.20",
	})
}

func be16At(b []byte, off int) uint16 { return uint16(b[off])<<8 | uint16(b[off+1]) }

// TestDNSAnswerA 逐字节校验 A 应答。
func TestDNSAnswerA(t *testing.T) {
	d := testResponder()
	q := buildQuery(0xBEEF, "oa.corp.internal", dnsTypeA, dnsClassIN)

	got, ok := d.answer(q)
	if !ok {
		t.Fatal("A 查询必须有应答")
	}

	name := encodeName("oa.corp.internal")
	var want []byte
	want = append(want, 0xBE, 0xEF) // ID 原样回显
	want = append(want, 0x85, 0x00) // QR=1 AA=1 RD=1 RCODE=0
	want = append(want, 0x00, 0x01) // QDCOUNT
	want = append(want, 0x00, 0x01) // ANCOUNT
	want = append(want, 0x00, 0x00) // NSCOUNT
	want = append(want, 0x00, 0x00) // ARCOUNT（刻意不回 EDNS OPT）
	want = append(want, name...)
	want = append(want, 0x00, 0x01, 0x00, 0x01) // QTYPE=A QCLASS=IN
	want = append(want, name...)                // 应答 NAME 重写全名，不用压缩指针
	want = append(want, 0x00, 0x01)             // TYPE=A
	want = append(want, 0x00, 0x01)             // CLASS=IN
	want = append(want, 0x00, 0x00, 0x00, 0x1E) // TTL=30
	want = append(want, 0x00, 0x04)             // RDLENGTH
	want = append(want, 10, 20, 1, 10)          // RDATA

	if !bytes.Equal(got, want) {
		t.Fatalf("应答字节不符\n实得 %x\n期望 %x", got, want)
	}
}

// TestDNSAnswerAAAAIsNODATANotNXDomain 守住那个只在双栈机器上现形的经典陷阱。
//
// ★症状：若 AAAA 回 NXDOMAIN（RCODE=3），客户端会认定"这个名字不存在"，
// 连已经拿到的 A 记录也一并作废——表现为"明明配了 A 记录却解析失败"，
// 且只在开了 IPv6 的机器上复现，同事的机器一切正常。
// 正确姿态是 NODATA：RCODE=NOERROR + ANCOUNT=0 + 权威位。
func TestDNSAnswerAAAAIsNODATANotNXDomain(t *testing.T) {
	d := testResponder()
	got, ok := d.answer(buildQuery(0x0102, "oa.corp.internal", dnsTypeAAAA, dnsClassIN))
	if !ok {
		t.Fatal("AAAA 查询必须有应答")
	}
	flags := be16At(got, 2)
	if rcode := flags & 0xF; rcode == dnsRcodeNXDomain {
		t.Fatal("AAAA 回了 NXDOMAIN：会让客户端连 A 记录一起丢弃（双栈机器上必现解析失败）")
	} else if rcode != dnsRcodeNoError {
		t.Fatalf("AAAA 的 RCODE 必须是 NOERROR，实得 %d", rcode)
	}
	if flags&dnsFlagAA == 0 {
		t.Fatal("名字是我们自己的，NODATA 应答必须置权威位")
	}
	if an := be16At(got, 6); an != 0 {
		t.Fatalf("AAAA 应答记录数必须为 0，实得 %d", an)
	}
	if qd := be16At(got, 4); qd != 1 {
		t.Fatalf("必须回显问题段，QDCOUNT 实得 %d", qd)
	}
	// 应答长度 = 头 + 问题段，一字节多余都不该有
	if want := dnsHeaderLen + len(encodeName("oa.corp.internal")) + 4; len(got) != want {
		t.Fatalf("NODATA 应答长度应为 %d，实得 %d", want, len(got))
	}
}

// TestDNSAnswerCaseInsensitiveAndTrailingDot 覆盖大小写与尾点的规范化。
func TestDNSAnswerCaseInsensitiveAndTrailingDot(t *testing.T) {
	d := testResponder()

	// ① 查询侧大小写混排：必须命中，且问题段要**原样回显大小写**
	//    （0x20 编码探测的客户端会逐字节比对，改了大小写会被当成投毒丢弃）。
	q := buildQuery(1, "OA.Corp.INTERNAL", dnsTypeA, dnsClassIN)
	got, ok := d.answer(q)
	if !ok || be16At(got, 6) != 1 {
		t.Fatalf("大小写混排的查询未命中：%x", got)
	}
	if !bytes.Contains(got, encodeName("OA.Corp.INTERNAL")) {
		t.Fatal("问题段未原样回显大小写")
	}
	if !bytes.HasSuffix(got, []byte{10, 20, 1, 10}) {
		t.Fatalf("解析结果错误：%x", got)
	}

	// ② 记录表键带大小写：查小写命中
	if got, ok := d.answer(buildQuery(2, "oa2.corp.internal", dnsTypeA, dnsClassIN)); !ok ||
		!bytes.HasSuffix(got, []byte{10, 99, 0, 14}) {
		t.Fatalf("记录键大小写未规范化：%x", got)
	}
	// ③ 记录表键带尾点：查无尾点命中（线上格式本来就不带尾点）
	if got, ok := d.answer(buildQuery(3, "db.corp.internal", dnsTypeA, dnsClassIN)); !ok ||
		!bytes.HasSuffix(got, []byte{10, 20, 1, 20}) {
		t.Fatalf("记录键尾点未规范化：%x", got)
	}
}

// TestDNSAnswerUnknownNameRefused 未命中回 REFUSED，且**不转发上游**。
func TestDNSAnswerUnknownNameRefused(t *testing.T) {
	d := testResponder()
	got, ok := d.answer(buildQuery(7, "www.example.com", dnsTypeA, dnsClassIN))
	if !ok {
		t.Fatal("未命中也要回包，否则客户端只能干等超时")
	}
	flags := be16At(got, 2)
	if rcode := flags & 0xF; rcode != dnsRcodeRefused {
		t.Fatalf("未命中应回 REFUSED(5)，实得 %d（NXDOMAIN 会被负缓存，域名后来配上也解析不了）", rcode)
	}
	if flags&dnsFlagAA != 0 {
		t.Fatal("不属于我们的名字不得置权威位")
	}
	if an := be16At(got, 6); an != 0 {
		t.Fatalf("REFUSED 不应带应答记录，实得 %d", an)
	}
}

// TestDNSAnswerRejectedShapes 一组「格式合法但我们不受理」的查询。
func TestDNSAnswerRejectedShapes(t *testing.T) {
	d := testResponder()
	cases := []struct {
		name string
		msg  []byte
	}{
		{"其它 QTYPE（CNAME）", buildQuery(1, "oa.corp.internal", 5, dnsClassIN)},
		{"其它 QCLASS（CHAOS）", buildQuery(2, "oa.corp.internal", dnsTypeA, 3)},
		{"ANY 查询", buildQuery(3, "oa.corp.internal", 255, dnsClassIN)},
	}
	for _, c := range cases {
		got, ok := d.answer(c.msg)
		if !ok {
			t.Fatalf("%s：应有应答", c.name)
		}
		if rcode := be16At(got, 2) & 0xF; rcode != dnsRcodeRefused {
			t.Fatalf("%s：应回 REFUSED，实得 %d", c.name, rcode)
		}
	}

	// OPCODE≠QUERY（这里用 STATUS=2）与 QDCOUNT≠1 走的是"连问题段都不回显"的空壳分支。
	shells := []struct {
		name string
		msg  []byte
	}{
		{"OPCODE=STATUS", func() []byte {
			m := buildQuery(4, "oa.corp.internal", dnsTypeA, dnsClassIN)
			m[2] = 0x10 // opcode=2
			return m
		}()},
		{"QDCOUNT=0", []byte{0, 5, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"QDCOUNT=2", func() []byte {
			m := buildQuery(6, "oa.corp.internal", dnsTypeA, dnsClassIN)
			m[5] = 2
			return m
		}()},
	}
	for _, c := range shells {
		got, ok := d.answer(c.msg)
		if !ok {
			t.Fatalf("%s：应有应答", c.name)
		}
		if len(got) != dnsHeaderLen {
			t.Fatalf("%s：应只回一个头（无法安全回显问题段），实得 %d 字节", c.name, len(got))
		}
		if rcode := be16At(got, 2) & 0xF; rcode != dnsRcodeRefused {
			t.Fatalf("%s：应回 REFUSED，实得 %d", c.name, rcode)
		}
		if be16At(got, 2)&dnsFlagQR == 0 {
			t.Fatalf("%s：应答必须置 QR 位", c.name)
		}
	}

	// OPCODE 必须原样回显，否则客户端匹配不上这条应答。
	got, _ := d.answer(shells[0].msg)
	if op := (be16At(got, 2) >> 11) & 0xF; op != 2 {
		t.Fatalf("OPCODE 未回显，实得 %d", op)
	}
}

// TestDNSAnswerMalformed 畸形报文：一律不 panic，且要么静默丢弃、要么 FORMERR。
func TestDNSAnswerMalformed(t *testing.T) {
	d := testResponder()
	name := encodeName("oa.corp.internal")
	hdr := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	with := func(tail ...byte) []byte { return append(append([]byte{}, hdr...), tail...) }

	// ① 连头都不完整 / 空包 → 不回包（回了对端也匹配不上）
	for _, msg := range [][]byte{nil, {}, {0x12}, hdr[:11]} {
		if _, ok := d.answer(msg); ok {
			t.Fatalf("头不完整的报文不应回包：%x", msg)
		}
	}
	// ② QR=1：这是别人的应答，绝不回包（否则两个解析器会无限对轰）
	resp := buildQuery(9, "oa.corp.internal", dnsTypeA, dnsClassIN)
	resp[2] |= 0x80
	if _, ok := d.answer(resp); ok {
		t.Fatal("对 QR=1 的报文回包会造成应答风暴")
	}
	// ③ 超长报文直接丢
	if _, ok := d.answer(make([]byte, dnsMaxMsg+1)); ok {
		t.Fatal("超长报文不应处理")
	}

	// ④ 各类结构性畸形 → FORMERR
	var longName []byte
	for i := 0; i < 6; i++ { // 6 × (1+50) = 306 > 255
		longName = append(longName, 50)
		longName = append(longName, bytes.Repeat([]byte{'a'}, 50)...)
	}
	longName = append(longName, 0, 0, 1, 0, 1)

	bad := map[string][]byte{
		"QNAME 未终止（截断）":   with(0x02, 'o', 'a'),
		"标签长度越过报文尾":       with(0x3f, 'a', 'b', 'c'),
		"压缩指针（防指针环）":      with(0xc0, 0x0c),
		"保留标签类型 0x40":     with(0x40, 'a'),
		"缺少 QTYPE/QCLASS": append(with(name...), 0x00, 0x01), // 只给了一半
		"名字编码总长 > 255":    with(longName...),
	}
	for label, msg := range bad {
		got, ok := d.answer(msg)
		if !ok {
			t.Fatalf("%s：头完整就该回包（便于客户端立即失败）", label)
		}
		if rcode := be16At(got, 2) & 0xF; rcode != dnsRcodeFormErr {
			t.Fatalf("%s：应回 FORMERR(1)，实得 %d", label, rcode)
		}
		if be16At(got, 4) != 0 || be16At(got, 6) != 0 {
			t.Fatalf("%s：解析失败时不得回显问题段/应答", label)
		}
	}
}

// TestNewDNSResponderSkipsBadRecords 非法记录跳过而不是整表装不上。
func TestNewDNSResponderSkipsBadRecords(t *testing.T) {
	d := newDNSResponder(map[string]string{
		"ok.corp.internal":   " 10.20.1.30 ", // 值带空白要容忍
		"v6.corp.internal":   "fd00::1",      // 只答 A，IPv6 值无处安放
		"junk.corp.internal": "not-an-ip",
		"":                   "10.0.0.1",
		"  ":                 "10.0.0.2",
	})
	if len(d.records) != 1 {
		t.Fatalf("只应装入 1 条合法记录，实得 %d", len(d.records))
	}
	if got, ok := d.answer(buildQuery(1, "ok.corp.internal", dnsTypeA, dnsClassIN)); !ok ||
		!bytes.HasSuffix(got, []byte{10, 20, 1, 30}) {
		t.Fatalf("合法记录未生效：%x", got)
	}
	// 被跳过的记录必须表现为"未命中"，而不是解析到零值地址 0.0.0.0
	got, _ := d.answer(buildQuery(2, "junk.corp.internal", dnsTypeA, dnsClassIN))
	if rcode := be16At(got, 2) & 0xF; rcode != dnsRcodeRefused {
		t.Fatalf("非法记录应表现为未命中，实得 RCODE=%d", rcode)
	}
}

// TestServeSessionHandlesTwoQueriesOnOneSession 守住"收一条就关会话"的坑。
//
// ★glibc / systemd-resolved 会用同一个源端口并发发出 A 与 AAAA 两条查询。
// 若答完第一条就收摊，第二条要么被丢要么绕路重建端点，症状是"能解析但每次都卡好几秒"，
// 而且只在双栈机器上出现。
func TestServeSessionHandlesTwoQueriesOnOneSession(t *testing.T) {
	d := testResponder()
	client, server := net.Pipe()
	defer client.Close()
	go d.serveSession(server)

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, dnsMaxMsg)

	for i, q := range [][]byte{
		buildQuery(0x1111, "oa.corp.internal", dnsTypeA, dnsClassIN),
		buildQuery(0x2222, "oa.corp.internal", dnsTypeAAAA, dnsClassIN),
	} {
		if _, err := client.Write(q); err != nil {
			t.Fatalf("第 %d 条查询写入失败：%v", i+1, err)
		}
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("第 %d 条查询没有拿到应答（同一会话上的后续查询被吃掉了）：%v", i+1, err)
		}
		if want := be16At(q, 0); be16At(buf[:n], 0) != want {
			t.Fatalf("第 %d 条应答的事务 ID 不匹配", i+1)
		}
	}
}

// FuzzDNSAnswer 报文解析的模糊测试：任何字节序列都不得 panic、不得死循环。
//
// 死循环这一条是针对压缩指针的：一旦哪天有人"顺手支持一下指针"，互指的两个指针
// 会让解析原地打转，表现不是崩溃而是**整个客户端的 DNS 全部卡死**，比 panic 难查得多。
// 这里用看门狗把"卡住"变成一次可见的失败。
func FuzzDNSAnswer(f *testing.F) {
	f.Add(buildQuery(1, "oa.corp.internal", dnsTypeA, dnsClassIN))
	f.Add(buildQuery(2, "oa.corp.internal", dnsTypeAAAA, dnsClassIN))
	f.Add(buildQuery(3, "x.y.z", 255, 3))
	f.Add([]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c}) // 指针环
	f.Add([]byte{0x12, 0x34, 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})

	d := testResponder()
	f.Fuzz(func(t *testing.T, data []byte) {
		type result struct {
			out []byte
			ok  bool
		}
		ch := make(chan result, 1)
		go func() {
			out, ok := d.answer(data)
			ch <- result{out, ok}
		}()
		var r result
		select {
		case r = <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("answer 未在 2s 内返回，疑似死循环：%x", data)
		}
		if !r.ok {
			return
		}
		// 不变量：回了包就必须是一个能被对端认出来的应答。
		if len(r.out) < dnsHeaderLen {
			t.Fatalf("应答短于固定头：%x", r.out)
		}
		if be16At(r.out, 0) != be16At(data, 0) {
			t.Fatalf("事务 ID 未回显：查询 %x 应答 %x", data[:2], r.out[:2])
		}
		if be16At(r.out, 2)&dnsFlagQR == 0 {
			t.Fatalf("应答未置 QR 位：%x", r.out)
		}
	})
}

// ── 端到端：真的把 IP 包灌进协议栈 ──
//
// 上面的用例只测编解码。这一段测的是**接线**：TUN → netstack → udp handler →
// forwarder → 解析器 → 回包出 TUN。接线错了（比如地址比较写成了 16 字节形式、
// 或者忘了注册 udp.NewProtocol）编解码测试全绿，而现实里 DNS 一个包都收不到——
// 又是一个"看起来都对、就是不通"的静默失效，必须有测试盯住。

// fakeTun 用 channel 冒充 TUN 设备：in 是内核发给我们的包，out 是我们回给内核的包。
type fakeTun struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
}

func newFakeTun() *fakeTun {
	return &fakeTun{in: make(chan []byte, 8), out: make(chan []byte, 8), closed: make(chan struct{})}
}

func (f *fakeTun) File() *os.File { return nil }

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-f.in:
		copy(bufs[0][offset:], p)
		sizes[0] = len(p)
		return 1, nil
	case <-f.closed:
		return 0, errors.New("fakeTun 已关闭")
	}
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case f.out <- append([]byte(nil), bufs[0][offset:]...):
	default: // 测试只关心前几个包，满了就丢，别把数据面卡住
	}
	return 1, nil
}

func (f *fakeTun) MTU() (int, error)        { return 1420, nil }
func (f *fakeTun) Name() (string, error)    { return "utunTest", nil }
func (f *fakeTun) Events() <-chan tun.Event { return make(chan tun.Event) }
func (f *fakeTun) Close() error             { close(f.closed); return nil }
func (f *fakeTun) BatchSize() int           { return 1 }

// buildUDPPacket 手工拼一个 IPv4+UDP 包（含两层校验和）——协议栈会校验，凑不对就被静默丢。
func buildUDPPacket(src, dst tcpip.Address, sport, dport uint16, payload []byte) []byte {
	udpLen := header.UDPMinimumSize + len(payload)
	total := header.IPv4MinimumSize + udpLen
	buf := make([]byte, total)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	u := header.UDP(buf[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: sport, DstPort: dport, Length: uint16(udpLen)})
	copy(buf[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(udpLen))
	u.SetChecksum(^u.CalculateChecksum(checksum.Checksum(payload, xsum)))
	return buf
}

// startTestDataplane 起一个只用于测 UDP 路径的数据面。隧道/敲门全部指向必然拒绝的
// 127.0.0.1:1——本用例不碰 TCP 隧道，敲门失败只会打一行警告，不影响 UDP 通路。
func startTestDataplane(t *testing.T, cfg *Config) *fakeTun {
	t.Helper()
	dev := newFakeTun()
	cfg.Control = "http://127.0.0.1:1"
	cfg.SpaAddr = "127.0.0.1:1"
	cfg.ProxyAddr = "127.0.0.1:1"
	cfg.Reknock = time.Hour
	done := make(chan error, 1)
	go func() { done <- Run(dev, cfg) }()
	t.Cleanup(func() {
		_ = dev.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("数据面未能在 dev 关闭后退出")
		}
	})
	time.Sleep(200 * time.Millisecond) // 等 Run 建栈
	return dev
}

func TestDataplaneAnswersDNSThroughStack(t *testing.T) {
	dev := startTestDataplane(t, &Config{
		DNSListen:  "10.99.0.53",
		DNSRecords: map[string]string{"oa.corp.internal": "10.20.1.10"},
	})

	client := tcpip.AddrFrom4([4]byte{10, 99, 0, 2})
	resolver := tcpip.AddrFrom4([4]byte{10, 99, 0, 53})
	q := buildQuery(0x4242, "oa.corp.internal", dnsTypeA, dnsClassIN)
	dev.in <- buildUDPPacket(client, resolver, 40000, dnsPort, q)

	select {
	case p := <-dev.out:
		ip := header.IPv4(p)
		if ip.Protocol() != uint8(header.UDPProtocolNumber) {
			t.Fatalf("回包不是 UDP：protocol=%d", ip.Protocol())
		}
		u := header.UDP(p[ip.HeaderLength():])
		// 源地址/端口必须是解析器 VIP:53，否则客户端会把它当成无关报文丢弃。
		if !ip.SourceAddress().Equal(resolver) || u.SourcePort() != dnsPort {
			t.Fatalf("应答的源地址/端口不对：%s:%d", ip.SourceAddress(), u.SourcePort())
		}
		if !ip.DestinationAddress().Equal(client) || u.DestinationPort() != 40000 {
			t.Fatalf("应答没回到查询方：%s:%d", ip.DestinationAddress(), u.DestinationPort())
		}
		resp := p[int(ip.HeaderLength())+header.UDPMinimumSize:]
		if be16At(resp, 0) != 0x4242 || be16At(resp, 6) != 1 {
			t.Fatalf("应答内容不对：%x", resp)
		}
		if !bytes.HasSuffix(resp, []byte{10, 20, 1, 10}) {
			t.Fatalf("解析结果不对：%x", resp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3s 内没从 TUN 收到 DNS 应答：UDP 没接通（协议未注册？监听地址比较写错？）")
	}
}

// TestDataplaneRejectsNonDNSUDP 非 DNS 的 UDP 不接管，但要回 ICMP 端口不可达。
//
// ★别改成黑洞丢弃：QUIC（UDP/443）会先卡满自己的重试超时才降级到 TCP，
// 用户看到的是"接入隧道后网页奇慢"——比直接失败难查得多。
func TestDataplaneRejectsNonDNSUDP(t *testing.T) {
	dev := startTestDataplane(t, &Config{
		DNSListen:  "10.99.0.53",
		DNSRecords: map[string]string{"oa.corp.internal": "10.20.1.10"},
	})

	client := tcpip.AddrFrom4([4]byte{10, 99, 0, 2})
	backend := tcpip.AddrFrom4([4]byte{10, 20, 1, 10})
	dev.in <- buildUDPPacket(client, backend, 40001, 443, []byte("quic"))

	select {
	case p := <-dev.out:
		ip := header.IPv4(p)
		if ip.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
			t.Fatalf("非 DNS 的 UDP 竟被接管了（回包 protocol=%d）", ip.Protocol())
		}
		icmp := header.ICMPv4(p[ip.HeaderLength():])
		if icmp.Type() != header.ICMPv4DstUnreachable || icmp.Code() != header.ICMPv4PortUnreachable {
			t.Fatalf("期望 ICMP 端口不可达，实得 type=%d code=%d", icmp.Type(), icmp.Code())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("非 DNS 的 UDP 被黑洞丢弃了（应回 ICMP 端口不可达，让应用快速降级）")
	}
}

// TestBuildResolverRejectsBadListen 配了但配错 → 直接报错停机，不许半残地跑。
func TestBuildResolverRejectsBadListen(t *testing.T) {
	if r, _, err := buildResolver(&Config{}); err != nil || r != nil {
		t.Fatalf("未配置时应静默不启用，实得 r=%v err=%v", r, err)
	}
	for _, bad := range []string{"not-an-ip", "fd00::53", "10.99.0.53:53"} {
		if _, _, err := buildResolver(&Config{DNSListen: bad}); err == nil {
			t.Fatalf("非法监听地址 %q 必须报错（否则现象是域名全解析不了，日志里那行警告早被刷走了）", bad)
		}
	}
	r, addr, err := buildResolver(&Config{DNSListen: " 10.99.0.53 ", DNSRecords: map[string]string{"a.b": "1.2.3.4"}})
	if err != nil || r == nil {
		t.Fatalf("合法配置装载失败：%v", err)
	}
	if !addr.Equal(tcpip.AddrFrom4([4]byte{10, 99, 0, 53})) {
		t.Fatalf("监听地址解析错误：%s", addr)
	}
}

// TCP/53 必须由解析器直接作答，而不是掉进隧道转发路径。
//
// ★守的是一个只有特定查询方式才暴露的故障：解析器 VIP 会随 routes 被 utun 接管，
// 若 TCP 转发器不对它短路，发往 :53 的 TCP 连接会被当成普通业务访问去 CONNECT 一个
// 不存在的资源 id——现象是「dig +tcp 挂住不返回」，而 UDP 查询一切正常。
// 没有这条测试，重构掉那个短路不会有任何信号。
func TestResolverServesDNSOverTCP(t *testing.T) {
	d := newDNSResponder(map[string]string{"oa.corp.internal": "10.20.1.10"})

	// net.Pipe 是同步内存连接，正好模拟 gonet.TCPConn 的字节流语义。
	cli, srv := net.Pipe()
	go d.serveTCPSession(srv)
	defer cli.Close()

	q := buildQuery(0x1234, "oa.corp.internal", dnsTypeA, dnsClassIN)
	// RFC 1035 §4.2.2：TCP 上每条报文前加 2 字节大端长度前缀。
	req := append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
	if err := cli.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("设置超时失败：%v", err)
	}
	if _, err := cli.Write(req); err != nil {
		t.Fatalf("写查询失败：%v", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(cli, lenBuf[:]); err != nil {
		t.Fatalf("读长度前缀失败（TCP/53 很可能没被短路，连接被隧道路径吞了）：%v", err)
	}
	n := int(dnsBE16(lenBuf[:]))
	if n == 0 || n > dnsMaxMsg {
		t.Fatalf("长度前缀非法：%d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(cli, resp); err != nil {
		t.Fatalf("读应答失败：%v", err)
	}
	if got := dnsBE16(resp[0:2]); got != 0x1234 {
		t.Fatalf("事务 ID 未回显：期望 0x1234，实得 %#x", got)
	}
	if ancount := dnsBE16(resp[6:8]); ancount != 1 {
		t.Fatalf("应答数应为 1，实得 %d", ancount)
	}
	// RDATA 落在报文末尾 4 字节（单条 A 记录）。
	rdata := resp[len(resp)-4:]
	if !bytes.Equal(rdata, []byte{10, 20, 1, 10}) {
		t.Fatalf("A 记录应为 10.20.1.10，实得 %v", rdata)
	}

	// 同一条连接必须能连答两条：TCP 上客户端常复用连接连发 A 与 AAAA。
	q2 := buildQuery(0x5678, "oa.corp.internal", dnsTypeAAAA, dnsClassIN)
	req2 := append([]byte{byte(len(q2) >> 8), byte(len(q2))}, q2...)
	if _, err := cli.Write(req2); err != nil {
		t.Fatalf("写第二条查询失败：%v", err)
	}
	if _, err := io.ReadFull(cli, lenBuf[:]); err != nil {
		t.Fatalf("同一连接的第二条查询无应答（会话被提前关闭了）：%v", err)
	}
	resp2 := make([]byte, dnsBE16(lenBuf[:]))
	if _, err := io.ReadFull(cli, resp2); err != nil {
		t.Fatalf("读第二条应答失败：%v", err)
	}
	// AAAA 命中名字应为 NOERROR + 0 应答（NODATA），不是 NXDOMAIN——
	// 回 NXDOMAIN 会让客户端认为整个名字不存在，连 A 都不再查。
	if rcode := resp2[3] & 0x0F; rcode != 0 {
		t.Fatalf("AAAA 查询的 RCODE 应为 0(NOERROR)，实得 %d", rcode)
	}
	if ancount := dnsBE16(resp2[6:8]); ancount != 0 {
		t.Fatalf("AAAA 应答数应为 0，实得 %d", ancount)
	}
}
