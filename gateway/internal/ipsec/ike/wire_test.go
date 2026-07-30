package ike

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// 本文件测报文层的**外壳**：头部、Next Payload 链、以及未认证攻击面上的解析防护。
// 载荷各自的字段级用例在 payload_test.go，SK 在 sk_test.go。
//
// ★为什么畸形用例比正例重要：IKE_SA_INIT 必须在任何认证之前解析对端报文，
// 是网关上第一个「非暗」的对外端口，SPA 敲门保护不到它。一个 4 字节的畸形包
// 若能让解析器死循环或 panic，整台网关就被一个 UDP 包打挂了。

// wtHeader 造一个合法的基准头（SPIi 非零，多位非零以确保单 bit 翻转不会把它变成全零）。
func wtHeader(et ExchangeType, mid uint32) Header {
	return Header{
		SPIi:         [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		SPIr:         [8]byte{0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01},
		Version:      Version,
		ExchangeType: et,
		Flags:        FlagInitiator,
		MessageID:    mid,
	}
}

// wtRaw 手工拼一条报文：头 + 已含通用头的载荷字节，并回填总长。
// 用它构造 Encode 产不出来的畸形报文——那正是对端可能发过来的东西。
func wtRaw(next PayloadType, body []byte) []byte {
	h := wtHeader(ExchangeIKEAuth, 1)
	h.NextPayload = next
	raw := h.AppendTo(nil)
	raw = append(raw, body...)
	binary.BigEndian.PutUint32(raw[24:28], uint32(len(raw)))
	return raw
}

// wtSamplePayloads 覆盖本轮全部会上线的载荷类型（SK 除外，见 sk_test.go）。
func wtSamplePayloads() []Payload {
	return []Payload{
		&SAPayload{Proposals: []Proposal{{
			Num:      1,
			Protocol: ProtocolIKE,
			Transforms: []Transform{
				{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256},
				{Type: TransformPRF, ID: PRFHMACSHA256},
				{Type: TransformInteg, ID: IntegNone},
				{Type: TransformDH, ID: DHEcp256},
			},
		}}},
		&KEPayload{Group: DHEcp256, Data: bytes.Repeat([]byte{0x5a}, 64)},
		&NoncePayload{Nonce: bytes.Repeat([]byte{0x3c}, 32)},
		&IDPayload{T: PayloadIDi, IDType: IDFQDN, Data: []byte("gw-a.baidi")},
		&AuthPayload{Method: AuthSharedKeyMIC, Data: bytes.Repeat([]byte{0x7e}, 32)},
		&TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{TSFromPrefix(netip.MustParsePrefix("10.20.0.0/16"))}},
		&TSPayload{T: PayloadTSr, Selectors: []TrafficSelector{TSFromPrefix(netip.MustParsePrefix("10.60.0.0/16"))}},
		&NotifyPayload{Protocol: ProtocolNone, NotifyType: NotifyNATDetectionSourceIP, Data: bytes.Repeat([]byte{0x11}, 20)},
		&NotifyPayload{Protocol: ProtocolESP, SPI: []byte{0xde, 0xad, 0xbe, 0xef}, NotifyType: NotifyRekeySA},
		&DeletePayload{Protocol: ProtocolESP, SPIs: [][]byte{{0x01, 0x02, 0x03, 0x04}}},
		&RawPayload{T: PayloadVendor, Body: []byte("baidi-ike/0.1")},
	}
}

func TestWireHeaderRoundTrip(t *testing.T) {
	h := wtHeader(ExchangeIKESAInit, 0)
	h.NextPayload = PayloadSA
	h.Flags = FlagInitiator | FlagResponse
	h.Length = 128
	got, err := ParseHeader(h.AppendTo(nil))
	if err != nil {
		t.Fatalf("解析头失败: %v", err)
	}
	if got != h {
		t.Fatalf("头部往返不一致:\n发出 %+v\n解出 %+v", h, got)
	}
	if got.IsRequest() {
		t.Fatal("R 位已置位，IsRequest 应为 false")
	}
	if !got.FromInitiator() {
		t.Fatal("I 位已置位，FromInitiator 应为 true")
	}
}

// TestWireEncodeDecodeIdempotent 断言 Encode→Decode→Encode 字节相等。
//
// ★这条排除的是「能自解析但线格式偏移错了」——一个把 Length 写在错误位置的实现
// 完全可以自洽地跑通往返，只有对端才会发现。逐字节固定的期望值在
// payload_test.go 的布局用例里补齐，两者配合才算把线格式钉死。
func TestWireEncodeDecodeIdempotent(t *testing.T) {
	hdr := wtHeader(ExchangeIKEAuth, 1)
	ps := wtSamplePayloads()

	first, err := Encode(hdr, ps)
	if err != nil {
		t.Fatalf("首次编码失败: %v", err)
	}
	m, err := Decode(first)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(m.Payloads) != len(ps) {
		t.Fatalf("载荷数不符：编码 %d 个，解出 %d 个", len(ps), len(m.Payloads))
	}
	for i := range ps {
		if m.Payloads[i].Type() != ps[i].Type() {
			t.Fatalf("第 %d 个载荷类型不符：编码 %s，解出 %s", i, ps[i].Type(), m.Payloads[i].Type())
		}
	}
	second, err := Encode(m.Hdr, m.Payloads)
	if err != nil {
		t.Fatalf("二次编码失败: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("往返不幂等:\n首次 %x\n二次 %x", first, second)
	}
	if int(m.Hdr.Length) != len(first) {
		t.Fatalf("头部 Length=%d 与实际报文 %d 字节不符", m.Hdr.Length, len(first))
	}
}

// TestWireNextPayloadChain 逐字节验证 Next Payload 链的**前向声明**语义：
// 头部指向第一个载荷，载荷 i 指向载荷 i+1，最后一个指向 NONE。
// 写成「载荷 i 声明自己的类型」是这类协议实现的经典错误，且两端各自实现相同的错误时
// 还能互通，直到遇上真正的 strongSwan 才暴露。
func TestWireNextPayloadChain(t *testing.T) {
	ps := wtSamplePayloads()
	raw, err := Encode(wtHeader(ExchangeIKEAuth, 1), ps)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	if PayloadType(raw[16]) != ps[0].Type() {
		t.Fatalf("头部 Next Payload=%s，应为第一个载荷 %s", PayloadType(raw[16]), ps[0].Type())
	}
	off := HeaderLen
	for i := range ps {
		want := PayloadNone
		if i+1 < len(ps) {
			want = ps[i+1].Type()
		}
		if got := PayloadType(raw[off]); got != want {
			t.Fatalf("第 %d 个载荷（%s）的 Next Payload=%s，应为 %s", i, ps[i].Type(), got, want)
		}
		off += int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
	}
	if off != len(raw) {
		t.Fatalf("载荷链走完后 off=%d，报文共 %d 字节", off, len(raw))
	}
}

// TestWireDecodeMalformed 是解析防护（2-ike.md §10.4）的执行点。
// 每条用例都必须**返回 error 且不 panic、不死循环**。
func TestWireDecodeMalformed(t *testing.T) {
	valid, err := Encode(wtHeader(ExchangeIKEAuth, 1), wtSamplePayloads())
	if err != nil {
		t.Fatalf("构造基准报文失败: %v", err)
	}

	mutate := func(f func(b []byte)) []byte {
		b := append([]byte(nil), valid...)
		f(b)
		return b
	}

	// 33 个 4 字节空载荷，链条一路指向 Vendor：用极少字节撑出极多结构。
	var manyPayloads []byte
	for i := 0; i < 33; i++ {
		next := byte(PayloadVendor)
		if i == 32 {
			next = byte(PayloadNone)
		}
		manyPayloads = append(manyPayloads, next, 0, 0, 4)
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{"报文短于 IKE 头", valid[:HeaderLen-1]},
		{"主版本号不是 2", mutate(func(b []byte) { b[17] = 0x10 })},
		{"头部 Length 与实际长度不符", mutate(func(b []byte) { binary.BigEndian.PutUint32(b[24:28], uint32(len(b)+1)) })},
		{"尾部有多余字节", append(append([]byte(nil), valid...), 0x00)},
		{"SPIi 全零", mutate(func(b []byte) { copy(b[0:8], make([]byte, 8)) })},
		{"IKE_SA_INIT 请求携带非零 SPIr", mutate(func(b []byte) { b[18] = byte(ExchangeIKESAInit) })},
		// plen=0 时 off 永不前进：不拦就是一个 32 字节包让 CPU 空转到天荒地老。
		{"零长载荷（死循环构造）", wtRaw(PayloadNonce, []byte{0x00, 0x00, 0x00, 0x00})},
		{"载荷长度小于通用头", wtRaw(PayloadNonce, []byte{0x00, 0x00, 0x00, 0x03})},
		{"载荷长度越界", wtRaw(PayloadNonce, []byte{0x00, 0x00, 0x00, 0x64})},
		{"链条声称还有载荷但报文已尽", wtRaw(PayloadNonce, nil)},
		{"载荷数超过上限", wtRaw(PayloadVendor, manyPayloads)},
		{"SK 之后仍有外层载荷", wtRaw(PayloadSK, []byte{0x00, 0x00, 0x00, 0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x04})},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Decode(c.raw)
			if err == nil {
				t.Fatalf("畸形报文竟解析成功，解出 %d 个载荷", len(m.Payloads))
			}
			if m != nil {
				t.Fatalf("返回 error 的同时还返回了非 nil 的 Message，调用方可能误用")
			}
		})
	}
}

// TestWireDecodeUnknownPayload 未知载荷的处置：Critical=0 必须**跳过**（互通生命线），
// Critical=1 必须能被上层识别出来以便回 UNSUPPORTED_CRITICAL_PAYLOAD。
//
// ★把「对端多发了一个我们不认识的可选载荷」当成错误，结果是完全建不起连——
// strongSwan 默认就会多发好几个通知与厂商载荷。
func TestWireDecodeUnknownPayload(t *testing.T) {
	// 类型 99 未登记；先测非关键。
	raw := wtRaw(PayloadType(99), []byte{0x00, 0x00, 0x00, 0x06, 0xaa, 0xbb})
	m, err := Decode(raw)
	if err != nil {
		t.Fatalf("非关键的未知载荷应被跳过，却报错: %v", err)
	}
	if _, bad := m.UnsupportedCritical(); bad {
		t.Fatal("Critical=0 的未知载荷不该被判为「不支持的关键载荷」")
	}

	// Critical 位在通用头第 2 字节的最高位。
	raw = wtRaw(PayloadType(99), []byte{0x00, 0x80, 0x00, 0x06, 0xaa, 0xbb})
	m, err = Decode(raw)
	if err != nil {
		t.Fatalf("关键的未知载荷应解析成功后交由上层处置，却报错: %v", err)
	}
	pt, bad := m.UnsupportedCritical()
	if !bad || pt != PayloadType(99) {
		t.Fatalf("应识别出关键未知载荷 99，实际 (%s, %v)", pt, bad)
	}
}

// FuzzDecode 喂随机字节给未认证攻击面上的解析入口。
// 判据不是「解析成功」，而是**永不 panic、永不死循环、成功时结构自洽**。
func FuzzDecode(f *testing.F) {
	if raw, err := Encode(wtHeader(ExchangeIKEAuth, 1), wtSamplePayloads()); err == nil {
		f.Add(raw)
	}
	if raw, err := Encode(wtHeader(ExchangeIKESAInit, 0), []Payload{
		&NoncePayload{Nonce: bytes.Repeat([]byte{0x01}, 32)},
	}); err == nil {
		f.Add(raw)
	}
	f.Add(wtRaw(PayloadNonce, []byte{0x00, 0x00, 0x00, 0x00}))                      // 零长载荷
	f.Add(wtRaw(PayloadSA, []byte{0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x08})) // 提案自指
	f.Add([]byte{})
	f.Add(make([]byte, HeaderLen))

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := Decode(raw)
		if err != nil {
			if m != nil {
				t.Fatalf("Decode 返回 error 的同时返回了非 nil Message")
			}
			return
		}
		if m == nil {
			t.Fatal("Decode 返回 (nil, nil)")
		}
		if int(m.Hdr.Length) != len(raw) {
			t.Fatalf("解析成功但 Length=%d 与实际 %d 不符", m.Hdr.Length, len(raw))
		}
		if len(m.Payloads) > MaxPayloads {
			t.Fatalf("解出 %d 个载荷，超过上限 %d", len(m.Payloads), MaxPayloads)
		}
		// 解析成功的报文必须能被再次编码而不 panic（载荷内部状态自洽）。
		for _, p := range m.Payloads {
			_ = p.appendBody(nil)
		}
	})
}
