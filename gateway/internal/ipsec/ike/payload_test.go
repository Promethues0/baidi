package ike

import (
	"bytes"
	"net/netip"
	"testing"
)

// 本文件逐载荷验证三件事：
//  ① marshal→unmarshal→marshal 幂等（排除「能自解析但偏移错了」）；
//  ② 关键载荷的**逐字节线格式**（排除「两端各自实现同一个错误所以互通」）；
//  ③ 畸形输入一律 error 且不 panic（未认证攻击面）。

// pltRoundTrip 断言「编码 → 解析 → 再编码」字节相等。
func pltRoundTrip(t *testing.T, p Payload, fresh Payload) {
	t.Helper()
	first := p.appendBody(nil)
	if err := fresh.parseBody(first); err != nil {
		t.Fatalf("解析自己编码出的 %s 载荷失败: %v（体=%x）", p.Type(), err, first)
	}
	second := fresh.appendBody(nil)
	if !bytes.Equal(first, second) {
		t.Fatalf("%s 载荷往返不幂等:\n首次 %x\n二次 %x", p.Type(), first, second)
	}
	if fresh.Type() != p.Type() {
		t.Fatalf("往返后载荷类型从 %s 变成了 %s", p.Type(), fresh.Type())
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		p     Payload
		fresh Payload
	}{
		{"SA/IKE 提案", &SAPayload{Proposals: []Proposal{{
			Num:      1,
			Protocol: ProtocolIKE,
			Transforms: []Transform{
				{Type: TransformEncr, ID: EncrAESCBC, KeyLen: 256},
				{Type: TransformPRF, ID: PRFHMACSHA256},
				{Type: TransformInteg, ID: IntegHMACSHA256128},
				{Type: TransformDH, ID: DHModp2048},
			},
		}}}, &SAPayload{}},
		{"SA/多提案多变换", &SAPayload{Proposals: []Proposal{
			{Num: 1, Protocol: ProtocolESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{
				{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256},
				{Type: TransformInteg, ID: IntegNone},
				{Type: TransformESN, ID: ESNNone},
			}},
			{Num: 2, Protocol: ProtocolESP, SPI: []byte{5, 6, 7, 8}, Transforms: []Transform{
				{Type: TransformEncr, ID: EncrSM4GCM16, KeyLen: 128},
				{Type: TransformInteg, ID: IntegNone},
				{Type: TransformESN, ID: ESNNone},
			}},
		}}, &SAPayload{}},
		{"SA/重协商 IKE（8 字节 SPI）", &SAPayload{Proposals: []Proposal{{
			Num: 1, Protocol: ProtocolIKE, SPI: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			Transforms: []Transform{{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256}},
		}}}, &SAPayload{}},
		{"KE/ECP256", &KEPayload{Group: DHEcp256, Data: bytes.Repeat([]byte{0xa5}, 64)}, &KEPayload{}},
		{"KE/MODP2048", &KEPayload{Group: DHModp2048, Data: bytes.Repeat([]byte{0x01}, 256)}, &KEPayload{}},
		{"KE/sm2p256", &KEPayload{Group: DHSm2P256, Data: bytes.Repeat([]byte{0x7f}, 64)}, &KEPayload{}},
		{"Nonce/最短", &NoncePayload{Nonce: bytes.Repeat([]byte{0x11}, MinNonceLen)}, &NoncePayload{}},
		{"Nonce/最长", &NoncePayload{Nonce: bytes.Repeat([]byte{0x22}, MaxNonceLen)}, &NoncePayload{}},
		{"IDi/FQDN", &IDPayload{T: PayloadIDi, IDType: IDFQDN, Data: []byte("gw-a.baidi")}, &IDPayload{T: PayloadIDi}},
		{"IDr/IPv4", &IDPayload{T: PayloadIDr, IDType: IDIPv4Addr, Data: []byte{10, 0, 0, 1}}, &IDPayload{T: PayloadIDr}},
		{"AUTH/PSK", &AuthPayload{Method: AuthSharedKeyMIC, Data: bytes.Repeat([]byte{0x33}, 32)}, &AuthPayload{}},
		{"TSi/IPv4", &TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{
			TSFromPrefix(netip.MustParsePrefix("10.20.0.0/16")),
		}}, &TSPayload{T: PayloadTSi}},
		{"TSr/IPv6", &TSPayload{T: PayloadTSr, Selectors: []TrafficSelector{
			TSFromPrefix(netip.MustParsePrefix("fd00:ba1d::/64")),
		}}, &TSPayload{T: PayloadTSr}},
		{"N/无 SPI 带数据", &NotifyPayload{Protocol: ProtocolNone, NotifyType: NotifyNATDetectionSourceIP,
			Data: bytes.Repeat([]byte{0x44}, 20)}, &NotifyPayload{}},
		{"N/REKEY_SA 带 4 字节 SPI", &NotifyPayload{Protocol: ProtocolESP, SPI: []byte{0xde, 0xad, 0xbe, 0xef},
			NotifyType: NotifyRekeySA}, &NotifyPayload{}},
		{"N/COOKIE", &NotifyPayload{Protocol: ProtocolNone, NotifyType: NotifyCookie,
			Data: bytes.Repeat([]byte{0x55}, 17)}, &NotifyPayload{}},
		{"D/删 IKE SA", &DeletePayload{Protocol: ProtocolIKE}, &DeletePayload{}},
		{"D/删两条 Child SA", &DeletePayload{Protocol: ProtocolESP,
			SPIs: [][]byte{{1, 2, 3, 4}, {5, 6, 7, 8}}}, &DeletePayload{}},
		{"未知载荷原样保留", &RawPayload{T: PayloadVendor, Body: []byte("strongSwan 5.9.x")}, &RawPayload{T: PayloadVendor}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { pltRoundTrip(t, c.p, c.fresh) })
	}
}

// TestPayloadSAWireLayout 把 SA 载荷的线格式逐字节钉死。
//
// ★这条用例存在的唯一理由是那两个 Last Substruc：**提案用 2、变换用 3**。
// 幂等测试对「两个都写成 2」的实现同样是绿的，只有固定期望值才拦得住。
// 顺带钉死 Key Length 属性的 TV 编码 `80 0E 01 00`——漏发它不会协商失败，
// 而是双方按不同密钥长度切材料，最终以一句「认证失败」收场。
func TestPayloadSAWireLayout(t *testing.T) {
	sa := &SAPayload{Proposals: []Proposal{{
		Num:      1,
		Protocol: ProtocolIKE,
		Transforms: []Transform{
			{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256},
			{Type: TransformPRF, ID: PRFHMACSHA256},
			{Type: TransformInteg, ID: IntegNone},
			{Type: TransformDH, ID: DHEcp256},
		},
	}}}
	want := []byte{
		0, 0, 0, 44, // Last Substruc=0（末条提案）/ RESERVED / Proposal Length=44
		1, 1, 0, 4, // Num=1 / Protocol=IKE / SPI Size=0（SPI 在报文头里）/ Num Transforms=4
		3, 0, 0, 12, 1, 0, 0, 20, 0x80, 0x0E, 0x01, 0x00, // Last=3（还有变换）ENCR=20 + KeyLen 256 位
		3, 0, 0, 8, 2, 0, 0, 5, // PRF=HMAC-SHA256
		3, 0, 0, 8, 3, 0, 0, 0, // INTEG=NONE（combined 模式必须如此）
		0, 0, 0, 8, 4, 0, 0, 19, // Last=0（末条变换）DH=ECP256
	}
	if got := sa.appendBody(nil); !bytes.Equal(got, want) {
		t.Fatalf("SA 线格式不符:\n实际 %x\n期望 %x", got, want)
	}
}

// TestPayloadSAMalformed 覆盖 SA 三层嵌套里每一处能让解析器出轨的地方。
func TestPayloadSAMalformed(t *testing.T) {
	valid := (&SAPayload{Proposals: []Proposal{{
		Num: 1, Protocol: ProtocolESP, SPI: []byte{1, 2, 3, 4},
		Transforms: []Transform{
			{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256},
			{Type: TransformInteg, ID: IntegNone},
			{Type: TransformESN, ID: ESNNone},
		},
	}}}).appendBody(nil)
	// 布局：[0..7]=提案头 [8..11]=SPI [12..]=首个变换（长 12，含 KeyLen 属性）
	mutate := func(f func(b []byte)) []byte {
		b := append([]byte(nil), valid...)
		f(b)
		return b
	}

	// 17 条提案：每条都声称「后面还有」，用来撞 MaxProposals。
	var many []Proposal
	for i := 0; i < 17; i++ {
		many = append(many, Proposal{Num: uint8(i + 1), Protocol: ProtocolESP, SPI: []byte{0, 0, 0, byte(i)},
			Transforms: []Transform{{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256}}})
	}

	cases := []struct {
		name string
		body []byte
	}{
		{"载荷体为空", nil},
		{"提案的 Last Substruc 写成了变换的 3", mutate(func(b []byte) { b[0] = 3 })},
		{"变换的 Last Substruc 写成了提案的 2", mutate(func(b []byte) { b[12] = 2 })},
		{"提案长度小于提案头", mutate(func(b []byte) { b[3] = 7 })},
		{"提案长度越界", mutate(func(b []byte) { b[3] = 0xFF })},
		{"SPI 长度不在 0/4/8 之列", mutate(func(b []byte) { b[6] = 5 })},
		{"Num Transforms 与实际不符", mutate(func(b []byte) { b[7] = 5 })},
		{"声称 0 个变换", mutate(func(b []byte) { b[7] = 0 })},
		{"变换长度小于变换头", mutate(func(b []byte) { b[15] = 7 })},
		{"变换长度越界", mutate(func(b []byte) { b[15] = 0xFF })},
		{"末条提案之后仍有多余字节", append(append([]byte(nil), valid...), 0xFF)},
		{"提案头被截断", valid[:6]},
		{"提案数超过上限", (&SAPayload{Proposals: many}).appendBody(nil)},
		// Key Length 用 TLV 编码：静默忽略会退化成「没带 Key Length」，
		// 最终又落回那句无头无尾的「认证失败」。
		{"Key Length 用了 TLV 格式", []byte{
			0, 0, 0, 22, // 提案：Last=0 / RESERVED / Length=22
			1, 1, 0, 1, // Num=1 / IKE / SPI Size=0 / 1 个变换
			0, 0, 0, 14, 1, 0, 0, 12, // 变换：Last=0 / Length=14 / ENCR=AES-CBC
			0x00, 0x0E, 0x00, 0x02, 0x01, 0x00, // TLV：AF=0 / 类型 14 / 值长 2 / 值 256
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var sa SAPayload
			if err := sa.parseBody(c.body); err == nil {
				t.Fatalf("畸形 SA 竟解析成功：%+v", sa.Proposals)
			}
		})
	}
}

func TestPayloadSAFindTransform(t *testing.T) {
	pr := Proposal{Num: 1, Protocol: ProtocolIKE, Transforms: []Transform{
		{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256},
		{Type: TransformEncr, ID: EncrAESCBC, KeyLen: 256},
		{Type: TransformPRF, ID: PRFHMACSHA256},
	}}
	if got, ok := pr.FindTransform(TransformEncr); !ok || got.ID != EncrAESGCM16 {
		t.Fatalf("FindTransform 应返回第一个 ENCR（AES-GCM），实际 %+v ok=%v", got, ok)
	}
	if got := pr.TransformsOfType(TransformEncr); len(got) != 2 {
		t.Fatalf("TransformsOfType 应返回 2 个 ENCR 候选，实际 %d 个", len(got))
	}
	if _, ok := pr.FindTransform(TransformDH); ok {
		t.Fatal("提案里没有 DH 变换，FindTransform 却报告找到了")
	}
}

// ── KE / Nonce ──

func TestPayloadKEMalformed(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"体长不足固定头", []byte{0, 19, 0}},
		{"公钥数据为空", []byte{0, 19, 0, 0}},
		{"DH 群为 NONE", append([]byte{0, 0, 0, 0}, bytes.Repeat([]byte{1}, 64)...)},
		// 群 19 的公钥恒为 64 字节（X‖Y，不带 0x04 前缀）。少一个字节就算错 g^ir，
		// 而症状统一是「认证失败」。
		{"ECP256 公钥少一字节", append([]byte{0, 19, 0, 0}, bytes.Repeat([]byte{1}, 63)...)},
		{"ECP256 公钥带了 0x04 前缀（65 字节）", append([]byte{0, 19, 0, 0}, bytes.Repeat([]byte{1}, 65)...)},
		{"MODP2048 公钥未补零到 256 字节", append([]byte{0, 14, 0, 0}, bytes.Repeat([]byte{1}, 255)...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ke KEPayload
			if err := ke.parseBody(c.body); err == nil {
				t.Fatalf("畸形 KE 竟解析成功：群=%d 数据=%d 字节", ke.Group, len(ke.Data))
			}
		})
	}

	// 未知群必须**解析通过**：正确回应是 N(INVALID_KE_PAYLOAD) 告诉对端我们要哪个群，
	// 在解析层判死会退化成静默丢包，对端只能看到超时重传。
	var ke KEPayload
	if err := ke.parseBody(append([]byte{0, 31, 0, 0}, bytes.Repeat([]byte{1}, 32)...)); err != nil {
		t.Fatalf("未知 DH 群（31=Curve25519）应解析通过交由状态机回 INVALID_KE_PAYLOAD，却报错: %v", err)
	}
}

func TestPayloadNonceBounds(t *testing.T) {
	for _, n := range []int{0, 1, MinNonceLen - 1, MaxNonceLen + 1} {
		var np NoncePayload
		if err := np.parseBody(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Fatalf("长度 %d 的 nonce 越界（应在 %d..%d），却解析成功", n, MinNonceLen, MaxNonceLen)
		}
	}
	var np NoncePayload
	if err := np.parseBody(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("32 字节 nonce 应合法，却报错: %v", err)
	}
}

// ── ID / AUTH ──

// TestPayloadIDRestOfIDPayload 钉死 AUTH 计算的输入形状：
// `IDType(1) ‖ RESERVED(3) ‖ Data`，**不含 4 字节通用头**。
//
// ★少算那 3 个保留字节（只拼 IDType‖Data）是 PSK 路径六大同症状根因之一，
// 而对端报回来的只有一句「认证失败」，从报错里根本看不出差在哪 3 个字节上。
func TestPayloadIDRestOfIDPayload(t *testing.T) {
	id := &IDPayload{T: PayloadIDi, IDType: IDFQDN, Data: []byte("gw-a.baidi")}
	want := append([]byte{byte(IDFQDN), 0, 0, 0}, []byte("gw-a.baidi")...)
	if got := id.RestOfIDPayload(); !bytes.Equal(got, want) {
		t.Fatalf("RestOfIDPayload 不符:\n实际 %x\n期望 %x", got, want)
	}
	if n := len(id.RestOfIDPayload()); n != 4+len(id.Data) {
		t.Fatalf("RestOfIDPayload 长度 %d，应为 4+%d", n, len(id.Data))
	}
}

func TestPayloadIDAuthMalformed(t *testing.T) {
	cases := []struct {
		name string
		p    Payload
		body []byte
	}{
		{"ID 体长不足固定头", &IDPayload{T: PayloadIDi}, []byte{2, 0, 0}},
		{"ID 身份数据为空", &IDPayload{T: PayloadIDi}, []byte{2, 0, 0, 0}},
		{"ID_IPV4_ADDR 长度不是 4", &IDPayload{T: PayloadIDi}, []byte{1, 0, 0, 0, 10, 0, 0}},
		{"ID_IPV6_ADDR 长度不是 16", &IDPayload{T: PayloadIDr}, []byte{5, 0, 0, 0, 1, 2, 3, 4}},
		{"AUTH 体长不足固定头", &AuthPayload{}, []byte{2, 0, 0}},
		{"AUTH 认证数据为空", &AuthPayload{}, []byte{2, 0, 0, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.p.parseBody(c.body); err == nil {
				t.Fatal("畸形载荷竟解析成功")
			}
		})
	}

	// 不支持的认证方法必须解析通过：此时报文已在加密的 IKE_AUTH 内，
	// 正确回应是 N(AUTHENTICATION_FAILED)，而不是静默丢包让对端干等超时。
	var ap AuthPayload
	if err := ap.parseBody(append([]byte{byte(AuthDigitalSig), 0, 0, 0}, bytes.Repeat([]byte{1}, 64)...)); err != nil {
		t.Fatalf("不支持的 AUTH 方法应解析通过交由状态机拒绝，却报错: %v", err)
	}
}

// ── TS ──

func TestTSFromPrefixRoundTrip(t *testing.T) {
	cases := []struct {
		cidr      string
		wantStart string
		wantEnd   string
	}{
		{"10.20.0.0/16", "10.20.0.0", "10.20.255.255"},
		{"192.168.1.0/24", "192.168.1.0", "192.168.1.255"},
		{"10.0.0.7/32", "10.0.0.7", "10.0.0.7"},
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255"},
		{"fd00:ba1d::/64", "fd00:ba1d::", "fd00:ba1d::ffff:ffff:ffff:ffff"},
	}
	for _, c := range cases {
		t.Run(c.cidr, func(t *testing.T) {
			p := netip.MustParsePrefix(c.cidr)
			ts := TSFromPrefix(p)
			if ts.Start.String() != c.wantStart || ts.End.String() != c.wantEnd {
				t.Fatalf("%s → %s..%s，期望 %s..%s", c.cidr, ts.Start, ts.End, c.wantStart, c.wantEnd)
			}
			if ts.StartPort != 0 || ts.EndPort != 65535 || ts.Proto != 0 {
				t.Fatalf("站点隧道的 TS 应覆盖全端口全协议，实际 %s", ts)
			}
			back, ok := ts.Prefix()
			if !ok {
				t.Fatalf("%s 转出的 TS 应能还原成 CIDR", c.cidr)
			}
			if back != p.Masked() {
				t.Fatalf("往返得到 %s，期望 %s", back, p.Masked())
			}
		})
	}
}

// TestTSPrefixRejectsNonCIDR 断言非对齐区间**不会被凑成**某个 CIDR。
//
// ★对端完全可以合法地送来 `10.20.0.5 - 10.20.7.9`。本轮不做 narrowing，
// 就绝不能就近取整——凑出来的策略与对端理解的不一致，又是一次无报错的假成功
// （与 baidi-tun 只接管单网段那次事故同构）。
func TestTSPrefixRejectsNonCIDR(t *testing.T) {
	cases := []struct{ start, end string }{
		{"10.20.0.5", "10.20.7.9"},   // 起点不在边界上
		{"10.20.0.0", "10.20.7.9"},   // 终点不在边界上
		{"10.20.0.0", "10.20.255.0"}, // 主机位没填满
	}
	for _, c := range cases {
		ts := TrafficSelector{Type: TSIPv4AddrRange, EndPort: 65535,
			Start: netip.MustParseAddr(c.start), End: netip.MustParseAddr(c.end)}
		if p, ok := ts.Prefix(); ok {
			t.Fatalf("%s..%s 不是整 CIDR，却被还原成了 %s", c.start, c.end, p)
		}
	}
}

func TestTSEqual(t *testing.T) {
	base := TSFromPrefix(netip.MustParsePrefix("10.20.0.0/16"))
	if !base.Equal(TSFromPrefix(netip.MustParsePrefix("10.20.0.0/16"))) {
		t.Fatal("同一网段转出的 TS 应相等")
	}
	diffs := map[string]TrafficSelector{
		"网段不同":  TSFromPrefix(netip.MustParsePrefix("10.21.0.0/16")),
		"掩码不同":  TSFromPrefix(netip.MustParsePrefix("10.20.0.0/24")),
		"协议号不同": func() TrafficSelector { x := base; x.Proto = 6; return x }(),
		"端口区间不同": func() TrafficSelector {
			x := base
			x.EndPort = 443
			return x
		}(),
	}
	for name, d := range diffs {
		if base.Equal(d) {
			t.Fatalf("%s 的 TS 不应判为相等：%s vs %s", name, base, d)
		}
	}

	// 载荷级：数量、顺序、TSi/TSr 身份都算在内。
	a := &TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{base}}
	if !a.Equal(&TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{base}}) {
		t.Fatal("同构 TS 载荷应相等")
	}
	if a.Equal(&TSPayload{T: PayloadTSr, Selectors: []TrafficSelector{base}}) {
		t.Fatal("TSi 与 TSr 不应判为相等")
	}
	if a.Equal(&TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{base, base}}) {
		t.Fatal("选择器数量不同不应判为相等")
	}
}

func TestPayloadTSMalformed(t *testing.T) {
	valid := (&TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{
		TSFromPrefix(netip.MustParsePrefix("10.20.0.0/16")),
	}}).appendBody(nil)
	mutate := func(f func(b []byte)) []byte {
		b := append([]byte(nil), valid...)
		f(b)
		return b
	}

	var manySel []TrafficSelector
	for i := 0; i < MaxTrafficSelectors+1; i++ {
		manySel = append(manySel, TSFromPrefix(netip.MustParsePrefix("10.20.0.0/16")))
	}

	cases := []struct {
		name string
		body []byte
	}{
		{"体长不足固定头", []byte{1, 0, 0}},
		{"选择器数量为 0", []byte{0, 0, 0, 0}},
		{"选择器数量超过上限", (&TSPayload{T: PayloadTSi, Selectors: manySel}).appendBody(nil)},
		{"不支持的选择器类型", mutate(func(b []byte) { b[4] = 9 })},
		{"IPv4 选择器长度不是 16", mutate(func(b []byte) { b[7] = 20 })},
		{"起始地址大于结束地址", mutate(func(b []byte) { b[12] = 200 })},
		{"起始端口大于结束端口", mutate(func(b []byte) { b[8], b[9] = 0xFF, 0xFF; b[10], b[11] = 0, 1 })},
		{"选择器数量与实际数据不符", mutate(func(b []byte) { b[0] = 2 })},
		{"选择器之后有多余字节", append(append([]byte(nil), valid...), 0xFF)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := TSPayload{T: PayloadTSi}
			if err := ts.parseBody(c.body); err == nil {
				t.Fatalf("畸形 TS 竟解析成功：%v", ts.Selectors)
			}
		})
	}
}

// ── Notify / Delete ──

func TestPayloadNotifyDeleteMalformed(t *testing.T) {
	cases := []struct {
		name string
		p    Payload
		body []byte
	}{
		{"N 体长不足固定头", &NotifyPayload{}, []byte{0, 0, 0}},
		{"N 的 SPI 长度非 0/4/8", &NotifyPayload{}, []byte{3, 3, 0x40, 0x09, 1, 2, 3}},
		{"N 声称的 SPI 超出体长", &NotifyPayload{}, []byte{3, 8, 0x40, 0x09, 1, 2}},
		{"D 体长不足固定头", &DeletePayload{}, []byte{1, 0, 0}},
		// 删 IKE SA 却带 SPI：上层若按 Child 逻辑处理就会删错 SA，
		// 症状是「隧道莫名其妙断了」，最难回溯。
		{"D 删 IKE SA 却带了 SPI", &DeletePayload{}, []byte{1, 4, 0, 1, 1, 2, 3, 4}},
		{"D 删 ESP SA 的 SPI 长度不是 4", &DeletePayload{}, []byte{3, 8, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8}},
		{"D 删 ESP SA 但列表为空", &DeletePayload{}, []byte{3, 4, 0, 0}},
		{"D 的 SPI 数量与体长不符", &DeletePayload{}, []byte{3, 4, 0, 2, 1, 2, 3, 4}},
		{"D 的协议既不是 IKE 也不是 ESP", &DeletePayload{}, []byte{7, 0, 0, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.p.parseBody(c.body); err == nil {
				t.Fatal("畸形载荷竟解析成功")
			}
		})
	}
}

// TestPayloadNotifyUnknownTypeAccepted 断言未知通知类型**解析通过**。
//
// ★这是互通生命线：strongSwan 默认会发 IKE_FRAGMENTATION_SUPPORTED(16430)、
// SIGNATURE_HASH_ALGORITHMS(16431)、MOBIKE_SUPPORTED(16396) 等一串状态类通知，
// 把任何一个当成解析错误，结果都是完全建不起连。
func TestPayloadNotifyUnknownTypeAccepted(t *testing.T) {
	var n NotifyPayload
	if err := n.parseBody([]byte{0, 0, 0x40, 0x2E, 0xaa}); err != nil {
		t.Fatalf("未知状态类通知 16430 应解析通过，却报错: %v", err)
	}
	if n.NotifyType != NotifyIKEFragmentationSupported {
		t.Fatalf("解出的通知类型 %d，期望 16430", uint16(n.NotifyType))
	}
	if n.NotifyType.IsError() {
		t.Fatal("≥16384 属状态类，IsError 应为 false（当成错误会导致完全建不起连）")
	}
}
