package ike

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// 流量选择器（TS）是 IKEv2 里唯一一处「协议表达能力比本实现的策略模型宽」的地方：
// 线格式描述的是**任意地址区间 + 端口区间 + 协议号**，而白帝的站点配置只有一个 CIDR。
//
// ★本轮**不做 narrowing**：responder 要求收到的 TS 与本地配置逐字段相等，
// 否则回 N(TS_UNACCEPTABLE)。理由是策略权威在控制面——网关侧自作主张收窄会造成
// 「控制台配了 /16、实际只通了 /24」这种无报错的假成功，与项目历史上
// `baidi-tun -route` 只接管单网段那次事故同构（无报错、UI 显示已接入、就是不通）。
// 因此本文件提供的是 Equal（逐字段相等）而不是 Contains/Narrow。

// 选择器固定长度（Selector Length 字段的合法取值）。
const (
	tsIPv4SelectorLen = 16 // 4 头 + 4 端口 + 4 + 4 地址
	tsIPv6SelectorLen = 40 // 4 头 + 4 端口 + 16 + 16 地址
)

// ── TSi / TSr ──

// Type 实现 Payload 接口。零值退化为 TSi，理由同 IDPayload.Type。
func (p *TSPayload) Type() PayloadType {
	if p.T == PayloadTSr {
		return PayloadTSr
	}
	return PayloadTSi
}

func (p *TSPayload) appendBody(dst []byte) []byte {
	if len(p.Selectors) > 255 {
		panic(fmt.Sprintf("ike: 流量选择器数 %d 超过单字节 Number of TSs 字段的表达范围", len(p.Selectors)))
	}
	dst = append(dst, byte(len(p.Selectors)), 0, 0, 0) // Number of TSs + RESERVED(3)
	for _, ts := range p.Selectors {
		dst = ts.appendTo(dst)
	}
	return dst
}

func (p *TSPayload) parseBody(b []byte) error {
	p.Selectors = nil
	if len(b) < 4 {
		return payloadErr(p.Type(), fmt.Sprintf("体长 %d 不足 4 字节固定头（Number of TSs 1 + RESERVED 3）", len(b)))
	}
	n := int(b[0])
	if n == 0 {
		return payloadErr(p.Type(), "选择器数量为 0")
	}
	if n > MaxTrafficSelectors {
		return payloadErr(p.Type(), fmt.Sprintf("选择器数量 %d 超过上限 %d", n, MaxTrafficSelectors))
	}
	off := 4
	for i := 0; i < n; i++ {
		if off+4 > len(b) {
			return payloadErr(p.Type(), fmt.Sprintf("第 %d 个选择器的头越界（off=%d，剩余 %d 字节）", i+1, off, len(b)-off))
		}
		var ts TrafficSelector
		ts.Type = TSType(b[off])
		ts.Proto = b[off+1]
		selLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))

		var addrLen, wantLen int
		switch ts.Type {
		case TSIPv4AddrRange:
			addrLen, wantLen = 4, tsIPv4SelectorLen
		case TSIPv6AddrRange:
			addrLen, wantLen = 16, tsIPv6SelectorLen
		default:
			// 不认识的 TS 类型不能跳过：跳过等于「对这段流量没有约束」，
			// 而 TS 恰恰是唯一约束对端能往隧道里塞什么地址的东西。
			return payloadErr(p.Type(), fmt.Sprintf("不支持的选择器类型 %d（只支持 7=IPv4 区间、8=IPv6 区间）", uint8(ts.Type)))
		}
		if selLen != wantLen {
			return payloadErr(p.Type(), fmt.Sprintf("选择器长度 %d 与类型 %d 要求的 %d 不符", selLen, uint8(ts.Type), wantLen))
		}
		if off+selLen > len(b) {
			return payloadErr(p.Type(), fmt.Sprintf("第 %d 个选择器越界（off=%d 长度=%d，体总长=%d）", i+1, off, selLen, len(b)))
		}
		ts.StartPort = binary.BigEndian.Uint16(b[off+4 : off+6])
		ts.EndPort = binary.BigEndian.Uint16(b[off+6 : off+8])
		var ok bool
		if ts.Start, ok = netip.AddrFromSlice(b[off+8 : off+8+addrLen]); !ok {
			return payloadErr(p.Type(), "起始地址解析失败")
		}
		if ts.End, ok = netip.AddrFromSlice(b[off+8+addrLen : off+8+2*addrLen]); !ok {
			return payloadErr(p.Type(), "结束地址解析失败")
		}
		// 起 > 止 的区间是空集，但沿着「空集匹配不到任何包」的路径走下去，
		// 表现是隧道建成后一个包也不通、且哪儿都不报错。在解析层直接拒掉。
		if ts.Start.Compare(ts.End) > 0 {
			return payloadErr(p.Type(), fmt.Sprintf("起始地址 %s 大于结束地址 %s", ts.Start, ts.End))
		}
		if ts.StartPort > ts.EndPort {
			return payloadErr(p.Type(), fmt.Sprintf("起始端口 %d 大于结束端口 %d", ts.StartPort, ts.EndPort))
		}
		p.Selectors = append(p.Selectors, ts)
		off += selLen
	}
	if off != len(b) {
		return payloadErr(p.Type(), fmt.Sprintf("选择器之后仍有 %d 字节多余数据", len(b)-off))
	}
	return nil
}

// Equal 逐字段比较两个 TS 载荷（含类型、顺序与数量）。
// responder 用它判定对端提的 TS 是否与本地配置完全一致，见文件头「不做 narrowing」。
func (p *TSPayload) Equal(o *TSPayload) bool {
	if p == nil || o == nil {
		return p == nil && o == nil
	}
	if p.Type() != o.Type() || len(p.Selectors) != len(o.Selectors) {
		return false
	}
	for i := range p.Selectors {
		if !p.Selectors[i].Equal(o.Selectors[i]) {
			return false
		}
	}
	return true
}

// ── 单个选择器 ──

// appendTo 序列化一个选择器。
//
// panic 的理由同 Proposal.appendTo：地址族与声明类型不符只可能是本进程构造错误
// （解析路径按声明类型定长读取，产不出不一致的组合）。写一段长度自洽但地址错位的
// TS 出去，对端会回 TS_UNACCEPTABLE，而本端日志里什么线索都没有。
func (t TrafficSelector) appendTo(dst []byte) []byte {
	var addr []byte
	var selLen int
	switch t.Type {
	case TSIPv4AddrRange:
		if !t.Start.Is4() || !t.End.Is4() {
			panic(fmt.Sprintf("ike: 选择器声明为 IPv4 区间，地址却是 %s..%s", t.Start, t.End))
		}
		s, e := t.Start.As4(), t.End.As4()
		addr = append(append([]byte(nil), s[:]...), e[:]...)
		selLen = tsIPv4SelectorLen
	case TSIPv6AddrRange:
		if t.Start.Is4() || t.End.Is4() {
			panic(fmt.Sprintf("ike: 选择器声明为 IPv6 区间，地址却是 %s..%s", t.Start, t.End))
		}
		s, e := t.Start.As16(), t.End.As16()
		addr = append(append([]byte(nil), s[:]...), e[:]...)
		selLen = tsIPv6SelectorLen
	default:
		panic(fmt.Sprintf("ike: 不支持的流量选择器类型 %d", uint8(t.Type)))
	}
	dst = append(dst, byte(t.Type), t.Proto)
	dst = binary.BigEndian.AppendUint16(dst, uint16(selLen))
	dst = binary.BigEndian.AppendUint16(dst, t.StartPort)
	dst = binary.BigEndian.AppendUint16(dst, t.EndPort)
	return append(dst, addr...)
}

// Equal 逐字段相等判定（本轮 TS 协商的唯一判据）。
func (t TrafficSelector) Equal(o TrafficSelector) bool {
	return t.Type == o.Type &&
		t.Proto == o.Proto &&
		t.StartPort == o.StartPort &&
		t.EndPort == o.EndPort &&
		t.Start == o.Start &&
		t.End == o.End
}

// String 供日志与错误信息使用：`10.20.0.0-10.20.255.255:0-65535/any`。
// ★TS 不匹配时必须把两侧的实际区间都打出来，只回一句 TS_UNACCEPTABLE 排不了障。
func (t TrafficSelector) String() string {
	proto := "any"
	if t.Proto != 0 {
		proto = fmt.Sprintf("%d", t.Proto)
	}
	return fmt.Sprintf("%s-%s:%d-%d/%s", t.Start, t.End, t.StartPort, t.EndPort, proto)
}

// TSFromPrefix 把配置里的 CIDR 转成一个「全端口、全协议」的流量选择器。
//
// 换算规则：`10.20.0.0/16` → 起 `10.20.0.0`、止 `10.20.255.255`，端口 0..65535，协议 0（任意）。
// 入参无效时返回零值选择器——调用方应在装载期就用 SiteConfig.Validate 拦住无效网段，
// 而不是让一个零值 TS 混进协商。
func TSFromPrefix(p netip.Prefix) TrafficSelector {
	if !p.IsValid() {
		return TrafficSelector{}
	}
	p = p.Masked()
	ts := TrafficSelector{
		Proto:     0,
		StartPort: 0,
		EndPort:   65535,
		Start:     p.Addr(),
		End:       lastAddrOfPrefix(p),
	}
	if p.Addr().Is4() {
		ts.Type = TSIPv4AddrRange
	} else {
		ts.Type = TSIPv6AddrRange
	}
	return ts
}

// Prefix 把选择器还原成 CIDR。第二个返回值为 false 表示该区间**不是一个整 CIDR**。
//
// ★对端完全可以合法地送来 `10.20.0.5 - 10.20.7.9` 这种非对齐区间。本轮既然不做
// narrowing，就不能把它「就近凑」成某个 CIDR——凑出来的策略与对端理解的不一致，
// 又是一次无报错的假成功。拿不到整 CIDR 时调用方应回 TS_UNACCEPTABLE。
func (t TrafficSelector) Prefix() (netip.Prefix, bool) {
	if !t.Start.IsValid() || !t.End.IsValid() || t.Start.Is4() != t.End.Is4() {
		return netip.Prefix{}, false
	}
	var sb, eb []byte
	if t.Start.Is4() {
		s, e := t.Start.As4(), t.End.As4()
		sb, eb = s[:], e[:]
	} else {
		s, e := t.Start.As16(), t.End.As16()
		sb, eb = s[:], e[:]
	}
	total := len(sb) * 8
	bits := 0
	for ; bits < total; bits++ {
		m := byte(0x80 >> (bits % 8))
		if sb[bits/8]&m != eb[bits/8]&m {
			break
		}
	}
	// 前 bits 位（网络号）相同之后，剩下的主机位必须是 start 全 0、end 全 1，
	// 否则这个区间跨越了 CIDR 边界。
	for i := bits; i < total; i++ {
		m := byte(0x80 >> (i % 8))
		if sb[i/8]&m != 0 || eb[i/8]&m == 0 {
			return netip.Prefix{}, false
		}
	}
	return netip.PrefixFrom(t.Start, bits), true
}

// lastAddrOfPrefix 返回网段内的最后一个地址（主机位全置 1）。
func lastAddrOfPrefix(p netip.Prefix) netip.Addr {
	a := p.Addr()
	bits := p.Bits()
	if a.Is4() {
		b := a.As4()
		setHostBits(b[:], bits)
		return netip.AddrFrom4(b)
	}
	b := a.As16()
	setHostBits(b[:], bits)
	return netip.AddrFrom16(b)
}

func setHostBits(b []byte, prefixBits int) {
	if prefixBits < 0 {
		prefixBits = 0
	}
	for i := prefixBits; i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
}
