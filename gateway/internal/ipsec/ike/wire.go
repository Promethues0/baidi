package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Header IKE 固定头（RFC 7296 §3.1），全部字段网络字节序。
type Header struct {
	SPIi, SPIr   [8]byte
	NextPayload  PayloadType
	Version      uint8
	ExchangeType ExchangeType
	Flags        Flags
	MessageID    uint32
	Length       uint32
}

// IsRequest 报告本报文是请求（R 位为 0）。
func (h Header) IsRequest() bool { return h.Flags&FlagResponse == 0 }

// FromInitiator 报告本报文由该 IKE SA 的**原始发起方**发出（I 位）。
// 注意不是「本次交换的发起方」，见 const.go 中 FlagInitiator 的说明。
func (h Header) FromInitiator() bool { return h.Flags&FlagInitiator != 0 }

// AppendTo 序列化头部。Length 由调用方（Encode）在整条报文拼好后回填。
func (h Header) AppendTo(dst []byte) []byte {
	dst = append(dst, h.SPIi[:]...)
	dst = append(dst, h.SPIr[:]...)
	dst = append(dst, byte(h.NextPayload), h.Version, byte(h.ExchangeType), byte(h.Flags))
	dst = binary.BigEndian.AppendUint32(dst, h.MessageID)
	dst = binary.BigEndian.AppendUint32(dst, h.Length)
	return dst
}

// ParseHeader 解析固定头，只做结构性校验（语义校验在 Decode）。
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderLen {
		return h, fmt.Errorf("ike: 报文长度 %d 不足 IKE 头的 %d 字节", len(b), HeaderLen)
	}
	copy(h.SPIi[:], b[0:8])
	copy(h.SPIr[:], b[8:16])
	h.NextPayload = PayloadType(b[16])
	h.Version = b[17]
	h.ExchangeType = ExchangeType(b[18])
	h.Flags = Flags(b[19])
	h.MessageID = binary.BigEndian.Uint32(b[20:24])
	h.Length = binary.BigEndian.Uint32(b[24:28])
	return h, nil
}

// Message 一条 IKE 报文。
type Message struct {
	Hdr      Header
	Payloads []Payload

	// Raw 是收发时的**原始字节**，必须保留。
	//
	// ★AUTH 载荷签的是 IKE_SA_INIT 报文的确切字节（RealMessage1/2，见 auth.go）。
	// 事后重新序列化即使语义完全等价，也可能因为载荷顺序、属性编码形式、保留位
	// 的细微差异而产出不同字节，进而算出不同的 AUTH——而对端报回来的只有一句
	// 「认证失败」，根本看不出问题出在序列化上。所以：签名只用 Raw，永不重编码。
	Raw []byte
}

// ErrNotIKEv2 表示主版本号不是 2。调用方应回 INVALID_MAJOR_VERSION 而不是静默丢弃。
var ErrNotIKEv2 = errors.New("ike: 非 IKEv2 报文")

// Decode 解析一条 IKE 报文的**外层**结构。
//
// SK 载荷保持密文原样（解密需要协商出的密钥，那是上层的事），
// 其余载荷解析到具体类型。解析失败一律返回 error，调用方按 §10.4 的原则处置：
// 未认证阶段**静默丢包**，不回任何东西——回错误就把自己变成了反射放大器。
func Decode(raw []byte) (*Message, error) {
	hdr, err := ParseHeader(raw)
	if err != nil {
		return nil, err
	}
	if hdr.Version>>4 != 2 {
		return nil, ErrNotIKEv2
	}
	// ★严格相等，不接受尾部多余字节。允许尾部垃圾会给「同一报文两种解析」
	// 留下空间，而 AUTH 恰恰对字节敏感——宽容在这里等于制造歧义。
	if int(hdr.Length) != len(raw) {
		return nil, fmt.Errorf("ike: 头部声明长度 %d 与实际 %d 不符", hdr.Length, len(raw))
	}
	if hdr.Length > MaxMessageLen {
		return nil, fmt.Errorf("ike: 报文长度 %d 超过上限", hdr.Length)
	}
	// SPIi 全零是非法的（RFC 7296 §2.6）；用它可以低成本挡掉一部分扫描流量。
	if hdr.SPIi == ([8]byte{}) {
		return nil, errors.New("ike: SPIi 全零")
	}
	if hdr.ExchangeType == ExchangeIKESAInit && hdr.IsRequest() && hdr.SPIr != ([8]byte{}) {
		return nil, errors.New("ike: IKE_SA_INIT 请求的 SPIr 必须为零")
	}

	m := &Message{Hdr: hdr, Raw: raw}
	next := hdr.NextPayload
	off := HeaderLen
	for next != PayloadNone {
		if len(m.Payloads) >= MaxPayloads {
			return nil, fmt.Errorf("ike: 载荷数超过上限 %d", MaxPayloads)
		}
		if off+4 > len(raw) {
			return nil, errors.New("ike: 载荷头越界")
		}
		thisType := next
		next = PayloadType(raw[off])
		critical := raw[off+1]&0x80 != 0
		plen := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
		// plen 必须 ≥ 4（含通用头）。若允许 0，下面的 off += plen 就永远不前进，
		// 一个 4 字节的畸形包即可让解析器死循环——这类"用极少字节撑出无限工作量"
		// 的构造正是未认证攻击面上最需要防的。
		if plen < 4 {
			return nil, fmt.Errorf("ike: %s 载荷长度 %d 非法（须 ≥4）", thisType, plen)
		}
		if off+plen > len(raw) {
			return nil, fmt.Errorf("ike: %s 载荷越界（off=%d len=%d 总长=%d）", thisType, off, plen, len(raw))
		}
		body := raw[off+4 : off+plen]

		p := newPayload(thisType)
		if rp, ok := p.(*RawPayload); ok {
			rp.Critical = critical
		}
		// ★SK 的 Next Payload 指向**被加密的第一个内层载荷**，而 next 只有这个循环
		// 看得到（parseBody 拿到的是载荷体，通用头已被剥掉）。不在此处回填，
		// 解密后就无从知道内层链的起点，症状是「解密成功但报文里什么都没有」。
		if sk, ok := p.(*SKPayload); ok {
			sk.Inner = next
		}
		if err := p.parseBody(body); err != nil {
			return nil, err
		}
		m.Payloads = append(m.Payloads, p)
		off += plen

		// SK 之后不允许再有外层载荷：它的 Next Payload 指向的是**被加密的第一个内层
		// 载荷**类型，不是外层链的下一个。不在此处终止就会把密文当载荷继续解析。
		if thisType == PayloadSK {
			if off != len(raw) {
				return nil, errors.New("ike: SK 载荷之后不应再有外层载荷")
			}
			break
		}
	}
	return m, nil
}

// Encode 序列化一条报文：自动回填 Next Payload 链与总长度。
//
// Next Payload 是**前向声明**（载荷 N 的字段描述载荷 N+1 的类型），所以必须先把
// 所有载荷排好、记下各自偏移，再回头写类型字节。先写后排是这类协议实现的经典 bug。
func Encode(hdr Header, ps []Payload) ([]byte, error) {
	if len(ps) > MaxPayloads {
		return nil, fmt.Errorf("ike: 载荷数 %d 超过上限", len(ps))
	}
	hdr.Version = Version
	buf := hdr.AppendTo(make([]byte, 0, 256))

	// offsets[i] 是第 i 个载荷通用头的起始偏移，供回填 Next Payload 用。
	offsets := make([]int, len(ps))
	for i, p := range ps {
		offsets[i] = len(buf)
		buf = append(buf, 0, 0, 0, 0) // 通用头占位：NextPayload / Critical / Length(2)
		before := len(buf)
		buf = p.appendBody(buf)
		plen := 4 + (len(buf) - before)
		if plen > 0xFFFF {
			return nil, fmt.Errorf("ike: %s 载荷过长（%d）", p.Type(), plen)
		}
		binary.BigEndian.PutUint16(buf[offsets[i]+2:offsets[i]+4], uint16(plen))
	}

	// 回填链：头部指向第一个载荷；载荷 i 指向载荷 i+1；最后一个指向 NONE。
	if len(ps) == 0 {
		buf[16] = byte(PayloadNone)
	} else {
		buf[16] = byte(ps[0].Type())
		for i := range ps {
			var nt PayloadType
			if i+1 < len(ps) {
				nt = ps[i+1].Type()
			}
			buf[offsets[i]] = byte(nt)
		}
	}
	if len(buf) > MaxMessageLen {
		return nil, fmt.Errorf("ike: 报文长度 %d 超过上限", len(buf))
	}
	binary.BigEndian.PutUint32(buf[24:28], uint32(len(buf)))
	return buf, nil
}

// Find 取第一个指定类型的载荷；没有返回 nil。
func (m *Message) Find(t PayloadType) Payload {
	for _, p := range m.Payloads {
		if p.Type() == t {
			return p
		}
	}
	return nil
}

// FindAll 取全部指定类型的载荷（Notify 常有多个）。
func (m *Message) FindAll(t PayloadType) []Payload {
	var out []Payload
	for _, p := range m.Payloads {
		if p.Type() == t {
			out = append(out, p)
		}
	}
	return out
}

// FindNotify 取指定类型的通知载荷；没有返回 nil。
func (m *Message) FindNotify(t NotifyType) *NotifyPayload {
	for _, p := range m.Payloads {
		if n, ok := p.(*NotifyPayload); ok && n.NotifyType == t {
			return n
		}
	}
	return nil
}

// FirstErrorNotify 返回报文里第一个**错误类**通知（< 16384）。
// 状态类通知（≥ 16384）一律不算错误——不认识的必须忽略，见 NotifyType 的说明。
func (m *Message) FirstErrorNotify() *NotifyPayload {
	for _, p := range m.Payloads {
		if n, ok := p.(*NotifyPayload); ok && n.NotifyType.IsError() {
			return n
		}
	}
	return nil
}

// UnsupportedCritical 返回第一个「不认识且 Critical=1」的载荷类型。
// 有则调用方必须回 UNSUPPORTED_CRITICAL_PAYLOAD（RFC 7296 §2.5）。
func (m *Message) UnsupportedCritical() (PayloadType, bool) {
	for _, p := range m.Payloads {
		if rp, ok := p.(*RawPayload); ok && rp.Critical {
			switch rp.T {
			case PayloadCERT, PayloadCERTREQ, PayloadVendor:
				// 这几个我们认识边界、有意跳过，不算「不认识」。
				continue
			}
			return rp.T, true
		}
	}
	return 0, false
}
