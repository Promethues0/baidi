package ike

import (
	"encoding/binary"
	"fmt"
)

// Notify（N）与 Delete（D）是控制面的「带外话筒」：前者说明为什么失败/支持什么特性，
// 后者优雅拆 SA。
//
// ★关于 Notify 有一条互通生命线（判定逻辑在状态机，但解析层必须把原样字节交上去）：
// **类型 < 16384 是错误，≥ 16384 是状态；不认识的状态类通知必须静默忽略**。
// strongSwan 默认会发 IKE_FRAGMENTATION_SUPPORTED(16430)、SIGNATURE_HASH_ALGORITHMS(16431)、
// MOBIKE_SUPPORTED(16396)、REDIRECT_SUPPORTED(16406)，任何一个被当成错误处理，
// 结果都是完全建不起连——所以解析层对未知通知类型**不报错**，只如实解出。
//
// ★关于 Delete：不实现它不会有任何报错，代价是每次重协商/拆站点都在对端留一条幽灵 SA，
// 对端要等到硬生存期或 DPD 判死才清理，期间流量落进一条本端已经不认的 SA 里黑洞掉。

// maxDeleteSPIs 一条 Delete 载荷里允许的最大 SPI 数。
//
// 报文总长本身就是上界（65535/4 ≈ 16k），但那意味着一个包能逼我们分配上万个切片。
// 本实现每条 IKE SA 的 Child SA 数是个位数，64 已经宽松到不可能误伤。
const maxDeleteSPIs = 64

// ── Notify ──

// Type 实现 Payload 接口。
func (p *NotifyPayload) Type() PayloadType { return PayloadNotify }

func (p *NotifyPayload) appendBody(dst []byte) []byte {
	if len(p.SPI) > 255 {
		panic(fmt.Sprintf("ike: 通知载荷 SPI 长度 %d 超过单字节 SPI Size 字段的表达范围", len(p.SPI)))
	}
	dst = append(dst, byte(p.Protocol), byte(len(p.SPI)))
	dst = binary.BigEndian.AppendUint16(dst, uint16(p.NotifyType))
	dst = append(dst, p.SPI...)
	return append(dst, p.Data...)
}

func (p *NotifyPayload) parseBody(b []byte) error {
	if len(b) < 4 {
		return payloadErr(PayloadNotify, fmt.Sprintf("体长 %d 不足 4 字节固定头（Protocol 1 + SPI Size 1 + Type 2）", len(b)))
	}
	p.Protocol = ProtocolID(b[0])
	spiSize := int(b[1])
	p.NotifyType = NotifyType(binary.BigEndian.Uint16(b[2:4]))
	// SPI 长度白名单：0（不针对特定 SA）、4（ESP，如 REKEY_SA）、8（IKE SA）。
	// 其余取值本实现产不出也用不上，放行只会让上层拿到一段无从解释的字节。
	switch spiSize {
	case 0, 4, 8:
	default:
		return payloadErr(PayloadNotify, fmt.Sprintf("通知 %s 的 SPI 长度 %d 非法（只允许 0/4/8）", p.NotifyType, spiSize))
	}
	if 4+spiSize > len(b) {
		return payloadErr(PayloadNotify, fmt.Sprintf("通知 %s 声称 SPI 长 %d，但体只剩 %d 字节", p.NotifyType, spiSize, len(b)-4))
	}
	p.SPI = append([]byte(nil), b[4:4+spiSize]...)
	p.Data = append([]byte(nil), b[4+spiSize:]...)
	return nil
}

// String 供日志：`N(NO_PROPOSAL_CHOSEN)` / `N(REKEY_SA ESP spi=1a2b3c4d)`。
func (p *NotifyPayload) String() string {
	s := fmt.Sprintf("N(%s", p.NotifyType)
	if p.Protocol != ProtocolNone {
		s += " " + protocolName(p.Protocol)
	}
	if len(p.SPI) > 0 {
		s += fmt.Sprintf(" spi=%x", p.SPI)
	}
	if len(p.Data) > 0 {
		s += fmt.Sprintf(" data=%d字节", len(p.Data))
	}
	return s + ")"
}

// ── Delete ──

// Type 实现 Payload 接口。
func (p *DeletePayload) Type() PayloadType { return PayloadDelete }

func (p *DeletePayload) appendBody(dst []byte) []byte {
	spiSize := 0
	if len(p.SPIs) > 0 {
		spiSize = len(p.SPIs[0])
	}
	if spiSize > 255 || len(p.SPIs) > 0xFFFF {
		panic(fmt.Sprintf("ike: 删除载荷的 SPI 长度 %d / 数量 %d 超出字段表达范围", spiSize, len(p.SPIs)))
	}
	dst = append(dst, byte(p.Protocol), byte(spiSize))
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(p.SPIs)))
	for _, s := range p.SPIs {
		if len(s) != spiSize {
			// 线格式只有一个全局 SPI Size 字段，长度不齐的列表根本无法表达。
			panic(fmt.Sprintf("ike: 删除载荷的 SPI 长度不一致（%d vs %d）", len(s), spiSize))
		}
		dst = append(dst, s...)
	}
	return dst
}

func (p *DeletePayload) parseBody(b []byte) error {
	p.SPIs = nil
	if len(b) < 4 {
		return payloadErr(PayloadDelete, fmt.Sprintf("体长 %d 不足 4 字节固定头（Protocol 1 + SPI Size 1 + Num SPIs 2）", len(b)))
	}
	p.Protocol = ProtocolID(b[0])
	spiSize := int(b[1])
	num := int(binary.BigEndian.Uint16(b[2:4]))

	// 协议与 SPI 形态强绑定（RFC 7296 §3.11）：
	//   删 IKE SA → Protocol=1、SPI Size=0、Num SPIs=0（SPI 在报文头里，不用再说一遍）
	//   删 Child SA → Protocol=3、SPI Size=4，列表放**自己入向**的 SPI
	// 不校验的话，一条 `Protocol=IKE 且带 SPI` 的畸形删除会被上层按 Child 逻辑处理，
	// 结果是删错 SA——而「隧道莫名其妙断了」这种症状最难回溯。
	switch p.Protocol {
	case ProtocolIKE:
		if spiSize != 0 || num != 0 {
			return payloadErr(PayloadDelete, fmt.Sprintf("删除 IKE SA 时 SPI Size 与 Num SPIs 必须为 0（实际 %d/%d）", spiSize, num))
		}
	case ProtocolESP, ProtocolAH:
		if spiSize != 4 {
			return payloadErr(PayloadDelete, fmt.Sprintf("删除 %s SA 时 SPI 长度必须为 4（实际 %d）", protocolName(p.Protocol), spiSize))
		}
		if num == 0 {
			return payloadErr(PayloadDelete, fmt.Sprintf("删除 %s SA 但 SPI 列表为空", protocolName(p.Protocol)))
		}
	default:
		return payloadErr(PayloadDelete, fmt.Sprintf("不支持的协议 %d（只允许 1=IKE、3=ESP）", uint8(p.Protocol)))
	}
	if num > maxDeleteSPIs {
		return payloadErr(PayloadDelete, fmt.Sprintf("SPI 数量 %d 超过上限 %d", num, maxDeleteSPIs))
	}
	// 严格相等而不是 ≥：多出来的尾巴意味着我们和对端对这条载荷的理解不同，
	// 而删除是破坏性操作，宁可拒绝也不要「大致解析对了」。
	if want := 4 + num*spiSize; want != len(b) {
		return payloadErr(PayloadDelete, fmt.Sprintf("体长 %d 与 %d 个 %d 字节 SPI 所需的 %d 不符", len(b), num, spiSize, want))
	}
	for i := 0; i < num; i++ {
		off := 4 + i*spiSize
		p.SPIs = append(p.SPIs, append([]byte(nil), b[off:off+spiSize]...))
	}
	return nil
}

// String 供日志：`D(ESP spi=[1a2b3c4d])` / `D(IKE)`。
func (p *DeletePayload) String() string {
	s := fmt.Sprintf("D(%s", protocolName(p.Protocol))
	if len(p.SPIs) > 0 {
		s += " spi=["
		for i, x := range p.SPIs {
			if i > 0 {
				s += " "
			}
			s += fmt.Sprintf("%x", x)
		}
		s += "]"
	}
	return s + ")"
}
