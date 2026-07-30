package ike

import (
	"encoding/binary"
	"fmt"
)

// KE 与 Nonce 是 IKE_SA_INIT 里除 SA 之外仅有的两个必需载荷，格式都极简单——
// 但它们承载的字节**直接进密钥派生**（KE 数据算 g^ir、Nonce 值进 SKEYSEED 与
// SignedOctets），所以任何长度上的宽容都会在 AUTH 阶段变成一句「认证失败」。
// 这两个 parseBody 因此都做严格长度校验，而不是「先收下、用的时候再说」。

// ── KE ──

// Type 实现 Payload 接口。
func (p *KEPayload) Type() PayloadType { return PayloadKE }

func (p *KEPayload) appendBody(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, p.Group)
	dst = append(dst, 0, 0) // RESERVED
	return append(dst, p.Data...)
}

func (p *KEPayload) parseBody(b []byte) error {
	if len(b) < 4 {
		return payloadErr(PayloadKE, fmt.Sprintf("体长 %d 不足 4 字节固定头（Group 2 + RESERVED 2）", len(b)))
	}
	p.Group = binary.BigEndian.Uint16(b[0:2])
	p.Data = append([]byte(nil), b[4:]...)
	if len(p.Data) == 0 {
		return payloadErr(PayloadKE, "公钥数据为空")
	}
	if p.Group == DHNone {
		return payloadErr(PayloadKE, "DH 群为 NONE（0）——不带 KE 才是无 PFS 的正确表达，带一个空群的 KE 不是")
	}
	// 群长度校验（解析防护 §10.4 第 7 条）。
	//
	// ★只在**本端支持该群**时校验：对端提了我们不认识的群时，正确回应是
	// N(INVALID_KE_PAYLOAD) 并告诉它我们要哪个群——那是状态机的职责。
	// 在解析层就把未知群判为畸形包会让「群不匹配」退化成静默丢包，
	// 对端只能看到超时重传，永远得不到那条本可以指路的通知。
	if g, err := LookupDH(p.Group); err == nil && g != nil {
		if len(p.Data) != g.PubLen() {
			return payloadErr(PayloadKE, fmt.Sprintf("群 %d 的公钥应为 %d 字节，实际收到 %d 字节（ECP256 是 X‖Y 且不带 0x04 前缀，MODP2048 必须前导补零到 256）", p.Group, g.PubLen(), len(p.Data)))
		}
	}
	return nil
}

// ── Nonce ──

// Type 实现 Payload 接口。Ni 与 Nr 共用类型 40，靠在报文中的位置区分。
func (p *NoncePayload) Type() PayloadType { return PayloadNonce }

func (p *NoncePayload) appendBody(dst []byte) []byte { return append(dst, p.Nonce...) }

func (p *NoncePayload) parseBody(b []byte) error {
	// RFC 7296 §3.9：nonce 长度 16..256，且不少于协商 PRF 密钥长度的一半。
	// 上界同时是解析防护——nonce 会被完整拼进 SignedOctets 与 prf+ 的 seed，
	// 允许超长 nonce 等于让对端单方面决定我们的哈希输入规模。
	if len(b) < MinNonceLen || len(b) > MaxNonceLen {
		return payloadErr(PayloadNonce, fmt.Sprintf("长度 %d 越界（须在 %d..%d 之间）", len(b), MinNonceLen, MaxNonceLen))
	}
	p.Nonce = append([]byte(nil), b...)
	return nil
}
