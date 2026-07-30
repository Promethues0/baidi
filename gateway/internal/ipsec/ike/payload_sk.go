package ike

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
)

// 本文件是 SK（加密载荷）的全部实现。**两种套件在 IV/AAD/ICV/补齐上的差异全部收敛在这里**，
// 状态机与其余载荷完全看不到 GCM 与 CBC 的区别——这是刻意的：这些差异一共只有 6 条，
// 但每一条写错的症状都是同一句「解密失败」，散落到多处后根本无从二分定位。
//
// 差异表（RFC 7296 §3.14 + RFC 5282）：
//
//	                     AES/SM4-CBC + HMAC              AES/SM4-GCM-16（combined）
//	 INTEG transform     12（或私有 1024）                **必须 0=NONE**
//	 SK_e 长度           32（纯密钥）                     36（32 密钥 + **末尾 4 字节 salt**）
//	 SK_a 长度           32                               **0（不派生）**
//	 IV 字段             16 字节，**随机**                 8 字节，**单调递增计数器**
//	 真实密码学 nonce     IV 本身                          salt(4) ‖ IV(8)
//	 补齐分组            16（padLen 0..15）                1（padLen 恒 0，明文尾巴就一个 0x00）
//	 ICV                 HMAC 截断至 16 字节               GCM tag 16 字节
//	 ICV/AAD 覆盖        HMAC 覆盖 raw[:len-16]            AAD = raw[:SK体起点+8]（头 ~ IV 末字节）
//	 校验顺序            **先验 ICV 再解密**（防 padding oracle）  GCM 自带，Open 失败即丢
//
// ★GCM 的 IV 绝不能用随机数。8 字节随机在同一 SA 上跑久了会碰撞，而 GCM 的 nonce 复用
// 是**灾难性**的（可直接恢复明文与认证密钥），且不会有任何报错。因此 EncryptSK 把 IV
// 计数器做成必填入参，由调用方（IKESA）保证每 SA 每方向单调递增；响应重传必须
// **原样回放缓存**而不是重新加密，否则同一个计数器会被用两次。

// Type 实现 Payload 接口。
func (p *SKPayload) Type() PayloadType { return PayloadSK }

// appendBody 原样写出密文块。
//
// 正常发送路径不走这里（见 EncryptSK 为什么不复用 Encode）；实现它是为了满足
// Payload 接口，并让「解析 → 原样重编码」的幂等测试对 SK 也成立。
func (p *SKPayload) appendBody(dst []byte) []byte { return append(dst, p.Body...) }

func (p *SKPayload) parseBody(b []byte) error {
	if len(b) == 0 {
		return payloadErr(PayloadSK, "密文块为空")
	}
	p.Body = append([]byte(nil), b...)
	return nil
}

// EncryptSK 把内层载荷封装进 SK 并产出**完整报文**（含 IKE 头）。
//
// ★刻意不复用 wire.Encode。Encode 的 Next Payload 回填把 SK 当作普通载荷，给它写
// 外层链的下一个类型（SK 是唯一载荷时写 0）；而 SK 的 Next Payload 必须指向
// **被加密的第一个内层载荷**。用 Encode 生成的 SK 报文，对端能解出密文却找不到
// 内层链的起点，症状是「解密成功、报文里却什么都没有」。两条路径分开是有意的。
//
// ivCounter 只对 combined（GCM）套件有意义：它被大端写成 8 字节显式 nonce。
// CBC 忽略之，用随机 IV（CBC 要求 IV 不可预测，计数器反而不安全）。
func EncryptSK(hdr Header, su *Suite, encKey, integKey []byte, ivCounter uint64, inner []Payload) ([]byte, error) {
	if su == nil || su.Encr == nil {
		return nil, errors.New("ike: SK 封装缺少加密套件")
	}
	if err := checkSKKeys(su, encKey, integKey); err != nil {
		return nil, err
	}

	innerBytes, first, err := appendPayloadChain(nil, inner)
	if err != nil {
		return nil, err
	}

	// 明文恒为 `内层载荷 ‖ Padding[padLen] ‖ PadLen(1字节)`。
	// ★PadLen 字节**永远存在**，即使 padLen=0——GCM 下 blockSize=1，明文尾巴就是一个 0x00。
	// 漏掉它会让对端把最后一个字节当补齐长度切掉，报文尾部悄悄少一段。
	bs := su.Encr.BlockSize()
	padLen := 0
	if bs > 1 {
		padLen = (bs - (len(innerBytes)+1)%bs) % bs
	}
	plain := make([]byte, 0, len(innerBytes)+padLen+1)
	plain = append(plain, innerBytes...)
	plain = append(plain, make([]byte, padLen)...) // RFC 7296 §3.14：补齐内容可任意，收方不校验
	plain = append(plain, byte(padLen))

	ivLen, icvLen := su.Encr.IVLen(), su.ICVLen()
	skLen := 4 + ivLen + len(plain) + icvLen // 4 = 载荷通用头
	total := HeaderLen + skLen
	if total > MaxMessageLen {
		return nil, fmt.Errorf("ike: SK 报文长度 %d 超过上限 %d（本实现不做 IKE 分片，见 doc.go 不实现清单）", total, MaxMessageLen)
	}

	// 头与 SK 通用头必须在加密**之前**就写死：它们都落在 AAD/ICV 覆盖范围内，
	// 事后再改任何一个字节都会让对端校验失败。
	hdr.Version = Version
	hdr.NextPayload = PayloadSK
	hdr.Length = uint32(total)
	buf := hdr.AppendTo(make([]byte, 0, total))
	buf = append(buf, byte(first), 0, 0, 0) // Next Payload=内层第一个载荷 / Critical=0 / Length 占位
	binary.BigEndian.PutUint16(buf[HeaderLen+2:HeaderLen+4], uint16(skLen))

	iv := make([]byte, ivLen)
	if su.Encr.Combined() {
		if ivLen != 8 {
			return nil, fmt.Errorf("ike: combined 套件（算法 %d）的显式 nonce 应为 8 字节，实际 %d", su.Encr.ID(), ivLen)
		}
		binary.BigEndian.PutUint64(iv, ivCounter)
	} else {
		copy(iv, RandBytes(ivLen))
	}
	buf = append(buf, iv...)

	if su.Encr.Combined() {
		// AAD = 报文第 0 字节 ~ IV 字段最后一字节（此刻 buf 恰好就是这一段）。
		// Seal 的输出是 `密文 ‖ tag`，tag 长度已计入 icvLen。
		out, err := su.Encr.Seal(encKey, iv, buf, plain)
		if err != nil {
			return nil, fmt.Errorf("ike: SK 加密失败: %w", err)
		}
		buf = append(buf, out...)
	} else {
		ct, err := su.Encr.Seal(encKey, iv, nil, plain)
		if err != nil {
			return nil, fmt.Errorf("ike: SK 加密失败: %w", err)
		}
		buf = append(buf, ct...)
		// HMAC 覆盖 `报文第 0 字节 ~ 密文最后一字节`，即除 ICV 本身之外的全部。
		buf = append(buf, su.Integ.Sum(integKey, buf)...)
	}

	// 长度自检：算错一个字节，对端表现是「解密失败」而本端毫无察觉。
	// 与其把错误留给对端，不如在这里当场炸掉。
	if len(buf) != total {
		return nil, fmt.Errorf("ike: SK 报文长度自检失败（预算 %d 字节，实产 %d 字节）", total, len(buf))
	}
	return buf, nil
}

// DecryptSK 校验并解开 m 中的 SK 载荷，把内层载荷填回 m.Payloads。
//
// 成功后 m.Payloads 变成「SK 之前的外层载荷 ‖ 解出的内层载荷」，SK 本身被移除——
// 这样上层的 m.Find(PayloadIDi) 之类查询无需关心报文是否加密过；重复调用会因为
// 找不到 SK 而报错，天然挡住「解了两次」的逻辑错误。
//
// 失败一律返回 error 且**不修改** m：半解开的报文比解不开危险得多。
func DecryptSK(m *Message, su *Suite, encKey, integKey []byte) error {
	if m == nil || len(m.Raw) < HeaderLen {
		return errors.New("ike: SK 解封的报文为空或短于 IKE 头")
	}
	if su == nil || su.Encr == nil {
		return errors.New("ike: SK 解封缺少加密套件")
	}
	if err := checkSKKeys(su, encKey, integKey); err != nil {
		return err
	}

	idx, sk := -1, (*SKPayload)(nil)
	for i, p := range m.Payloads {
		if s, ok := p.(*SKPayload); ok {
			idx, sk = i, s
			break
		}
	}
	if sk == nil {
		return fmt.Errorf("ike: 报文（交换 %s，MID %d）中没有 SK 载荷", m.Hdr.ExchangeType, m.Hdr.MessageID)
	}

	// ICV/AAD 的覆盖范围是按**原始字节**定义的，所以必须在 m.Raw 上定位 SK 体的起点。
	// Decode 保证 SK 之后不再有外层载荷（SK 体一定收尾于报文末尾），据此倒推起点；
	// 再用一次内容比对兜住「手工拼装的 Message」这种非 Decode 来源。
	raw := m.Raw
	bodyOff := len(raw) - len(sk.Body)
	if bodyOff < HeaderLen+4 || !bytes.Equal(raw[bodyOff:], sk.Body) {
		return errors.New("ike: SK 密文块与报文原始字节对不上（Message.Raw 必须是收到时的原文，不能事后重新序列化）")
	}

	ivLen, icvLen := su.Encr.IVLen(), su.ICVLen()
	// 至少还得放得下 1 字节明文（Pad Length）。DPD 的空 SK{} 就是这个极端情形。
	if len(sk.Body) < ivLen+icvLen+1 {
		return fmt.Errorf("ike: SK 密文块 %d 字节，装不下 IV(%d)+ICV(%d)+至少 1 字节明文", len(sk.Body), ivLen, icvLen)
	}
	iv := sk.Body[:ivLen]

	var plain []byte
	if su.Encr.Combined() {
		aad := raw[:bodyOff+ivLen]
		p, err := su.Encr.Open(encKey, iv, aad, sk.Body[ivLen:])
		if err != nil {
			// 这一句要能同时指向三个根因，否则排障时只会盯着密钥看。
			return fmt.Errorf("ike: SK 认证解密失败（密钥不匹配、报文被改动、或 IKE 头被中间设备重写——AAD 覆盖整个 IKE 头）: %w", err)
		}
		plain = p
	} else {
		// ★先验 ICV 再解密，顺序不能反：先解密再验完整性 = 把 CBC 解密结果的
		// 补齐是否合法暴露给攻击者，即经典的 padding oracle。
		want := su.Integ.Sum(integKey, raw[:len(raw)-icvLen])
		got := sk.Body[len(sk.Body)-icvLen:]
		if !hmac.Equal(want, got) {
			return errors.New("ike: SK 完整性校验失败（ICV 不匹配：完整性密钥不对，或报文含 IKE 头在内的任一字节被改动）")
		}
		ct := sk.Body[ivLen : len(sk.Body)-icvLen]
		if bs := su.Encr.BlockSize(); len(ct) == 0 || len(ct)%bs != 0 {
			return fmt.Errorf("ike: SK 密文 %d 字节，不是分组长 %d 的整数倍", len(ct), bs)
		}
		p, err := su.Encr.Open(encKey, iv, nil, ct)
		if err != nil {
			return fmt.Errorf("ike: SK 解密失败: %w", err)
		}
		plain = p
	}

	if len(plain) == 0 {
		return errors.New("ike: SK 明文为空（至少应有 1 字节 Pad Length）")
	}
	padLen := int(plain[len(plain)-1])
	if padLen+1 > len(plain) {
		return fmt.Errorf("ike: SK 补齐长度 %d 超出明文 %d 字节", padLen, len(plain))
	}
	inner, err := parsePayloadChain(sk.Inner, plain[:len(plain)-1-padLen])
	if err != nil {
		return err
	}

	// Decode 保证 SK 是最后一个外层载荷，故 idx 之后不会有别的东西被丢掉。
	next := make([]Payload, 0, idx+len(inner))
	next = append(next, m.Payloads[:idx]...)
	next = append(next, inner...)
	m.Payloads = next
	return nil
}

// checkSKKeys 在动用密钥之前把长度与套件形态校验干净。
//
// ★错误信息必须同时给出实际值与期望值：密钥长度不符最常见的成因是 GCM 的 4 字节
// salt 被算漏（36 写成 32），只报「长度不符」的话没人能一眼看出差的正是那 4 个字节。
func checkSKKeys(su *Suite, encKey, integKey []byte) error {
	if n := su.Encr.KeyLen(); len(encKey) != n {
		return fmt.Errorf("ike: SK 加密密钥 %d 字节与算法 %d 要求的 %d 字节不符（GCM 类算法的密钥**末尾 4 字节是 salt**，长度已含在内）", len(encKey), su.Encr.ID(), n)
	}
	if su.Encr.Combined() {
		// RFC 5282：combined 模式必须协商 INTEG=NONE。这里还挂着 Integ 说明套件构造有误。
		// 放行的后果很隐蔽：ICV 长度按 Encr 算（GCM tag），完整性却被误以为由 Integ 承担，
		// 两边各做一半，最终表现成「偶发解密失败」。
		if su.Integ != nil {
			return fmt.Errorf("ike: combined 套件（算法 %d）必须搭配 INTEG=NONE，实际挂着完整性算法 %d", su.Encr.ID(), su.Integ.ID())
		}
		return nil
	}
	if su.Integ == nil {
		return fmt.Errorf("ike: 非 combined 套件（算法 %d）缺少完整性算法——没有 ICV 的 SK 等于没有保护，绝不放行", su.Encr.ID())
	}
	if n := su.Integ.KeyLen(); len(integKey) != n {
		return fmt.Errorf("ike: SK 完整性密钥 %d 字节与算法 %d 要求的 %d 字节不符", len(integKey), su.Integ.ID(), n)
	}
	return nil
}

// appendPayloadChain 把一串载荷编成「通用头 + 体」的连续字节，并回填 Next Payload 链。
// 返回值第二项是链的**起点类型**（供 SK 通用头的 Next Payload 字段使用），空链为 NONE。
func appendPayloadChain(dst []byte, ps []Payload) ([]byte, PayloadType, error) {
	if len(ps) > MaxPayloads {
		return nil, PayloadNone, fmt.Errorf("ike: SK 内层载荷数 %d 超过上限 %d", len(ps), MaxPayloads)
	}
	offsets := make([]int, len(ps))
	for i, p := range ps {
		offsets[i] = len(dst)
		dst = append(dst, 0, 0, 0, 0) // 通用头占位
		before := len(dst)
		dst = p.appendBody(dst)
		plen := 4 + (len(dst) - before)
		if plen > 0xFFFF {
			return nil, PayloadNone, fmt.Errorf("ike: %s 载荷过长（%d 字节）", p.Type(), plen)
		}
		binary.BigEndian.PutUint16(dst[offsets[i]+2:offsets[i]+4], uint16(plen))
	}
	// 前向声明：载荷 i 的字段描述的是载荷 i+1 的类型，所以必须排完再回填。
	for i := range ps {
		var nt PayloadType
		if i+1 < len(ps) {
			nt = ps[i+1].Type()
		}
		dst[offsets[i]] = byte(nt)
	}
	if len(ps) == 0 {
		return dst, PayloadNone, nil
	}
	return dst, ps[0].Type(), nil
}

// parsePayloadChain 解析一段连续的载荷链（SK 解密后的明文）。
//
// 与 wire.Decode 的外层循环是同构逻辑，但**刻意分开写**：Decode 处理的是
// 「原始报文 + 报文头」，这里处理的是「解密后的明文 + 一个外部传入的起点类型」，
// 两者的越界基准、终止条件与错误措辞都不同，硬合并会让两边都变难读。
// 代价是这 20 行结构重复——防护上限与「plen<4 必拒」两条必须与 Decode 保持一致。
func parsePayloadChain(first PayloadType, b []byte) ([]Payload, error) {
	var out []Payload
	next := first
	off := 0
	for next != PayloadNone {
		if len(out) >= MaxPayloads {
			return nil, fmt.Errorf("ike: SK 内层载荷数超过上限 %d", MaxPayloads)
		}
		if off+4 > len(b) {
			return nil, fmt.Errorf("ike: SK 内层载荷头越界（off=%d，明文共 %d 字节）", off, len(b))
		}
		t := next
		next = PayloadType(b[off])
		critical := b[off+1]&0x80 != 0
		plen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		// plen<4 会让 off 原地踏步 → 死循环。SK 内层虽已通过完整性校验（对端是可信的），
		// 但「可信」不等于「无 bug」，这条与外层同样不能省。
		if plen < 4 {
			return nil, fmt.Errorf("ike: SK 内层 %s 载荷长度 %d 非法（须 ≥4）", t, plen)
		}
		if off+plen > len(b) {
			return nil, fmt.Errorf("ike: SK 内层 %s 载荷越界（off=%d 长度=%d，明文共 %d 字节）", t, off, plen, len(b))
		}
		if t == PayloadSK {
			return nil, errors.New("ike: SK 内层不允许再嵌套 SK 载荷")
		}
		p := newPayload(t)
		if rp, ok := p.(*RawPayload); ok {
			rp.Critical = critical
		}
		if err := p.parseBody(b[off+4 : off+plen]); err != nil {
			return nil, err
		}
		out = append(out, p)
		off += plen
	}
	// 链已终止却还有剩余字节：要么补齐长度算错，要么载荷长度串了位。
	// 不报的话，多出来的那段就成了「解出来但没人看的字节」，正是隐蔽注入的落脚点。
	if off != len(b) {
		return nil, fmt.Errorf("ike: SK 明文尾部有 %d 字节未被载荷链覆盖（补齐长度或载荷长度有误）", len(b)-off)
	}
	return out, nil
}
