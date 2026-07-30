package ike

import (
	"encoding/binary"
	"fmt"
)

// 本文件实现 SA 载荷的三层嵌套编解码：SA → Proposal(1..n) → Transform(1..n) → Attribute(0..n)。
//
// ★整个 IKEv2 报文层最密集的错误来源就在这三层的两个「Last Substruc」字段上：
// **Proposal 用 2 表示后面还有，Transform 用 3**（不是 2）。写反的后果不是解析失败，
// 而是对端把第二个 Transform 当成一条新 Proposal 去解，得到一堆语义荒唐但长度自洽的
// 结构，最终回一句 NO_PROPOSAL_CHOSEN——从报错里完全看不出根因在编码上。
// 因此 parse 侧对这两个取值做**白名单校验**并在错误信息里点名「提案用 2、变换用 3」。
//
// 关于 SelectProposal（提案选择）：按 PLAN §1.5 它的签名依赖 SuiteSpec，
// 而 SuiteSpec 由 WP-B 定义在 suite.go。本文件**只负责编解码**，选择逻辑连同
// SuiteSpec 一起留在 suite.go——把「哪些算法组合可接受」的判断放进报文层会让
// 报文层反过来依赖套件层，破坏单向依赖。本文件提供 FindTransform/TransformsOfType
// 两个查询原语供选择逻辑复用。

// Proposal / Transform 子结构的固定头长度。
const (
	proposalHdrLen  = 8 // Last(1) RESERVED(1) Length(2) Num(1) Protocol(1) SPISize(1) NumTransforms(1)
	transformHdrLen = 8 // Last(1) RESERVED(1) Length(2) Type(1) RESERVED(1) ID(2)
)

// Last Substruc 取值。**两个子结构用的值不同**，见文件头说明。
const (
	lastSubstrucEnd            uint8 = 0 // 本子结构是最后一个
	lastSubstrucMoreProposals  uint8 = 2 // 后面还有 Proposal
	lastSubstrucMoreTransforms uint8 = 3 // 后面还有 Transform
)

// Type 实现 Payload 接口。
func (p *SAPayload) Type() PayloadType { return PayloadSA }

func (p *SAPayload) appendBody(dst []byte) []byte {
	for i := range p.Proposals {
		last := lastSubstrucEnd
		if i+1 < len(p.Proposals) {
			last = lastSubstrucMoreProposals
		}
		dst = p.Proposals[i].appendTo(dst, last)
	}
	return dst
}

// appendTo 序列化一条提案。last 是本提案的 Last Substruc 取值。
//
// ★这里的 panic 只可能由**本进程构造错误**触发（SPI 或变换数超过一个字节能表达的范围），
// 对端输入永远走不到编码路径。选择 panic 而不是静默截断：截断会产出一条长度自洽、
// 语义却完全不同的提案，对端照单全收后在 AUTH 阶段才炸，症状退化成一句「认证失败」。
func (pr Proposal) appendTo(dst []byte, last uint8) []byte {
	if len(pr.SPI) > 255 {
		panic(fmt.Sprintf("ike: 提案 SPI 长度 %d 超过单字节 SPI Size 字段的表达范围", len(pr.SPI)))
	}
	if len(pr.Transforms) > 255 {
		panic(fmt.Sprintf("ike: 提案变换数 %d 超过单字节 Num Transforms 字段的表达范围", len(pr.Transforms)))
	}
	off := len(dst)
	dst = append(dst, last, 0, 0, 0) // Last Substruc / RESERVED / Length 占位
	dst = append(dst, pr.Num, byte(pr.Protocol), byte(len(pr.SPI)), byte(len(pr.Transforms)))
	dst = append(dst, pr.SPI...)
	for i := range pr.Transforms {
		l := lastSubstrucEnd
		if i+1 < len(pr.Transforms) {
			l = lastSubstrucMoreTransforms
		}
		dst = pr.Transforms[i].appendTo(dst, l)
	}
	binary.BigEndian.PutUint16(dst[off+2:off+4], uint16(len(dst)-off))
	return dst
}

// appendTo 序列化一个变换（含 Key Length 属性）。
func (t Transform) appendTo(dst []byte, last uint8) []byte {
	off := len(dst)
	dst = append(dst, last, 0, 0, 0) // Last Substruc / RESERVED / Length 占位
	dst = append(dst, byte(t.Type), 0)
	dst = binary.BigEndian.AppendUint16(dst, t.ID)
	// Key Length 属性用 TV 格式（AF 位=1，属性类型 14），值为**密钥位数**：
	//	80 0E 01 00  →  256 位
	// ★AES/SM4 必须带它。漏发不会协商失败，而是双方各按不同长度切密钥，
	// 症状是协商「成功」后一句无头无尾的「认证失败」。
	if t.KeyLen != 0 {
		dst = binary.BigEndian.AppendUint16(dst, 0x8000|AttrKeyLength)
		dst = binary.BigEndian.AppendUint16(dst, t.KeyLen)
	}
	binary.BigEndian.PutUint16(dst[off+2:off+4], uint16(len(dst)-off))
	return dst
}

func (p *SAPayload) parseBody(b []byte) error {
	p.Proposals = nil
	if len(b) == 0 {
		return payloadErr(PayloadSA, "体为空（至少需要一个提案）")
	}
	off := 0
	for {
		if len(p.Proposals) >= MaxProposals {
			return payloadErr(PayloadSA, fmt.Sprintf("提案数超过上限 %d", MaxProposals))
		}
		if off+proposalHdrLen > len(b) {
			return payloadErr(PayloadSA, fmt.Sprintf("提案头越界（off=%d，剩余 %d 字节，需 %d）", off, len(b)-off, proposalHdrLen))
		}
		last := b[off]
		plen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		// plen < proposalHdrLen 时 off 不前进（甚至倒退），一个几字节的畸形包
		// 就能让解析器空转——SA 载荷出现在未认证的 IKE_SA_INIT 里，必须挡住。
		if plen < proposalHdrLen {
			return payloadErr(PayloadSA, fmt.Sprintf("提案长度 %d 非法（须 ≥%d）", plen, proposalHdrLen))
		}
		if off+plen > len(b) {
			return payloadErr(PayloadSA, fmt.Sprintf("提案越界（off=%d 长度=%d，体总长=%d）", off, plen, len(b)))
		}

		var pr Proposal
		pr.Num = b[off+4]
		pr.Protocol = ProtocolID(b[off+5])
		spiSize := int(b[off+6])
		nxform := int(b[off+7])
		// SPI 长度白名单：IKE_SA_INIT 的 IKE 提案为 0、CREATE_CHILD_SA 重协商 IKE 为 8、
		// ESP 提案为 4。其余取值要么是畸形包，要么是我们不支持的协议（AH 也用 4）。
		switch spiSize {
		case 0, 4, 8:
		default:
			return payloadErr(PayloadSA, fmt.Sprintf("提案 SPI 长度 %d 非法（IKE_SA_INIT 用 0、重协商 IKE 用 8、ESP 用 4）", spiSize))
		}
		if proposalHdrLen+spiSize > plen {
			return payloadErr(PayloadSA, fmt.Sprintf("提案 SPI（%d 字节）超出提案长度 %d", spiSize, plen))
		}
		pr.SPI = append([]byte(nil), b[off+proposalHdrLen:off+proposalHdrLen+spiSize]...)
		if err := pr.parseTransforms(b[off+proposalHdrLen+spiSize:off+plen], nxform); err != nil {
			return err
		}
		p.Proposals = append(p.Proposals, pr)
		off += plen

		switch last {
		case lastSubstrucEnd:
			if off != len(b) {
				return payloadErr(PayloadSA, fmt.Sprintf("末条提案之后仍有 %d 字节多余数据", len(b)-off))
			}
			return nil
		case lastSubstrucMoreProposals:
			if off == len(b) {
				return payloadErr(PayloadSA, "提案声称后续仍有提案，但载荷体已到末尾")
			}
		default:
			return payloadErr(PayloadSA, fmt.Sprintf("提案的 Last Substruc=%d 非法（须为 0 或 2；提案用 2、变换用 3，写反是经典错误）", last))
		}
	}
}

// parseTransforms 解析一条提案内的变换链。want 是提案头里声明的 Num Transforms。
func (pr *Proposal) parseTransforms(b []byte, want int) error {
	if want == 0 {
		// 零变换的提案没有任何语义，却能让「选提案」逻辑误判为「所有必需类型都缺失」
		// 之外的奇怪状态。直接在解析层拒掉。
		return payloadErr(PayloadSA, fmt.Sprintf("提案 #%d 声称含 0 个变换", pr.Num))
	}
	if want > MaxTransformsPerPro {
		return payloadErr(PayloadSA, fmt.Sprintf("提案 #%d 声称含 %d 个变换，超过上限 %d", pr.Num, want, MaxTransformsPerPro))
	}
	if len(b) == 0 {
		return payloadErr(PayloadSA, fmt.Sprintf("提案 #%d 声称含 %d 个变换，实际没有变换数据", pr.Num, want))
	}
	off := 0
	for {
		if len(pr.Transforms) >= MaxTransformsPerPro {
			return payloadErr(PayloadSA, fmt.Sprintf("提案 #%d 的变换数超过上限 %d", pr.Num, MaxTransformsPerPro))
		}
		if off+transformHdrLen > len(b) {
			return payloadErr(PayloadSA, fmt.Sprintf("变换头越界（off=%d，剩余 %d 字节，需 %d）", off, len(b)-off, transformHdrLen))
		}
		last := b[off]
		tlen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if tlen < transformHdrLen {
			return payloadErr(PayloadSA, fmt.Sprintf("变换长度 %d 非法（须 ≥%d）", tlen, transformHdrLen))
		}
		if off+tlen > len(b) {
			return payloadErr(PayloadSA, fmt.Sprintf("变换越界（off=%d 长度=%d，变换区总长=%d）", off, tlen, len(b)))
		}
		t := Transform{
			Type: TransformType(b[off+4]),
			ID:   binary.BigEndian.Uint16(b[off+6 : off+8]),
		}
		if err := t.parseAttrs(b[off+transformHdrLen : off+tlen]); err != nil {
			return err
		}
		pr.Transforms = append(pr.Transforms, t)
		off += tlen

		if last == lastSubstrucEnd {
			if off != len(b) {
				return payloadErr(PayloadSA, fmt.Sprintf("末条变换之后仍有 %d 字节多余数据", len(b)-off))
			}
			break
		}
		if last != lastSubstrucMoreTransforms {
			return payloadErr(PayloadSA, fmt.Sprintf("变换的 Last Substruc=%d 非法（须为 0 或 3；提案用 2、变换用 3，写反是经典错误）", last))
		}
		if off == len(b) {
			return payloadErr(PayloadSA, "变换声称后续仍有变换，但变换区已到末尾")
		}
	}
	if len(pr.Transforms) != want {
		// 声明与实际不符说明对端编码有 bug 或是刻意构造。放行会让「选提案」在一个
		// 与对端理解不同的集合上做判断，谈成的套件双方各执一词。
		return payloadErr(PayloadSA, fmt.Sprintf("提案 #%d 的 Num Transforms 声称 %d，实际解析出 %d", pr.Num, want, len(pr.Transforms)))
	}
	return nil
}

// parseAttrs 解析一个变换的属性区。本轮只关心 Key Length；其余属性**跳过而不报错**
// （互通要求：不认识的可选属性不该导致建连失败）。
func (t *Transform) parseAttrs(b []byte) error {
	off, n := 0, 0
	for off < len(b) {
		n++
		if n > MaxAttributesPerXform {
			return payloadErr(PayloadSA, fmt.Sprintf("单个变换的属性数超过上限 %d", MaxAttributesPerXform))
		}
		if off+4 > len(b) {
			return payloadErr(PayloadSA, fmt.Sprintf("变换属性头越界（off=%d，剩余 %d 字节，需 4）", off, len(b)-off))
		}
		hdr := binary.BigEndian.Uint16(b[off : off+2])
		isTV := hdr&0x8000 != 0 // AF 位：1=TV（值就在后 2 字节），0=TLV（后 2 字节是长度）
		atype := hdr & 0x7FFF
		if isTV {
			if atype == AttrKeyLength {
				t.KeyLen = binary.BigEndian.Uint16(b[off+2 : off+4])
			}
			off += 4
			continue
		}
		alen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if off+4+alen > len(b) {
			return payloadErr(PayloadSA, fmt.Sprintf("TLV 属性越界（off=%d 值长=%d，属性区总长=%d）", off, alen, len(b)))
		}
		if atype == AttrKeyLength {
			// RFC 7296 §3.3.5 规定 Key Length 恒为 TV。收到 TLV 形式说明对端编码有误，
			// 静默忽略会退化成「没带 Key Length」，最终又落回那句「认证失败」。
			return payloadErr(PayloadSA, "Key Length 属性必须使用 TV 格式（AF=1），收到的是 TLV")
		}
		off += 4 + alen
	}
	return nil
}

// FindTransform 取该提案中第一个指定类型的变换。
func (pr Proposal) FindTransform(t TransformType) (Transform, bool) {
	for _, x := range pr.Transforms {
		if x.Type == t {
			return x, true
		}
	}
	return Transform{}, false
}

// TransformsOfType 取该提案中全部指定类型的变换。
// 对端在同一 Type 下可以并列多个候选（如同时提 AES-GCM 与 AES-CBC），选提案时要遍历。
func (pr Proposal) TransformsOfType(t TransformType) []Transform {
	var out []Transform
	for _, x := range pr.Transforms {
		if x.Type == t {
			out = append(out, x)
		}
	}
	return out
}

// String 便于把「对端到底提了什么」原样打进日志。
//
// ★NO_PROPOSAL_CHOSEN 只回一个码点等于什么都没说。排障时必须能同时看到
// 「对端提了什么」与「本端要什么」，否则两边各改各的配置能耗掉一整天。
func (pr Proposal) String() string {
	s := fmt.Sprintf("#%d %s", pr.Num, protocolName(pr.Protocol))
	if len(pr.SPI) > 0 {
		s += fmt.Sprintf(" SPI=%x", pr.SPI)
	}
	s += " ["
	for i, t := range pr.Transforms {
		if i > 0 {
			s += " "
		}
		s += t.String()
	}
	return s + "]"
}

func (t Transform) String() string {
	if t.KeyLen != 0 {
		return fmt.Sprintf("%s=%d/%d", t.Type, t.ID, t.KeyLen)
	}
	return fmt.Sprintf("%s=%d", t.Type, t.ID)
}

// protocolName 故意是包内小写函数而不是 ProtocolID.String()：
// 常量层（const.go）归骨架所有，报文层不去给它加方法，避免与其它工作包撞名。
func protocolName(p ProtocolID) string {
	switch p {
	case ProtocolIKE:
		return "IKE"
	case ProtocolAH:
		return "AH"
	case ProtocolESP:
		return "ESP"
	case ProtocolNone:
		return "NONE"
	}
	return fmt.Sprintf("PROTO(%d)", uint8(p))
}
