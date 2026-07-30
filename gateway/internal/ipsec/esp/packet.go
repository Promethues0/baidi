package esp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/ike"
)

// ESP 报文的固定尺寸常量。导出是因为上层要拿它算隧道 MTU（见 Overhead）。
const (
	// HeaderLen ESP 头：SPI(4) + Sequence Number(4)。
	HeaderLen = 8
	// TrailerLen ESP 尾：Pad Length(1) + Next Header(1)。**永远存在**，即使补齐长度为 0。
	TrailerLen = 2
	// espAlign RFC 4303 §2.4 硬性要求：密文（含 ESP 尾）必须终结在 4 字节边界上，
	// 即 Pad Length / Next Header 两个字节右对齐于一个 4 字节字。
	//
	// ★这条与 IKEv2 的 SK 载荷不同——SK 只需按分组长补齐。照抄 payload_sk.go 的补齐逻辑
	// 会让 GCM（分组长 1）产出长度不是 4 倍数的 ESP 报文：白帝↔白帝依旧全绿（两端都不校验），
	// 与任何遵循 RFC 的实现对接时才会被拒，且对方只会回一句「invalid packet」。
	espAlign = 4
)

// 隧道模式下 Next Header 的合法取值：被封装的是一个完整的 IP 包。
const (
	protoIPv4 uint8 = 4
	protoIPv6 uint8 = 41
	// protoNoNextHeader 59 是 RFC 4303 的哑包/TFC 填充包标记。本实现不发也不收，
	// 单独列出来只是为了让收到它时能给出一句有指向性的错误。
	protoNoNextHeader uint8 = 59
)

// espCrypto 一条 SA **单个方向**上的加解密上下文。
//
// 出向与入向各持一份：两个方向的密钥不同（KEYMAT 按 encr_i‖integ_i‖encr_r‖integ_r 切开），
// 把它们塞进同一个结构再靠布尔量切换，是「方向写反」这类 bug 最好的温床，
// 而方向写反的症状恰恰是「解密恒失败」，与密钥错、salt 算漏完全无法区分。
type espCrypto struct {
	encr     ike.EncrAlg
	integ    ike.IntegAlg // combined（GCM）套件下恒为 nil
	encKey   []byte
	integKey []byte
}

// newCrypto 由协商结果的 Transform ID 构造一个方向的加解密上下文。
//
// 算法一律走 ike.LookupEncr/LookupInteg 取——国密（SM4-GCM / SM4-CBC / HMAC-SM3）
// 因此对 ESP 是免费的：注册表里已经有了，本包一行都不用为它写。
func newCrypto(encrID uint16, keyBits int, integID uint16, encKey, integKey []byte) (*espCrypto, error) {
	encr, err := ike.LookupEncr(encrID, keyBits)
	if err != nil {
		return nil, fmt.Errorf("esp: 装载加密算法失败: %w", err)
	}
	integ, err := ike.LookupInteg(integID)
	if err != nil {
		return nil, fmt.Errorf("esp: 装载完整性算法失败: %w", err)
	}
	c := &espCrypto{
		encr:  encr,
		integ: integ,
		// 拷贝一份：调用方的 ChildSAParams 可能被复用或回收，
		// 密钥被别人改掉的症状同样是「某一刻起解密全失败」。
		encKey:   append([]byte(nil), encKey...),
		integKey: append([]byte(nil), integKey...),
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return c, nil
}

// check 在动用密钥之前把长度与套件形态校验干净。
//
// ★错误信息必须同时给出实际值与期望值。密钥长度不符最常见的成因是 GCM 的 4 字节 salt
// 被算漏（36 写成 32），只报一句「长度不符」没人看得出差的正是那 4 个字节。
func (c *espCrypto) check() error {
	if n := c.encr.KeyLen(); len(c.encKey) != n {
		return fmt.Errorf("esp: 加密密钥 %d 字节与算法 %d 要求的 %d 字节不符"+
			"（GCM 类算法的密钥**末尾 4 字节是 salt**，长度已含在内；KEYMAT 每方向应切 %d 字节）",
			len(c.encKey), c.encr.ID(), n, n)
	}
	if c.encr.Combined() {
		// RFC 4106：combined 模式必须协商 INTEG=NONE。这里还挂着 Integ 说明提案构造有误。
		// 放行的后果很隐蔽：ICV 长度按 GCM tag 算，完整性却被当成由 HMAC 承担，
		// 两边各做一半，最终表现成「偶发解密失败」。
		if c.integ != nil {
			return fmt.Errorf("esp: combined 套件（加密算法 %d）必须搭配 INTEG=NONE，实际挂着完整性算法 %d", c.encr.ID(), c.integ.ID())
		}
		if len(c.integKey) != 0 {
			return fmt.Errorf("esp: combined 套件（加密算法 %d）不派生完整性密钥，却收到 %d 字节"+
				"（多半是 KEYMAT 按 CBC 的 128 字节切了，而 GCM 只有 72 字节）", c.encr.ID(), len(c.integKey))
		}
		return nil
	}
	if c.integ == nil {
		return fmt.Errorf("esp: 非 combined 套件（加密算法 %d）缺少完整性算法——"+
			"没有 ICV 的 ESP 等于把内网写权限交给任何能改包的人，绝不放行", c.encr.ID())
	}
	if n := c.integ.KeyLen(); len(c.integKey) != n {
		return fmt.Errorf("esp: 完整性密钥 %d 字节与算法 %d 要求的 %d 字节不符", len(c.integKey), c.integ.ID(), n)
	}
	return nil
}

// ivLen 线上 IV 字段长度（GCM 8 / CBC 16）。
func (c *espCrypto) ivLen() int { return c.encr.IVLen() }

// icvLen 报文尾部校验数据长度。combined 模式由 GCM tag 承担，否则由 HMAC 承担。
func (c *espCrypto) icvLen() int {
	if c.encr.Combined() {
		return c.encr.ICVLen()
	}
	return c.integ.ICVLen()
}

// minPlainLen 密文段的最小合法长度：至少要放得下 ESP 尾，且 CBC 还得是整分组。
func (c *espCrypto) minPlainLen() int {
	if bs := c.encr.BlockSize(); bs > TrailerLen {
		return bs
	}
	return TrailerLen
}

// padLenFor 计算内层包需要补多少字节。
//
// 两条约束同时成立：①密文长度是分组长的整数倍（CBC 才有意义，GCM 分组长为 1）；
// ②密文（含 2 字节 ESP 尾）终结在 4 字节边界上（RFC 4303 §2.4，两种套件都要）。
// 取二者的最小公倍数太重，直接取 max 即可——分组长要么是 1，要么是 16，都与 4 相容。
func (c *espCrypto) padLenFor(innerLen int) int {
	align := c.encr.BlockSize()
	if align < espAlign {
		align = espAlign
	}
	return (align - (innerLen+TrailerLen)%align) % align
}

// encap 把一个内层 IP 包封装成完整的 ESP 报文。
//
// seq 由调用方（sa.nextSeq）保证在本方向上严格单调递增且不回绕。
// ★GCM 的显式 IV 直接取 seq：这让「nonce 复用」在结构上不可能发生——只要序号不重复，
// nonce 就不重复。反过来，若这里改用随机 8 字节，同一条 SA 上跑久了会碰撞，
// 而 GCM 的 nonce 复用是**灾难性**的（可同时恢复明文与认证密钥）且**不会有任何报错**。
// 序号用尽时的正确动作是拒发并 rekey，绝不是回绕（见 sa.nextSeq）。
func (c *espCrypto) encap(spi uint32, seq uint64, inner []byte, nextHeader uint8) ([]byte, error) {
	if len(inner) == 0 {
		return nil, fmt.Errorf("esp: 内层包为空，无可封装")
	}
	if seq == 0 || seq > MaxSeq {
		return nil, fmt.Errorf("esp: 序号 %d 越界（合法区间 1..%d）", seq, MaxSeq)
	}

	ivLen, icvLen := c.ivLen(), c.icvLen()
	padLen := c.padLenFor(len(inner))

	// 明文恒为 `内层整包 ‖ Padding[padLen] ‖ PadLen(1) ‖ NextHeader(1)`。
	// 补齐内容按 RFC 4303 §2.4 的默认规则填 1,2,3,…（收方 MAY 校验；本实现不校验，
	// 理由见 decap——校验它会与用随机/全零补齐的实现互不相通，收益却接近于零）。
	plain := make([]byte, 0, len(inner)+padLen+TrailerLen)
	plain = append(plain, inner...)
	for i := 1; i <= padLen; i++ {
		plain = append(plain, byte(i))
	}
	plain = append(plain, byte(padLen), nextHeader)

	total := HeaderLen + ivLen + len(plain) + icvLen
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint32(out, spi)
	out = binary.BigEndian.AppendUint32(out, uint32(seq))

	iv := make([]byte, ivLen)
	if c.encr.Combined() {
		if ivLen != 8 {
			return nil, fmt.Errorf("esp: combined 套件（算法 %d）的显式 nonce 应为 8 字节，实际 %d", c.encr.ID(), ivLen)
		}
		binary.BigEndian.PutUint64(iv, seq)
	} else {
		// ★CBC 的 IV 必须**不可预测**，不能用计数器：可预测 IV 会让 CBC 退化到可被
		// 选择明文区分（BEAST 那一类）。这也意味着 CBC 的 encap 是非确定性的，
		// 因此 kat_test.go 对 CBC 只能做「独立解密验证」而不是逐字节比对。
		copy(iv, ike.RandBytes(ivLen))
	}
	out = append(out, iv...)

	if c.encr.Combined() {
		// ★AAD 只有 SPI‖Seq（RFC 4106 §5），**不含 IV**——这与 IKEv2 SK 载荷
		// （RFC 5282，AAD 覆盖到 IV 末字节）刚好差一段。切片用三索引形式截死容量，
		// 万一后来有人往 aad 上 append，会立刻分配新数组而不是悄悄改写 out。
		aad := out[:HeaderLen:HeaderLen]
		ct, err := c.encr.Seal(c.encKey, iv, aad, plain)
		if err != nil {
			return nil, fmt.Errorf("esp: 封装加密失败: %w", err)
		}
		out = append(out, ct...)
	} else {
		ct, err := c.encr.Seal(c.encKey, iv, nil, plain)
		if err != nil {
			return nil, fmt.Errorf("esp: 封装加密失败: %w", err)
		}
		out = append(out, ct...)
		// ICV 覆盖 `SPI ‖ Seq ‖ IV ‖ 密文`，即除 ICV 自身之外的全部（RFC 4303 §2.8）。
		// 漏掉 SPI/Seq 的后果不是解不开，而是攻击者可以随意改写序号来打反重放窗口。
		out = append(out, c.integ.Sum(c.integKey, out)...)
	}

	// 长度自检：算错一个字节，本端毫无察觉，对端只会报「解密失败」。
	// 与其把错误留给对端，不如在这里当场炸掉。
	if len(out) != total {
		return nil, fmt.Errorf("esp: 报文长度自检失败（预算 %d 字节，实产 %d 字节）", total, len(out))
	}
	return out, nil
}

// decap 校验并解开一个 ESP 报文，返回内层 IP 包与 Next Header。
//
// 认证失败一律返回包装了 ipsec.ErrAuth 的错误；结构性畸形返回普通错误。
// 调用方据此分别计数——把两者混成一个计数器，就分不清「对端密钥不对」
// 和「链路上有人在乱塞字节」，而这两者的处置完全不同。
func (c *espCrypto) decap(pkt []byte) (inner []byte, nextHeader uint8, err error) {
	ivLen, icvLen := c.ivLen(), c.icvLen()
	minLen := HeaderLen + ivLen + icvLen + c.minPlainLen()
	if len(pkt) < minLen {
		return nil, 0, fmt.Errorf("esp: 报文 %d 字节，装不下 头(%d)+IV(%d)+ICV(%d)+至少 %d 字节密文（共需 %d）",
			len(pkt), HeaderLen, ivLen, icvLen, c.minPlainLen(), minLen)
	}
	iv := pkt[HeaderLen : HeaderLen+ivLen]

	var plain []byte
	if c.encr.Combined() {
		aad := pkt[:HeaderLen:HeaderLen]
		p, e := c.encr.Open(c.encKey, iv, aad, pkt[HeaderLen+ivLen:])
		if e != nil {
			// 这一句要能同时指向三个根因，否则排障时所有人都只会盯着密钥看。
			return nil, 0, fmt.Errorf("esp: 认证解密失败（密钥/salt 不匹配、报文被改动、或 SPI/序号被中间设备重写——AAD 覆盖这 8 个字节）: %w", ipsec.ErrAuth)
		}
		plain = p
	} else {
		// ★先验 ICV 再解密，顺序绝不能反。
		// 反过来（先解密再验完整性）等于把「CBC 补齐是否合法」暴露给攻击者，
		// 即经典的 padding oracle：攻击者能在不知道密钥的情况下逐字节解出明文。
		want := c.integ.Sum(c.integKey, pkt[:len(pkt)-icvLen])
		got := pkt[len(pkt)-icvLen:]
		if !hmac.Equal(want, got) {
			return nil, 0, fmt.Errorf("esp: 完整性校验失败（ICV 不匹配：完整性密钥不对，或报文含 SPI/序号在内的任一字节被改动）: %w", ipsec.ErrAuth)
		}
		ct := pkt[HeaderLen+ivLen : len(pkt)-icvLen]
		if bs := c.encr.BlockSize(); len(ct) == 0 || len(ct)%bs != 0 {
			return nil, 0, fmt.Errorf("esp: 密文 %d 字节，不是分组长 %d 的整数倍", len(ct), bs)
		}
		p, e := c.encr.Open(c.encKey, iv, nil, ct)
		if e != nil {
			return nil, 0, fmt.Errorf("esp: 解密失败: %w", e)
		}
		plain = p
	}

	if len(plain) < TrailerLen {
		return nil, 0, fmt.Errorf("esp: 明文 %d 字节，不足 %d 字节 ESP 尾（PadLen+NextHeader）", len(plain), TrailerLen)
	}
	padLen := int(plain[len(plain)-2])
	nextHeader = plain[len(plain)-1]
	if TrailerLen+padLen > len(plain) {
		return nil, 0, fmt.Errorf("esp: 补齐长度 %d + ESP 尾 %d 超出明文 %d 字节", padLen, TrailerLen, len(plain))
	}
	// 补齐**内容**刻意不校验：RFC 4303 只说收方 MAY 检查，而各家实现填的东西
	// 五花八门（1,2,3… / 全零 / 随机）。校验它换不来任何安全性——这段字节已经在
	// ICV 覆盖范围内了——却会凭空制造一类只在特定对端出现的「解密成功但被丢弃」。
	inner = plain[:len(plain)-TrailerLen-padLen]
	if len(inner) == 0 {
		if nextHeader == protoNoNextHeader {
			return nil, 0, fmt.Errorf("esp: 收到 NextHeader=59 的哑包/TFC 填充包，本实现不支持（也从不发送）")
		}
		return nil, 0, fmt.Errorf("esp: 解出的内层包为空（补齐长度 %d 吃掉了全部明文）", padLen)
	}
	return inner, nextHeader, nil
}

// parseHeader 在查 SA **之前**从 ESP 报文头取出 SPI 与序号。
//
// 这一步先于任何密码学运算，因此必须假定输入完全不可信：只做长度与保留值检查，
// 不做任何按长度字段分配内存的动作。
func parseHeader(pkt []byte) (spi uint32, seq uint64, err error) {
	if len(pkt) < HeaderLen {
		return 0, 0, fmt.Errorf("esp: 报文仅 %d 字节，不足 %d 字节 ESP 头", len(pkt), HeaderLen)
	}
	spi = binary.BigEndian.Uint32(pkt[:4])
	seq = uint64(binary.BigEndian.Uint32(pkt[4:8]))
	if spi < SPIMin {
		// SPI 0 在 UDP 4500 上就是 non-ESP marker 的前 4 字节，1..255 是 RFC 4303 保留值。
		// 走到这里说明分流逻辑漏了或对端实现有问题，两种都值得说清楚。
		return 0, 0, fmt.Errorf("esp: SPI 0x%08x 落在保留区间（0 与 1..255 保留；0 还与 UDP-4500 的 non-ESP marker 撞形）", spi)
	}
	return spi, seq, nil
}

// Overhead 返回一条 SA 的**最坏情况**封装开销（字节），供上层反推隧道 MTU。
//
// 最坏情况 = 头(8) + IV + 最大补齐(对齐-1) + ESP 尾(2) + ICV。
// ★算 MTU 时必须用最坏值：按平均值算出来的 MTU 会让「大部分包能过、偶尔一个大包被丢」，
// 症状是「ping 通、HTTP 卡住」，是 IPSec 组网里最难查的一类故障。
// 注意这里**不含**外层 IP(20) + UDP(8) 头，那两层由封装它的一方计算。
func Overhead(encrID uint16, keyBits int, integID uint16) (int, error) {
	encr, err := ike.LookupEncr(encrID, keyBits)
	if err != nil {
		return 0, fmt.Errorf("esp: 计算封装开销失败: %w", err)
	}
	integ, err := ike.LookupInteg(integID)
	if err != nil {
		return 0, fmt.Errorf("esp: 计算封装开销失败: %w", err)
	}
	icv := 0
	if encr.Combined() {
		icv = encr.ICVLen()
	} else if integ != nil {
		icv = integ.ICVLen()
	}
	align := encr.BlockSize()
	if align < espAlign {
		align = espAlign
	}
	return HeaderLen + encr.IVLen() + (align - 1) + TrailerLen + icv, nil
}
