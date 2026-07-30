package esp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"testing"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"

	"baidi.dev/gateway/internal/ipsec/ike"
)

// 本文件是整个 esp 包里**最有价值**的测试，理由只有一条：
//
//	往返测试（自己 Seal 自己 Open）对着一个 XOR 也能过。
//
// 它只能证明"两边做的是同一件事"，证明不了"这件事是 ESP"。而两端都是自家实现时，
// 任何口径错误（AAD 覆盖范围、nonce 拼法、补齐规则、ICV 覆盖范围）都会被两端
// 一致地犯下，测试全绿、与任何第三方实现都不通——而互通问题恰恰是最难查的一类。
//
// 因此这里用 crypto/aes + crypto/cipher（以及国密的 gmsm）**独立按 RFC 4106 / RFC 4303
// 重算一遍**，与 packet.go 的输出逐字节比对。这条测试红了，说明口径变了，
// 不要顺手改期望值——先确认改的是哪一条 RFC 规定。

// espExpectPlain 按 RFC 4303 §2 手工拼出待加密明文：内层包 ‖ 补齐(1,2,3…) ‖ PadLen ‖ NextHeader。
// align 由套件决定：CBC 16，GCM 4（4 字节边界要求对两者都成立，CBC 的 16 已经涵盖）。
func espExpectPlain(inner []byte, align int, nh uint8) []byte {
	padLen := (align - (len(inner)+2)%align) % align
	out := append([]byte(nil), inner...)
	for i := 1; i <= padLen; i++ {
		out = append(out, byte(i))
	}
	return append(out, byte(padLen), nh)
}

// espESPHeader SPI‖Seq，也正是 RFC 4106 §5 规定的 AAD（非 ESN 情形）。
func espESPHeader(spi uint32, seq uint64) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint32(h[0:4], spi)
	binary.BigEndian.PutUint32(h[4:8], uint32(seq))
	return h
}

// espGCMKAT 用独立实现按 RFC 4106 算出完整 ESP 报文。
func espGCMKAT(t *testing.T, newBlock func([]byte) (cipher.Block, error), key []byte, ckLen int, spi uint32, seq uint64, inner []byte) []byte {
	t.Helper()
	blk, err := newBlock(key[:ckLen])
	if err != nil {
		t.Fatalf("独立实现构造分组密码失败：%v", err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatalf("独立实现构造 GCM 失败：%v", err)
	}
	// nonce = salt(密钥材料末 4 字节，不上线) ‖ 显式 IV(8，= 序号)
	iv := make([]byte, 8)
	binary.BigEndian.PutUint64(iv, seq)
	nonce := append(append([]byte(nil), key[ckLen:ckLen+4]...), iv...)

	hdr := espESPHeader(spi, seq)
	ct := aead.Seal(nil, nonce, espExpectPlain(inner, espAlign, protoIPv4), hdr)

	out := append([]byte(nil), hdr...)
	out = append(out, iv...)
	return append(out, ct...)
}

// TestKATAESGCMMatchesRFC4106 AES-GCM ESP 报文与独立实现逐字节相等。
func TestKATAESGCMMatchesRFC4106(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bits   int
		keyLen int
	}{
		{"AES-128-GCM-16", 128, 20},
		{"AES-256-GCM-16", 256, 36},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := espKey(tc.keyLen, 0x5A)
			c, err := newCrypto(ike.EncrAESGCM16, tc.bits, ike.IntegNone, key, nil)
			if err != nil {
				t.Fatalf("构造失败：%v", err)
			}
			const spi = uint32(0x11223344)
			for _, seq := range []uint64{1, 2, 0xABCD, 0x7FFFFFFF} {
				for _, n := range []int{0, 1, 2, 3, 37} {
					inner := espIPv4("10.60.0.5", "10.70.0.9", bytes.Repeat([]byte{0x5C}, n))
					got, err := c.encap(spi, seq, inner, protoIPv4)
					if err != nil {
						t.Fatalf("封装失败：%v", err)
					}
					want := espGCMKAT(t, aes.NewCipher, key, tc.bits/8, spi, seq, inner)
					if !bytes.Equal(got, want) {
						t.Fatalf("seq=%d 载荷 %d 字节：与 RFC 4106 独立实现不符\n实产 %x\n期望 %x", seq, n, got, want)
					}
				}
			}
		})
	}
}

// TestKATSM4GCMMatchesRFC4106Layout 国密套件走的是同一套 RFC 4106 布局，只是把
// 分组密码换成 SM4。这条证明「国密 ESP」是真的在跑，而不是只在注册表里存在。
//
// ★仍然要重复诚实边界：SM4-GCM 用的是 IANA 私有使用段码点（1044），
// **只承诺白帝↔白帝互通，与 GM/T 0022 无关，绝不可对外称"国密 IPSec"**。
// 这条测试证明的是密码学运算正确，不是合规。
func TestKATSM4GCMMatchesRFC4106Layout(t *testing.T) {
	key := espKey(20, 0x5A) // 16 密钥 + 4 salt
	c, err := newCrypto(ike.EncrSM4GCM16, 128, ike.IntegNone, key, nil)
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	const spi = uint32(0x55667788)
	for _, seq := range []uint64{1, 4096} {
		inner := espIPv4("10.60.0.5", "10.70.0.9", []byte("国密载荷"))
		got, err := c.encap(spi, seq, inner, protoIPv4)
		if err != nil {
			t.Fatalf("封装失败：%v", err)
		}
		want := espGCMKAT(t, sm4.NewCipher, key, 16, spi, seq, inner)
		if !bytes.Equal(got, want) {
			t.Fatalf("seq=%d：SM4-GCM 与独立实现不符\n实产 %x\n期望 %x", seq, got, want)
		}
	}
}

// TestKATGCMAADIsHeaderOnly 钉死「AAD 只有 SPI‖Seq，不含 IV」这条口径。
//
// ★这是本包最容易被写错、且**自证测试完全测不出来**的一处：IKEv2 的 SK 载荷
// （RFC 5282）AAD 覆盖到 IV 末字节，ESP（RFC 4106）只覆盖 SPI‖Seq。
// 照抄 payload_sk.go 的话两端会犯同一个错，往返全绿，只有第三方对接时才炸。
// 这里显式构造"错误口径"的密文，断言它与我们产出的**不同**——
// 一旦有人把 AAD 改宽，两个断言里必有一个会红。
func TestKATGCMAADIsHeaderOnly(t *testing.T) {
	key := espKey(36, 0x5A)
	c, err := newCrypto(ike.EncrAESGCM16, 256, ike.IntegNone, key, nil)
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	const spi, seq = uint32(0x11223344), uint64(7)
	inner := espIPv4("10.60.0.5", "10.70.0.9", []byte("aad-scope"))
	got, err := c.encap(spi, seq, inner, protoIPv4)
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}

	blk, _ := aes.NewCipher(key[:32])
	aead, _ := cipher.NewGCM(blk)
	iv := make([]byte, 8)
	binary.BigEndian.PutUint64(iv, seq)
	nonce := append(append([]byte(nil), key[32:36]...), iv...)
	plain := espExpectPlain(inner, espAlign, protoIPv4)

	// 正确口径：AAD = SPI‖Seq。
	right := aead.Seal(nil, nonce, plain, espESPHeader(spi, seq))
	if !bytes.Equal(got[HeaderLen+8:], right) {
		t.Fatalf("密文与「AAD=SPI‖Seq」的独立计算不符——AAD 口径已偏离 RFC 4106 §5")
	}
	// 错误口径（照抄 IKEv2 SK）：AAD = SPI‖Seq‖IV。
	wrong := aead.Seal(nil, nonce, plain, append(espESPHeader(spi, seq), iv...))
	if bytes.Equal(got[HeaderLen+8:], wrong) {
		t.Fatal("密文等于「AAD 含 IV」的计算结果——这是 IKEv2 SK 的口径，用在 ESP 上与任何 RFC 实现都不通")
	}
}

// TestKATAESCBCIndependentlyVerified CBC 的 IV 是随机的，无法逐字节固定期望值，
// 因此改为**独立解密验证**：用 crypto/hmac + crypto/aes 自己把报文拆开，
// 逐项核对 ICV 覆盖范围、密文内容、补齐规则与 ESP 尾。
func TestKATAESCBCIndependentlyVerified(t *testing.T) {
	espCBCIndependentCheck(t, "AES-256-CBC + HMAC-SHA256-128",
		ike.EncrAESCBC, 256, ike.IntegHMACSHA256128, 32, aes.NewCipher, sha256.New)
}

// TestKATSM4CBCIndependentlyVerified 国密 CBC 路径同法核对。
func TestKATSM4CBCIndependentlyVerified(t *testing.T) {
	espCBCIndependentCheck(t, "SM4-CBC + HMAC-SM3-128",
		ike.EncrSM4CBC, 128, ike.IntegHMACSM3128, 16, sm4.NewCipher, sm3.New)
}

func espCBCIndependentCheck(t *testing.T, name string, encrID uint16, bits int, integID uint16, keyLen int,
	newBlock func([]byte) (cipher.Block, error), newHash func() hash.Hash) {
	t.Helper()
	encKey, integKey := espKey(keyLen, 0x5A), espKey(32, 0x3C)
	c, err := newCrypto(encrID, bits, integID, encKey, integKey)
	if err != nil {
		t.Fatalf("%s 构造失败：%v", name, err)
	}
	const spi, seq = uint32(0x11223344), uint64(0x2A)
	inner := espIPv4("10.60.0.5", "10.70.0.9", []byte("cbc-kat-payload"))
	pkt, err := c.encap(spi, seq, inner, protoIPv4)
	if err != nil {
		t.Fatalf("%s 封装失败：%v", name, err)
	}

	// ①头部字段。
	if !bytes.Equal(pkt[:HeaderLen], espESPHeader(spi, seq)) {
		t.Fatalf("%s：ESP 头不是 SPI‖Seq", name)
	}
	// ②ICV 必须覆盖「除 ICV 自身外的全部」（RFC 4303 §2.8），截断到 16 字节。
	mac := hmac.New(newHash, integKey)
	mac.Write(pkt[:len(pkt)-16])
	if want := mac.Sum(nil)[:16]; !bytes.Equal(want, pkt[len(pkt)-16:]) {
		t.Fatalf("%s：ICV 与独立计算不符——ICV 覆盖范围写错了（必须含 SPI/Seq/IV/密文）\n实产 %x\n期望 %x",
			name, pkt[len(pkt)-16:], want)
	}
	// ③独立解密并核对明文结构。
	blk, err := newBlock(encKey)
	if err != nil {
		t.Fatalf("%s：独立实现构造分组密码失败：%v", name, err)
	}
	iv := pkt[HeaderLen : HeaderLen+16]
	ct := pkt[HeaderLen+16 : len(pkt)-16]
	if len(ct)%16 != 0 {
		t.Fatalf("%s：密文 %d 字节不是 16 的整数倍", name, len(ct))
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plain, ct)
	if want := espExpectPlain(inner, 16, protoIPv4); !bytes.Equal(plain, want) {
		t.Fatalf("%s：解出的明文与 RFC 4303 §2.4 规定的结构不符\n实产 %x\n期望 %x", name, plain, want)
	}
}
