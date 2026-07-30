package esp

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/ike"
)

// espCryptoPair 造一对同密钥的 espCrypto（自己封给自己解），用于报文层单测。
func espCryptoPair(t *testing.T, s espSuite) *espCrypto {
	t.Helper()
	c, err := newCrypto(s.encrID, s.keyBits, s.integID, espKey(s.keyLen, 0x5A), espKey(s.integLen, 0x3C))
	if err != nil {
		t.Fatalf("套件 %s 构造失败：%v", s.name, err)
	}
	if c.ivLen() != s.ivLen {
		t.Fatalf("套件 %s 的 IV 长度 %d，期望 %d", s.name, c.ivLen(), s.ivLen)
	}
	if c.icvLen() != s.icvLen {
		t.Fatalf("套件 %s 的 ICV 长度 %d，期望 %d", s.name, c.icvLen(), s.icvLen)
	}
	return c
}

// TestEncapDecapRoundTrip 封装→解封往返，五套件全跑。
func TestEncapDecapRoundTrip(t *testing.T) {
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			c := espCryptoPair(t, s)
			for _, n := range []int{0, 1, 2, 3, 15, 16, 17, 100, 1380} {
				inner := espIPv4("10.60.0.5", "10.70.0.9", bytes.Repeat([]byte{0xAB}, n))
				pkt, err := c.encap(0x11223344, 42, inner, protoIPv4)
				if err != nil {
					t.Fatalf("载荷 %d 字节封装失败：%v", n, err)
				}
				got, nh, err := c.decap(pkt)
				if err != nil {
					t.Fatalf("载荷 %d 字节解封失败：%v", n, err)
				}
				if nh != protoIPv4 {
					t.Fatalf("载荷 %d 字节：NextHeader=%d，期望 %d", n, nh, protoIPv4)
				}
				if !bytes.Equal(got, inner) {
					t.Fatalf("载荷 %d 字节：往返后内容不一致\n收到 %x\n期望 %x", n, got, inner)
				}
			}
		})
	}
}

// TestEncapAlignment 密文必须终结在 4 字节边界上（RFC 4303 §2.4），CBC 还要是整分组。
//
// ★这条守的是「照抄 IKE SK 的补齐逻辑」那个坑：GCM 分组长为 1，只按分组长补的话
// 长度想是几就是几，自测全绿，只有第三方实现会拒收。
func TestEncapAlignment(t *testing.T) {
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			c := espCryptoPair(t, s)
			for n := 0; n <= 64; n++ {
				inner := espIPv4("10.60.0.5", "10.70.0.9", make([]byte, n))
				pkt, err := c.encap(0x11223344, 1, inner, protoIPv4)
				if err != nil {
					t.Fatalf("载荷 %d 字节封装失败：%v", n, err)
				}
				ctLen := len(pkt) - HeaderLen - c.ivLen() - c.icvLen()
				if ctLen%espAlign != 0 {
					t.Fatalf("载荷 %d 字节：密文 %d 字节不是 %d 的整数倍（RFC 4303 §2.4 要求密文终结于 4 字节边界）", n, ctLen, espAlign)
				}
				if bs := c.encr.BlockSize(); bs > 1 && ctLen%bs != 0 {
					t.Fatalf("载荷 %d 字节：密文 %d 字节不是分组长 %d 的整数倍", n, ctLen, bs)
				}
			}
		})
	}
}

// TestDecapRejectsEveryBitFlip 报文里**任何一个字节**被改动都必须被拒。
//
// 这条把「AAD/ICV 覆盖范围写窄了」这一整类错误一网打尽：只要有一段字节没被
// 完整性保护覆盖到，翻转它就会解封成功，而正常往返测试对此完全无感。
// 特别是 ESP 头的 SPI 与序号——它们不在密文里，靠 AAD/ICV 保护；漏掉的后果是
// 攻击者可以任意改写序号来打反重放窗口。
func TestDecapRejectsEveryBitFlip(t *testing.T) {
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			c := espCryptoPair(t, s)
			inner := espIPv4("10.60.0.5", "10.70.0.9", []byte("payload-for-tamper-test"))
			pkt, err := c.encap(0x11223344, 9, inner, protoIPv4)
			if err != nil {
				t.Fatalf("封装失败：%v", err)
			}
			for i := range pkt {
				bad := append([]byte(nil), pkt...)
				bad[i] ^= 0x01
				got, _, err := c.decap(bad)
				if err == nil {
					t.Fatalf("第 %d 字节（共 %d）被翻转 1 bit 后仍解封成功，解出 %d 字节——"+
						"说明该字节不在 ICV/AAD 覆盖范围内", i, len(pkt), len(got))
				}
				if !errors.Is(err, ipsec.ErrAuth) {
					t.Fatalf("第 %d 字节被翻转后返回的错误不是 ipsec.ErrAuth：%v", i, err)
				}
			}
		})
	}
}

// TestDecapWrongKey 密钥不对必须报认证失败，而不是吐出损坏的明文。
func TestDecapWrongKey(t *testing.T) {
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			enc := espCryptoPair(t, s)
			other, err := newCrypto(s.encrID, s.keyBits, s.integID, espKey(s.keyLen, 0x11), espKey(s.integLen, 0x22))
			if err != nil {
				t.Fatalf("构造对照套件失败：%v", err)
			}
			pkt, err := enc.encap(0x11223344, 3, espIPv4("10.60.0.5", "10.70.0.9", []byte("x")), protoIPv4)
			if err != nil {
				t.Fatalf("封装失败：%v", err)
			}
			if _, _, err := other.decap(pkt); !errors.Is(err, ipsec.ErrAuth) {
				t.Fatalf("用错误密钥解封应返回 ipsec.ErrAuth，实得：%v", err)
			}
		})
	}
}

// TestDecapShortPacket 截断的报文必须在触碰密钥之前就被长度检查挡掉。
func TestDecapShortPacket(t *testing.T) {
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			c := espCryptoPair(t, s)
			pkt, err := c.encap(0x11223344, 1, espIPv4("10.60.0.5", "10.70.0.9", []byte("x")), protoIPv4)
			if err != nil {
				t.Fatalf("封装失败：%v", err)
			}
			for n := 0; n < HeaderLen+c.ivLen()+c.icvLen()+c.minPlainLen(); n++ {
				if _, _, err := c.decap(pkt[:n]); err == nil {
					t.Fatalf("截断到 %d 字节仍解封成功", n)
				}
			}
		})
	}
}

// TestGCMIVIsSequence GCM 的显式 IV 必须等于该包的序号——nonce 唯一性完全建立在这条上。
//
// ★若哪天有人把它改成随机数，本测试会红。别顺手改绿：8 字节随机在同一条 SA 上
// 会碰撞，而 GCM 的 nonce 复用可同时恢复明文与认证密钥，且不会有任何报错。
func TestGCMIVIsSequence(t *testing.T) {
	c := espCryptoPair(t, espSuites[0]) // AES256-GCM16
	for _, seq := range []uint64{1, 2, 255, 65536, MaxSeq} {
		pkt, err := c.encap(0x11223344, seq, espIPv4("10.60.0.5", "10.70.0.9", []byte("x")), protoIPv4)
		if err != nil {
			t.Fatalf("序号 %d 封装失败：%v", seq, err)
		}
		var want [8]byte
		want[4] = byte(seq >> 24)
		want[5] = byte(seq >> 16)
		want[6] = byte(seq >> 8)
		want[7] = byte(seq)
		if !bytes.Equal(pkt[HeaderLen:HeaderLen+8], want[:]) {
			t.Fatalf("序号 %d：线上 IV 为 %x，期望 %x（GCM 的显式 IV 必须就是序号）", seq, pkt[HeaderLen:HeaderLen+8], want)
		}
	}
}

// TestCBCIVIsUnpredictable CBC 的 IV 必须每次不同（不可预测），否则 CBC 会退化到可区分。
func TestCBCIVIsUnpredictable(t *testing.T) {
	c := espCryptoPair(t, espSuites[2]) // AES256-CBC
	seen := make(map[string]struct{})
	inner := espIPv4("10.60.0.5", "10.70.0.9", []byte("same-plaintext-every-time"))
	for i := 0; i < 64; i++ {
		pkt, err := c.encap(0x11223344, uint64(i+1), inner, protoIPv4)
		if err != nil {
			t.Fatalf("封装失败：%v", err)
		}
		iv := string(pkt[HeaderLen : HeaderLen+16])
		if _, dup := seen[iv]; dup {
			t.Fatalf("第 %d 次封装出现重复的 CBC IV——IV 必须不可预测且不重复", i)
		}
		seen[iv] = struct{}{}
	}
}

// TestParseHeader SPI/序号提取与保留值拒绝。
func TestParseHeader(t *testing.T) {
	if _, _, err := parseHeader([]byte{1, 2, 3}); err == nil {
		t.Fatal("3 字节报文应被拒")
	}
	// SPI 0 就是 UDP-4500 上 non-ESP marker 的形状，必须拒。
	for _, spi := range []uint32{0, 1, 255} {
		pkt := []byte{byte(spi >> 24), byte(spi >> 16), byte(spi >> 8), byte(spi), 0, 0, 0, 1}
		if _, _, err := parseHeader(pkt); err == nil {
			t.Fatalf("保留 SPI %d 应被拒", spi)
		}
	}
	spi, seq, err := parseHeader([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2A})
	if err != nil || spi != 256 || seq != 42 {
		t.Fatalf("解析结果 spi=%d seq=%d err=%v，期望 256/42/nil", spi, seq, err)
	}
}

// TestNewCryptoKeyLength 密钥长度错误必须在装载期被拦下，且错误信息要指名 salt。
func TestNewCryptoKeyLength(t *testing.T) {
	// GCM 少了 4 字节 salt——这是 combined 模式最常见的实现错误。
	_, err := newCrypto(ike.EncrAESGCM16, 256, ike.IntegNone, espKey(32, 1), nil)
	if err == nil {
		t.Fatal("GCM 密钥少 4 字节 salt 应被拒")
	}
	if !strings.Contains(err.Error(), "salt") {
		t.Fatalf("错误信息未提到 salt，排障时看不出差的正是那 4 个字节：%v", err)
	}
	// combined 套件挂着完整性算法。
	if _, err := newCrypto(ike.EncrAESGCM16, 256, ike.IntegHMACSHA256128, espKey(36, 1), espKey(32, 2)); err == nil {
		t.Fatal("combined 套件搭配 INTEG≠NONE 应被拒")
	}
	// CBC 缺完整性算法 = 没有 ICV 的 ESP。
	if _, err := newCrypto(ike.EncrAESCBC, 256, ike.IntegNone, espKey(32, 1), nil); err == nil {
		t.Fatal("CBC 搭配 INTEG=NONE 应被拒（没有 ICV 的 ESP 等于毫无保护）")
	}
	// combined 套件却带了完整性密钥（多半是 KEYMAT 按 CBC 的长度切的）。
	if _, err := newCrypto(ike.EncrAESGCM16, 256, ike.IntegNone, espKey(36, 1), espKey(32, 2)); err == nil {
		t.Fatal("combined 套件带完整性密钥应被拒")
	}
}

// TestOverhead 最坏封装开销要与实际封装出来的最大值吻合。
func TestOverhead(t *testing.T) {
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			want, err := Overhead(s.encrID, s.keyBits, s.integID)
			if err != nil {
				t.Fatalf("计算开销失败：%v", err)
			}
			c := espCryptoPair(t, s)
			worst := 0
			for n := 0; n < 64; n++ {
				inner := make([]byte, 20+n)
				inner[0] = 0x45
				pkt, err := c.encap(0x11223344, 1, inner, protoIPv4)
				if err != nil {
					t.Fatalf("封装失败：%v", err)
				}
				if d := len(pkt) - len(inner); d > worst {
					worst = d
				}
			}
			if worst != want {
				t.Fatalf("实测最大开销 %d 字节，Overhead 报 %d 字节——"+
					"按偏小的值算 MTU 会让大包偶发被丢（症状：ping 通、HTTP 卡住）", worst, want)
			}
		})
	}
}
