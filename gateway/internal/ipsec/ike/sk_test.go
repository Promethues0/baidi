package ike

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// SK 是整个报文层唯一「写错了也照样跑得通」的地方：自己加密自己解密，
// 哪怕 AAD 只覆盖了半个头、哪怕 ICV 算漏了 IV，往返测试一样是绿的。
// 因此本文件的重点不是正例，而是三组反例：
//
//	① 篡改 ICV      → 证明校验确实在做
//	② 篡改 IKE 头     → 证明 AAD/ICV **覆盖到了报文第 0 字节**（最能证明范围没写错的一条）
//	③ 密文里搜明文金丝雀 → 证明真的加密了，而不是把明文抄了一遍
//
// 四个套件全量跑：AES-GCM（combined）、AES-CBC+HMAC（两段式）、以及对应的国密私有码点，
// 这样「国密只在单测里被 Lookup 过一次、整条链路没走通」不会发生。

type sktSuite struct {
	name string
	su   *Suite
}

func sktSuites(t *testing.T) []sktSuite {
	t.Helper()
	build := func(encrID uint16, keyBits int, prfID, integID uint16) *Suite {
		e, err := LookupEncr(encrID, keyBits)
		if err != nil {
			t.Fatalf("取加密算法 %d 失败: %v", encrID, err)
		}
		p, err := LookupPRF(prfID)
		if err != nil {
			t.Fatalf("取 PRF %d 失败: %v", prfID, err)
		}
		i, err := LookupInteg(integID)
		if err != nil {
			t.Fatalf("取完整性算法 %d 失败: %v", integID, err)
		}
		return &Suite{Encr: e, PRF: p, Integ: i}
	}
	return []sktSuite{
		{"AES256-GCM16", build(EncrAESGCM16, 256, PRFHMACSHA256, IntegNone)},
		{"AES256-CBC+SHA256", build(EncrAESCBC, 256, PRFHMACSHA256, IntegHMACSHA256128)},
		{"SM4-GCM16（白帝私有码点）", build(EncrSM4GCM16, 128, PRFHMACSM3, IntegNone)},
		{"SM4-CBC+SM3（白帝私有码点）", build(EncrSM4CBC, 128, PRFHMACSM3, IntegHMACSM3128)},
	}
}

// sktKeys 造一对长度正确的密钥。GCM 的 KeyLen 已含末尾 4 字节 salt。
func sktKeys(su *Suite) (encKey, integKey []byte) {
	encKey = bytes.Repeat([]byte{0x5a}, su.Encr.KeyLen())
	if su.Integ != nil {
		integKey = bytes.Repeat([]byte{0xa5}, su.Integ.KeyLen())
	}
	return
}

// sktCanary 是塞进内层身份载荷的可搜索标记：密文里出现它就说明根本没加密。
const sktCanary = "BAIDI-SK-CANARY-4f2a9c31"

func sktInner() []Payload {
	return []Payload{
		&IDPayload{T: PayloadIDi, IDType: IDFQDN, Data: []byte(sktCanary)},
		&AuthPayload{Method: AuthSharedKeyMIC, Data: bytes.Repeat([]byte{0x77}, 32)},
		&SAPayload{Proposals: []Proposal{{
			Num: 1, Protocol: ProtocolESP, SPI: []byte{0xde, 0xad, 0xbe, 0xef},
			Transforms: []Transform{
				{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256},
				{Type: TransformInteg, ID: IntegNone},
				{Type: TransformESN, ID: ESNNone},
			},
		}}},
		&TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{TSFromPrefix(netip.MustParsePrefix("10.20.0.0/16"))}},
		&TSPayload{T: PayloadTSr, Selectors: []TrafficSelector{TSFromPrefix(netip.MustParsePrefix("10.60.0.0/16"))}},
	}
}

func sktHeader() Header {
	return Header{
		SPIi:         [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		SPIr:         [8]byte{0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01},
		Version:      Version,
		ExchangeType: ExchangeIKEAuth,
		Flags:        FlagInitiator,
		MessageID:    1,
	}
}

func TestSKRoundTrip(t *testing.T) {
	for _, s := range sktSuites(t) {
		t.Run(s.name, func(t *testing.T) {
			encKey, integKey := sktKeys(s.su)
			inner := sktInner()
			raw, err := EncryptSK(sktHeader(), s.su, encKey, integKey, 1, inner)
			if err != nil {
				t.Fatalf("封装失败: %v", err)
			}

			m, err := Decode(raw)
			if err != nil {
				t.Fatalf("解码失败: %v", err)
			}
			if len(m.Payloads) != 1 || m.Payloads[0].Type() != PayloadSK {
				t.Fatalf("外层应只有一个 SK 载荷，实际 %d 个", len(m.Payloads))
			}
			// ★SK 通用头的 Next Payload 必须指向**内层第一个载荷**，不是外层链的下一个。
			// 写成 0 的话解密照样成功，但内层链找不到起点——症状是「解密成功、报文里什么都没有」。
			sk := m.Payloads[0].(*SKPayload)
			if sk.Inner != PayloadIDi {
				t.Fatalf("SK 的 Next Payload=%s，应为内层第一个载荷 IDi", sk.Inner)
			}

			if err := DecryptSK(m, s.su, encKey, integKey); err != nil {
				t.Fatalf("解封失败: %v", err)
			}
			if len(m.Payloads) != len(inner) {
				t.Fatalf("解出 %d 个内层载荷，期望 %d 个", len(m.Payloads), len(inner))
			}
			for i := range inner {
				if m.Payloads[i].Type() != inner[i].Type() {
					t.Fatalf("第 %d 个内层载荷类型 %s，期望 %s", i, m.Payloads[i].Type(), inner[i].Type())
				}
				if a, b := inner[i].appendBody(nil), m.Payloads[i].appendBody(nil); !bytes.Equal(a, b) {
					t.Fatalf("第 %d 个内层载荷（%s）往返不一致:\n发出 %x\n解出 %x", i, inner[i].Type(), a, b)
				}
			}
			// 重复解封必须失败：SK 已被内层载荷替换，再解一次说明上层逻辑串了。
			if err := DecryptSK(m, s.su, encKey, integKey); err == nil {
				t.Fatal("对已解封的报文再次 DecryptSK 竟成功")
			}
		})
	}
}

// TestSKPlaintextNotOnWire 全偏移扫描密文，断言明文金丝雀一个字节都没漏出来。
// ★「只加密了一部分」或「压根没加密」在往返测试里完全看不出来。
func TestSKPlaintextNotOnWire(t *testing.T) {
	for _, s := range sktSuites(t) {
		t.Run(s.name, func(t *testing.T) {
			encKey, integKey := sktKeys(s.su)
			raw, err := EncryptSK(sktHeader(), s.su, encKey, integKey, 1, sktInner())
			if err != nil {
				t.Fatalf("封装失败: %v", err)
			}
			if bytes.Contains(raw, []byte(sktCanary)) {
				t.Fatalf("密文里搜到了明文金丝雀 %q——这段内容根本没被加密", sktCanary)
			}
			// 内层 TS 里的网段（10.20.0.0）也不该以明文出现。
			if bytes.Contains(raw[HeaderLen:], []byte{10, 20, 0, 0, 10, 20, 255, 255}) {
				t.Fatal("密文里搜到了明文的 TS 地址区间——这段内容根本没被加密")
			}
		})
	}
}

// TestSKEmptyInnerIsDPD 空 SK{} 是 DPD 探测报文的形态，必须能正确封装与解封。
// GCM 下 blockSize=1，明文就只有一个 0x00 的 Pad Length 字节——这是补齐逻辑的边界。
func TestSKEmptyInnerIsDPD(t *testing.T) {
	for _, s := range sktSuites(t) {
		t.Run(s.name, func(t *testing.T) {
			encKey, integKey := sktKeys(s.su)
			raw, err := EncryptSK(sktHeader(), s.su, encKey, integKey, 7, nil)
			if err != nil {
				t.Fatalf("封装空 SK 失败: %v", err)
			}
			m, err := Decode(raw)
			if err != nil {
				t.Fatalf("解码失败: %v", err)
			}
			if sk := m.Payloads[0].(*SKPayload); sk.Inner != PayloadNone {
				t.Fatalf("空 SK 的 Next Payload=%s，应为 NONE", sk.Inner)
			}
			if err := DecryptSK(m, s.su, encKey, integKey); err != nil {
				t.Fatalf("解封空 SK 失败: %v", err)
			}
			if len(m.Payloads) != 0 {
				t.Fatalf("空 SK 解出 %d 个载荷，应为 0", len(m.Payloads))
			}
		})
	}
}

// TestSKTamperICV 篡改校验数据必须失败——证明校验真的在做。
func TestSKTamperICV(t *testing.T) {
	for _, s := range sktSuites(t) {
		t.Run(s.name, func(t *testing.T) {
			encKey, integKey := sktKeys(s.su)
			raw, err := EncryptSK(sktHeader(), s.su, encKey, integKey, 1, sktInner())
			if err != nil {
				t.Fatalf("封装失败: %v", err)
			}
			bad := append([]byte(nil), raw...)
			bad[len(bad)-1] ^= 0x01
			m, err := Decode(bad)
			if err != nil {
				t.Fatalf("篡改 ICV 不应影响外层解码: %v", err)
			}
			if err := DecryptSK(m, s.su, encKey, integKey); err == nil {
				t.Fatal("ICV 被篡改却解封成功")
			}
		})
	}
}

// TestSKTamperCiphertext 翻转密文中间一个 bit 必须失败——排除「解密不校验，吐出损坏明文」。
func TestSKTamperCiphertext(t *testing.T) {
	for _, s := range sktSuites(t) {
		t.Run(s.name, func(t *testing.T) {
			encKey, integKey := sktKeys(s.su)
			raw, err := EncryptSK(sktHeader(), s.su, encKey, integKey, 1, sktInner())
			if err != nil {
				t.Fatalf("封装失败: %v", err)
			}
			ctStart := HeaderLen + 4 + s.su.Encr.IVLen()
			ctEnd := len(raw) - s.su.ICVLen()
			bad := append([]byte(nil), raw...)
			bad[(ctStart+ctEnd)/2] ^= 0x01
			m, err := Decode(bad)
			if err != nil {
				t.Fatalf("篡改密文不应影响外层解码: %v", err)
			}
			if err := DecryptSK(m, s.su, encKey, integKey); err == nil {
				t.Fatal("密文被篡改却解封成功")
			}
		})
	}
}

// TestSKTamperHeaderIsDetected 是本文件最重要的一条：
// **逐字节翻转 IKE 头与 SK 通用头、IV 的每一个 bit，全部必须失败**。
//
// ★它排除的是「AAD/ICV 范围没覆盖到报文头」。这种错误在正常流程里完全无害——
// 自己加自己解永远通过——只有攻击者改写 Exchange Type / Message ID / Flags 时才显形，
// 那时已经晚了。GCM 的 AAD 应为 raw[:SK体起点+IVLen]，CBC 的 HMAC 应覆盖 raw[:len-ICV]，
// 两者都从报文第 0 字节起算。
func TestSKTamperHeaderIsDetected(t *testing.T) {
	for _, s := range sktSuites(t) {
		t.Run(s.name, func(t *testing.T) {
			encKey, integKey := sktKeys(s.su)
			raw, err := EncryptSK(sktHeader(), s.su, encKey, integKey, 1, sktInner())
			if err != nil {
				t.Fatalf("封装失败: %v", err)
			}
			covered := HeaderLen + 4 + s.su.Encr.IVLen() // IKE 头 + SK 通用头 + IV
			byCrypto := 0
			for i := 0; i < covered; i++ {
				for _, mask := range []byte{0x01, 0x80} {
					bad := append([]byte(nil), raw...)
					bad[i] ^= mask
					// Decode 先失败也算检测到（例如改 Length 字段）；这里要的是
					// 「改了就一定过不去」，而不是具体在哪一层被拦下。
					m, derr := Decode(bad)
					if derr != nil {
						continue
					}
					if err := DecryptSK(m, s.su, encKey, integKey); err == nil {
						t.Fatalf("翻转第 %d 字节（掩码 %#x）后仍解封成功——AAD/ICV 没有覆盖到这个字节", i, mask)
					}
					byCrypto++
				}
			}
			// ★防止这条测试**空转成功**：若哪天 Decode 变严到把所有变异都提前拦下，
			// 上面的循环会一条密码学校验都没跑到却依然全绿，AAD 范围也就失去了守护。
			// SPIi/SPIr 那 16 个字节 Decode 是不管的，必须由 AAD/ICV 兜住。
			if byCrypto < 16 {
				t.Fatalf("只有 %d 个变异真正走到了密码学校验，这条测试已退化为空转", byCrypto)
			}
		})
	}
}

// TestSKGCMIVIsMonotonicCounter 断言 GCM 的显式 nonce 就是入参计数器的大端编码。
//
// ★GCM 的 nonce 复用是灾难性的（可直接恢复明文与认证密钥）且**不会有任何报错**。
// 8 字节随机数在长连接上会碰撞，所以这里必须是计数器。这条测试把「有人某天顺手
// 改成 RandBytes(8)」钉死在回归里。
func TestSKGCMIVIsMonotonicCounter(t *testing.T) {
	for _, s := range sktSuites(t) {
		if !s.su.Encr.Combined() {
			continue
		}
		t.Run(s.name, func(t *testing.T) {
			encKey, integKey := sktKeys(s.su)
			const counter = 0x0102030405060708
			raw, err := EncryptSK(sktHeader(), s.su, encKey, integKey, counter, sktInner())
			if err != nil {
				t.Fatalf("封装失败: %v", err)
			}
			iv := raw[HeaderLen+4 : HeaderLen+4+8]
			if got := binary.BigEndian.Uint64(iv); got != counter {
				t.Fatalf("IV=%x（解读为 %#x），应为计数器 %#x 的大端编码", iv, got, uint64(counter))
			}
			// 同一计数器两次封装必须产出完全相同的字节：响应重传要靠原样回放，
			// 若这里带了随机性，重放缓存与重新加密就会分叉。
			again, err := EncryptSK(sktHeader(), s.su, encKey, integKey, counter, sktInner())
			if err != nil {
				t.Fatalf("二次封装失败: %v", err)
			}
			if !bytes.Equal(raw, again) {
				t.Fatal("combined 套件的封装应是确定性的（同计数器同明文同密文）")
			}
		})
	}
}

func TestSKKeyAndSuiteChecks(t *testing.T) {
	suites := sktSuites(t)
	gcm, cbc := suites[0].su, suites[1].su

	// 密钥长度不符——最常见的成因是 GCM 的 4 字节 salt 被算漏（36 写成 32）。
	if _, err := EncryptSK(sktHeader(), gcm, bytes.Repeat([]byte{1}, 32), nil, 1, nil); err == nil {
		t.Fatal("加密密钥少了 4 字节 salt 却封装成功")
	}
	// combined 套件必须搭配 INTEG=NONE（RFC 5282）。
	bad := &Suite{Encr: gcm.Encr, PRF: gcm.PRF, Integ: cbc.Integ}
	ek, ik := sktKeys(gcm)
	if _, err := EncryptSK(sktHeader(), bad, ek, ik, 1, nil); err == nil {
		t.Fatal("combined 套件挂着完整性算法却封装成功")
	}
	// 非 combined 套件缺完整性算法 = 没有保护，必须拒绝。
	bad = &Suite{Encr: cbc.Encr, PRF: cbc.PRF}
	ek, _ = sktKeys(cbc)
	if _, err := EncryptSK(sktHeader(), bad, ek, nil, 1, nil); err == nil {
		t.Fatal("CBC 套件没有完整性算法却封装成功")
	}
	// 完整性密钥长度不符。
	ek, _ = sktKeys(cbc)
	if _, err := EncryptSK(sktHeader(), cbc, ek, bytes.Repeat([]byte{1}, 8), 1, nil); err == nil {
		t.Fatal("完整性密钥长度不符却封装成功")
	}
}

// TestSKDecryptRejectsBrokenInput 解封路径上的畸形输入必须全部 error 且不 panic。
func TestSKDecryptRejectsBrokenInput(t *testing.T) {
	su := sktSuites(t)[0].su
	encKey, integKey := sktKeys(su)
	raw, err := EncryptSK(sktHeader(), su, encKey, integKey, 1, sktInner())
	if err != nil {
		t.Fatalf("封装失败: %v", err)
	}

	t.Run("报文里没有 SK 载荷", func(t *testing.T) {
		plain, err := Encode(sktHeader(), []Payload{&NoncePayload{Nonce: bytes.Repeat([]byte{1}, 32)}})
		if err != nil {
			t.Fatalf("构造失败: %v", err)
		}
		m, err := Decode(plain)
		if err != nil {
			t.Fatalf("解码失败: %v", err)
		}
		if err := DecryptSK(m, su, encKey, integKey); err == nil {
			t.Fatal("没有 SK 载荷却解封成功")
		}
	})

	t.Run("密文块装不下 IV+ICV", func(t *testing.T) {
		short := append([]byte(nil), raw[:HeaderLen+4+8]...) // 只留到 IV 结束
		binary.BigEndian.PutUint16(short[HeaderLen+2:HeaderLen+4], uint16(len(short)-HeaderLen))
		binary.BigEndian.PutUint32(short[24:28], uint32(len(short)))
		m, err := Decode(short)
		if err != nil {
			t.Fatalf("解码失败: %v", err)
		}
		if err := DecryptSK(m, su, encKey, integKey); err == nil {
			t.Fatal("密文块过短却解封成功")
		}
	})

	t.Run("Raw 与 SK 密文块对不上", func(t *testing.T) {
		m, err := Decode(raw)
		if err != nil {
			t.Fatalf("解码失败: %v", err)
		}
		// 模拟「有人事后重新序列化了 Message.Raw」：ICV/AAD 覆盖的是原始字节，
		// 重新序列化即使语义等价也会让校验必然失败，必须当场拒绝而不是让它去解密。
		m.Raw = append([]byte(nil), raw...)
		m.Raw = append(m.Raw, 0x00)
		if err := DecryptSK(m, su, encKey, integKey); err == nil {
			t.Fatal("Raw 与 SK 密文块对不上却解封成功")
		}
	})

	t.Run("补齐长度超出明文", func(t *testing.T) {
		// 用正确的密钥重新封装一条「PadLen 撒谎」的报文：直接改明文尾字节做不到
		// （会被 ICV 拦下），所以走内部函数手工构造。
		bs := su.Encr.BlockSize()
		plain := make([]byte, bs)
		plain[len(plain)-1] = 0xFF // 声称补齐了 255 字节，实际只有 blockSize 字节明文
		if err := sktSealRawWithPlain(t, su, encKey, integKey, plain, PayloadIDi); err == nil {
			t.Fatal("补齐长度超出明文却解封成功")
		}
	})
}

// sktSealRawWithPlain 用给定的**原始明文**（含补齐与 PadLen）封一条 SK 报文再解封，
// 返回解封的错误。用于构造那些正常封装路径产不出来的明文（如撒谎的 PadLen）。
func sktSealRawWithPlain(t *testing.T, su *Suite, encKey, integKey, plain []byte, inner PayloadType) error {
	t.Helper()
	ivLen, icvLen := su.Encr.IVLen(), su.ICVLen()
	skLen := 4 + ivLen + len(plain) + icvLen
	hdr := sktHeader()
	hdr.NextPayload = PayloadSK
	hdr.Length = uint32(HeaderLen + skLen)
	buf := hdr.AppendTo(nil)
	buf = append(buf, byte(inner), 0, 0, 0)
	binary.BigEndian.PutUint16(buf[HeaderLen+2:HeaderLen+4], uint16(skLen))
	iv := make([]byte, ivLen)
	buf = append(buf, iv...)
	if su.Encr.Combined() {
		out, err := su.Encr.Seal(encKey, iv, buf, plain)
		if err != nil {
			t.Fatalf("构造失败: %v", err)
		}
		buf = append(buf, out...)
	} else {
		ct, err := su.Encr.Seal(encKey, iv, nil, plain)
		if err != nil {
			t.Fatalf("构造失败: %v", err)
		}
		buf = append(buf, ct...)
		buf = append(buf, su.Integ.Sum(integKey, buf)...)
	}
	m, err := Decode(buf)
	if err != nil {
		return err
	}
	return DecryptSK(m, su, encKey, integKey)
}
