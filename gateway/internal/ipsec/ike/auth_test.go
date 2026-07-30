package ike

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// PSK 认证有 6 个互不相干的根因会导致同一句「认证失败」（见 auth.go 文件头）。
// 本文件对其中三个能在纯函数层面锁死的逐一设靶：
//
//	① "Key Pad for IKEv2" 常量  → TestKeyPadConstantBytes（逐字节 + 长度 + 无 NUL）
//	② Ni/Nr 交叉写反            → TestSignedOctetsCrossNonce
//	③ RestOfIDPayload 少算 3 字节 → TestMACedIDUsesRestOfIDPayload
//
// 另外三个（RealMessage 重新序列化、COOKIE 重试用错报文、KE 未补零）是状态机层的事，
// 这里只保证 SignedOctets 不会自作主张改动传进来的字节。

var (
	atPSK     = []byte("baidi-ipsec-psk-测试")
	atNi      = bytes.Repeat([]byte{0x11}, 32)
	atNr      = bytes.Repeat([]byte{0x22}, 32)
	atSKpi    = bytes.Repeat([]byte{0x66}, 32)
	atSKpr    = bytes.Repeat([]byte{0x77}, 32)
	atRealMsg = bytes.Repeat([]byte{0xAB}, 120) // 冒充 RealMessage1 的原始字节
)

func atPRF(t *testing.T) PRF {
	t.Helper()
	p, err := LookupPRF(PRFHMACSHA256)
	if err != nil {
		t.Fatalf("取 PRF 失败: %v", err)
	}
	return p
}

func atMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// TestKeyPadConstantBytes 逐字节锁死 RFC 7296 §2.15 的固定字符串。
//
// ★靶子：从 C 移植或用定长数组写这个常量时会带上 NUL 结尾，长度变 18。
// 两端只要有一端多这一个字节，AUTH 就恒不匹配，而报错只有「认证失败」。
func TestKeyPadConstantBytes(t *testing.T) {
	want := []byte{0x4B, 0x65, 0x79, 0x20, 0x50, 0x61, 0x64, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x49, 0x4B, 0x45, 0x76, 0x32}
	got := []byte(keyPadForIKEv2)

	if len(got) != 17 {
		t.Fatalf("常量长度 %d，应为 17（无 NUL 结尾、无长度前缀）", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 字节为 %#02x，应为 %#02x", i, got[i], want[i])
		}
	}
	if bytes.IndexByte(got, 0x00) >= 0 {
		t.Error("常量里含 NUL 字节")
	}
	if string(got) != "Key Pad for IKEv2" {
		t.Errorf("常量文本为 %q", string(got))
	}
}

// TestMACedIDUsesRestOfIDPayload MACedID 的输入必须是 IDType(1) ‖ RESERVED(3) ‖ Data。
//
// ★靶子：手拼成 IDType‖Data（漏掉 3 个 RESERVED 字节）。它同样能算出一个 32 字节的
// 合法 HMAC，长度、类型全对，只有值不同——除了显式断言"不等于错误拼法"没有别的抓法。
func TestMACedIDUsesRestOfIDPayload(t *testing.T) {
	prf := atPRF(t)
	id := &IDPayload{T: PayloadIDi, IDType: IDFQDN, Data: []byte("gw-a.baidi")}

	rest := append([]byte{byte(IDFQDN), 0, 0, 0}, id.Data...)
	ktWant := atMAC(atSKpi, rest)
	got := MACedID(prf, atSKpi, id)
	if !bytes.Equal(got, ktWant) {
		t.Errorf("MACedID 不符\n实际 %x\n期望 %x", got, ktWant)
	}

	// 少算 3 个保留字节的错误拼法。
	wrong := atMAC(atSKpi, append([]byte{byte(IDFQDN)}, id.Data...))
	if bytes.Equal(got, wrong) {
		t.Error("MACedID 漏掉了 3 个 RESERVED 字节")
	}
	// 多算 4 字节通用头的错误拼法（Next Payload/Critical/Length）。
	withHdr := atMAC(atSKpi, append([]byte{byte(PayloadAUTH), 0, 0, 18}, rest...))
	if bytes.Equal(got, withHdr) {
		t.Error("MACedID 把 4 字节通用载荷头也算进去了")
	}

	// SK_pi / SK_pr 必须配对：用错那把密钥算出的值两端都复现不了。
	if bytes.Equal(got, MACedID(prf, atSKpr, id)) {
		t.Error("MACedID 对 SK_p* 不敏感")
	}
	// 身份不同 → MACedID 必须不同（否则「你是谁」这一问答被短路）。
	other := &IDPayload{T: PayloadIDi, IDType: IDFQDN, Data: []byte("gw-b.baidi")}
	if bytes.Equal(got, MACedID(prf, atSKpi, other)) {
		t.Error("不同身份算出同一个 MACedID")
	}
	// ID 类型不同、数据相同也必须不同。
	sameData := &IDPayload{T: PayloadIDi, IDType: IDRFC822, Data: []byte("gw-a.baidi")}
	if bytes.Equal(got, MACedID(prf, atSKpi, sameData)) {
		t.Error("ID Type 没有参与 MACedID 计算")
	}
}

// TestSignedOctetsOrder 拼接顺序 = RealMessage ‖ 对端 nonce ‖ MACedID。
func TestSignedOctetsOrder(t *testing.T) {
	macedID := bytes.Repeat([]byte{0x99}, 32)
	got := SignedOctets(atRealMsg, atNr, macedID)

	want := make([]byte, 0, len(atRealMsg)+len(atNr)+len(macedID))
	want = append(want, atRealMsg...)
	want = append(want, atNr...)
	want = append(want, macedID...)
	if !bytes.Equal(got, want) {
		t.Fatalf("拼接结果不符\n实际 %x\n期望 %x", got, want)
	}

	// 三种换位的错误拼法都必须与正确结果不同。
	wrongOrders := map[string][]byte{
		"nonce 与 MACedID 换位": append(append(append([]byte{}, atRealMsg...), macedID...), atNr...),
		"报文放到最后":             append(append(append([]byte{}, atNr...), macedID...), atRealMsg...),
		"MACedID 放最前":        append(append(append([]byte{}, macedID...), atRealMsg...), atNr...),
	}
	for name, w := range wrongOrders {
		if bytes.Equal(got, w) {
			t.Errorf("SignedOctets 的拼接顺序退化成了「%s」", name)
		}
	}

	// 快照：长度与摘要一起锁死，防止某天有人在中间插了个分隔符还"看起来正常"。
	sum := sha256.Sum256(got)
	if len(got) != 184 {
		t.Errorf("待签串长度 %d，应为 120+32+32=184", len(got))
	}
	const wantSum = "f33d331922919f24fc31a93ce0f686144e8f5b35c9a24968dd346548f573ca61"
	if h := hex.EncodeToString(sum[:]); h != wantSum {
		t.Errorf("待签串快照不符\n实际 %s\n期望 %s", h, wantSum)
	}
}

// TestSignedOctetsCrossNonce 发起方用 Nr、响应方用 Ni——交叉，极易写反。
//
// ★两个 nonce 类型相同、长度也相同（都 32 字节），编译器挡不住任何一种写反。
// 具名包装 InitiatorSignedOctets / ResponderSignedOctets 存在的唯一理由就是这个。
func TestSignedOctetsCrossNonce(t *testing.T) {
	macedI := bytes.Repeat([]byte{0x01}, 32)
	macedR := bytes.Repeat([]byte{0x02}, 32)
	msg1 := bytes.Repeat([]byte{0xA1}, 100)
	msg2 := bytes.Repeat([]byte{0xA2}, 110)

	gotI := InitiatorSignedOctets(msg1, atNr, macedI)
	gotR := ResponderSignedOctets(msg2, atNi, macedR)

	if !bytes.Equal(gotI, SignedOctets(msg1, atNr, macedI)) {
		t.Error("InitiatorSignedOctets 与 SignedOctets(msg1, Nr, MACedIDForI) 不一致")
	}
	if !bytes.Equal(gotR, SignedOctets(msg2, atNi, macedR)) {
		t.Error("ResponderSignedOctets 与 SignedOctets(msg2, Ni, MACedIDForR) 不一致")
	}
	// 写反的版本必须产出不同字节。
	if bytes.Equal(gotI, SignedOctets(msg1, atNi, macedI)) {
		t.Error("发起方待签串用了 Ni——应当用对端的 Nr")
	}
	if bytes.Equal(gotR, SignedOctets(msg2, atNr, macedR)) {
		t.Error("响应方待签串用了 Nr——应当用对端的 Ni")
	}
}

// TestSignedOctetsNoAliasing SignedOctets 不得与入参共享底层数组。
//
// 靶子：`append(realMsg, ...)` 这种写法在 realMsg 有富余容量时会**就地改写**
// Message.Raw——而 Raw 正是后续重传与 AUTH 复算的唯一依据，被改写后症状是
// 「第一次握手好好的，重传一次就认证失败」。
func TestSignedOctetsNoAliasing(t *testing.T) {
	msg := make([]byte, 8, 128) // 故意留大容量
	copy(msg, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	nonce := []byte{0xAA, 0xBB}
	maced := []byte{0xCC}

	so := SignedOctets(msg, nonce, maced)
	before := append([]byte(nil), so...)

	// 改动入参后，已产出的待签串不得随之变化。
	msg[0] = 0xFF
	nonce[0] = 0xFF
	maced[0] = 0xFF
	if !bytes.Equal(so, before) {
		t.Error("SignedOctets 的返回值与入参共享底层数组")
	}
	// 反向：改动返回值不得污染入参。
	if msg[0] != 0xFF || len(msg) != 8 {
		t.Error("入参被 SignedOctets 就地修改了")
	}
}

// TestPSKAuthFormula AUTH = prf(prf(PSK, "Key Pad for IKEv2"), SignedOctets)。
func TestPSKAuthFormula(t *testing.T) {
	prf := atPRF(t)
	so := SignedOctets(atRealMsg, atNr, bytes.Repeat([]byte{0x99}, 32))

	inner := atMAC(atPSK, []byte("Key Pad for IKEv2"))
	want := atMAC(inner, so)
	got := PSKAuth(prf, atPSK, so)
	if !bytes.Equal(got, want) {
		t.Fatalf("AUTH 不符\n实际 %x\n期望 %x", got, want)
	}
	if len(got) != 32 {
		t.Errorf("AUTH 长度 %d，PRF-HMAC-SHA256 应为 32", len(got))
	}

	// 内外层写反（prf(prf(pad, PSK), so)）必须产出不同值。
	if bytes.Equal(got, atMAC(atMAC([]byte("Key Pad for IKEv2"), atPSK), so)) {
		t.Error("内层 prf 的 key/data 写反了（key 必须是 PSK 原文）")
	}
	// 少一层（直接 prf(PSK, so)）也必须不同。
	if bytes.Equal(got, atMAC(atPSK, so)) {
		t.Error("AUTH 少算了 Key Pad 那一层")
	}
	// 带 NUL 的常量必须产出不同值——这条把「常量写错」与「其它根因」区分开。
	if bytes.Equal(got, atMAC(atMAC(atPSK, append([]byte("Key Pad for IKEv2"), 0x00)), so)) {
		t.Error("Key Pad 常量带了 NUL 结尾")
	}
}

// TestPSKAuthSnapshot 固定输入的 AUTH 快照。
func TestPSKAuthSnapshot(t *testing.T) {
	so := SignedOctets(atRealMsg, atNr, bytes.Repeat([]byte{0x99}, 32))
	got := PSKAuth(atPRF(t), atPSK, so)
	const want = "5122cf87a8b1fdec26762791c3e01dd874937f64bccb07e3dfb3c5b43cd2543a"
	if h := hex.EncodeToString(got); h != want {
		t.Errorf("AUTH 快照不符\n实际 %s\n期望 %s", h, want)
	}
}

// TestVerifyPSKAuth 校验路径的正例与四类反例。
func TestVerifyPSKAuth(t *testing.T) {
	prf := atPRF(t)
	so := SignedOctets(atRealMsg, atNr, bytes.Repeat([]byte{0x99}, 32))
	good := PSKAuth(prf, atPSK, so)

	if !VerifyPSKAuth(prf, atPSK, so, good) {
		t.Fatal("正确的 AUTH 未通过校验")
	}
	if VerifyPSKAuth(prf, []byte("另一把 PSK"), so, good) {
		t.Error("PSK 不同却通过了校验")
	}
	if VerifyPSKAuth(prf, atPSK, append(append([]byte{}, so...), 0x00), good) {
		t.Error("待签串不同却通过了校验")
	}
	if VerifyPSKAuth(prf, atPSK, so, good[:31]) {
		t.Error("截断的 AUTH 通过了校验")
	}
	// ★空 AUTH 必须判假。若上层某处写成「长度为 0 则跳过比较」，空 AUTH 就是万能钥匙。
	if VerifyPSKAuth(prf, atPSK, so, nil) {
		t.Error("空 AUTH 通过了校验")
	}
	if VerifyPSKAuth(prf, atPSK, so, []byte{}) {
		t.Error("零长 AUTH 通过了校验")
	}
	// 翻转任意一比特都必须失败。
	for i := range good {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0x01
		if VerifyPSKAuth(prf, atPSK, so, bad) {
			t.Fatalf("第 %d 字节翻转一比特后仍通过校验", i)
		}
	}
}

// TestPSKAuthPanicsOnEmptyPSK 空 PSK 必须炸而不是算出一个"能用"的 AUTH。
//
// ★空 PSK 在密码学上完全可用：两端都空就能建立一条**没有任何认证**的隧道，
// 全程零报错、界面显示 up。真正的闸在 SiteConfig.Validate()，这里是最后一道绊线。
func TestPSKAuthPanicsOnEmptyPSK(t *testing.T) {
	prf := atPRF(t)
	so := SignedOctets(atRealMsg, atNr, bytes.Repeat([]byte{0x99}, 32))

	for _, c := range []struct {
		name string
		psk  []byte
		so   []byte
	}{
		{"PSK 为 nil", nil, so},
		{"PSK 为空切片", []byte{}, so},
		{"待签串为空", atPSK, nil},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s 时 PSKAuth 未 panic", c.name)
				}
			}()
			PSKAuth(prf, c.psk, c.so)
		}()
	}
}

// TestMACedIDPanicsOnNilInputs 缺 ID 载荷或缺 SK_p* 时给出可读 panic 而不是裸崩。
func TestMACedIDPanicsOnNilInputs(t *testing.T) {
	prf := atPRF(t)
	id := &IDPayload{T: PayloadIDi, IDType: IDFQDN, Data: []byte("gw-a.baidi")}

	for _, c := range []struct {
		name string
		skp  []byte
		id   *IDPayload
	}{
		{"ID 载荷为 nil", atSKpi, nil},
		{"SK_p* 为空", nil, id},
	} {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("%s 时 MACedID 未 panic", c.name)
					return
				}
				if s, ok := r.(string); !ok || !strings.Contains(s, "ike:") {
					t.Errorf("%s 的 panic 信息不可读: %v", c.name, r)
				}
			}()
			MACedID(prf, c.skp, c.id)
		}()
	}
}

// TestSignedOctetsDigest 排障摘要必须含三段长度，且不泄漏任何密钥材料。
func TestSignedOctetsDigest(t *testing.T) {
	maced := bytes.Repeat([]byte{0x99}, 32)
	s := SignedOctetsDigest(atRealMsg, atNr, maced)

	for _, want := range []string{"报文=120", "(32B)", "待签=", "MACedID="} {
		if !strings.Contains(s, want) {
			t.Errorf("摘要里缺少 %q：%s", want, s)
		}
	}
	// 摘要必须随任一段变化而变化，否则排障时区分不出是哪一段不同。
	if s == SignedOctetsDigest(atRealMsg, atNi, maced) {
		t.Error("换掉对端 nonce 后摘要没变")
	}
	if s == SignedOctetsDigest(atRealMsg[:100], atNr, maced) {
		t.Error("换掉报文后摘要没变")
	}
	// ★不得出现原文：待签串本身是公开值，但它的**原文**也不该进日志（体积大且无益）。
	if strings.Contains(s, hex.EncodeToString(atNr)) {
		t.Error("摘要里出现了 nonce 原文")
	}
}
