package ike

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// 本文件守两件事，缺一不可：
//
//  1. **独立复算**：用 crypto/hmac 直接按 RFC 公式再算一遍，与 keys.go 的输出逐字节比。
//     这排除了"自己算自己验"——那种测试对着一个恒等函数也能过。
//  2. **快照锁死**：RFC 7296 没给官方测试向量，所以用固定输入产出的十六进制被写死在这里。
//     它挡的是重构：某天有人把七段密钥的切片顺序换一下，独立复算若也跟着改就发现不了，
//     快照不会跟着改。
//
// 固定输入取成可肉眼识别的模式（0x11/0x22/0x33…），快照对不上时从 hex 里就能看出
// 是哪一段跑偏了。

var (
	ktNi   = bytes.Repeat([]byte{0x11}, 32)
	ktNr   = bytes.Repeat([]byte{0x22}, 32)
	ktDH   = bytes.Repeat([]byte{0x33}, 32)
	ktDH2  = bytes.Repeat([]byte{0x44}, 32) // 重协商用的新 g^ir
	ktSKd  = bytes.Repeat([]byte{0x55}, 32) // 旧 SA 的 SK_d
	ktSPIi = [8]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7}
	ktSPIr = [8]byte{0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7}
)

// ktPRFPlusRef 是 prf+ 的**独立参考实现**：直接用 crypto/hmac，不碰 ike 包的任何函数。
func ktPRFPlusRef(key, seed []byte, n int) []byte {
	var out, prev []byte
	for i := 1; len(out) < n; i++ {
		m := hmac.New(sha256.New, key)
		m.Write(prev)
		m.Write(seed)
		m.Write([]byte{byte(i)})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func ktPRF(t *testing.T) PRF {
	t.Helper()
	p, err := LookupPRF(PRFHMACSHA256)
	if err != nil {
		t.Fatalf("取 PRF 失败: %v", err)
	}
	return p
}

// ktGCMSuite AES-256-GCM-16 + PRF-HMAC-SHA256 + ECP256（combined 模式，SK_ai/SK_ar 长度 0）。
func ktGCMSuite(t *testing.T) *Suite {
	t.Helper()
	su, err := SuiteSpec{EncrID: EncrAESGCM16, KeyBits: 256, PRFID: PRFHMACSHA256, IntegID: IntegNone, DHID: DHEcp256}.Build()
	if err != nil {
		t.Fatalf("构造 GCM 套件失败: %v", err)
	}
	return su
}

// ktCBCSuite AES-256-CBC + HMAC-SHA256-128 + MODP2048（非 combined，七段各 32 字节）。
func ktCBCSuite(t *testing.T) *Suite {
	t.Helper()
	su, err := SuiteSpec{EncrID: EncrAESCBC, KeyBits: 256, PRFID: PRFHMACSHA256, IntegID: IntegHMACSHA256128, DHID: DHModp2048}.Build()
	if err != nil {
		t.Fatalf("构造 CBC 套件失败: %v", err)
	}
	return su
}

func ktEqual(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s 不符\n实际 %x\n期望 %x", name, got, want)
	}
}

func ktEqualHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	if hex.EncodeToString(got) != wantHex {
		t.Errorf("%s 快照不符\n实际 %s\n期望 %s", name, hex.EncodeToString(got), wantHex)
	}
}

// ── prf+ ──

// TestPRFPlusManualVectors 逐轮手工比对 T1/T2/T3。
//
// 这条测试的靶子是「计数器字节放错位置」：把 byte(i) 放在 seed 前面、或者从 0 开始计数，
// 输出长度完全正确、每一轮也都是合法的 HMAC，只有值不同——除了逐轮比对没有别的抓法。
func TestPRFPlusManualVectors(t *testing.T) {
	prf := ktPRF(t)
	key := []byte("prf+ 测试密钥")
	seed := []byte("seed-0123456789")

	mac := func(data []byte) []byte {
		m := hmac.New(sha256.New, key)
		m.Write(data)
		return m.Sum(nil)
	}
	// T1 = prf(K, S ‖ 0x01)
	t1 := mac(append(append([]byte{}, seed...), 0x01))
	// T2 = prf(K, T1 ‖ S ‖ 0x02)
	t2 := mac(append(append(append([]byte{}, t1...), seed...), 0x02))
	// T3 = prf(K, T2 ‖ S ‖ 0x03)
	t3 := mac(append(append(append([]byte{}, t2...), seed...), 0x03))

	got, err := PRFPlus(prf, key, seed, 96)
	if err != nil {
		t.Fatalf("PRFPlus: %v", err)
	}
	ktEqual(t, "T1", got[0:32], t1)
	ktEqual(t, "T2", got[32:64], t2)
	ktEqual(t, "T3", got[64:96], t3)

	// 反例：若计数器从 0 起算，T1 会变成 prf(K, S‖0x00)。断言它与实际输出**不同**，
	// 免得哪天参考实现和被测实现一起改错还相互对得上。
	if bytes.Equal(got[0:32], mac(append(append([]byte{}, seed...), 0x00))) {
		t.Error("T1 用了 0x00 计数器——prf+ 的计数器必须从 1 开始")
	}
}

// TestPRFPlusTruncationAndEdges 截断与边界。
func TestPRFPlusTruncationAndEdges(t *testing.T) {
	prf := ktPRF(t)
	key, seed := []byte("k"), []byte("s")
	full := ktPRFPlusRef(key, seed, 96)

	for _, n := range []int{0, 1, 31, 32, 33, 64, 96} {
		got, err := PRFPlus(prf, key, seed, n)
		if err != nil {
			t.Fatalf("PRFPlus(n=%d): %v", n, err)
		}
		if len(got) != n {
			t.Errorf("PRFPlus(n=%d) 返回 %d 字节", n, len(got))
		}
		ktEqual(t, "PRFPlus 截断", got, full[:n])
	}
	if _, err := PRFPlus(prf, key, seed, -1); err == nil {
		t.Error("负长度必须报错")
	}
	// 单字节计数器上限：255 轮 × 32 字节 = 8160 字节可行，再多必须报错。
	if _, err := PRFPlus(prf, key, seed, 255*32); err != nil {
		t.Errorf("255 轮应当可行: %v", err)
	}
	if _, err := PRFPlus(prf, key, seed, 255*32+1); err == nil {
		t.Error("超过 255 轮必须报错（单字节计数器会回绕，回绕后密钥材料重复）")
	}
}

// ── SKEYSEED ──

// TestSKEYSEEDKeyDataOrder key=Ni‖Nr、data=g^ir，写反不会报错但两端算不到一起。
func TestSKEYSEEDKeyDataOrder(t *testing.T) {
	prf := ktPRF(t)
	got := SKEYSEED(prf, ktNi, ktNr, ktDH)

	m := hmac.New(sha256.New, append(append([]byte{}, ktNi...), ktNr...))
	m.Write(ktDH)
	ktEqual(t, "SKEYSEED", got, m.Sum(nil))

	// key/data 互换必须得到不同结果（否则说明实现里把两者搞混了）。
	m2 := hmac.New(sha256.New, ktDH)
	m2.Write(append(append([]byte{}, ktNi...), ktNr...))
	if bytes.Equal(got, m2.Sum(nil)) {
		t.Error("SKEYSEED 的 key 与 data 写反了")
	}
	// Ni/Nr 顺序也必须敏感。
	if bytes.Equal(got, SKEYSEED(prf, ktNr, ktNi, ktDH)) {
		t.Error("SKEYSEED 对 Ni/Nr 顺序不敏感")
	}
}

// ── IKE 密钥 ──

// TestDeriveIKEKeysGCMLayout GCM 套件的长度表与切片顺序（独立复算）。
//
// ★这是本文件最重要的一条：GCM 的 SK_ei/SK_er 是 **36** 字节（32 密钥 + 4 salt）、
// SK_ai/SK_ar 是 **0**。按 32 切会让 SK_er 之后每一段整体前移 8 字节，
// 症状是 IKE_SA_INIT 全绿、IKE_AUTH 解密失败。
func TestDeriveIKEKeysGCMLayout(t *testing.T) {
	su := ktGCMSuite(t)
	k, err := DeriveIKEKeys(su, ktDH, ktNi, ktNr, ktSPIi, ktSPIr)
	if err != nil {
		t.Fatalf("DeriveIKEKeys: %v", err)
	}

	want := map[string]int{"SKd": 32, "SKai": 0, "SKar": 0, "SKei": 36, "SKer": 36, "SKpi": 32, "SKpr": 32}
	got := map[string]int{"SKd": len(k.SKd), "SKai": len(k.SKai), "SKar": len(k.SKar),
		"SKei": len(k.SKei), "SKer": len(k.SKer), "SKpi": len(k.SKpi), "SKpr": len(k.SKpr)}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s 长度 %d，应为 %d", name, got[name], w)
		}
	}

	// 独立复算：seed 在测试里**逐字节手拼**，不复用被测代码的拼法。
	seed := make([]byte, 0, 80)
	seed = append(seed, ktNi...)
	seed = append(seed, ktNr...)
	seed = append(seed, ktSPIi[:]...)
	seed = append(seed, ktSPIr[:]...)
	ref := ktPRFPlusRef(SKEYSEED(ktPRF(t), ktNi, ktNr, ktDH), seed, 168)

	var cat []byte
	for _, s := range [][]byte{k.SKd, k.SKai, k.SKar, k.SKei, k.SKer, k.SKpi, k.SKpr} {
		cat = append(cat, s...)
	}
	if len(cat) != 168 {
		t.Fatalf("七段密钥合计 %d 字节，AES-GCM-16-256 应为 168", len(cat))
	}
	ktEqual(t, "SK_d‖SK_ai‖SK_ar‖SK_ei‖SK_er‖SK_pi‖SK_pr", cat, ref)
}

// TestDeriveIKEKeysCBCLayout CBC+HMAC 套件：七段各 32 字节，合计 224。
func TestDeriveIKEKeysCBCLayout(t *testing.T) {
	su := ktCBCSuite(t)
	k, err := DeriveIKEKeys(su, ktDH, ktNi, ktNr, ktSPIi, ktSPIr)
	if err != nil {
		t.Fatalf("DeriveIKEKeys: %v", err)
	}
	var cat []byte
	for name, s := range map[string][]byte{"SKd": k.SKd, "SKai": k.SKai, "SKar": k.SKar,
		"SKei": k.SKei, "SKer": k.SKer, "SKpi": k.SKpi, "SKpr": k.SKpr} {
		if len(s) != 32 {
			t.Errorf("%s 长度 %d，CBC 套件应为 32", name, len(s))
		}
	}
	for _, s := range [][]byte{k.SKd, k.SKai, k.SKar, k.SKei, k.SKer, k.SKpi, k.SKpr} {
		cat = append(cat, s...)
	}
	if len(cat) != 224 {
		t.Fatalf("七段密钥合计 %d 字节，AES-CBC-256+SHA256-128 应为 224", len(cat))
	}

	seed := make([]byte, 0, 80)
	seed = append(seed, ktNi...)
	seed = append(seed, ktNr...)
	seed = append(seed, ktSPIi[:]...)
	seed = append(seed, ktSPIr[:]...)
	ktEqual(t, "CBC 七段拼接", cat, ktPRFPlusRef(SKEYSEED(ktPRF(t), ktNi, ktNr, ktDH), seed, 224))
}

// TestDeriveIKEKeysSnapshot 快照锁死。
//
// 值由本实现产出并经上面两条独立复算测试交叉验证过。**改动 keys.go 后这条红了，
// 先问自己是不是把切片顺序或长度改坏了，不要顺手更新快照。**
func TestDeriveIKEKeysSnapshot(t *testing.T) {
	k, err := DeriveIKEKeys(ktGCMSuite(t), ktDH, ktNi, ktNr, ktSPIi, ktSPIr)
	if err != nil {
		t.Fatalf("DeriveIKEKeys: %v", err)
	}
	ktEqualHex(t, "SK_d", k.SKd, "d61d8f297e6eab7c6f0838ab175162c18383625790aee1f517e121fe833028fa")
	ktEqualHex(t, "SK_ei", k.SKei, "91d14f5a79feb1d235b29b469833b27bb3d903207814fe40627e72a4404c0fd7d74af86d")
	ktEqualHex(t, "SK_er", k.SKer, "fb27388f3362428dc52a20a784cd1a913a102c59276b4e5b2b11c8945c9c2e9ae803593b")
	ktEqualHex(t, "SK_pi", k.SKpi, "671e9f96b368030b776dd55637bd1d48226ef9d835e9cd152fc43ad28a04b4d0")
	ktEqualHex(t, "SK_pr", k.SKpr, "dcf1580994de5765788099970192920402b3e89a3b1d8765f295def5c9ad3138")
	if len(k.SKai) != 0 || len(k.SKar) != 0 {
		t.Errorf("GCM 套件不该派生 SK_ai/SK_ar（实际 %d/%d 字节）", len(k.SKai), len(k.SKar))
	}
}

// TestDeriveIKEKeysSeedSensitivity seed 的四个组成部分任一换位都必须改变结果。
//
// 靶子是「按本端角色调换 SPIi/SPIr」这个诱人但错误的写法：它会让两端各算一套
// 自洽但互不相同的密钥，两边日志都只说「解密失败」。
func TestDeriveIKEKeysSeedSensitivity(t *testing.T) {
	su := ktGCMSuite(t)
	base, err := DeriveIKEKeys(su, ktDH, ktNi, ktNr, ktSPIi, ktSPIr)
	if err != nil {
		t.Fatalf("DeriveIKEKeys: %v", err)
	}
	cases := []struct {
		name       string
		ni, nr     []byte
		spii, spir [8]byte
		dh         []byte
	}{
		{"交换 Ni/Nr", ktNr, ktNi, ktSPIi, ktSPIr, ktDH},
		{"交换 SPIi/SPIr", ktNi, ktNr, ktSPIr, ktSPIi, ktDH},
		{"换 g^ir", ktNi, ktNr, ktSPIi, ktSPIr, ktDH2},
	}
	for _, c := range cases {
		got, err := DeriveIKEKeys(su, c.dh, c.ni, c.nr, c.spii, c.spir)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if bytes.Equal(got.SKd, base.SKd) {
			t.Errorf("%s 之后 SK_d 未变——派生对该输入不敏感", c.name)
		}
	}
}

// TestDeriveRekeyedIKEKeys 重协商密钥：公式形状与新建完全不同。
func TestDeriveRekeyedIKEKeys(t *testing.T) {
	su := ktGCMSuite(t)
	k, err := DeriveRekeyedIKEKeys(su, ktSKd, ktDH2, ktNi, ktNr, ktSPIi, ktSPIr)
	if err != nil {
		t.Fatalf("DeriveRekeyedIKEKeys: %v", err)
	}

	// 独立复算：SKEYSEED = prf(SK_d(旧), g^ir(新) ‖ Ni ‖ Nr)——注意 g^ir 在**最前**。
	m := hmac.New(sha256.New, ktSKd)
	m.Write(ktDH2)
	m.Write(ktNi)
	m.Write(ktNr)
	seed := make([]byte, 0, 80)
	seed = append(seed, ktNi...)
	seed = append(seed, ktNr...)
	seed = append(seed, ktSPIi[:]...)
	seed = append(seed, ktSPIr[:]...)
	ref := ktPRFPlusRef(m.Sum(nil), seed, 168)
	ktEqual(t, "重协商 SK_d", k.SKd, ref[:32])
	ktEqual(t, "重协商 SK_ei", k.SKei, ref[32:68])

	// 与新建 SA 的派生必须不同——用错公式（沿用 §2.14）不会报错，只会让新 SA 立刻断流。
	fresh, err := DeriveIKEKeys(su, ktDH2, ktNi, ktNr, ktSPIi, ktSPIr)
	if err != nil {
		t.Fatalf("DeriveIKEKeys: %v", err)
	}
	if bytes.Equal(k.SKd, fresh.SKd) {
		t.Error("重协商派生与新建派生结果相同——SKEYSEED 公式没换")
	}
	if _, err := DeriveRekeyedIKEKeys(su, nil, ktDH2, ktNi, ktNr, ktSPIi, ktSPIr); err == nil {
		t.Error("缺少旧 SK_d 必须报错")
	}
	ktEqualHex(t, "重协商 SK_d 快照", k.SKd, "ec55f29db25939e137a78692a5f5ed724f8af61d4c25616f7412f04934603ef9")
}

// ── Child SA KEYMAT ──

// TestDeriveChildKeysOrder KEYMAT 顺序 encr_i ‖ integ_i ‖ encr_r ‖ integ_r（独立复算）。
//
// ★靶子是 encr_i‖encr_r‖integ_i‖integ_r 这个常见误读：两端会算出**一致但错位**的
// 密钥，握手全绿、ESP 解密恒失败。所以这里不能只断言"两端相等"，必须断言"与参考拼接相等"。
func TestDeriveChildKeysOrder(t *testing.T) {
	prf := ktPRF(t)

	t.Run("有PFS", func(t *testing.T) {
		ck, err := DeriveChildKeys(prf, ktSKd, ktDH2, ktNi, ktNr, 32, 32)
		if err != nil {
			t.Fatalf("DeriveChildKeys: %v", err)
		}
		seed := make([]byte, 0, 96)
		seed = append(seed, ktDH2...)
		seed = append(seed, ktNi...)
		seed = append(seed, ktNr...)
		ref := ktPRFPlusRef(ktSKd, seed, 128)
		ktEqual(t, "encr_i", ck.EncrI, ref[0:32])
		ktEqual(t, "integ_i", ck.IntegI, ref[32:64])
		ktEqual(t, "encr_r", ck.EncrR, ref[64:96])
		ktEqual(t, "integ_r", ck.IntegR, ref[96:128])
	})

	t.Run("无PFS", func(t *testing.T) {
		// dhShared 传 nil，seed 退化成 Ni‖Nr。
		ck, err := DeriveChildKeys(prf, ktSKd, nil, ktNi, ktNr, 36, 0)
		if err != nil {
			t.Fatalf("DeriveChildKeys: %v", err)
		}
		seed := append(append([]byte{}, ktNi...), ktNr...)
		ref := ktPRFPlusRef(ktSKd, seed, 72)
		ktEqual(t, "encr_i(GCM 36 字节含 salt)", ck.EncrI, ref[0:36])
		ktEqual(t, "encr_r(GCM 36 字节含 salt)", ck.EncrR, ref[36:72])
		if ck.IntegI != nil || ck.IntegR != nil {
			t.Error("integLen=0 时完整性密钥应为 nil（明确表达“没有这把钥匙”）")
		}
		// 无 PFS 与有 PFS 必须不同：漏拼 g^ir 是 PFS 形同虚设的静默形态。
		withPFS, err := DeriveChildKeys(prf, ktSKd, ktDH2, ktNi, ktNr, 36, 0)
		if err != nil {
			t.Fatalf("DeriveChildKeys: %v", err)
		}
		if bytes.Equal(ck.EncrI, withPFS.EncrI) {
			t.Error("带 g^ir 与不带 g^ir 派生出同一把密钥——PFS 没有真正参与")
		}
	})
}

// TestDeriveChildKeysSnapshot 快照锁死。
func TestDeriveChildKeysSnapshot(t *testing.T) {
	ck, err := DeriveChildKeys(ktPRF(t), ktSKd, ktDH2, ktNi, ktNr, 36, 0)
	if err != nil {
		t.Fatalf("DeriveChildKeys: %v", err)
	}
	ktEqualHex(t, "encr_i", ck.EncrI, "e244fb7495cd1663c392fd2c516c8953dafa6519b7457a7b76d029b338bf831c2ccd46e2")
	ktEqualHex(t, "encr_r", ck.EncrR, "0381b37149118f1bab4f86c538126f8320464e90fc2fde5324b453d1a90b79f193dbe734")
}

// ── 拒绝路径 ──

// TestDeriveKeysRejects 所有「不报错就会静默产出一条不安全隧道」的输入。
func TestDeriveKeysRejects(t *testing.T) {
	gcm, cbc := ktGCMSuite(t), ktCBCSuite(t)

	// AEAD 叠 INTEG：多派生两段，其后所有密钥整体错位。
	bad := *gcm
	bad.Integ, _ = LookupInteg(IntegHMACSHA256128)
	if _, err := DeriveIKEKeys(&bad, ktDH, ktNi, ktNr, ktSPIi, ktSPIr); err == nil {
		t.Error("combined 模式叠 INTEG 必须报错")
	}
	// 非 AEAD 缺 INTEG：报文没有任何完整性保护，而功能一切正常。
	bad2 := *cbc
	bad2.Integ = nil
	if _, err := DeriveIKEKeys(&bad2, ktDH, ktNi, ktNr, ktSPIi, ktSPIr); err == nil {
		t.Error("非 combined 模式缺 INTEG 必须报错")
	}

	cases := []struct {
		name       string
		su         *Suite
		dh, ni, nr []byte
	}{
		{"空套件", nil, ktDH, ktNi, ktNr},
		{"空 g^ir", gcm, nil, ktNi, ktNr},
		{"空 Ni", gcm, ktDH, nil, ktNr},
		{"空 Nr", gcm, ktDH, ktNi, nil},
	}
	for _, c := range cases {
		if _, err := DeriveIKEKeys(c.su, c.dh, c.ni, c.nr, ktSPIi, ktSPIr); err == nil {
			t.Errorf("%s 必须报错（空值也能算出一套自洽的密钥）", c.name)
		}
		if _, err := DeriveRekeyedIKEKeys(c.su, ktSKd, c.dh, c.ni, c.nr, ktSPIi, ktSPIr); err == nil {
			t.Errorf("重协商 · %s 必须报错", c.name)
		}
	}

	childCases := []struct {
		name              string
		prf               PRF
		skd, ni, nr       []byte
		encrLen, integLen int
	}{
		{"缺 PRF", nil, ktSKd, ktNi, ktNr, 32, 32},
		{"缺 SK_d", ktPRF(t), nil, ktNi, ktNr, 32, 32},
		{"缺 Ni", ktPRF(t), ktSKd, nil, ktNr, 32, 32},
		{"缺 Nr", ktPRF(t), ktSKd, ktNi, nil, 32, 32},
		{"加密密钥长度为 0", ktPRF(t), ktSKd, ktNi, ktNr, 0, 32},
		{"完整性密钥长度为负", ktPRF(t), ktSKd, ktNi, ktNr, 32, -1},
	}
	for _, c := range childCases {
		if _, err := DeriveChildKeys(c.prf, c.skd, nil, c.ni, c.nr, c.encrLen, c.integLen); err == nil {
			t.Errorf("Child SA · %s 必须报错", c.name)
		}
	}
}

// TestDerivedKeysDoNotAlias 七段密钥各自持有独立底层数组。
//
// 若它们共享同一个 prf+ 输出缓冲，任何一处 append 都会静默改写相邻密钥——
// 现象是「某天开始解密失败」，排查成本极高。cap==len 保证 append 必定重新分配。
func TestDerivedKeysDoNotAlias(t *testing.T) {
	k, err := DeriveIKEKeys(ktGCMSuite(t), ktDH, ktNi, ktNr, ktSPIi, ktSPIr)
	if err != nil {
		t.Fatalf("DeriveIKEKeys: %v", err)
	}
	for name, s := range map[string][]byte{"SKd": k.SKd, "SKei": k.SKei, "SKer": k.SKer, "SKpi": k.SKpi, "SKpr": k.SKpr} {
		if cap(s) != len(s) {
			t.Errorf("%s 的 cap=%d > len=%d，append 会踩到相邻密钥", name, cap(s), len(s))
		}
	}
	ck, err := DeriveChildKeys(ktPRF(t), ktSKd, nil, ktNi, ktNr, 32, 32)
	if err != nil {
		t.Fatalf("DeriveChildKeys: %v", err)
	}
	for name, s := range map[string][]byte{"EncrI": ck.EncrI, "IntegI": ck.IntegI, "EncrR": ck.EncrR, "IntegR": ck.IntegR} {
		if cap(s) != len(s) {
			t.Errorf("%s 的 cap=%d > len=%d", name, cap(s), len(s))
		}
	}
}
