package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"baidi.dev/gateway/internal/ipsec"
)

// 本文件守的核心命题只有一条：**控制台配了什么，线上就跑什么；对不上就必须报错。**
//
// 所以每条正例断言的是"字符串 → 具体码点"，每条反例断言的是"报错，而且错误信息里
// 带着用户填的那个原值"。后者尤其重要：一句「不支持的算法」会让管理员在三个字段里
// 挨个试，而「phase1.dh="group24" 不可用：本实现支持 group14 / group19 / sm2p256」
// 是可以直接照着改的。

func sutPhase(enc, hash, dh string) ipsec.Phase {
	return ipsec.Phase{Enc: enc, Hash: hash, DH: dh}
}

// sutWire 把一条提案编码成 SA 载荷体字节，用于逐字节检查线格式。
func sutWire(t *testing.T, p Proposal) []byte {
	t.Helper()
	sa := &SAPayload{Proposals: []Proposal{p}}
	return sa.appendBody(nil)
}

// TestSpecFromPhaseTable 每一条受支持的组合都映射到确切码点。
//
// 这张表就是 store.IpsecPhase 注释里承诺给控制台的全集；表里没有的字符串一律拒绝。
func TestSpecFromPhaseTable(t *testing.T) {
	cases := []struct {
		name     string
		ph       ipsec.Phase
		suite    string
		forChild bool
		want     SuiteSpec
	}{
		{
			"标准 · AES256-GCM/SHA256/group19（IKE）",
			sutPhase("AES256-GCM", "SHA256", "group19"), SuiteStandard, false,
			SuiteSpec{EncrAESGCM16, 256, PRFHMACSHA256, IntegNone, DHEcp256},
		},
		{
			"标准 · AES256-CBC/SHA256/group14（IKE）",
			sutPhase("AES256-CBC", "SHA256", "group14"), SuiteStandard, false,
			SuiteSpec{EncrAESCBC, 256, PRFHMACSHA256, IntegHMACSHA256128, DHModp2048},
		},
		{
			// ★ESP 提案不协商 PRF，故 PRFID 必须是 0。填上一个 PRF 会让提案里多出
			// 一个 ESP 根本不认的变换类型，对端多半直接 NO_PROPOSAL_CHOSEN。
			"标准 · AES256-GCM/SHA256/group19（Child）",
			sutPhase("AES256-GCM", "SHA256", "group19"), SuiteStandard, true,
			SuiteSpec{EncrAESGCM16, 256, 0, IntegNone, DHEcp256},
		},
		{
			"标准 · AES256-CBC/SHA256/group14（Child）",
			sutPhase("AES256-CBC", "SHA256", "group14"), SuiteStandard, true,
			SuiteSpec{EncrAESCBC, 256, 0, IntegHMACSHA256128, DHModp2048},
		},
		{
			// 国密走私有码点。SM4 只有 128 位密钥。
			"国密 · SM4-GCM/SM3/sm2p256（IKE）",
			sutPhase("SM4-GCM", "SM3", "sm2p256"), SuiteGM, false,
			SuiteSpec{EncrSM4GCM16, 128, PRFHMACSM3, IntegNone, DHSm2P256},
		},
		{
			"国密 · SM4-CBC/SM3/sm2p256（Child）",
			sutPhase("SM4-CBC", "SM3", "sm2p256"), SuiteGM, true,
			SuiteSpec{EncrSM4CBC, 128, 0, IntegHMACSM3128, DHSm2P256},
		},
		{
			// suite=gm 只是"放行私有码点"的闸门，不强制全套国密：
			// SM4-GCM 配 SHA256 在密码学上完全可用，拒绝它没有任何安全收益。
			"国密闸门下混用标准摘要",
			sutPhase("SM4-GCM", "SHA256", "group19"), SuiteGM, false,
			SuiteSpec{EncrSM4GCM16, 128, PRFHMACSHA256, IntegNone, DHEcp256},
		},
		{
			// 大小写与首尾空格不携带语义，不该成为一条永久 failed 的站点的成因。
			"大小写与空格归一化",
			sutPhase("  aes256-gcm ", "sha256", "GROUP19"), "STANDARD", false,
			SuiteSpec{EncrAESGCM16, 256, PRFHMACSHA256, IntegNone, DHEcp256},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := SpecFromPhase(c.ph, c.suite, c.forChild)
			if err != nil {
				t.Fatalf("映射失败: %v", err)
			}
			if got != c.want {
				t.Errorf("码点不符\n实际 %+v\n期望 %+v", got, c.want)
			}
			// 映射成功必须等价于"跑得起来"：立刻构造一次算法对象。
			if _, err := got.Build(); err != nil {
				t.Errorf("映射出来的码点构造不出算法: %v", err)
			}
		})
	}
}

// TestSpecFromPhaseRejects 不认识的值必须报错，且错误里带上原值与字段名。
//
// ★这是全文件最该常驻的一条。静默降级（比如未知算法回落成 AES128）造成的
// 「控制台配了 SM4-GCM、实际跑了 AES128」在任何一端都不会报错，
// 排障时没有任何线索会指向这里。
func TestSpecFromPhaseRejects(t *testing.T) {
	cases := []struct {
		name      string
		ph        ipsec.Phase
		suite     string
		forChild  bool
		wantField string
		wantValue string
	}{
		{"未知加密算法", sutPhase("AES128-CTR", "SHA256", "group19"), SuiteStandard, false, "phase1.enc", "AES128-CTR"},
		{"未知摘要", sutPhase("AES256-GCM", "SHA1", "group19"), SuiteStandard, false, "phase1.hash", "SHA1"},
		{"未实现的 DH 群 group24", sutPhase("AES256-GCM", "SHA256", "group24"), SuiteStandard, false, "phase1.dh", "group24"},
		{"Child 相的字段前缀是 phase2", sutPhase("3DES", "SHA256", "group14"), SuiteStandard, true, "phase2.enc", "3DES"},
		{"DH 留空也要拒", sutPhase("AES256-GCM", "SHA256", ""), SuiteStandard, false, "phase1.dh", ""},
		{"未知 suite", sutPhase("AES256-GCM", "SHA256", "group19"), "quantum", false, "suite", "quantum"},
		// ★私有码点闸门：suite=standard 下配国密算法必须拒。放行的话，一条
		// 「对外声称标准、实际只有白帝能连」的隧道就诞生了，且界面上看不出来。
		{"standard 下用 SM4", sutPhase("SM4-GCM", "SHA256", "group19"), SuiteStandard, false, "phase1.enc", "SM4-GCM"},
		{"standard 下用 SM3", sutPhase("AES256-GCM", "SM3", "group19"), SuiteStandard, false, "phase1.hash", "SM3"},
		{"standard 下用 sm2p256", sutPhase("AES256-GCM", "SHA256", "sm2p256"), SuiteStandard, false, "phase1.dh", "sm2p256"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := SpecFromPhase(c.ph, c.suite, c.forChild)
			if err == nil {
				t.Fatal("必须报错")
			}
			var se *SpecError
			if !errors.As(err, &se) {
				t.Fatalf("错误类型不是 *SpecError（上层要 errors.As 出 Field 填进 ipsec.ConfigError）: %T", err)
			}
			if se.Field != c.wantField {
				t.Errorf("Field=%q，应为 %q", se.Field, c.wantField)
			}
			if se.Value != c.wantValue {
				t.Errorf("Value=%q，应原样带上用户填的值 %q", se.Value, c.wantValue)
			}
			// 错误信息本身要能直接指导排障：既有原值，也有"支持哪些"。
			msg := err.Error()
			if c.wantValue != "" && !strings.Contains(msg, c.wantValue) {
				t.Errorf("错误信息里没有原值 %q：%s", c.wantValue, msg)
			}
			if !strings.Contains(msg, c.wantField) {
				t.Errorf("错误信息里没有字段名 %q：%s", c.wantField, msg)
			}
		})
	}

	// 私有码点被拒时必须指明"改成 suite=gm 就能用"，否则管理员会以为国密压根没实现。
	_, err := SpecFromPhase(sutPhase("SM4-GCM", "SM3", "sm2p256"), SuiteStandard, false)
	if err == nil || !strings.Contains(err.Error(), SuiteGM) {
		t.Errorf("拒绝私有码点时应提示 suite=%s：%v", SuiteGM, err)
	}
}

// TestSpecFromPhaseSeeds control 的三条种子站点必须全部映射得出来。
//
// ★种子里留一条永远映射不出来的站点，等于把「本实现不支持」伪装成「对端有问题」。
// 这条测试把 store/ipsec.go 的种子与本包的能力集绑在一起：改了任一边都会红。
func TestSpecFromPhaseSeeds(t *testing.T) {
	seeds := []struct {
		name   string
		suite  string
		p1, p2 ipsec.Phase
	}{
		{"site-sh 上海分支", SuiteStandard, sutPhase("AES256-GCM", "SHA256", "group19"), sutPhase("AES256-GCM", "SHA256", "group19")},
		{"site-gz 广州分支（国密）", SuiteGM, sutPhase("SM4-GCM", "SM3", "sm2p256"), sutPhase("SM4-GCM", "SM3", "sm2p256")},
		{"site-cd 成都分支", SuiteStandard, sutPhase("AES256-CBC", "SHA256", "group14"), sutPhase("AES256-CBC", "SHA256", "group14")},
	}
	for _, s := range seeds {
		t.Run(s.name, func(t *testing.T) {
			if _, err := SpecFromPhase(s.p1, s.suite, false); err != nil {
				t.Errorf("phase1 映射失败: %v", err)
			}
			if _, err := SpecFromPhase(s.p2, s.suite, true); err != nil {
				t.Errorf("phase2 映射失败: %v", err)
			}
		})
	}
}

// TestSuiteSpecBuild 构造出的算法对象参数正确，且两条一致性闸都拦得住。
func TestSuiteSpecBuild(t *testing.T) {
	gcm, err := SuiteSpec{EncrAESGCM16, 256, PRFHMACSHA256, IntegNone, DHEcp256}.Build()
	if err != nil {
		t.Fatalf("构造 GCM 套件: %v", err)
	}
	if !gcm.Encr.Combined() {
		t.Error("AES-GCM 应为 combined 模式")
	}
	if gcm.Encr.KeyLen() != 36 {
		t.Errorf("AES-256-GCM 的密钥材料应为 36 字节（32 密钥 + 4 salt），实际 %d", gcm.Encr.KeyLen())
	}
	if gcm.Integ != nil || gcm.IntegKeyLen() != 0 {
		t.Error("combined 模式不该有 INTEG")
	}
	if gcm.DH == nil || gcm.DH.ID() != DHEcp256 {
		t.Error("DH 群没构造出来")
	}
	if gcm.ESN {
		t.Error("本轮不实现 ESN，Suite.ESN 必须为 false")
	}

	cbc, err := SuiteSpec{EncrAESCBC, 256, PRFHMACSHA256, IntegHMACSHA256128, DHModp2048}.Build()
	if err != nil {
		t.Fatalf("构造 CBC 套件: %v", err)
	}
	if cbc.Encr.Combined() || cbc.Integ == nil || cbc.IntegKeyLen() != 32 {
		t.Error("CBC 套件必须带 32 字节 INTEG 密钥")
	}

	// ESP 的 spec 没有 PRF（PRFID=0），Suite.PRF 应为 nil 且不报错。
	esp, err := SuiteSpec{EncrAESGCM16, 256, 0, IntegNone, DHNone}.Build()
	if err != nil {
		t.Fatalf("构造 ESP 套件: %v", err)
	}
	if esp.PRF != nil {
		t.Error("ESP 提案不协商 PRF，Suite.PRF 应为 nil")
	}
	if esp.DH != nil {
		t.Error("DHNone 应构造出 nil DH 群")
	}

	// 两条一致性闸。
	if _, err := (SuiteSpec{EncrAESGCM16, 256, PRFHMACSHA256, IntegHMACSHA256128, DHEcp256}).Build(); err == nil {
		t.Error("combined 模式叠 INTEG 必须报错（会多派生两段密钥导致整体错位）")
	}
	if _, err := (SuiteSpec{EncrAESCBC, 256, PRFHMACSHA256, IntegNone, DHEcp256}).Build(); err == nil {
		t.Error("非 combined 模式缺 INTEG 必须报错（报文将毫无完整性保护而功能一切正常）")
	}
	// 漏发 Key Length 的 AES：LookupEncr 必须拒绝而不是猜一个默认值。
	if _, err := (SuiteSpec{EncrAESGCM16, 0, PRFHMACSHA256, IntegNone, DHEcp256}).Build(); err == nil {
		t.Error("AES 未给密钥长度必须报错（猜一个默认值就是「协商成功后认证失败」的经典造法）")
	}
}

// TestIKEProposalWire IKE 提案的线格式。
//
// ★关键断言是 Key Length 属性 `80 0E 01 00`：AES 提案漏掉它不会协商失败，
// 而是双方各按不同长度切密钥，症状退化成一句无头无尾的「认证失败」。
func TestIKEProposalWire(t *testing.T) {
	spec := SuiteSpec{EncrAESGCM16, 256, PRFHMACSHA256, IntegNone, DHEcp256}
	pr := spec.IKEProposal(1)

	if pr.Protocol != ProtocolIKE {
		t.Errorf("Protocol=%d，应为 IKE", pr.Protocol)
	}
	// IKE_SA_INIT 的 IKE 提案 SPI 长度必须是 0——SPI 在报文头里。
	if len(pr.SPI) != 0 {
		t.Errorf("IKE 提案的 SPI 长度应为 0，实际 %d", len(pr.SPI))
	}
	want := map[TransformType]uint16{
		TransformEncr:  EncrAESGCM16,
		TransformPRF:   PRFHMACSHA256,
		TransformInteg: IntegNone,
		TransformDH:    DHEcp256,
	}
	for tt, id := range want {
		x, ok := pr.FindTransform(tt)
		if !ok {
			t.Errorf("缺少 %s 变换（IKE 提案缺任一类型，对端就回 NO_PROPOSAL_CHOSEN）", tt)
			continue
		}
		if x.ID != id {
			t.Errorf("%s 的 ID=%d，应为 %d", tt, x.ID, id)
		}
	}
	if _, ok := pr.FindTransform(TransformESN); ok {
		t.Error("IKE 提案不该带 ESN（ESN 只属于 ESP）")
	}

	raw := sutWire(t, pr)
	if !bytes.Contains(raw, []byte{0x80, 0x0E, 0x01, 0x00}) {
		t.Errorf("线格式里没有 AES-256 的 Key Length 属性 80 0E 01 00：% x", raw)
	}
	// 编解码往返：解析回来必须还是同一个 spec。
	var sa SAPayload
	if err := sa.parseBody(raw); err != nil {
		t.Fatalf("解析自己编出来的提案失败: %v", err)
	}
	got, err := SpecFromProposal(sa.Proposals[0])
	if err != nil {
		t.Fatalf("SpecFromProposal: %v", err)
	}
	if got != spec {
		t.Errorf("往返后码点变了\n实际 %+v\n期望 %+v", got, spec)
	}

	// 国密：SM4 是 128 位，属性应为 80 0E 00 80。
	gmRaw := sutWire(t, SuiteSpec{EncrSM4GCM16, 128, PRFHMACSM3, IntegNone, DHSm2P256}.IKEProposal(1))
	if !bytes.Contains(gmRaw, []byte{0x80, 0x0E, 0x00, 0x80}) {
		t.Errorf("SM4 提案缺少 128 位的 Key Length 属性：% x", gmRaw)
	}
}

// TestESPProposalWire ESP 提案的线格式：SPI 4 字节网络序、ESN=0、DH 随 PFS。
func TestESPProposalWire(t *testing.T) {
	spec := SuiteSpec{EncrAESCBC, 256, 0, IntegHMACSHA256128, DHModp2048}

	t.Run("开PFS", func(t *testing.T) {
		pr := spec.ESPProposal(1, 0xDEADBEEF, true)
		if pr.Protocol != ProtocolESP {
			t.Errorf("Protocol=%d，应为 ESP", pr.Protocol)
		}
		if len(pr.SPI) != 4 {
			t.Fatalf("ESP 提案的 SPI 长度应为 4，实际 %d", len(pr.SPI))
		}
		if got := binary.BigEndian.Uint32(pr.SPI); got != 0xDEADBEEF {
			t.Errorf("SPI=%#x，应为 0xDEADBEEF（字节序写反会得到一个完全合法但对端收不到包的值）", got)
		}
		if spi, err := pr.ESPSPI(); err != nil || spi != 0xDEADBEEF {
			t.Errorf("ESPSPI()=%#x, err=%v", spi, err)
		}
		if x, ok := pr.FindTransform(TransformDH); !ok || x.ID != DHModp2048 {
			t.Error("开 PFS 时必须带 D-H 变换")
		}
		if x, ok := pr.FindTransform(TransformESN); !ok || x.ID != ESNNone {
			t.Error("ESP 提案必须显式提 ESN=0")
		}
		if _, ok := pr.FindTransform(TransformPRF); ok {
			t.Error("ESP 提案不该带 PRF")
		}
	})

	t.Run("关PFS", func(t *testing.T) {
		pr := spec.ESPProposal(2, 0x01020304, false)
		if _, ok := pr.FindTransform(TransformDH); ok {
			t.Error("关 PFS 时不该带 D-H 变换（RFC 允许省略，兼容性最好）")
		}
		if !bytes.Equal(pr.SPI, []byte{0x01, 0x02, 0x03, 0x04}) {
			t.Errorf("SPI 字节序不对：% x", pr.SPI)
		}
	})

	t.Run("要PFS但套件没DH必须炸", func(t *testing.T) {
		// ★静默发出一条没有 D-H 的提案 = 悄悄把 PFS 关掉：对端照单全收、
		// 隧道正常建立、界面显示 PFS 已启用，而前向保密根本不存在。
		defer func() {
			if recover() == nil {
				t.Error("PFS=true 且 DHID=0 时必须 panic，不能静默降级")
			}
		}()
		SuiteSpec{EncrAESCBC, 256, 0, IntegHMACSHA256128, DHNone}.ESPProposal(1, 0x1000, true)
	})
}

// TestSpecFromProposalRejects 协商结果里每种类型只能有一个，且不接受 ESN。
func TestSpecFromProposalRejects(t *testing.T) {
	cases := []struct {
		name string
		pr   Proposal
		want string
	}{
		{
			"没有 ENCR",
			Proposal{Num: 1, Protocol: ProtocolIKE, Transforms: []Transform{{Type: TransformPRF, ID: PRFHMACSHA256}}},
			"ENCR",
		},
		{
			// 两个 ENCR 意味着两端可能各选各的，而这种分歧的症状是解密失败、不是协商失败。
			"两个 ENCR",
			Proposal{Num: 1, Protocol: ProtocolIKE, Transforms: []Transform{
				{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256},
				{Type: TransformEncr, ID: EncrAESCBC, KeyLen: 256},
				{Type: TransformPRF, ID: PRFHMACSHA256},
				{Type: TransformDH, ID: DHEcp256},
			}},
			"2 个",
		},
		{
			"选了 ESN",
			Proposal{Num: 1, Protocol: ProtocolESP, SPI: []byte{0, 0, 0x10, 0}, Transforms: []Transform{
				{Type: TransformEncr, ID: EncrAESGCM16, KeyLen: 256},
				{Type: TransformESN, ID: ESNUse},
			}},
			"ESN",
		},
		{
			// AES 漏发 Key Length：不猜默认值，报出带实际值的错误。
			"AES 漏发 Key Length",
			Proposal{Num: 1, Protocol: ProtocolIKE, Transforms: []Transform{
				{Type: TransformEncr, ID: EncrAESGCM16},
				{Type: TransformPRF, ID: PRFHMACSHA256},
				{Type: TransformDH, ID: DHEcp256},
			}},
			"密钥",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := SpecFromProposal(c.pr)
			if err == nil {
				t.Fatal("必须报错")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误信息里应含 %q：%v", c.want, err)
			}
		})
	}

	// SM4 可以漏发 Key Length（只有 128 位一种），能确定地补齐。
	pr := Proposal{Num: 1, Protocol: ProtocolESP, SPI: []byte{0, 0, 0x10, 0}, Transforms: []Transform{
		{Type: TransformEncr, ID: EncrSM4GCM16},
		{Type: TransformESN, ID: ESNNone},
	}}
	got, err := SpecFromProposal(pr)
	if err != nil {
		t.Fatalf("SM4 漏发 Key Length 应能补齐: %v", err)
	}
	if got.KeyBits != 128 {
		t.Errorf("SM4 的密钥长度应补成 128，实际 %d", got.KeyBits)
	}
}

// TestSelectProposal 提案选择的正例与全部反例。
func TestSelectProposal(t *testing.T) {
	ikeWant := SuiteSpec{EncrAESGCM16, 256, PRFHMACSHA256, IntegNone, DHEcp256}
	espWant := SuiteSpec{EncrAESCBC, 256, 0, IntegHMACSHA256128, DHModp2048}
	espNoPFS := SuiteSpec{EncrAESCBC, 256, 0, IntegHMACSHA256128, DHNone}

	t.Run("IKE 命中", func(t *testing.T) {
		offered := []Proposal{ikeWant.IKEProposal(1)}
		sel, spec, err := SelectProposal(offered, ikeWant, ProtocolIKE)
		if err != nil {
			t.Fatalf("应当命中: %v", err)
		}
		if sel.Num != 1 || spec != ikeWant {
			t.Errorf("选中结果不对：Num=%d spec=%+v", sel.Num, spec)
		}
	})

	t.Run("多条提案里命中第二条", func(t *testing.T) {
		other := SuiteSpec{EncrAESCBC, 256, PRFHMACSHA256, IntegHMACSHA256128, DHModp2048}.IKEProposal(1)
		mine := ikeWant.IKEProposal(2)
		sel, _, err := SelectProposal([]Proposal{other, mine}, ikeWant, ProtocolIKE)
		if err != nil {
			t.Fatalf("应当命中第二条: %v", err)
		}
		if sel.Num != 2 {
			t.Errorf("选中的 Proposal Num=%d，应为 2（响应必须回选中的那个编号）", sel.Num)
		}
	})

	t.Run("combined 模式省略 INTEG 也接受", func(t *testing.T) {
		// strongSwan 对 AEAD 是**省略** INTEG 变换的；本实现按设计显式发 INTEG=0。
		// 收侧必须两种都认，只认一种会莫名其妙地 NO_PROPOSAL_CHOSEN。
		pr := ikeWant.IKEProposal(1)
		var kept []Transform
		for _, x := range pr.Transforms {
			if x.Type != TransformInteg {
				kept = append(kept, x)
			}
		}
		pr.Transforms = kept
		if _, _, err := SelectProposal([]Proposal{pr}, ikeWant, ProtocolIKE); err != nil {
			t.Errorf("省略 INTEG 的 AEAD 提案应当接受: %v", err)
		}
	})

	t.Run("ESP 命中并取出对端 SPI", func(t *testing.T) {
		offered := []Proposal{espWant.ESPProposal(1, 0x11223344, true)}
		sel, _, err := SelectProposal(offered, espWant, ProtocolESP)
		if err != nil {
			t.Fatalf("应当命中: %v", err)
		}
		spi, err := sel.ESPSPI()
		if err != nil || spi != 0x11223344 {
			t.Errorf("对端 SPI=%#x err=%v", spi, err)
		}
	})

	t.Run("ESP 未开 PFS 时拒绝对端的 D-H", func(t *testing.T) {
		// ★接受它等于**静默把 PFS 降级掉**：安全属性的降级必须谈崩，不能悄悄接受。
		offered := []Proposal{espWant.ESPProposal(1, 0x11223344, true)}
		_, _, err := SelectProposal(offered, espNoPFS, ProtocolESP)
		if err == nil {
			t.Fatal("对端要 PFS、本端没开，不该选中")
		}
		if !strings.Contains(err.Error(), "PFS") {
			t.Errorf("错误信息应点明是 PFS 分歧：%v", err)
		}
	})

	t.Run("ESP SPI 落在保留区间", func(t *testing.T) {
		// SPI=0 在 UDP-4500 上与 non-ESP marker 撞形；1..255 是 IANA 保留。
		for _, spi := range []uint32{0, 1, 255} {
			pr := espWant.ESPProposal(1, spi, true)
			if _, _, err := SelectProposal([]Proposal{pr}, espWant, ProtocolESP); err == nil {
				t.Errorf("SPI=%d 应当被拒", spi)
			}
		}
		if _, _, err := SelectProposal([]Proposal{espWant.ESPProposal(1, 256, true)}, espWant, ProtocolESP); err != nil {
			t.Errorf("SPI=256 是合法的最小值: %v", err)
		}
	})

	t.Run("落选原因必须同时含双方信息", func(t *testing.T) {
		offered := []Proposal{SuiteSpec{EncrAESCBC, 256, PRFHMACSHA256, IntegHMACSHA256128, DHModp2048}.IKEProposal(1)}
		_, _, err := SelectProposal(offered, ikeWant, ProtocolIKE)
		if err == nil {
			t.Fatal("套件不相交，必须谈崩")
		}
		msg := err.Error()
		// ★只回一个 NO_PROPOSAL_CHOSEN 码点等于什么都没说：两端管理员各改各的配置
		// 能耗掉一整天。错误里必须能看出「对端提了什么」与「本端要什么」。
		for _, want := range []string{"AES256-GCM16", "ENCR=12"} {
			if !strings.Contains(msg, want) {
				t.Errorf("落选原因里缺少 %q：%s", want, msg)
			}
		}
	})

	t.Run("协议不符", func(t *testing.T) {
		offered := []Proposal{espWant.ESPProposal(1, 0x1000, true)}
		if _, _, err := SelectProposal(offered, ikeWant, ProtocolIKE); err == nil {
			t.Error("ESP 提案不该被当作 IKE 提案选中")
		}
	})

	t.Run("密钥长度不符", func(t *testing.T) {
		pr := ikeWant.IKEProposal(1)
		for i := range pr.Transforms {
			if pr.Transforms[i].Type == TransformEncr {
				pr.Transforms[i].KeyLen = 128
			}
		}
		if _, _, err := SelectProposal([]Proposal{pr}, ikeWant, ProtocolIKE); err == nil {
			t.Error("128 位对 256 位不该命中（这正是「协商成功后认证失败」的成因）")
		}
	})

	t.Run("空提案列表", func(t *testing.T) {
		if _, _, err := SelectProposal(nil, ikeWant, ProtocolIKE); err == nil {
			t.Error("空提案列表必须报错")
		}
	})

	t.Run("ESP 完全不提 ESN 时宽容", func(t *testing.T) {
		pr := espWant.ESPProposal(1, 0x2000, true)
		var kept []Transform
		for _, x := range pr.Transforms {
			if x.Type != TransformESN {
				kept = append(kept, x)
			}
		}
		pr.Transforms = kept
		if _, _, err := SelectProposal([]Proposal{pr}, espWant, ProtocolESP); err != nil {
			t.Errorf("对端不提 ESN 时应按「不用 ESN」处理: %v", err)
		}
	})

	t.Run("ESP 只提 ESN=1 必须拒", func(t *testing.T) {
		pr := espWant.ESPProposal(1, 0x2000, true)
		for i := range pr.Transforms {
			if pr.Transforms[i].Type == TransformESN {
				pr.Transforms[i].ID = ESNUse
			}
		}
		if _, _, err := SelectProposal([]Proposal{pr}, espWant, ProtocolESP); err == nil {
			t.Error("本实现的反重放窗口按 32 位序号写，不能接受 ESN")
		}
	})
}

// TestForPFSNormalizesDH 关 PFS 时 DH 群必须被清零，否则一条配置正确的站点永远谈不拢。
//
// ★SpecFromPhase(phase2, …, true) 总是带回一个 DH 群（Phase2.DH 是必填项），
// 而关了 PFS 的对端提案里根本没有 D-H 变换。不清零 → matchDH 判「候选为空」→
// 站点永久 failed，而错误信息还指着 DH 群，极具误导性。
func TestForPFSNormalizesDH(t *testing.T) {
	spec, err := SpecFromPhase(sutPhase("AES256-CBC", "SHA256", "group14"), SuiteStandard, true)
	if err != nil {
		t.Fatalf("映射失败: %v", err)
	}
	if spec.DHID != DHModp2048 {
		t.Fatalf("Phase2 的 DH 群应原样保留，实际 %d", spec.DHID)
	}
	if got := spec.ForPFS(true); got != spec {
		t.Error("ForPFS(true) 不该改动 spec")
	}
	off := spec.ForPFS(false)
	if off.DHID != DHNone {
		t.Errorf("ForPFS(false) 后 DHID=%d，应为 0", off.DHID)
	}
	if off.EncrID != spec.EncrID || off.IntegID != spec.IntegID || off.KeyBits != spec.KeyBits {
		t.Error("ForPFS 只该动 DH 群")
	}

	// 端到端：对端发来不带 D-H 的 ESP 提案，用归一化后的 spec 必须命中。
	peer := off.ESPProposal(1, 0x30000, false)
	if _, _, err := SelectProposal([]Proposal{peer}, off, ProtocolESP); err != nil {
		t.Errorf("关 PFS 的提案应当命中: %v", err)
	}
	// 不归一化则谈不拢——这正是本方法要挡住的失败。
	if _, _, err := SelectProposal([]Proposal{peer}, spec, ProtocolESP); err == nil {
		t.Error("没归一化时本该谈不拢（说明这条测试没有真的守住什么）")
	}
}

// TestSuiteSpecString 协商结果文案。
//
// ★它是 SiteState.NegotiatedProposal 的来源，必须显示**真实算法**而不是 suite 标签——
// 「配的是 A、谈出来 B」时能被一眼看出来，正是"真的在谈判"最直观的证据。
func TestSuiteSpecString(t *testing.T) {
	cases := []struct {
		spec SuiteSpec
		want string
	}{
		{SuiteSpec{EncrAESGCM16, 256, PRFHMACSHA256, IntegNone, DHEcp256}, "AES256-GCM16/PRF-HMAC-SHA256/ECP256"},
		{SuiteSpec{EncrAESCBC, 256, PRFHMACSHA256, IntegHMACSHA256128, DHModp2048}, "AES256-CBC/PRF-HMAC-SHA256/HMAC-SHA256-128/MODP2048"},
		{SuiteSpec{EncrSM4GCM16, 128, PRFHMACSM3, IntegNone, DHSm2P256}, "SM4-GCM16/PRF-HMAC-SM3/SM2P256"},
		{SuiteSpec{EncrAESGCM16, 256, 0, IntegNone, DHNone}, "AES256-GCM16"}, // ESP 无 PFS
		{SuiteSpec{EncrSM4CBC, 128, 0, IntegHMACSM3128, DHSm2P256}, "SM4-CBC/HMAC-SM3-128/SM2P256"},
		// 未知码点也要打得出来：只回一个 NO_PROPOSAL_CHOSEN 等于什么都没说。
		{SuiteSpec{9999, 192, 8888, 7777, 6666}, "ENCR(9999)/192/PRF(8888)/INTEG(7777)/DH(6666)"},
	}
	for _, c := range cases {
		if got := c.spec.String(); got != c.want {
			t.Errorf("String()=%q，应为 %q", got, c.want)
		}
	}
}

// TestESPSPIErrors ESPSPI 的两条拒绝路径。
func TestESPSPIErrors(t *testing.T) {
	if _, err := (Proposal{Protocol: ProtocolIKE}).ESPSPI(); err == nil {
		t.Error("IKE 提案没有 4 字节 SPI，应报错")
	}
	if _, err := (Proposal{Protocol: ProtocolESP, SPI: []byte{1, 2}}).ESPSPI(); err == nil {
		t.Error("SPI 长度不是 4，应报错")
	}
}
