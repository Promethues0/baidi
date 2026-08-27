package api

import (
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// IPSec 站点保存必须校验密码套件组合，与数据面 ike.SpecFromPhase 的拒绝判据同真同假。
//
// 缺这道校验的后果：管理员选「标准」套件、加密改成 SM4-GCM，页面不置灰、保存回 200、
// 站点列表看起来一切正常且无 ConfigWarning，而承载网关在装载期就把它拒掉、隧道永远
// 建不起来；若站点尚未指派网关或组网网关未上线，连 SA 的 LastError 都没有，
// 站点安静地停在 connecting。这是 wave8 行动 17（peer 收 FQDN）在同一个函数里的另一半。
//
// ★两侧分属两个 go module，控制面不能 import 数据面那个校验函数，所以这里用表驱动
// 锁死行为——每个基准对旁边注明它对应数据面的哪条规则（ike/suite.go）。
func TestIpsecSuiteValidation(t *testing.T) {
	site := func(suite, enc, hash, dh string) store.IpsecSite {
		return store.IpsecSite{
			ID: "s1", Name: "站点", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.30.0.0/16",
			Peer: "203.0.113.9", Suite: suite,
			Phase1: store.IpsecPhase{Enc: enc, Hash: hash, DH: dh},
			Phase2: store.IpsecPhase{Enc: enc, Hash: hash, DH: dh},
		}
	}
	cases := []struct {
		name              string
		suite, e, h, d    string
		wantOK            bool
		note              string
	}{
		// 数据面：suiteAllowsPrivate(standard)=false → 私有码点全拒
		{"标准全 RFC", "standard", "AES256-GCM", "SHA256", "group19", true, "全 RFC 码点"},
		{"标准配 SM4", "standard", "SM4-GCM", "SHA256", "group19", false, "SM4 是私有码点，standard 下 enc.private && !allowPrivate → 拒"},
		{"标准配 SM3", "standard", "AES256-GCM", "SM3", "group19", false, "SM3 私有码点，hash.private 拒"},
		{"标准配 sm2p256", "standard", "AES256-GCM", "SHA256", "sm2p256", false, "sm2p256 私有码点，dh.private 拒"},
		// 数据面：suiteAllowsPrivate(gm)=true → 私有码点放行
		{"国密全私有", "gm", "SM4-GCM", "SM3", "sm2p256", true, "gm 放行私有码点"},
		// ★数据面明写 suite 只是闸门、不强制全套国密：SM4-GCM 配 SHA256 完全可用
		{"国密混标准摘要", "gm", "SM4-GCM", "SHA256", "group19", true, "SpecFromPhase 注释：拒绝它没有安全收益，入口不得更严"},
		// 不认识的算法一律拒（同 lookupEnc/lookupHash 的"不认识就报错"）
		{"未知算法", "standard", "AES128-GCM", "SHA256", "group19", false, "AES128 不在支持集内"},
		{"空算法", "standard", "", "SHA256", "group19", false, "enc 为空"},
	}
	for _, c := range cases {
		msg := validateIpsecSite(site(c.suite, c.e, c.h, c.d))
		gotOK := msg == ""
		if gotOK != c.wantOK {
			t.Errorf("[%s] 期望 ok=%v 实得 ok=%v（%s）；msg=%q", c.name, c.wantOK, gotOK, c.note, msg)
		}
		// 拒绝时理由要说得出是套件问题，别让人对着一句笼统的话反复试
		if !gotOK && !c.wantOK && strings.Contains(c.name, "配") {
			if !strings.Contains(msg, "私有码点") && !strings.Contains(msg, "suite") {
				t.Errorf("[%s] 拒绝理由要点名套件/私有码点：%s", c.name, msg)
			}
		}
	}
}

// 只填网段与对端、不填算法时，按 suite 补默认，而不是拒收
// （空 enc 在数据面 lookupEnc 会失败，但那是"没填"不是"填错"，产品行为应是补默认）。
func TestIpsecFillsSuiteDefaults(t *testing.T) {
	std := store.IpsecSite{Name: "标准站点", Peer: "203.0.113.9",
		LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.80.0.0/16", Suite: "standard"}
	fillIpsecSuiteDefaults(&std)
	if std.Phase1.Enc != "AES256-GCM" || std.Phase1.Hash != "SHA256" || std.Phase1.DH != "group19" {
		t.Errorf("standard 默认应是 AES256-GCM/SHA256/group19，实得 %+v", std.Phase1)
	}
	if validateIpsecSite(std) != "" {
		t.Errorf("补默认后应校验通过：%s", validateIpsecSite(std))
	}

	gm := store.IpsecSite{Name: "国密站点", Peer: "203.0.113.9",
		LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.80.0.0/16", Suite: "gm"}
	fillIpsecSuiteDefaults(&gm)
	if gm.Phase1.Enc != "SM4-GCM" || gm.Phase1.Hash != "SM3" || gm.Phase1.DH != "sm2p256" {
		t.Errorf("gm 默认应是 SM4-GCM/SM3/sm2p256，实得 %+v", gm.Phase1)
	}

	// ★半配不补：只填了 enc、漏了 hash/dh，往往是笔误，交给校验报错而不是替他猜。
	half := store.IpsecSite{Name: "半配", Peer: "203.0.113.9",
		LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.80.0.0/16", Suite: "standard",
		Phase1: store.IpsecPhase{Enc: "AES256-GCM"}}
	fillIpsecSuiteDefaults(&half)
	if half.Phase1.Hash != "" {
		t.Error("半配阶段不该被默认值补全——那会把笔误掩盖成一个能保存的配置")
	}
	if validateIpsecSite(half) == "" {
		t.Error("半配应被 validateIpsecSite 拦住")
	}
}
