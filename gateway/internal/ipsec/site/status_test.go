package site

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"baidi.dev/gateway/internal/ipsec"
)

// 辅助一律加 stt 前缀（status test）。

// ★错误码点的译文必须回答"接下来该查什么"。
// 「NO_PROPOSAL_CHOSEN」原样甩给用户等于没说；
// 这里逐条断言译文里出现了对应的排障线索关键词。
func TestExplainNotifyIsActionable(t *testing.T) {
	for _, tc := range []struct {
		code uint16
		want []string
	}{
		{notifyNoProposalChosen, []string{"套件", "DH", "gm"}},
		{notifyAuthenticationFailed, []string{"PSK", "localId", "NAT"}},
		{notifyTSUnacceptable, []string{"镜像", "localSubnet", "remoteSubnet"}},
		{notifyInvalidKEPayload, []string{"phase1.dh"}},
		{notifyTemporaryFailure, []string{"自动重试"}},
		{notifyInvalidMajorVersion, []string{"IKEv2"}},
	} {
		got := ExplainNotify(tc.code)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("码点 %d 的译文里缺少排障线索 %q：%s", tc.code, w, got)
			}
		}
	}
}

// 未识别的码点也要分清是"错误"还是"可忽略的状态"——
// 把状态类当错误处理会导致完全无法与 strongSwan 之类的实现建连。
func TestExplainNotifyUnknownCodes(t *testing.T) {
	if s := ExplainNotify(999); !strings.Contains(s, "错误") {
		t.Errorf("小于 16384 的未知码点应当被说成错误：%s", s)
	}
	if s := ExplainNotify(16999); !strings.Contains(s, "忽略") {
		t.Errorf("大于等于 16384 的未知码点应当被说成可忽略的状态：%s", s)
	}
}

func TestExplainErrors(t *testing.T) {
	ce := &ipsec.ConfigError{SiteID: "site-x", Field: "phase1.dh", Reason: "group24 不支持"}
	if got := Explain(ce); !strings.Contains(got, "site-x") || !strings.Contains(got, "group24") {
		t.Errorf("ConfigError 应原样透出站点与取值：%s", got)
	}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{ipsec.ErrNoPolicy, "remoteSubnet"},
		{ipsec.ErrTSMismatch, "越权"},
		{ipsec.ErrAuth, "密钥"},
		{fmt.Errorf("包了一层：%w", ipsec.ErrReplay), "重放"},
	} {
		if got := Explain(tc.err); !strings.Contains(got, tc.want) {
			t.Errorf("%v 的译文里缺少 %q：%s", tc.err, tc.want, got)
		}
	}
	if Explain(nil) != "" {
		t.Errorf("nil 应译成空串")
	}
	if got := Explain(errors.New("原样透传")); got != "原样透传" {
		t.Errorf("未识别的错误应原样透传，实得 %q", got)
	}
}

// ★配置摘要绝不能带 PSK。
// 日志会被归档、被转发、被贴进工单——一次打印就是一次永久泄漏。
func TestDescribeConfigNeverLeaksPSK(t *testing.T) {
	c := bktCfg("site-a")
	c.PSK = []byte("SUPER-SECRET-PSK-DO-NOT-PRINT")
	got := DescribeConfig(c)
	if strings.Contains(got, "SUPER-SECRET") {
		t.Fatalf("★配置摘要里出现了 PSK 原文：%s", got)
	}
	for _, w := range []string{"site-a", "203.0.113.88", "10.10.0.0/16", "10.20.0.0/16"} {
		if !strings.Contains(got, w) {
			t.Errorf("摘要里缺少 %q（少了它就没法据以排障）：%s", w, got)
		}
	}
}

func TestDescribeState(t *testing.T) {
	st := ipsec.SiteState{
		SiteID: "site-a", State: ipsec.StateUp,
		IKESPIi: "aabbccdd00112233", IKESPIr: "44556677889900aa",
		ChildSPIIn: 0x1234, ChildSPIOut: 0x5678,
		NegotiatedProposal: "AES256-GCM16/PRF-HMAC-SHA256/ECP256",
		Counters:           ipsec.Counters{RxBytes: 100, TxBytes: 200, PacketsIn: 2, PacketsOut: 3},
	}
	got := DescribeState(st)
	// SPI 是"真的协商过"最硬的证据，摘要里必须能看到。
	for _, w := range []string{"site-a", "up", "aabbccdd", "00001234", "AES256-GCM16", "rx=100B"} {
		if !strings.Contains(got, w) {
			t.Errorf("状态摘要里缺少 %q：%s", w, got)
		}
	}
}

// ★路由网段必须从站点配置推导，而且只收"启用且归本机"的。
// 给一条停用站点配路由，会把流量吸进一个没有 SA 的黑洞——
// 表现为该网段整段不通，而站点状态是 down，两件事看起来毫不相干。
func TestSubnetSummary(t *testing.T) {
	a := bktCfg("a")
	b := bktCfg("b")
	b.RemoteSubnet = netip.MustParsePrefix("10.30.0.0/16")
	dis := bktCfg("disabled")
	dis.Enabled = false
	dis.RemoteSubnet = netip.MustParsePrefix("10.40.0.0/16")
	other := bktCfg("other")
	other.GatewayID = "gw-2"
	other.RemoteSubnet = netip.MustParsePrefix("10.50.0.0/16")
	dup := bktCfg("dup") // 与 a 同网段，应当去重

	got := SubnetSummary("gw-1", []ipsec.SiteConfig{a, b, dis, other, dup})
	var ss []string
	for _, p := range got {
		ss = append(ss, p.String())
	}
	joined := strings.Join(ss, ",")
	if joined != "10.20.0.0/16,10.30.0.0/16" {
		t.Errorf("网段清单不符：期望 10.20.0.0/16,10.30.0.0/16，实得 %s", joined)
	}
}

// TunnelMTU 必须按**最坏情况**开销反推。
// 按平均值算出来的 MTU 会得到"能 ping 通、HTTP 一传大文件就卡死"这种最难查的故障。
func TestTunnelMTU(t *testing.T) {
	mtu, err := TunnelMTU(1500, 20 /*AES-GCM-16*/, 256, 0)
	if err != nil {
		t.Fatalf("推算失败：%v", err)
	}
	if mtu >= 1500-outerIPv4UDPOverhead {
		t.Errorf("推算出的 MTU %d 没有扣掉 ESP 开销", mtu)
	}
	if mtu < 1300 || mtu > 1460 {
		t.Errorf("AES-256-GCM 下的隧道 MTU 应在 1300~1460 之间，实得 %d", mtu)
	}
	// 外层 MTU 填错（比如把隧道 MTU 又填了一遍再扣一次）时必须报错，
	// 而不是返回一个什么都传不动的小数字。
	if _, err := TunnelMTU(300, 20, 256, 0); err == nil {
		t.Errorf("外层 MTU 过小应当报错")
	}
	if _, err := TunnelMTU(1500, 9999, 256, 0); err == nil {
		t.Errorf("未知加密算法应当报错")
	}
}

// 配置指纹必须覆盖 PSK：改了 PSK 却不重建 SA，隧道会一直用旧密钥跑到下一次 rekey
// 才突然认证失败，那时距离改密钥可能已过去几小时。
func TestFingerprintCoversPSKAndFields(t *testing.T) {
	base := bktCfg("site-a")
	fp := fingerprint(base)

	same := bktCfg("site-a")
	if fingerprint(same) != fp {
		t.Errorf("相同配置的指纹应当相同")
	}
	for name, mut := range map[string]func(*ipsec.SiteConfig){
		"PSK":          func(c *ipsec.SiteConfig) { c.PSK = []byte("another-psk-value-0000000000000") },
		"PSKVersion":   func(c *ipsec.SiteConfig) { c.PSKVersion = 9 },
		"Enabled":      func(c *ipsec.SiteConfig) { c.Enabled = false },
		"Peer":         func(c *ipsec.SiteConfig) { c.Peer = netip.MustParseAddrPort("198.51.100.1:500") },
		"RemoteSubnet": func(c *ipsec.SiteConfig) { c.RemoteSubnet = netip.MustParsePrefix("10.99.0.0/16") },
		"LocalID":      func(c *ipsec.SiteConfig) { c.LocalID = "gw-z.baidi" },
		"Phase1.DH":    func(c *ipsec.SiteConfig) { c.Phase1.DH = "group14" },
		"PFS":          func(c *ipsec.SiteConfig) { c.PFS = false },
		"Suite":        func(c *ipsec.SiteConfig) { c.Suite = "gm" },
	} {
		c := bktCfg("site-a")
		mut(&c)
		if fingerprint(c) == fp {
			t.Errorf("改动 %s 后指纹没变——这条配置变更不会触发重建 SA", name)
		}
	}
	// 指纹前缀用于日志，必须是稳定的 8 个十六进制字符且不泄露密钥材料。
	if s := shortFP(fp); len(s) != 8 {
		t.Errorf("指纹前缀应为 8 个字符，实得 %q", s)
	}
}

// 分隔符要防"ab"+"c" 与 "a"+"bc" 撞同一个指纹。
func TestFingerprintFieldBoundaries(t *testing.T) {
	a := bktCfg("site")
	a.LocalID = "ab.x"
	a.RemoteID = "c.x"
	b := bktCfg("site")
	b.LocalID = "a.x"
	b.RemoteID = "bc.x"
	if fingerprint(a) == fingerprint(b) {
		t.Errorf("相邻字段拼接产生了指纹碰撞（缺少分隔符）")
	}
}
