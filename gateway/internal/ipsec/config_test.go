package ipsec

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// 本文件守的是一条纪律：**每一条装载期拒绝，都必须指名道姓地说出是哪个字段的哪个值不行**。
//
// 为什么把"错误信息里带没带具体值"当成断言对象来测：
// 这些拒绝最终会原样出现在控制台的站点列表里，是管理员唯一能看到的东西。
// 一条「配置不合法」的错误在功能上完全正确，在现场却毫无价值——
// 管理员看不出该改哪一格，只能回来问人。所以 Reason 里没有实际取值 = 这条校验没写完。
//
// 测试辅助一律加 cft 前缀（config_test），避免与同包其它测试文件撞名。

// cftValid 一份能通过全部校验的基准配置。各用例只改动自己关心的那一个字段，
// 这样任何一条断言失败都能直接归因到被改的那个字段上。
func cftValid() SiteConfig {
	return SiteConfig{
		ID:           "site-sh",
		Name:         "上海分部",
		GatewayID:    "gw-1",
		Enabled:      true,
		Peer:         netip.MustParseAddrPort("203.0.113.88:500"),
		LocalSubnet:  netip.MustParsePrefix("10.10.0.0/16"),
		RemoteSubnet: netip.MustParsePrefix("10.20.0.0/16"),
		LocalID:      "gw-a.baidi",
		RemoteID:     "gw-b.baidi",
		Auth:         "psk",
		Suite:        "standard",
		Phase1:       Phase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		Phase2:       Phase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		PFS:          true,
		PSK:          []byte("baidi-ipsec-psk-0123456789abcdef"),
	}
}

// cftReject 断言 err 是一条 *ConfigError，字段名正确，且 Error() 里包含全部 want 片段。
func cftReject(t *testing.T, err error, wantField string, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望被拒绝，实际通过了校验")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("期望 *ConfigError（控制面要靠 Field 定位到界面上那一格），实得 %T：%v", err, err)
	}
	if ce.Field != wantField {
		t.Errorf("字段名不符：期望 %q，实得 %q（完整错误：%s）", wantField, ce.Field, ce.Error())
	}
	msg := ce.Error()
	for _, w := range want {
		if !strings.Contains(msg, w) {
			t.Errorf("错误信息里没有出现 %q —— 报错不指名具体取值等于没报。\n完整错误：%s", w, msg)
		}
	}
}

// ── 本轮明确不支持的开关 ──

func TestValidateRejectsIKEv1(t *testing.T) {
	c := cftValid()
	err := c.ValidateWith(ExtraOptions{IKEVersion: "IKEv1"})
	cftReject(t, err, "ikeVersion", "IKEv1", "IKEv2")
}

func TestValidateAcceptsIKEv2Spellings(t *testing.T) {
	// 控制面历史上写过好几种形态，全都应当放行——否则会出现
	// 「控制台明明选的就是 IKEv2，网关却说不支持」这种自相矛盾的报错。
	for _, v := range []string{"ikev2", "IKEv2", "v2", "2", "IKE_v2"} {
		c := cftValid()
		if err := c.ValidateWith(ExtraOptions{IKEVersion: v}); err != nil {
			t.Errorf("ikeVersion=%q 本应放行，却被拒：%v", v, err)
		}
	}
}

func TestValidateRejectsPqHybrid(t *testing.T) {
	c := cftValid()
	err := c.ValidateWith(ExtraOptions{PqHybrid: true})
	// ★这条的价值全在"当面拒绝"上：控制台有这个开关，实现里一行代码都没有。
	// 静默忽略 = 管理员以为自己开了后量子保护。
	cftReject(t, err, "pqHybrid", "pqHybrid=true", "未实现")
}

func TestValidateRejectsCertAuth(t *testing.T) {
	for _, tc := range []struct{ auth, want string }{
		{"cert", "cert"},
		{"sm2cert", "sm2cert"},
		{"rsasig", "rsasig"},
		{"eap", "eap"},
	} {
		c := cftValid()
		c.Auth = tc.auth
		// 必须带上"本轮唯一支持 psk"，否则管理员不知道该改成什么。
		cftReject(t, c.Validate(), "auth", tc.want, "psk")
	}
}

func TestValidateRejectsUnknownAuth(t *testing.T) {
	c := cftValid()
	c.Auth = "psk2"
	cftReject(t, c.Validate(), "auth", "psk2")
}

func TestValidateRejectsEmptyAuth(t *testing.T) {
	c := cftValid()
	c.Auth = ""
	cftReject(t, c.Validate(), "auth", "psk")
}

// ★空 PSK：本文件里最重要的一条。
// 空 PSK 两端一样能协商成功——隧道真的建起来、界面真的显示 up、流量真的加密，
// 只是认证强度为零。「配错了连不上」是小事故，「配错了连上了」才是真事故。
func TestValidateRejectsEmptyPSK(t *testing.T) {
	for _, psk := range [][]byte{nil, {}} {
		c := cftValid()
		c.PSK = psk
		cftReject(t, c.Validate(), "psk", "空", "up")
	}
}

func TestWeakPSKIsWarnedNotRejected(t *testing.T) {
	c := cftValid()
	c.PSK = []byte("baidi")
	if err := c.Validate(); err != nil {
		t.Fatalf("短 PSK 应当放行（只告警），实际被拒：%v", err)
	}
	if !c.WeakPSK() {
		t.Errorf("5 字节 PSK 应被判为过短（推荐 ≥%d 字节）", RecommendedPSKBytes)
	}
	full := cftValid()
	if full.WeakPSK() {
		t.Errorf("%d 字节 PSK 不该被判为过短", len(full.PSK))
	}
}

// ── DH 群 ──

func TestValidateRejectsGroup24(t *testing.T) {
	c := cftValid()
	c.Phase1.DH = "group24"
	// 必须点名 group24 本身，并给出可用的替代项——只说"不支持"会让人去猜。
	cftReject(t, c.Validate(), "phase1.dh", "group24", "group14", "group19")
}

func TestValidateRejectsGroup24InPhase2(t *testing.T) {
	c := cftValid()
	c.Phase2.DH = "GROUP-24" // 大小写与连字符都该被归一
	cftReject(t, c.Validate(), "phase2.dh", "GROUP-24", "group19")
}

func TestValidateRejectsOtherUnsupportedDH(t *testing.T) {
	for _, dh := range []string{"group2", "group5", "group20", "curve25519"} {
		c := cftValid()
		c.Phase1.DH = dh
		cftReject(t, c.Validate(), "phase1.dh", dh)
	}
}

func TestValidateRejectsEmptyCryptoFields(t *testing.T) {
	for _, tc := range []struct {
		field string
		mut   func(*SiteConfig)
	}{
		{"phase1.enc", func(c *SiteConfig) { c.Phase1.Enc = "" }},
		{"phase1.hash", func(c *SiteConfig) { c.Phase1.Hash = "" }},
		{"phase1.dh", func(c *SiteConfig) { c.Phase1.DH = "" }},
		{"phase2.enc", func(c *SiteConfig) { c.Phase2.Enc = "" }},
		{"phase2.hash", func(c *SiteConfig) { c.Phase2.Hash = "" }},
	} {
		c := cftValid()
		tc.mut(&c)
		cftReject(t, c.Validate(), tc.field, tc.field)
	}
}

func TestValidateRejectsPFSWithoutDH(t *testing.T) {
	for _, dh := range []string{"", "none", "NONE"} {
		c := cftValid()
		c.PFS = true
		c.Phase2.DH = dh
		// ★没有 DH 群的 PFS = 界面开关是开的、实际没有前向保密。
		cftReject(t, c.Validate(), "phase2.dh", "pfs=true", "前向保密")
	}
}

func TestValidateAllowsNoneDHWhenPFSOff(t *testing.T) {
	c := cftValid()
	c.PFS = false
	c.Phase2.DH = "none"
	if err := c.Validate(); err != nil {
		t.Fatalf("PFS 关闭时 phase2.dh=none 应当放行，实际被拒：%v", err)
	}
}

func TestValidateRejectsUnknownSuite(t *testing.T) {
	c := cftValid()
	c.Suite = "guomi"
	cftReject(t, c.Validate(), "suite", "guomi", "standard", "gm")
}

// ── 身份 ──

// ★IP 形态的 ID 在 NAT 下必挂，且症状只有一句「认证失败」。
func TestValidateRejectsIPTypeID(t *testing.T) {
	for _, tc := range []struct{ field, val string }{
		{"localId", "10.1.2.3"},
		{"remoteId", "2001:db8::1"},
	} {
		c := cftValid()
		switch tc.field {
		case "localId":
			c.LocalID = tc.val
		default:
			c.RemoteID = tc.val
		}
		cftReject(t, c.Validate(), tc.field, tc.val, "NAT", "FQDN")
	}
}

func TestValidateRejectsEmptyIDs(t *testing.T) {
	c := cftValid()
	c.LocalID = "  "
	cftReject(t, c.Validate(), "localId", "localId")

	c = cftValid()
	c.RemoteID = ""
	cftReject(t, c.Validate(), "remoteId", "remoteId")
}

func TestValidateRejectsOverlongID(t *testing.T) {
	c := cftValid()
	c.LocalID = strings.Repeat("a", MaxIDLen+1)
	cftReject(t, c.Validate(), "localId", "254", "253")
}

func TestValidateRejectsEmptyIDField(t *testing.T) {
	c := cftValid()
	c.ID = ""
	cftReject(t, c.Validate(), "id")
}

// ★无主站点会被每台网关同时抢建，表现为隧道周期性抖动而两端日志都正常。
func TestValidateRejectsEmptyGatewayID(t *testing.T) {
	c := cftValid()
	c.GatewayID = ""
	cftReject(t, c.Validate(), "gatewayId", "网关")
}

// ── 地址与网段 ──

func TestValidateRejectsBadPeer(t *testing.T) {
	c := cftValid()
	c.Peer = netip.AddrPort{}
	cftReject(t, c.Validate(), "peer")

	c = cftValid()
	c.Peer = netip.MustParseAddrPort("0.0.0.0:500")
	cftReject(t, c.Validate(), "peer", "0.0.0.0")

	c = cftValid()
	c.Peer = netip.MustParseAddrPort("224.0.0.1:500")
	cftReject(t, c.Validate(), "peer", "224.0.0.1")
}

func TestValidateFillsDefaultIKEPort(t *testing.T) {
	c := cftValid()
	c.Peer = netip.AddrPortFrom(netip.MustParseAddr("203.0.113.88"), 0)
	if err := c.Validate(); err != nil {
		t.Fatalf("端口留空应当补 %d，实际被拒：%v", DefaultIKEPort, err)
	}
	if c.Peer.Port() != DefaultIKEPort {
		t.Errorf("对端端口应补成 %d，实得 %d", DefaultIKEPort, c.Peer.Port())
	}
}

// ★含主机位的网段意图不明确，且对端只会回一个 TS_UNACCEPTABLE。
// 错误信息必须同时给出"整段"和"单机"两种改法，管理员才知道自己想要哪一种。
func TestValidateRejectsSubnetWithHostBits(t *testing.T) {
	c := cftValid()
	c.LocalSubnet = netip.MustParsePrefix("10.1.2.3/24")
	cftReject(t, c.Validate(), "localSubnet", "10.1.2.3/24", "10.1.2.0/24", "10.1.2.3/32")

	c = cftValid()
	c.RemoteSubnet = netip.MustParsePrefix("192.168.5.7/16")
	cftReject(t, c.Validate(), "remoteSubnet", "192.168.5.7/16", "192.168.0.0/16")
}

func TestValidateRejectsInvalidSubnet(t *testing.T) {
	c := cftValid()
	c.LocalSubnet = netip.Prefix{}
	cftReject(t, c.Validate(), "localSubnet", "localSubnet")
}

func TestValidateRejectsMixedAddressFamily(t *testing.T) {
	c := cftValid()
	c.RemoteSubnet = netip.MustParsePrefix("2001:db8::/64")
	cftReject(t, c.Validate(), "remoteSubnet", "10.10.0.0/16", "2001:db8::/64")
}

// ★两端网段重叠 → 同一地址既算本端又算对端，出向选路必然二义。
func TestValidateRejectsOverlappingSubnets(t *testing.T) {
	c := cftValid()
	c.RemoteSubnet = netip.MustParsePrefix("10.10.5.0/24")
	cftReject(t, c.Validate(), "remoteSubnet", "10.10.0.0/16", "10.10.5.0/24", "重叠")
}

// ── 生存期与定时器 ──

func TestValidateFillsTimerDefaults(t *testing.T) {
	c := cftValid()
	if err := c.Validate(); err != nil {
		t.Fatalf("基准配置应当通过：%v", err)
	}
	if c.IKELifetime != DefaultIKELifetime || c.ESPLifetime != DefaultESPLifetime ||
		c.DPDDelay != DefaultDPDDelay || c.RetryInitial != DefaultRetryInitial {
		t.Errorf("缺省值未补齐：ike=%s esp=%s dpd=%s retry=%s",
			c.IKELifetime, c.ESPLifetime, c.DPDDelay, c.RetryInitial)
	}
}

// ★Child SA 不能比父 IKE SA 活得久：父先到期后既无法 rekey 也发不出 Delete，
// 隧道会静默停摆而状态仍显示 up。
func TestValidateRejectsESPLifetimeGEIKELifetime(t *testing.T) {
	c := cftValid()
	c.IKELifetime = 1 * time.Hour
	c.ESPLifetime = 1 * time.Hour
	cftReject(t, c.Validate(), "espLifetime", "1h0m0s")

	c = cftValid()
	c.IKELifetime = 30 * time.Minute
	c.ESPLifetime = 45 * time.Minute
	cftReject(t, c.Validate(), "espLifetime", "45m0s", "30m0s")
}

func TestValidateRejectsOutOfRangeTimers(t *testing.T) {
	for _, tc := range []struct {
		field string
		want  string
		mut   func(*SiteConfig)
	}{
		{"espLifetime", "1m0s", func(c *SiteConfig) { c.ESPLifetime = time.Minute }},
		{"ikeLifetime", "2m0s", func(c *SiteConfig) { c.IKELifetime = 2 * time.Minute }},
		{"ikeLifetime", "48h0m0s", func(c *SiteConfig) { c.IKELifetime = 48 * time.Hour }},
		{"dpdDelay", "1s", func(c *SiteConfig) { c.DPDDelay = time.Second }},
		{"dpdDelay", "2h0m0s", func(c *SiteConfig) { c.DPDDelay = 2 * time.Hour }},
		{"retryInitial", "2h0m0s", func(c *SiteConfig) { c.RetryInitial = 2 * time.Hour }},
	} {
		c := cftValid()
		tc.mut(&c)
		cftReject(t, c.Validate(), tc.field, tc.want)
	}
}

// ── 正例 ──

func TestValidateAcceptsGMSuite(t *testing.T) {
	c := cftValid()
	c.Suite = "gm"
	c.Phase1 = Phase{Enc: "SM4-GCM", Hash: "SM3", DH: "sm2p256"}
	c.Phase2 = Phase{Enc: "SM4-GCM", Hash: "SM3", DH: "sm2p256"}
	if err := c.Validate(); err != nil {
		t.Fatalf("suite=gm 应当放行（算法名的权威映射在 ike.SpecFromPhase）：%v", err)
	}
}

// Validate 不该改动调用方没让它改的东西：只补缺省值，不做任何"美化"。
// 悄悄改写管理员填的值是另一种形式的静默降级。
func TestValidateDoesNotRewriteExplicitValues(t *testing.T) {
	c := cftValid()
	c.IKELifetime = 2 * time.Hour
	c.ESPLifetime = 30 * time.Minute
	c.DPDDelay = 10 * time.Second
	before := c
	if err := c.Validate(); err != nil {
		t.Fatalf("应当通过：%v", err)
	}
	if c.IKELifetime != before.IKELifetime || c.ESPLifetime != before.ESPLifetime ||
		c.DPDDelay != before.DPDDelay || c.Peer != before.Peer ||
		c.LocalSubnet != before.LocalSubnet || c.RemoteSubnet != before.RemoteSubnet {
		t.Errorf("Validate 改写了显式填入的值：改前 %+v，改后 %+v", before, c)
	}
}

// 拒绝顺序：最根本的那条要先冒出来。
// 先报"网段含主机位"再报"你选的是 IKEv1"，会让管理员以为改完网段就能跑。
func TestValidateReportsMostFundamentalFirst(t *testing.T) {
	c := cftValid()
	c.LocalSubnet = netip.MustParsePrefix("10.1.2.3/24") // 也有问题
	err := c.ValidateWith(ExtraOptions{IKEVersion: "IKEv1"})
	cftReject(t, err, "ikeVersion", "IKEv1")
}
