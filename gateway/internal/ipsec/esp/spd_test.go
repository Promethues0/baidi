package esp

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// TestInnerAddrs 内层 IP 包地址解析：正例、族判别、畸形。
func TestInnerAddrs(t *testing.T) {
	src, dst, nh, err := innerAddrs(espIPv4("10.60.0.5", "10.70.0.9", []byte("x")))
	if err != nil || src.String() != "10.60.0.5" || dst.String() != "10.70.0.9" || nh != protoIPv4 {
		t.Fatalf("IPv4 解析结果 %s→%s nh=%d err=%v", src, dst, nh, err)
	}
	src, dst, nh, err = innerAddrs(espIPv6("fd00::1", "fd00::2", []byte("x")))
	if err != nil || src.String() != "fd00::1" || dst.String() != "fd00::2" || nh != protoIPv6 {
		t.Fatalf("IPv6 解析结果 %s→%s nh=%d err=%v", src, dst, nh, err)
	}

	bad := []struct {
		name string
		pkt  []byte
	}{
		{"空包", nil},
		{"版本号 5", []byte{0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"IPv4 头不足 20 字节", []byte{0x45, 0, 0, 0}},
		{"IPv4 IHL 声明 4（<20 字节）", append([]byte{0x44}, make([]byte, 19)...)},
		{"IPv4 IHL 超出实际长度", append([]byte{0x4F}, make([]byte, 19)...)},
		{"IPv6 头不足 40 字节", append([]byte{0x60}, make([]byte, 20)...)},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, _, _, err := innerAddrs(c.pkt); err == nil {
				t.Fatalf("%s 应被拒", c.name)
			}
		})
	}
}

// espTestSA 造一条只填了 SPD 判定所需字段的 sa（不涉及密钥）。
func espTestSA(site string, inSPI uint32, local, remote string, created time.Time, hard time.Time) *sa {
	return &sa{
		siteID:     site,
		inSPI:      inSPI,
		localTS:    netip.MustParsePrefix(local).Masked(),
		remoteTS:   netip.MustParsePrefix(remote).Masked(),
		createdAt:  created,
		hardExpire: hard,
	}
}

// TestSelectOutboundMatch 正常命中。
func TestSelectOutboundMatch(t *testing.T) {
	clk := newESPClock()
	table := map[uint32]*sa{
		1000: espTestSA("site-a", 1000, "10.60.0.0/24", "10.70.0.0/24", clk.now(), time.Time{}),
	}
	s, err := selectOutbound(table, describeTable(table), netip.MustParseAddr("10.60.0.5"), netip.MustParseAddr("10.70.0.9"), clk.now())
	if err != nil || s.siteID != "site-a" {
		t.Fatalf("应命中 site-a，实得 %v / %v", s, err)
	}
}

// TestSelectOutboundNoPolicy 无匹配必须返回 ErrNoPolicy，且错误信息要把
// 「你的包」和「现有策略」摆在一起——这是本项目最迷惑人失败形态的正面防御。
func TestSelectOutboundNoPolicy(t *testing.T) {
	clk := newESPClock()
	table := map[uint32]*sa{
		1000: espTestSA("site-a", 1000, "10.60.0.0/24", "10.70.0.0/24", clk.now(), time.Time{}),
	}
	_, err := selectOutbound(table, describeTable(table), netip.MustParseAddr("10.60.0.5"), netip.MustParseAddr("8.8.8.8"), clk.now())
	if !errors.Is(err, ipsec.ErrNoPolicy) {
		t.Fatalf("目的地址在 RemoteTS 之外应返回 ipsec.ErrNoPolicy，实得：%v", err)
	}
	for _, want := range []string{"8.8.8.8", "10.60.0.0/24", "10.70.0.0/24"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误信息缺少 %q，运维只能靠猜：%v", want, err)
		}
	}

	// 空表也要说人话。
	empty := map[uint32]*sa{}
	_, err = selectOutbound(empty, describeTable(empty), netip.MustParseAddr("10.60.0.5"), netip.MustParseAddr("10.70.0.9"), clk.now())
	if !errors.Is(err, ipsec.ErrNoPolicy) || !strings.Contains(err.Error(), "没有装载任何") {
		t.Fatalf("空表时的错误信息不合格：%v", err)
	}
}

// TestSelectOutboundSrcMismatch 目的匹配但源不匹配时，错误必须专门点出源地址问题
// （典型成因：TUN 网卡地址与控制面下发的本端网段对不上）。
func TestSelectOutboundSrcMismatch(t *testing.T) {
	clk := newESPClock()
	table := map[uint32]*sa{
		1000: espTestSA("site-a", 1000, "10.60.0.0/24", "10.70.0.0/24", clk.now(), time.Time{}),
	}
	_, err := selectOutbound(table, describeTable(table), netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("10.70.0.9"), clk.now())
	if !errors.Is(err, ipsec.ErrNoPolicy) {
		t.Fatalf("源地址越界应返回 ipsec.ErrNoPolicy，实得：%v", err)
	}
	if !strings.Contains(err.Error(), "源地址不在本端 LocalTS") {
		t.Fatalf("错误信息没有指向源地址：%v", err)
	}
}

// TestSelectOutboundPrefersNewest rekey 期间新旧两条 SA 并存，出向必须走新的。
func TestSelectOutboundPrefersNewest(t *testing.T) {
	clk := newESPClock()
	old := espTestSA("site-a", 1000, "10.60.0.0/24", "10.70.0.0/24", clk.at(-time.Hour), time.Time{})
	fresh := espTestSA("site-a", 2000, "10.60.0.0/24", "10.70.0.0/24", clk.now(), time.Time{})
	table := map[uint32]*sa{1000: old, 2000: fresh}
	for i := 0; i < 50; i++ { // 多跑几轮，map 遍历顺序随机，抖动会被抓到
		s, err := selectOutbound(table, describeTable(table), netip.MustParseAddr("10.60.0.5"), netip.MustParseAddr("10.70.0.9"), clk.now())
		if err != nil || s != fresh {
			t.Fatalf("第 %d 轮应选中较新的 SA（SPI 2000），实得 %v / %v", i, s, err)
		}
	}
}

// TestSelectOutboundDeterministicTieBreak CreatedAt 相同时结果必须稳定，
// 否则同一条流会在两条 SA 之间逐包抖动，把之后所有排查都带偏。
func TestSelectOutboundDeterministicTieBreak(t *testing.T) {
	clk := newESPClock()
	table := map[uint32]*sa{
		1000: espTestSA("site-a", 1000, "10.60.0.0/24", "10.70.0.0/24", clk.now(), time.Time{}),
		2000: espTestSA("site-a", 2000, "10.60.0.0/24", "10.70.0.0/24", clk.now(), time.Time{}),
		3000: espTestSA("site-a", 3000, "10.60.0.0/24", "10.70.0.0/24", clk.now(), time.Time{}),
	}
	for i := 0; i < 100; i++ {
		s, err := selectOutbound(table, describeTable(table), netip.MustParseAddr("10.60.0.5"), netip.MustParseAddr("10.70.0.9"), clk.now())
		if err != nil || s.inSPI != 3000 {
			t.Fatalf("第 %d 轮选中 SPI %v（err=%v），期望恒为 3000", i, s, err)
		}
	}
}

// TestSelectOutboundSkipsExpired 过了硬生存期的 SA 不得再承载出向流量。
func TestSelectOutboundSkipsExpired(t *testing.T) {
	clk := newESPClock()
	table := map[uint32]*sa{
		1000: espTestSA("site-a", 1000, "10.60.0.0/24", "10.70.0.0/24", clk.at(-2*time.Hour), clk.at(-time.Hour)),
	}
	_, err := selectOutbound(table, describeTable(table), netip.MustParseAddr("10.60.0.5"), netip.MustParseAddr("10.70.0.9"), clk.now())
	if !errors.Is(err, ipsec.ErrNoPolicy) {
		t.Fatalf("已过硬生存期的 SA 不应被选中，实得：%v", err)
	}
}

// TestCheckInnerTS 入向内层地址校验，两个方向都要拦。
func TestCheckInnerTS(t *testing.T) {
	s := espTestSA("site-a", 1000, "10.60.0.0/24", "10.70.0.0/24", time.Time{}, time.Time{})
	if err := checkInnerTS(s, netip.MustParseAddr("10.70.0.9"), netip.MustParseAddr("10.60.0.5")); err != nil {
		t.Fatalf("合法内层地址被拒：%v", err)
	}
	// 对端伪造源地址。
	err := checkInnerTS(s, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("10.60.0.5"))
	if !errors.Is(err, ipsec.ErrTSMismatch) || !strings.Contains(err.Error(), "源地址") {
		t.Fatalf("伪造源地址应返回 ipsec.ErrTSMismatch 且点名源地址，实得：%v", err)
	}
	// 对端往本端任意内网地址注包。
	err = checkInnerTS(s, netip.MustParseAddr("10.70.0.9"), netip.MustParseAddr("192.168.1.1"))
	if !errors.Is(err, ipsec.ErrTSMismatch) || !strings.Contains(err.Error(), "目的地址") {
		t.Fatalf("越权目的地址应返回 ipsec.ErrTSMismatch 且点名目的地址，实得：%v", err)
	}
}

// TestCheckVersion ESP 头声明的 NextHeader 必须与内层 IP 头自称的版本一致。
func TestCheckVersion(t *testing.T) {
	if err := checkVersion(protoIPv4, protoIPv4); err != nil {
		t.Fatalf("一致时不应报错：%v", err)
	}
	if err := checkVersion(protoIPv4, protoIPv6); err == nil {
		t.Fatal("声明 IPv4 实为 IPv6 应被拒")
	}
}
