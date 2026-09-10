package ike

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// ── 同一对端配了多条站点（wave11 行动 10-②）──
//
// 改造前 findSiteByPeer 是 `for _, s := range e.sites { …; return s }`——
// Go 的 map 迭代序是**随机**的。于是本机作为响应方时，对端每发起一次协商就掷一次骰子：
// 选中的若不是对端想建的那条，就会用错的 spec1/网段去谈，谈崩后 failSite 把
// **那条被随机选中的、本来健康的站点**打成 failed，而 LastError 写的是
// 「对端的提案不可接受」——方向完全相反。下一次协商可能选对，站点自己"好了"，
// 再下一次又坏，是一条谁也解释不清的间歇性故障。

// dupEngine 造一个只装了几条站点、不跑事件循环的引擎。
//
// 不用 hsSetup：这里要验的是**选站点**这一步本身，跑完整握手反而会让
// "选错了"被后面的失败路径掩盖成一句 AUTHENTICATION_FAILED。
func dupEngine(t *testing.T, log *slog.Logger, cfgs ...ipsec.SiteConfig) *Engine {
	t.Helper()
	e := NewEngine(EngineOptions{
		Log:      log,
		LocalIKE: netip.MustParseAddrPort("10.0.0.1:500"),
		LocalNAT: netip.MustParseAddrPort("10.0.0.1:4500"),
	})
	for _, c := range cfgs {
		if err := e.AddSite(c); err != nil {
			t.Fatalf("装载站点 %s 失败：%v", c.ID, err)
		}
	}
	return e
}

// dupSite 一条指向 peer 的站点（网段按 id 区分，避免两条完全同形）。
func dupSite(id, peer, local, remote string, enabled bool) ipsec.SiteConfig {
	c := hsSiteA("dup-test-psk-please-rotate-0123456789")
	c.ID = id
	c.Name = id
	c.Enabled = enabled
	c.Peer = netip.MustParseAddrPort(peer)
	c.LocalSubnet = netip.MustParsePrefix(local)
	c.RemoteSubnet = netip.MustParsePrefix(remote)
	return c
}

// TestFindSiteByPeerIsDeterministic 同一对端多条站点时必须**每次都选同一条**。
//
// ★循环 200 次不是凑数：Go 对两个键的 map 迭代序是随机的，只跑一次有 50% 概率
// 恰好命中"正确"的那条，用例会时绿时红——而时绿时红的用例最终会被当成 flaky 关掉，
// 那正是这条缺陷能活下来的方式。200 次让随机实现的漏网概率降到 2^-200。
//
// 变异验证：把 findSiteByPeer 里的 `if best == nil || s.cfg.ID < best.cfg.ID`
// 改回 `return s`（先遇到的就返回），本用例立刻变红。
func TestFindSiteByPeerIsDeterministic(t *testing.T) {
	peer := "203.0.113.7:500"
	e := dupEngine(t, nil,
		dupSite("site-b", peer, "10.20.0.0/16", "10.60.0.0/16", true),
		dupSite("site-a", peer, "10.21.0.0/16", "10.61.0.0/16", true),
		dupSite("site-c", peer, "10.22.0.0/16", "10.62.0.0/16", true),
	)
	remote := netip.MustParseAddrPort("203.0.113.7:41234") // 源端口与配置不同：NAT 后的常态

	e.mu.Lock()
	defer e.mu.Unlock()
	for i := 0; i < 200; i++ {
		got := e.findSiteByPeer(remote)
		if got == nil {
			t.Fatal("同一对端的站点在册，却没匹配上")
		}
		// 站点 id 字典序最小的那条。控制面的 ipsecDuplicatePeers 按同一判据
		// 告诉管理员「谁会被选中」，两处必须同真同假。
		if got.cfg.ID != "site-a" {
			t.Fatalf("第 %d 次选中了 %s，期望恒为 site-a——按 map 迭代序选站点是随机的，"+
				"现场表现为一条健康站点被间歇性打成协商失败", i, got.cfg.ID)
		}
	}
}

// TestFindSiteByPeerSkipsDisabled 停用的站点不参与匹配（且不该被算进"重复"）。
func TestFindSiteByPeerSkipsDisabled(t *testing.T) {
	peer := "203.0.113.8:500"
	var buf syncBuf
	e := dupEngine(t, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		dupSite("site-a", peer, "10.20.0.0/16", "10.60.0.0/16", false), // 已停用
		dupSite("site-b", peer, "10.21.0.0/16", "10.61.0.0/16", true),
	)
	e.mu.Lock()
	got := e.findSiteByPeer(netip.MustParseAddrPort("203.0.113.8:500"))
	e.mu.Unlock()

	if got == nil || got.cfg.ID != "site-b" {
		t.Fatalf("应选中唯一那条已启用的 site-b，得到 %v", got)
	}
	if strings.Contains(buf.String(), "同一对端 IP 配了多条已启用的站点") {
		t.Fatal("只有一条已启用站点时不该报重复——停用的那条根本不会被响应方选中，" +
			"为它报警会让这条告警变成噪声")
	}
}

// TestDuplicatePeerWarnsOnceAndNamesAll 重复必须**喊出来**，且被节流。
//
// 两半都要：
//   - 不喊：存量库里那对重复站点会一直安静地互相打架（入口只拦新配置）。
//   - 不节流：IKE_SA_INIT 是未认证报文，对端能把它打成高频，这条告警会把
//     日志冲成噪声，从而失去自己的作用。
func TestDuplicatePeerWarnsOnceAndNamesAll(t *testing.T) {
	var buf syncBuf
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	peer := "203.0.113.9:500"
	e := dupEngine(t, log,
		dupSite("site-b", peer, "10.20.0.0/16", "10.60.0.0/16", true),
		dupSite("site-a", peer, "10.21.0.0/16", "10.61.0.0/16", true),
	)
	// 注入时钟：节流窗口是 5 分钟，用真实时钟就只能 sleep。
	now := time.Unix(1_800_000_000, 0)
	e.opt.Now = func() time.Time { return now }

	remote := netip.MustParseAddrPort("203.0.113.9:41234")
	e.mu.Lock()
	for i := 0; i < 50; i++ {
		e.findSiteByPeer(remote)
	}
	e.mu.Unlock()

	out := buf.String()
	if n := strings.Count(out, "同一对端 IP 配了多条已启用的站点"); n != 1 {
		t.Fatalf("50 次匹配只该喊 1 次（5 分钟节流），实际 %d 次", n)
	}
	// 必须点名**全部**冲突站点与本次选中的那条：只说"有冲突"的话，
	// 管理员还得自己去翻配置找是哪几条。
	for _, want := range []string{"site-a", "site-b", "本次选中"} {
		if !strings.Contains(out, want) {
			t.Fatalf("告警里缺少 %q：\n%s", want, out)
		}
	}

	// 窗口过去之后要能再喊——否则一台长跑的网关只会在第一次留痕，
	// 而管理员多半是在故障发生后才去翻日志的。
	now = now.Add(dupPeerWarnEvery + time.Second)
	e.mu.Lock()
	e.findSiteByPeer(remote)
	e.mu.Unlock()
	if n := strings.Count(buf.String(), "同一对端 IP 配了多条已启用的站点"); n != 2 {
		t.Fatalf("节流窗口过后应能再喊一次，实际累计 %d 次", n)
	}
}

// syncBuf 一个并发安全的 bytes.Buffer（slog 的 handler 可能在别的 goroutine 写）。
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
