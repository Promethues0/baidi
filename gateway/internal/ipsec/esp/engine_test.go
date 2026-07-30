package esp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/ike"
)

// espPairEngines 起两台互为对端的引擎（A/B），共用一个注入时钟。
func espPairEngines(t *testing.T, s espSuite) (ea, eb *Engine, pa, pb ipsec.ChildSAParams, clk *espClock) {
	t.Helper()
	clk = newESPClock()
	pa, pb = espPair(s)
	ea, eb = New(nil, clk.now), New(nil, clk.now)
	espMustInstall(t, ea, pa)
	espMustInstall(t, eb, pb)
	return ea, eb, pa, pb, clk
}

// TestEngineRoundTrip A→B 与 B→A 双向往返，五套件全跑。
//
// 这是「ESP 真的在工作」的基础证据：出向封装的结果必须能被**另一台引擎**
// 用另一半密钥解开。单台引擎自封自解证明不了方向切分是对的。
func TestEngineRoundTrip(t *testing.T) {
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			ea, eb, pa, pb, _ := espPairEngines(t, s)

			ab := espIPv4("10.60.0.5", "10.70.0.9", []byte("A 发往 B 的业务载荷"))
			pkt, dst, err := ea.Protect(ab)
			if err != nil {
				t.Fatalf("A 封装失败：%v", err)
			}
			if dst != pb.Local {
				t.Fatalf("A 给出的出向落点 %s，期望 B 的 %s", dst, pb.Local)
			}
			if spi := binary.BigEndian.Uint32(pkt[:4]); spi != pa.OutSPI {
				t.Fatalf("报文 SPI 0x%08x，期望 A 的出向 SPI 0x%08x（= B 的入向 SPI）", spi, pa.OutSPI)
			}
			got, err := eb.Unprotect(pkt, pa.Local)
			if err != nil {
				t.Fatalf("B 解封失败：%v", err)
			}
			if !bytes.Equal(got, ab) {
				t.Fatalf("A→B 往返内容不一致\n收到 %x\n期望 %x", got, ab)
			}

			ba := espIPv4("10.70.0.9", "10.60.0.5", []byte("B 回给 A 的业务载荷"))
			pkt, dst, err = eb.Protect(ba)
			if err != nil {
				t.Fatalf("B 封装失败：%v", err)
			}
			if dst != pa.Local {
				t.Fatalf("B 给出的出向落点 %s，期望 A 的 %s", dst, pa.Local)
			}
			got, err = ea.Unprotect(pkt, pb.Local)
			if err != nil {
				t.Fatalf("A 解封失败：%v", err)
			}
			if !bytes.Equal(got, ba) {
				t.Fatalf("B→A 往返内容不一致\n收到 %x\n期望 %x", got, ba)
			}

			// 计数必须是线上字节，且两端对得上。
			ca, cb := ea.SiteCounters("site-a"), eb.SiteCounters("site-b")
			if ca.PacketsOut != 1 || ca.PacketsIn != 1 || cb.PacketsOut != 1 || cb.PacketsIn != 1 {
				t.Fatalf("包计数不对：A=%+v B=%+v", ca, cb)
			}
			if ca.TxBytes != cb.RxBytes || cb.TxBytes != ca.RxBytes {
				t.Fatalf("两端字节数对不上：A=%+v B=%+v", ca, cb)
			}
			if d := ea.Drops(); d.Total() != 0 {
				t.Fatalf("正常往返不该有任何丢弃：%+v", d)
			}
		})
	}
}

// TestEngineCiphertextHasNoPlaintext 全偏移扫描密文，不得含明文金丝雀。
//
// ★「全偏移」是关键：只比对报文开头能通过的实现里，包含「只加密了头部」
// 和「压根没加密只是套了个壳」这两种。这条测试把它们都挡在外面。
func TestEngineCiphertextHasNoPlaintext(t *testing.T) {
	canary := []byte("BAIDI-ESP-CANARY-4f2a91c7-do-not-leak")
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			ea, _, _, _, _ := espPairEngines(t, s)
			for _, n := range []int{0, 7, 64, 500} {
				inner := espIPv4("10.60.0.5", "10.70.0.9", append(bytes.Repeat(canary, 1+n/len(canary)), make([]byte, n%len(canary))...))
				pkt, _, err := ea.Protect(inner)
				if err != nil {
					t.Fatalf("封装失败：%v", err)
				}
				if bytes.Contains(pkt, canary) {
					t.Fatalf("ESP 报文里出现了明文金丝雀（载荷 %d 字节）——密文段没有真的被加密", n)
				}
				// 内层 IP 头里的地址同样不该出现在密文里（隧道模式的意义就在这）。
				if bytes.Contains(pkt[HeaderLen:], netip.MustParseAddr("10.70.0.9").AsSlice()) {
					t.Fatalf("ESP 报文里出现了内层目的地址明文——隧道模式必须把内层 IP 头一起加密")
				}
			}
		})
	}
}

// TestEngineBitFlipDropped 密文任一 bit 被翻转都必须丢弃并计数，
// 而**不是**把损坏数据投给内网。
func TestEngineBitFlipDropped(t *testing.T) {
	for _, s := range espSuites {
		t.Run(s.name, func(t *testing.T) {
			ea, eb, pa, _, _ := espPairEngines(t, s)
			inner := espIPv4("10.60.0.5", "10.70.0.9", []byte("payload"))
			pkt, _, err := ea.Protect(inner)
			if err != nil {
				t.Fatalf("封装失败：%v", err)
			}
			// 翻转密文段中间的一个 bit（跳过 SPI，否则会走到「查不到 SA」那条路径）。
			bad := append([]byte(nil), pkt...)
			mid := HeaderLen + len(pkt[HeaderLen:])/2
			bad[mid] ^= 0x40

			got, err := eb.Unprotect(bad, pa.Local)
			if !errors.Is(err, ipsec.ErrAuth) {
				t.Fatalf("翻转 1 bit 后应返回 ipsec.ErrAuth，实得：%v", err)
			}
			if got != nil {
				t.Fatalf("认证失败时仍返回了 %d 字节数据——损坏数据绝不能投给内网", len(got))
			}
			if d := eb.Drops(); d.Auth != 1 || d.Total() != 1 {
				t.Fatalf("丢弃计数应恰为 Auth=1，实得 %+v", d)
			}
			if c := eb.SiteCounters("site-b"); c.PacketsIn != 0 || c.RxBytes != 0 {
				t.Fatalf("被丢弃的包不该计入流量：%+v", c)
			}
			// 原始报文仍应能正常解开——上一步没有污染 SA 状态。
			if _, err := eb.Unprotect(pkt, pa.Local); err != nil {
				t.Fatalf("认证失败的包不该影响后续合法报文：%v", err)
			}
		})
	}
}

// TestEngineReplayDropped 已投递的包重放必须被丢弃且 replay 计数递增；
// 窗口外的旧序号同样丢。
func TestEngineReplayDropped(t *testing.T) {
	ea, eb, pa, _, _ := espPairEngines(t, espSuites[0])

	var first []byte
	for i := 0; i < 3; i++ {
		pkt, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte{byte(i)}))
		if err != nil {
			t.Fatalf("封装失败：%v", err)
		}
		if _, err := eb.Unprotect(pkt, pa.Local); err != nil {
			t.Fatalf("第 %d 个包解封失败：%v", i, err)
		}
		if i == 0 {
			first = pkt
		}
	}

	// 重放窗口内的旧包。
	if _, err := eb.Unprotect(first, pa.Local); !errors.Is(err, ipsec.ErrReplay) {
		t.Fatalf("重放应返回 ipsec.ErrReplay，实得：%v", err)
	}
	if d := eb.Drops(); d.Replay != 1 {
		t.Fatalf("replay 计数应为 1，实得 %+v", d)
	}

	// 把序号推远，再重放 first——这次它落在窗口左侧。
	for i := 0; i < WindowSize+5; i++ {
		pkt, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte{0}))
		if err != nil {
			t.Fatalf("封装失败：%v", err)
		}
		if _, err := eb.Unprotect(pkt, pa.Local); err != nil {
			t.Fatalf("推进序号时解封失败：%v", err)
		}
	}
	if _, err := eb.Unprotect(first, pa.Local); !errors.Is(err, ipsec.ErrReplay) {
		t.Fatalf("窗口外的陈旧包应返回 ipsec.ErrReplay，实得：%v", err)
	}
	if d := eb.Drops(); d.Replay != 2 {
		t.Fatalf("replay 计数应为 2，实得 %+v", d)
	}
	if c := eb.SiteCounters("site-b"); c.PacketsIn != uint64(3+WindowSize+5) {
		t.Fatalf("投递包数 %d，期望 %d（重放的两个不得计入）", c.PacketsIn, 3+WindowSize+5)
	}
}

// TestEngineSequenceStrictlyIncreasing 出向序号必须严格递增且无重复。
//
// ★对 GCM 这条不只是整洁问题：显式 IV 就是序号，序号重复即 nonce 复用，
// 可同时恢复明文与认证密钥，且不会有任何报错。
func TestEngineSequenceStrictlyIncreasing(t *testing.T) {
	ea, _, _, _, _ := espPairEngines(t, espSuites[0])
	const n = 500
	seen := make(map[uint32]struct{}, n)
	prev := uint32(0)
	for i := 0; i < n; i++ {
		pkt, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("x")))
		if err != nil {
			t.Fatalf("第 %d 个包封装失败：%v", i, err)
		}
		seq := binary.BigEndian.Uint32(pkt[4:8])
		if seq != uint32(i+1) {
			t.Fatalf("第 %d 个包序号 %d，期望 %d（首包序号必须是 1）", i, seq, i+1)
		}
		if seq <= prev && i > 0 {
			t.Fatalf("序号未严格递增：%d → %d", prev, seq)
		}
		if _, dup := seen[seq]; dup {
			t.Fatalf("序号 %d 重复", seq)
		}
		seen[seq] = struct{}{}
		prev = seq
	}
	out, _ := ea.SeqOf(0x11223344)
	if out != n {
		t.Fatalf("SeqOf 报出向序号 %d，期望 %d", out, n)
	}
}

// TestEngineInnerTSForged 对端伪造一个内层地址在 TS 之外的包，必须被拒。
//
// ★这条测试的构造方式本身就是它要防的攻击：用**合法密钥**封一个内层地址越权的包。
// ICV 会通过——ICV 只证明「来自持密钥方」，完全不约束内层写什么地址。
// 不做这一层校验，一条站点隧道就等于把内网写权限交给了分支机构的设备。
func TestEngineInnerTSForged(t *testing.T) {
	s := espSuites[0]
	_, eb, pa, _, _ := espPairEngines(t, s)
	// 用 A 的出向密钥直接构造报文，绕开 A 自己的出向 SPD 检查。
	c, err := newCrypto(s.encrID, s.keyBits, s.integID, pa.OutEncrKey, pa.OutIntegKey)
	if err != nil {
		t.Fatalf("构造伪造方密钥失败：%v", err)
	}

	cases := []struct {
		name       string
		src, dst   string
		wantSubstr string
	}{
		{"目的越权：往本端任意内网地址注包", "10.60.0.5", "192.168.1.1", "目的地址"},
		{"源伪造：冒充本端网段内的主机", "8.8.8.8", "10.70.0.9", "源地址"},
	}
	for i, c2 := range cases {
		t.Run(c2.name, func(t *testing.T) {
			pkt, err := c.encap(pa.OutSPI, uint64(100+i), espIPv4(c2.src, c2.dst, []byte("evil")), protoIPv4)
			if err != nil {
				t.Fatalf("伪造封装失败：%v", err)
			}
			got, err := eb.Unprotect(pkt, pa.Local)
			if !errors.Is(err, ipsec.ErrTSMismatch) {
				t.Fatalf("应返回 ipsec.ErrTSMismatch，实得：%v", err)
			}
			if got != nil {
				t.Fatalf("越权报文仍被投递了 %d 字节", len(got))
			}
			if !strings.Contains(err.Error(), c2.wantSubstr) {
				t.Fatalf("错误信息未点名 %q：%v", c2.wantSubstr, err)
			}
		})
	}
	if d := eb.Drops(); d.TSMismatch != 2 {
		t.Fatalf("TSMismatch 计数应为 2，实得 %+v", d)
	}
}

// TestEngineNoPolicy 无匹配策略必须返回 ErrNoPolicy 且**不产出任何报文**。
//
// ★返回值为 nil 是硬要求：只要还返回一个包，早晚会有人在上层写成
// 「err != nil 就原样发出去」，那就退化成本项目历史上最迷惑人的失败形态——
// 隧道显示已建立、流量却从旁路直连出去、全程零报错。
func TestEngineNoPolicy(t *testing.T) {
	ea, _, _, _, _ := espPairEngines(t, espSuites[0])
	pkt, dst, err := ea.Protect(espIPv4("10.60.0.5", "8.8.8.8", []byte("leak?")))
	if !errors.Is(err, ipsec.ErrNoPolicy) {
		t.Fatalf("应返回 ipsec.ErrNoPolicy，实得：%v", err)
	}
	if pkt != nil {
		t.Fatalf("无策略时仍产出了 %d 字节报文", len(pkt))
	}
	if dst.IsValid() {
		t.Fatalf("无策略时仍给出了出向落点 %s", dst)
	}
	if d := ea.Drops(); d.NoPolicy != 1 || d.Total() != 1 {
		t.Fatalf("丢弃计数应恰为 NoPolicy=1，实得 %+v", d)
	}
	if c := ea.SiteCounters("site-a"); c.PacketsOut != 0 {
		t.Fatalf("被丢弃的包不该计入流量：%+v", c)
	}
}

// TestEngineNoSA 未知 SPI 的入向报文。
func TestEngineNoSA(t *testing.T) {
	ea, eb, pa, _, _ := espPairEngines(t, espSuites[0])
	pkt, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("x")))
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}
	bad := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint32(bad[:4], 0xDEADBEEF)
	if _, err := eb.Unprotect(bad, pa.Local); !errors.Is(err, ipsec.ErrNoSA) {
		t.Fatalf("未知 SPI 应返回 ipsec.ErrNoSA，实得：%v", err)
	}
	if d := eb.Drops(); d.NoSA != 1 {
		t.Fatalf("NoSA 计数应为 1，实得 %+v", d)
	}
	// 保留区间的 SPI 在查表之前就该被挡下（畸形而非未知 SA）。
	binary.BigEndian.PutUint32(bad[:4], 0)
	if _, err := eb.Unprotect(bad, pa.Local); err == nil || errors.Is(err, ipsec.ErrNoSA) {
		t.Fatalf("SPI 0 应被判为畸形而非未知 SA，实得：%v", err)
	}
	if d := eb.Drops(); d.Malformed != 1 {
		t.Fatalf("Malformed 计数应为 1，实得 %+v", d)
	}
}

// TestEngineOversizeAndMalformed 出向的两类拒绝。
func TestEngineOversizeAndMalformed(t *testing.T) {
	ea, _, _, _, _ := espPairEngines(t, espSuites[0])
	if _, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", make([]byte, MaxInnerPacket))); !errors.Is(err, ErrOversize) {
		t.Fatalf("超长内层包应返回 ErrOversize，实得：%v", err)
	}
	if _, _, err := ea.Protect([]byte{0x99, 0x00, 0x00}); err == nil {
		t.Fatal("非 IP 包应被拒")
	}
	d := ea.Drops()
	if d.Oversize != 1 || d.Malformed != 1 {
		t.Fatalf("丢弃计数应为 Oversize=1 Malformed=1，实得 %+v", d)
	}
}

// TestEngineInstallRejects 装载期拒绝：错误必须当场报出来，而不是留到运行期变成「不通」。
func TestEngineInstallRejects(t *testing.T) {
	base, _ := espPair(espSuites[0])
	cases := []struct {
		name  string
		mutFn func(p *ipsec.ChildSAParams)
		want  string
	}{
		{"入向 SPI 落在保留区间", func(p *ipsec.ChildSAParams) { p.InSPI = 200 }, "保留区间"},
		{"出向 SPI 为 0", func(p *ipsec.ChildSAParams) { p.OutSPI = 0 }, "保留区间"},
		{"LocalTS 用了 4-in-6 形态", func(p *ipsec.ChildSAParams) {
			p.LocalTS = netip.MustParsePrefix("::ffff:10.60.0.0/120")
		}, "IPv4-mapped"},
		{"两端 TS 地址族不同", func(p *ipsec.ChildSAParams) {
			p.RemoteTS = netip.MustParsePrefix("fd00::/64")
		}, "地址族不同"},
		{"对端落点无效", func(p *ipsec.ChildSAParams) { p.Peer = netip.AddrPort{} }, "无处可发"},
		{"出向密钥长度不符", func(p *ipsec.ChildSAParams) { p.OutEncrKey = espKey(32, 1) }, "salt"},
		{"入向密钥长度不符", func(p *ipsec.ChildSAParams) { p.InEncrKey = espKey(35, 1) }, "入向密钥装载失败"},
		{"加密算法不支持", func(p *ipsec.ChildSAParams) { p.EncrID = 999 }, "不支持的加密算法"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := base
			c.mutFn(&p)
			err := New(nil, nil).Install(p)
			if err == nil {
				t.Fatalf("%s 应被拒", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("错误信息不含 %q：%v", c.want, err)
			}
		})
	}
}

// TestEngineRemoveFoldsCounters 拆除 SA 后，站点的历史计数不得归零。
//
// ★不归档的后果：每次 rekey（默认 1 小时）流量与丢包都重新从 0 开始，
// 「这条隧道一直在少量丢包」这种要横跨多个 SA 才看得出的问题就永远看不见。
func TestEngineRemoveFoldsCounters(t *testing.T) {
	ea, eb, pa, pb, _ := espPairEngines(t, espSuites[0])
	pkt, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("x")))
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}
	if _, err := eb.Unprotect(pkt, pa.Local); err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	// 制造一次认证失败，让 Drops 非零。
	// ★必须用一个**序号更新**的包来篡改：直接改上一个已投递的包，会先撞上反重放预检
	// （那也是正确行为——预检本来就跑在解密之前），计数落到 Replay 而不是 Auth。
	pkt2, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("y")))
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}
	bad := append([]byte(nil), pkt2...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := eb.Unprotect(bad, pa.Local); !errors.Is(err, ipsec.ErrAuth) {
		t.Fatalf("应认证失败：%v", err)
	}

	before, beforeDrops := eb.SiteCounters("site-b"), eb.SiteDrops("site-b")
	if err := eb.Remove(pb.InSPI); err != nil {
		t.Fatalf("拆除失败：%v", err)
	}
	if got := eb.SiteCounters("site-b"); got != before {
		t.Fatalf("拆除后站点计数变成 %+v，期望保持 %+v", got, before)
	}
	if got := eb.SiteDrops("site-b"); got != beforeDrops {
		t.Fatalf("拆除后站点丢弃计数变成 %+v，期望保持 %+v", got, beforeDrops)
	}
	if got := eb.Drops(); got.Auth != 1 {
		t.Fatalf("全局丢弃计数丢失了已拆除 SA 的部分：%+v", got)
	}
	// 重复拆除要报得清楚。
	if err := eb.Remove(pb.InSPI); !errors.Is(err, ipsec.ErrNoSA) {
		t.Fatalf("重复拆除应返回 ipsec.ErrNoSA，实得：%v", err)
	}
	// Counters（单 SA 口径）在拆除后归零是预期的，站点口径才跨世代。
	if c := eb.Counters(pb.InSPI); c != (ipsec.Counters{}) {
		t.Fatalf("已拆除 SA 的单条计数应为零值，实得 %+v", c)
	}
}

// TestEngineRekeyOverlap rekey 期间新旧入向 SA 并存：旧 SA 的在途包仍要收得下，
// 出向则必须已经切到新的。
func TestEngineRekeyOverlap(t *testing.T) {
	s := espSuites[0]
	ea, eb, pa, _, clk := espPairEngines(t, s)

	// A 先发一个包但**不投递**，模拟在途。
	inflight, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("in-flight")))
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}

	// 装载新一代 SA（新 SPI、新密钥），旧的先不拆。
	clk.advance(time.Minute)
	na, nb := espPair(s)
	na.InSPI, na.OutSPI = 0x99110000, 0x99220000
	nb.InSPI, nb.OutSPI = 0x99220000, 0x99110000
	na.OutEncrKey, nb.InEncrKey = espKey(s.keyLen, 0xC0), espKey(s.keyLen, 0xC0)
	na.InEncrKey, nb.OutEncrKey = espKey(s.keyLen, 0xD0), espKey(s.keyLen, 0xD0)
	espMustInstall(t, ea, na)
	espMustInstall(t, eb, nb)

	// 出向必须走新 SA。
	pkt, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("new-gen")))
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}
	if spi := binary.BigEndian.Uint32(pkt[:4]); spi != na.OutSPI {
		t.Fatalf("rekey 后出向 SPI 仍是 0x%08x，期望新的 0x%08x", spi, na.OutSPI)
	}
	if _, err := eb.Unprotect(pkt, pa.Local); err != nil {
		t.Fatalf("新 SA 解封失败：%v", err)
	}
	// 旧 SA 的在途包必须仍然收得下——立刻拆旧入向 SA 的表现就是「每次重协商掉几个包」。
	if _, err := eb.Unprotect(inflight, pa.Local); err != nil {
		t.Fatalf("旧 SA 的在途包被丢了：%v——rekey 时不要立刻拆旧入向 SA", err)
	}
}

// TestEngineNeedRekey 软阈值判定与理由文案。
func TestEngineNeedRekey(t *testing.T) {
	clk := newESPClock()
	pa, _ := espPair(espSuites[0])
	pa.CreatedAt = clk.now()
	pa.HardExpire = clk.at(time.Hour)
	e := New(nil, clk.now)
	espMustInstall(t, e, pa)

	info, ok := e.Info(pa.InSPI)
	if !ok || info.NeedRekey {
		t.Fatalf("刚装载时不该要求 rekey：%+v", info)
	}
	if info.SoftExpire != clk.at(time.Duration(float64(time.Hour)*softLifetimeRatio)) {
		t.Fatalf("软到期时间 %s 与预期不符", info.SoftExpire)
	}
	clk.advance(time.Duration(float64(time.Hour)*softLifetimeRatio) + time.Second)
	info, _ = e.Info(pa.InSPI)
	if !info.NeedRekey || !strings.Contains(info.RekeyReason, "软生存期") {
		t.Fatalf("过了软生存期应要求 rekey 并给出理由，实得 %+v", info)
	}
	clk.advance(time.Hour)
	if info, _ = e.Info(pa.InSPI); !info.Expired {
		t.Fatalf("过了硬生存期应标记 Expired：%+v", info)
	}
	// 过期后出向必须停下来，而不是继续用一把已判死的密钥。
	if _, _, err := e.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("x"))); !errors.Is(err, ipsec.ErrNoPolicy) {
		t.Fatalf("硬到期后出向应返回 ipsec.ErrNoPolicy，实得：%v", err)
	}
}

// TestEngineSeqExhausted 序号用尽必须拒发，绝不回绕。
func TestEngineSeqExhausted(t *testing.T) {
	ea, _, pa, _, _ := espPairEngines(t, espSuites[0])
	ea.mu.RLock()
	s := ea.byInSPI[pa.InSPI]
	ea.mu.RUnlock()
	s.mu.Lock()
	s.outSeq = MaxSeq
	s.mu.Unlock()

	_, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("x")))
	if !errors.Is(err, ErrSeqExhausted) {
		t.Fatalf("序号用尽应返回 ErrSeqExhausted，实得：%v", err)
	}
	if d := ea.Drops(); d.SeqExhausted != 1 {
		t.Fatalf("SeqExhausted 计数应为 1，实得 %+v", d)
	}
	if need, reason := s.needRekey(time.Now()); !need || !strings.Contains(reason, "序号") {
		t.Fatalf("序号到顶应要求 rekey，实得 %v / %q", need, reason)
	}
}

// TestEngineIPv6RoundTrip IPv6 隧道（NextHeader=41）也要真的能跑。
func TestEngineIPv6RoundTrip(t *testing.T) {
	s := espSuites[0]
	pa, pb := espPair(s)
	pa.LocalTS, pa.RemoteTS = netip.MustParsePrefix("fd00:60::/64"), netip.MustParsePrefix("fd00:70::/64")
	pb.LocalTS, pb.RemoteTS = pa.RemoteTS, pa.LocalTS
	ea, eb := New(nil, nil), New(nil, nil)
	espMustInstall(t, ea, pa)
	espMustInstall(t, eb, pb)

	inner := espIPv6("fd00:60::5", "fd00:70::9", []byte("v6 payload"))
	pkt, _, err := ea.Protect(inner)
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}
	got, err := eb.Unprotect(pkt, pa.Local)
	if err != nil {
		t.Fatalf("解封失败：%v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatalf("IPv6 往返内容不一致")
	}
}

// TestEngineNextHeaderMismatch ESP 头声明与内层实际版本不符的报文必须被拒。
func TestEngineNextHeaderMismatch(t *testing.T) {
	s := espSuites[0]
	_, eb, pa, _, _ := espPairEngines(t, s)
	c, err := newCrypto(s.encrID, s.keyBits, s.integID, pa.OutEncrKey, pa.OutIntegKey)
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	// 内层是 IPv4，却声称 NextHeader=41。
	pkt, err := c.encap(pa.OutSPI, 7, espIPv4("10.60.0.5", "10.70.0.9", []byte("x")), protoIPv6)
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}
	if _, err := eb.Unprotect(pkt, pa.Local); err == nil {
		t.Fatal("NextHeader 与内层版本不符应被拒")
	}
	// TFC 哑包（NextHeader=59）同样不接受。
	pkt, err = c.encap(pa.OutSPI, 8, espIPv4("10.60.0.5", "10.70.0.9", []byte("x")), protoNoNextHeader)
	if err != nil {
		t.Fatalf("封装失败：%v", err)
	}
	if _, err := eb.Unprotect(pkt, pa.Local); err == nil || !strings.Contains(err.Error(), "59") {
		t.Fatalf("NextHeader=59 应被拒并点名 59，实得：%v", err)
	}
}

// TestAllocSPI 分配的 SPI 必须避开 0 与 1..255。
func TestAllocSPI(t *testing.T) {
	for i := 0; i < 2000; i++ {
		spi, err := AllocSPI(rand.Reader)
		if err != nil {
			t.Fatalf("分配失败：%v", err)
		}
		if spi < SPIMin {
			t.Fatalf("分配出保留区间的 SPI 0x%08x", spi)
		}
	}
	// 退化随机源必须报错而不是死循环，也不能"修正"成某个固定值。
	if _, err := AllocSPI(espZeroReader{}); err == nil {
		t.Fatal("恒零随机源应报错")
	}
	if _, err := AllocSPI(espFailReader{}); err == nil {
		t.Fatal("读失败的随机源应报错")
	}
}

type espZeroReader struct{}

func (espZeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type espFailReader struct{}

func (espFailReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestEngineListStable List 输出按 SPI 升序，便于把两次采样直接 diff。
func TestEngineListStable(t *testing.T) {
	e := New(nil, nil)
	base, _ := espPair(espSuites[0])
	for _, spi := range []uint32{0x3000, 0x1000, 0x2000} {
		p := base
		p.InSPI = spi
		espMustInstall(t, e, p)
	}
	got := e.List()
	if len(got) != 3 {
		t.Fatalf("List 返回 %d 条，期望 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].InSPI > got[i].InSPI {
			t.Fatalf("List 未按 SPI 升序：%v", got)
		}
	}
}

// TestEngineConcurrentPumps 并发安全：出向泵与入向泵是两个 goroutine，
// 状态上报还会在第三个 goroutine 里全量读计数。
//
// ★真正被断言的不是「没崩」，而是**并发下序号仍然唯一**：GCM 的显式 IV 就是序号，
// 序号在竞态下重复 = nonce 复用 = 明文与认证密钥同时可恢复，且不会有任何报错。
// 这条测试必须配 -race 跑才有意义。
func TestEngineConcurrentPumps(t *testing.T) {
	ea, eb, pa, _, _ := espPairEngines(t, espSuites[0])

	const producers, perProducer = 8, 200
	total := producers * perProducer
	pkts := make(chan []byte, total)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { // 状态上报泵：不停地全量读，专门用来撞读写竞态
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				ea.List()
				ea.Drops()
				ea.SiteCounters("site-a")
				ea.SeqOf(pa.InSPI)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perProducer; j++ {
				pkt, _, err := ea.Protect(espIPv4("10.60.0.5", "10.70.0.9", []byte("concurrent")))
				if err != nil {
					t.Errorf("并发封装失败：%v", err)
					return
				}
				pkts <- pkt
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-done
	close(pkts)

	// 序号必须恰好覆盖 1..total，一个不多一个不少。
	seen := make(map[uint32][]byte, total)
	for pkt := range pkts {
		seq := binary.BigEndian.Uint32(pkt[4:8])
		if _, dup := seen[seq]; dup {
			t.Fatalf("并发下出现重复序号 %d——GCM 的 IV 就是序号，重复即 nonce 复用", seq)
		}
		seen[seq] = pkt
	}
	if len(seen) != total {
		t.Fatalf("收到 %d 个不同序号，期望 %d", len(seen), total)
	}
	for i := 1; i <= total; i++ {
		if _, ok := seen[uint32(i)]; !ok {
			t.Fatalf("序号 %d 缺失——出向序号必须连续无空洞", i)
		}
	}

	// 按序投递，全部应被接受（乱序投递会超出 64 的反重放窗口，那是链路问题不是引擎问题）。
	for i := 1; i <= total; i++ {
		if _, err := eb.Unprotect(seen[uint32(i)], pa.Local); err != nil {
			t.Fatalf("序号 %d 解封失败：%v", i, err)
		}
	}
	if c := eb.SiteCounters("site-b"); c.PacketsIn != uint64(total) {
		t.Fatalf("入向包数 %d，期望 %d", c.PacketsIn, total)
	}
}

// TestOverheadCoversAllSuites 四个码点（含两个国密私有码点）都要能算出封装开销。
//
// 这条顺带守住「国密只在 ike 的注册表里被 lookup 过、ESP 侧从没真正解析过」这种
// 纸面支持：Overhead 会实际构造算法对象，构造不出来就在这里红。
func TestOverheadCoversAllSuites(t *testing.T) {
	var _ ipsec.Protector = New(nil, nil) // 编译期断言接口完整

	for _, tc := range []struct {
		id    uint16
		bits  int
		integ uint16
	}{
		{ike.EncrAESGCM16, 256, ike.IntegNone},
		{ike.EncrAESCBC, 256, ike.IntegHMACSHA256128},
		{ike.EncrSM4GCM16, 128, ike.IntegNone},
		{ike.EncrSM4CBC, 128, ike.IntegHMACSM3128},
	} {
		n, err := Overhead(tc.id, tc.bits, tc.integ)
		if err != nil {
			t.Fatalf("算法 %d 的封装开销计算失败：%v", tc.id, err)
		}
		if n <= HeaderLen+TrailerLen {
			t.Fatalf("算法 %d 的封装开销 %d 明显偏小", tc.id, n)
		}
	}
}
