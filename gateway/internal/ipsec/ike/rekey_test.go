package ike

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// cryptoRandForTest 退避/抖动测试用的熵源。用真随机而不是固定种子：
// 这里要验证的恰恰是"抖动真的存在"，固定种子会让断言退化成自证。
func cryptoRandForTest() io.Reader { return rand.Reader }

// 重协商与超时的测试。
//
// ★全部走**注入时钟**，零 sleep。这不是可测性洁癖：这里的时间常数是 30 秒到 4 小时，
// 用真实时钟测就只能 sleep，测试会慢到被 `-short` 跳过，最终等于没有测试——
// 而 rekey 恰恰是"平时看不出问题、跑几小时后隧道莫名断掉"的重灾区。

// rkClock 一个可手工推进的时钟。
type rkClock struct {
	mu sync.Mutex
	t  time.Time
}

func newRKClock() *rkClock {
	return &rkClock{t: time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)}
}

func (c *rkClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *rkClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// rkSetup 起一对带注入时钟的引擎，并跑完首次握手。
func rkSetup(t *testing.T, tune func(c *ipsec.SiteConfig)) (*hsFixture, *rkClock) {
	t.Helper()
	clk := newRKClock()
	cfgA, cfgB := hsSiteA("baidi-ipsec-psk"), hsSiteB("baidi-ipsec-psk")
	if tune != nil {
		tune(&cfgA)
		tune(&cfgB)
	}
	f := hsSetupWith(t, cfgA, cfgB, clk.now, nil)
	hsWait(t, "首次握手完成", func() bool { return hsUp(f.a, "site-1") && hsUp(f.b, "site-1") })
	return f, clk
}

// rkLiveSPIs 取某端当前已装载的全部入向 SPI。
func rkLiveSPIs(p *hsProtector) map[uint32]ipsec.ChildSAParams {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[uint32]ipsec.ChildSAParams, len(p.live))
	for k, v := range p.live {
		out[k] = v
	}
	return out
}

// ── Child SA 重协商 ──

func TestChildRekeyInstallsNewSAAndDelaysOldRemoval(t *testing.T) {
	f, clk := rkSetup(t, func(c *ipsec.SiteConfig) {
		c.ESPLifetime = 10 * time.Minute
		c.IKELifetime = 24 * time.Hour // 别让 IKE SA 的软生存期插进来
		c.PFS = true
	})

	oldA := f.pa.only(t)
	oldB := f.pb.only(t)

	// 推到 Child SA 软生存期之后（0.85~0.95 × 10min，推 9.5 分钟必定越过）。
	clk.advance(9*time.Minute + 30*time.Second)
	f.a.runTimers()

	hsWait(t, "两端都装载了第二条 Child SA", func() bool {
		return len(rkLiveSPIs(f.pa)) == 2 && len(rkLiveSPIs(f.pb)) == 2
	})

	// ── ★旧 SA 必须还在：立刻拆掉会丢掉对端在途的报文，
	//    表现为「每次重协商掉几个包」——业务侧看是随机丢包，几乎无法归因。
	if _, ok := rkLiveSPIs(f.pa)[oldA.InSPI]; !ok {
		t.Fatal("旧 Child SA 被立刻拆掉了；必须延迟删除，否则对端在途报文会被丢")
	}

	var newA, newB ipsec.ChildSAParams
	for spi, p := range rkLiveSPIs(f.pa) {
		if spi != oldA.InSPI {
			newA = p
		}
	}
	for spi, p := range rkLiveSPIs(f.pb) {
		if spi != oldB.InSPI {
			newB = p
		}
	}

	// 新 SA 的 SPI 与密钥都必须与旧的不同（否则等于什么都没换）。
	if newA.InSPI == oldA.InSPI || newA.OutSPI == oldA.OutSPI {
		t.Fatal("重协商出的 Child SA 复用了旧 SPI")
	}
	if bytes.Equal(newA.OutEncrKey, oldA.OutEncrKey) {
		t.Fatal("重协商出的 Child SA 复用了旧密钥——PFS 形同虚设")
	}
	// 两端交叉相等：这是"新 SA 也是真协商出来的"的同一条判据。
	if newA.InSPI != newB.OutSPI || newA.OutSPI != newB.InSPI {
		t.Fatalf("新 Child SA 的 SPI 没有交叉相等：A(in=%08x out=%08x) B(in=%08x out=%08x)",
			newA.InSPI, newA.OutSPI, newB.InSPI, newB.OutSPI)
	}
	if !bytes.Equal(newA.OutEncrKey, newB.InEncrKey) || !bytes.Equal(newA.InEncrKey, newB.OutEncrKey) {
		t.Fatal("开了 PFS 的重协商，两端 KEYMAT 不一致（多半是 g^ir 没拼进 prf+ 的 seed）")
	}

	// ── 延迟删除到点后，旧 SA 才消失 ──
	clk.advance(childRetireDelay + time.Second)
	f.a.runTimers()
	hsWait(t, "旧 Child SA 被延迟删除", func() bool { return len(rkLiveSPIs(f.pa)) == 1 })
	if _, ok := rkLiveSPIs(f.pa)[newA.InSPI]; !ok {
		t.Fatal("延迟删除拆错了 SA：留下的应该是新的那条")
	}

	// 对端也得跟着拆（靠 D(ESP)），否则它的 SA 表会一直堆积。
	f.b.runTimers()
	hsWait(t, "B 侧旧 Child SA 也被拆掉", func() bool { return len(rkLiveSPIs(f.pb)) == 1 })

	if st := hsState(f.a, "site-1"); st.State != ipsec.StateUp {
		t.Fatalf("重协商结束后站点应回到 up，实际 %s", st.State)
	}
	if st := hsState(f.a, "site-1"); st.ChildSPIIn != newA.InSPI {
		t.Fatalf("回报的 Child SPI 应是新的那条（%08x），实际 %08x", newA.InSPI, st.ChildSPIIn)
	}
}

// ── 并发重协商：必须回 TEMPORARY_FAILURE 并最终收敛到一条 ──

func TestConcurrentChildRekeyYieldsTemporaryFailure(t *testing.T) {
	// ESPLifetime 取 20 分钟：发起方软生存期落在 [17, 19] 分钟，响应方（有 +10%
	// 兜底偏移，封顶 0.98）落在 [19, 19.6] 分钟。推进 19 分 40 秒能确保**两端都**
	// 越过软生存期，又不触碰 20 分钟的硬生存期——撞车场景必须是确定的，
	// 靠时序碰运气的测试等于没有测试。
	f, clk := rkSetup(t, func(c *ipsec.SiteConfig) {
		c.ESPLifetime = 20 * time.Minute
		c.IKELifetime = 24 * time.Hour
	})

	// ★制造确定的撞车：先把网断开，让两端各自把 CREATE_CHILD_SA 请求"发出去"
	// （实际被丢弃），于是双方都处于"有未完成 rekey"的状态；再把这两条请求
	// 手工投递给对方。不这样做就只能靠时序碰运气，而碰运气的测试等于没有测试。
	var held []hsPacket
	var mu sync.Mutex
	f.net.SetFilter(func(d ipsec.Datagram) (ipsec.Datagram, bool) {
		mu.Lock()
		held = append(held, hsPacket{from: d.Local, to: d.Remote, payload: append([]byte(nil), d.Payload...)})
		mu.Unlock()
		return d, false // 丢包
	})

	clk.advance(19*time.Minute + 40*time.Second)
	f.a.runTimers()
	f.b.runTimers()

	mu.Lock()
	pending := append([]hsPacket(nil), held...)
	mu.Unlock()
	if len(pending) != 2 {
		t.Fatalf("两端应各发出一条 CREATE_CHILD_SA 请求，实际拦下 %d 条", len(pending))
	}

	// ★响应也必须先扣住。否则会出现这样的时序：把 A 的请求喂给 B 之后，B 的
	// TEMPORARY_FAILURE 立刻经内存网回到 A 并被 A 的事件循环处理掉、清空了 A 的
	// pending；等我们再把 B 的请求喂给 A 时，A 已经"没有未完成的重协商"了，
	// 于是它会正常接受——测试就随机地变绿变红。扣住响应才能让撞车真正同时发生。
	var responses []hsPacket
	f.net.SetFilter(func(d ipsec.Datagram) (ipsec.Datagram, bool) {
		mu.Lock()
		responses = append(responses, hsPacket{from: d.Local, to: d.Remote, payload: append([]byte(nil), d.Payload...)})
		mu.Unlock()
		return d, false
	})
	for _, p := range pending {
		dst, src := f.b, hsAddrA
		if p.to == hsAddrA {
			dst, src = f.a, hsAddrB
		}
		dst.handle(ipsec.Datagram{Kind: ipsec.KindIKE, Local: p.to, Remote: src, Payload: p.payload})
	}

	mu.Lock()
	got := append([]hsPacket(nil), responses...)
	mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("两端应各回一条响应，实际 %d 条", len(got))
	}
	// 两端都该回 TEMPORARY_FAILURE。
	for i, p := range got {
		if !rkResponseHasNotify(t, f, p, NotifyTemporaryFailure) {
			t.Fatalf("第 %d 条响应里没有 TEMPORARY_FAILURE；并发重协商必须靠它收敛，"+
				"否则就得实现 RFC §2.8.1 的 nonce 比大小 + 双 SA 收敛", i+1)
		}
	}

	// 恢复正常投递，再把两条响应喂给各自的发起方。
	cap := &hsCapture{}
	f.net.SetFilter(cap.filter)

	// 把响应投给发起方，双方都应退回 Established 并排一次随机退避重试。
	for _, p := range got {
		dst, src := f.b, hsAddrA
		if p.to == hsAddrA {
			dst, src = f.a, hsAddrB
		}
		dst.handle(ipsec.Datagram{Kind: ipsec.KindIKE, Local: p.to, Remote: src, Payload: p.payload})
	}

	for name, e := range map[string]*Engine{"A": f.a, "B": f.b} {
		sa := hsPrimarySA(e, "site-1")
		if sa == nil || sa.State != SAEstablished {
			t.Fatalf("%s 端撞车后应退回 Established，实际 %v", name, sa)
		}
		if sa.pending != nil {
			t.Fatalf("%s 端撞车后不该还挂着未完成交换", name)
		}
		e.mu.Lock()
		var soft time.Time
		for _, c := range sa.children {
			if c.rekeying {
				t.Fatalf("%s 端撞车后 rekeying 标记没清掉，会永远不再重试", name)
			}
			soft = c.SoftExpire
		}
		e.mu.Unlock()
		// 退避窗口 1~5 秒，且必须**随机**——固定退避会让两端以完全相同的节奏
		// 反复撞车（活锁），日志里全是 TEMPORARY_FAILURE 而隧道永远不换密钥。
		d := soft.Sub(clk.now())
		if d < time.Second || d > 5*time.Second {
			t.Fatalf("%s 端的退避 %v 不在 [1s, 5s] 内", name, d)
		}
	}

	// 让 A 先醒来，重协商应当顺利完成。
	clk.advance(6 * time.Second)
	f.a.runTimers()
	hsWait(t, "撞车后最终收敛出一条新 Child SA", func() bool {
		return len(rkLiveSPIs(f.pa)) == 2 && len(rkLiveSPIs(f.pb)) == 2
	})
}

// rkResponseHasNotify 解开一条抓到的响应，看它是否带指定通知。
func rkResponseHasNotify(t *testing.T, f *hsFixture, p hsPacket, nt NotifyType) bool {
	t.Helper()
	// ★用**发送方**的出向密钥解：报文发往 B 就说明是 A 发的。
	// 这里写反的话报错会是"认证解密失败"，看起来像加密实现有问题，
	// 实际只是测试拿错了密钥——正是本项目最典型的误导性症状。
	e := f.b
	if p.to == hsAddrB {
		e = f.a
	}
	sa := hsPrimarySA(e, "site-1")
	if sa == nil {
		return false
	}
	m, err := Decode(p.payload)
	if err != nil {
		t.Fatalf("响应无法解析: %v", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := DecryptSK(m, sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut()); err != nil {
		t.Fatalf("响应无法解开: %v", err)
	}
	return m.FindNotify(nt) != nil
}

// ── IKE SA 重协商：Child SA 必须原样迁移，业务不中断 ──

func TestIKERekeyMigratesChildrenWithoutTouchingDataplane(t *testing.T) {
	f, clk := rkSetup(t, func(c *ipsec.SiteConfig) {
		c.IKELifetime = 10 * time.Minute
		c.ESPLifetime = 24 * time.Hour // 别让 Child SA 的软生存期插进来
	})

	oldSA_A := hsPrimarySA(f.a, "site-1")
	oldSA_B := hsPrimarySA(f.b, "site-1")
	childBefore := rkLiveSPIs(f.pa)

	clk.advance(9*time.Minute + 30*time.Second)
	f.a.runTimers()

	hsWait(t, "两端都换上了新的 IKE SA", func() bool {
		na, nb := hsPrimarySA(f.a, "site-1"), hsPrimarySA(f.b, "site-1")
		return na != nil && nb != nil && na != oldSA_A && nb != oldSA_B
	})
	newA, newB := hsPrimarySA(f.a, "site-1"), hsPrimarySA(f.b, "site-1")

	// ── 新 SA 的密钥两端一致，且与旧 SA 不同 ──
	if !bytes.Equal(newA.Keys.SKd, newB.Keys.SKd) || !bytes.Equal(newA.Keys.SKei, newB.Keys.SKei) {
		t.Fatal("重协商后的 IKE 密钥两端不一致")
	}
	if bytes.Equal(newA.Keys.SKd, oldSA_A.Keys.SKd) {
		t.Fatal("重协商后 SK_d 没变——等于没换")
	}
	if newA.SPIi == oldSA_A.SPIi || newA.SPIr == oldSA_A.SPIr {
		t.Fatal("重协商后的 IKE SPI 复用了旧值")
	}
	// ★发起重协商的一方就是新 SA 的原始发起方；抄旧 SA 的角色是这里最容易犯的错，
	// 症状是重协商"成功"之后所有报文都解不开。
	if !newA.LocalIsInit || newB.LocalIsInit {
		t.Fatalf("新 SA 的原始角色错了：A=%v B=%v（应为 true/false）", newA.LocalIsInit, newB.LocalIsInit)
	}
	// ★新 SA 双向 Message ID 归零。
	f.a.mu.Lock()
	txMID, rxMID := newA.nextTxMID, newA.expectRxMID
	f.a.mu.Unlock()
	if txMID != 0 || rxMID != 0 {
		t.Fatalf("新 IKE SA 的 Message ID 应双向归零，实际 tx=%d rx=%d", txMID, rxMID)
	}

	// ── ★Child SA 必须原样迁移：换 IKE SA 不该让业务流量断一下 ──
	childAfter := rkLiveSPIs(f.pa)
	if len(childAfter) != len(childBefore) {
		t.Fatalf("换 IKE SA 时 Child SA 数量变了（%d → %d）——数据面被无谓地动过了",
			len(childBefore), len(childAfter))
	}
	for spi := range childBefore {
		if _, ok := childAfter[spi]; !ok {
			t.Fatalf("Child SA %08x 在换 IKE SA 时被拆掉了；ESP 只认 SPI 与密钥，"+
				"换 IKE SA 不需要也不允许中断它", spi)
		}
	}
	f.a.mu.Lock()
	migrated := len(newA.children)
	leftBehind := len(oldSA_A.children)
	f.a.mu.Unlock()
	if migrated != len(childBefore) || leftBehind != 0 {
		t.Fatalf("Child SA 没有迁移到新 IKE SA 上（新 %d 条，旧 SA 还留着 %d 条）", migrated, leftBehind)
	}

	// ── 旧 IKE SA 延迟删除 ──
	clk.advance(ikeRetireDelay + time.Second)
	f.a.runTimers()
	hsWait(t, "旧 IKE SA 被拆除且对端也跟着拆", func() bool {
		// B 侧靠收到 D(IKE) 拆掉旧 SA，但把它从站点列表里摘走要等自己的定时器；
		// 测试里定时器是手工驱动的，所以两端都推一下。
		f.a.runTimers()
		f.b.runTimers()
		f.a.mu.Lock()
		na := len(f.a.sites["site-1"].sas)
		f.a.mu.Unlock()
		f.b.mu.Lock()
		nb := len(f.b.sites["site-1"].sas)
		f.b.mu.Unlock()
		return na == 1 && nb == 1
	})
	if !hsUp(f.a, "site-1") || !hsUp(f.b, "site-1") {
		t.Fatal("换完 IKE SA 后两端都应仍为 up")
	}
	if len(rkLiveSPIs(f.pa)) != len(childBefore) {
		t.Fatal("拆旧 IKE SA 时不该带走已经迁移走的 Child SA")
	}
}

// ── DPD：对端消失后必须判死并置 failed（而不是永远挂着 up）──

func TestDPDDeclaresPeerDeadAfterRetransmitsExhausted(t *testing.T) {
	f, clk := rkSetup(t, func(c *ipsec.SiteConfig) {
		c.DPDDelay = 30 * time.Second
		c.IKELifetime = 24 * time.Hour
		c.ESPLifetime = 24 * time.Hour
	})

	// 对端从网络上消失（不是优雅退出——那样会收到 D(IKE)）。
	f.net.SetFilter(func(d ipsec.Datagram) (ipsec.Datagram, bool) { return d, false })

	clk.advance(31 * time.Second)
	f.a.runTimers()
	f.a.mu.Lock()
	sa := f.a.sites["site-1"].primary()
	hasDPD := sa != nil && sa.pending != nil && sa.pending.kind == exDPD
	f.a.mu.Unlock()
	if !hasDPD {
		t.Fatal("空闲超过 DPDDelay 后应发出 DPD 探活")
	}

	// 走完整张退避表。★这里正是注入时钟的价值：真实时钟下这段要跑 182 秒。
	//
	// 判死之后**立刻停**：failSite 会同时排下一次重连（30 秒后），再推时钟站点
	// 就会重新变回 connecting——那也是正确行为（零信任下 fail-closed + 自动重试），
	// 只是断言要抓的是判死的那一刻。
	for i := 0; i <= maxRetransmits+2; i++ {
		clk.advance(70 * time.Second)
		f.a.runTimers()
		if hsState(f.a, "site-1").State == ipsec.StateFailed {
			break
		}
	}

	st := hsState(f.a, "site-1")
	if st.State != ipsec.StateFailed {
		t.Fatalf("对端消失后站点应判 failed（而不是永远显示 up），实际 %s", st.State)
	}
	// ★错误信息必须能直接指导排障：带上对端地址、重传次数与总时长。
	if !bytes.Contains([]byte(st.LastError), []byte("无响应")) ||
		!bytes.Contains([]byte(st.LastError), []byte("10.0.0.2:500")) {
		t.Fatalf("判死的错误信息应带上对端地址与重传情况，实际：%q", st.LastError)
	}
	if len(rkLiveSPIs(f.pa)) != 0 {
		t.Fatal("IKE SA 判死后其 Child SA 必须一起从数据面摘掉，否则流量会灌进一条没人接收的隧道")
	}
}

// ── ESP 收包要能刷新 DPD 计时 ──
//
// 只有 IKE 报文刷新计时是不够的：一条跑着满速业务流量的隧道，IKE 层可能几十分钟
// 一句话都没说。不接 Touch 回调的症状是"越忙的隧道越容易被 DPD 判死"。
func TestTouchRefreshesDPDTimer(t *testing.T) {
	f, clk := rkSetup(t, func(c *ipsec.SiteConfig) {
		c.DPDDelay = 30 * time.Second
		c.IKELifetime = 24 * time.Hour
		c.ESPLifetime = 24 * time.Hour
	})
	inSPI := f.pa.only(t).InSPI

	clk.advance(25 * time.Second)
	f.a.Touch(inSPI) // ESP 数据面收到一个合法报文
	clk.advance(20 * time.Second)
	f.a.runTimers()

	f.a.mu.Lock()
	sa := f.a.sites["site-1"].primary()
	pending := sa != nil && sa.pending != nil
	f.a.mu.Unlock()
	if pending {
		t.Fatal("ESP 收包刚刷新过计时，不该触发 DPD")
	}

	clk.advance(20 * time.Second) // 累计 40 秒没有任何流量
	f.a.runTimers()
	f.a.mu.Lock()
	sa = f.a.sites["site-1"].primary()
	pending = sa != nil && sa.pending != nil && sa.pending.kind == exDPD
	f.a.mu.Unlock()
	if !pending {
		t.Fatal("真的空闲超过 DPDDelay 后应触发 DPD")
	}
}

// ── 出向 IV 计数器必须单调递增，且绝不回绕 ──

func TestOutboundIVCounterIsMonotonicAndRefusesToWrap(t *testing.T) {
	sa := newIKESA("s", true, time.Now())
	seen := make(map[uint64]bool)
	for i := 0; i < 100; i++ {
		v, err := sa.nextIV()
		if err != nil {
			t.Fatalf("第 %d 次取 IV 失败: %v", i, err)
		}
		if seen[v] {
			// ★GCM 下 nonce 复用不是"安全性下降"，是认证密钥可被恢复。
			t.Fatalf("IV %d 被复用了", v)
		}
		seen[v] = true
	}
	sa.txIVCounter = 1<<63 - 1
	if _, err := sa.nextIV(); err != nil {
		t.Fatalf("尚未越界就拒绝了: %v", err)
	}
	if _, err := sa.nextIV(); err == nil {
		t.Fatal("计数器接近回绕时必须拒绝继续加密，而不是回绕复用 nonce")
	}
}

// ── 重传退避表 ──

func TestRetransmitBackoffGrowsAndJitters(t *testing.T) {
	rnd := cryptoRandForTest()
	var prev time.Duration
	for i := 1; i <= maxRetransmits; i++ {
		d := retransmitDelay(i, rnd)
		base := retransmitDelays[i-1]
		lo, hi := base*80/100, base*120/100
		if d < lo || d > hi {
			t.Fatalf("第 %d 次重传等待 %v 不在 ±20%% 抖动区间 [%v, %v] 内", i, d, lo, hi)
		}
		if i < len(retransmitDelays) && base < retransmitDelays[i] && d <= prev/2 {
			t.Fatalf("退避没有随次数增长：第 %d 次 %v，上一次 %v", i, d, prev)
		}
		prev = d
	}
	// 总窗口必须到分钟级：太短会在对端重启时误判死亡。
	if totalRetransmitWindow() < 2*time.Minute {
		t.Fatalf("重传总窗口 %v 太短，对端重启期间会被误判为死亡", totalRetransmitWindow())
	}
	// 抖动必须真的存在（同一次数连续取 20 个值不能全相同）。
	first := retransmitDelay(3, rnd)
	same := true
	for i := 0; i < 20; i++ {
		if retransmitDelay(3, rnd) != first {
			same = false
			break
		}
	}
	if same {
		t.Fatal("退避没有抖动：两端配置相同则会同时超时、同时重连，形成谐振")
	}
}

// ── 站点级重连退避 ──

func TestSiteRetryBackoffCapsAtFiveMinutes(t *testing.T) {
	rnd := cryptoRandForTest()
	for step := 0; step < 12; step++ {
		d := siteRetryDelay(step, rnd)
		if d < siteRetryMin*80/100 {
			t.Fatalf("第 %d 次重连间隔 %v 小于下界", step, d)
		}
		if d > siteRetryMax*120/100 {
			// ★不封顶的话，一条配错的站点会以指数增长后变成"几小时才试一次"，
			// 管理员改好配置后要等很久才恢复。
			t.Fatalf("第 %d 次重连间隔 %v 超过了 5 分钟封顶", step, d)
		}
	}
}
