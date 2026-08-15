package lockout

// 防爆破在**洪泛**下还成不成立（wave7 行动 13 附带的安全加固）。
//
// 由来：做「图形验证码接真还是摘除」的决策时，对抗验证挖出了一条真实可利用的路径——
// 失败计数表有上限（内存保护），而淘汰判据原本是「最后一次失败最早」，于是攻击者
// 只要在两次猜测之间灌进一批更新的键，受害账号那条计数就被整条删掉、下次猜测从 1 重来，
// 账号锁**永远够不到阈值**。当时的 PoC：连猜 50 次零锁定。
//
// 更恶劣的是它全程静默：审计与通知都只在「确实建立了锁定」时才写，攻击成功时
// 用户状态页干干净净、告警一条没有。
//
// 本文件是那批 PoC 转成的回归用例：能修的钉住修复，修不掉的**如实钉住边界**（见文件末尾）。

import (
	"fmt"
	"testing"
	"time"

	"baidi.dev/control/internal/store"
)

// 一个维度被灌爆，不得挤掉另一个维度的计数。
//
// 修复前两个维度共用一张 4096 表：灌水请求每个造两个键（新源 IP + 随机用户名），
// 账号维度的受害者计数被 IP 键连带挤出去，连猜 20 次不锁。
func TestFlood_IP维度洪泛不得稀释账号锁(t *testing.T) {
	g, now := newTestGuard()
	for round := 0; round < 6; round++ {
		if locked := g.Fail(ctx, "victim", "203.0.113.9"); len(locked) > 0 {
			for _, l := range locked {
				if l.Kind == store.LockKindAccount {
					return // 账号锁如期触发：防线成立
				}
			}
		}
		*now = now.Add(time.Second)
		// 每轮灌 2048 个**全新源 IP**（IPv6 各不相同），同时带全新用户名
		for i := 0; i < 2048; i++ {
			g.Fail(ctx, fmt.Sprintf("spam-%d-%d", round, i), fmt.Sprintf("2001:db8:1:%x::%x", round, i))
		}
		*now = now.Add(time.Second)
	}
	t.Fatal("受害账号连猜 6 轮仍未锁定——IP 维度的洪泛把账号维度的计数稀释掉了")
}

// IPv6 必须按 /64 聚合成键，否则 IP 维度在 IPv6 下形同虚设。
//
// 运营商给终端的通常是一整段 /64，换地址零成本；不聚合的话每个新地址都是全新的键，
// 「同一个人连错 5 次」这件事永远数不出来。
func TestFlood_IPv6按64聚合(t *testing.T) {
	g, _ := newTestGuard()
	var got store.Lockout
	for i := 0; i < 5; i++ {
		// 同一个 /64 里换 5 个不同地址
		for _, l := range g.Fail(ctx, fmt.Sprintf("u%d", i), fmt.Sprintf("2001:db8:abcd:1234::%x", i)) {
			if l.Kind == store.LockKindIP {
				got = l
			}
		}
	}
	if got.Key == "" {
		t.Fatal("同一个 /64 内换地址连错 5 次应触发 IP 锁（未聚合的话每个地址各自从 0 计数，永远锁不上）")
	}
	if got.Key != "2001:db8:abcd:1234::/64" {
		t.Fatalf("IP 锁的键应是聚合后的 /64，实得 %q", got.Key)
	}
	// 同段内的任一地址都应被这条锁命中
	if _, hit := g.Check("someone-else", "2001:db8:abcd:1234::dead"); !hit {
		t.Fatal("同 /64 内的其它地址应被同一条锁命中")
	}
	// 邻段不受影响（聚合粒度不能过粗）
	if _, hit := g.Check("someone-else", "2001:db8:abcd:9999::1"); hit {
		t.Fatal("相邻 /64 不该被牵连")
	}
	// IPv4 保持原样，不做任何聚合
	if k := normIPKey("203.0.113.9"); k != "203.0.113.9" {
		t.Fatalf("IPv4 应原样作键，实得 %q", k)
	}
}

// 淘汰必须优先牺牲「失败次数最少」的键，而不是「最后一次失败最早」的键。
//
// 已累计到差一次就锁定的那个键，恰恰是全表里最不能丢的。
func TestFlood_淘汰不得牺牲即将锁定的键(t *testing.T) {
	g, now := newTestGuard()
	// victim 先累计到 threshold-1 次
	for i := 0; i < g.Config().Threshold-1; i++ {
		g.Fail(ctx, "victim", "")
	}
	*now = now.Add(time.Second)
	// 灌满一整表**更新**的键（每个只失败 1 次）
	for i := 0; i < maxFailKeys+10; i++ {
		g.Fail(ctx, fmt.Sprintf("spam-%06d", i), "")
	}
	g.mu.Lock()
	ts, still := g.fails[store.LockKindAccount]["victim"]
	g.mu.Unlock()
	if !still {
		t.Fatal("victim 的计数被灌水挤掉了——淘汰判据必须是「失败次数最少优先」")
	}
	if len(ts) != g.Config().Threshold-1 {
		t.Fatalf("victim 的计数不应被削减，实得 %d 次", len(ts))
	}
	// 再失败一次就该锁上
	locked := g.Fail(ctx, "victim", "")
	if len(locked) == 0 {
		t.Fatal("补上最后一次失败后应立即锁定")
	}
}

// 生效锁定表必须有界，且满时淘汰的是**最快到期**的那条。
//
// ★刻意不「拒绝新建」：那等于让攻击者靠撑爆表给自己换来豁免。
func TestFlood_锁定表有界(t *testing.T) {
	g, _ := newTestGuard()
	th := g.Config().Threshold
	for i := 0; i < 3000; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		for j := 0; j < th; j++ {
			g.Fail(ctx, fmt.Sprintf("acct-%d-%d", i, j), ip)
		}
	}
	g.mu.Lock()
	n := len(g.locks)
	g.mu.Unlock()
	if n > maxLocks {
		t.Fatalf("生效锁定数应有界（≤%d），实得 %d", maxLocks, n)
	}
}

// ── 已知边界（修不掉的那条，如实钉住）─────────────────────────────────
//
// 攻击者若能在两次猜测之间灌进**一整表全新键**，受害账号的计数仍会被挤掉。
// 这不是判据没写对：失败计数表容量有限而攻击者可生成的键无限，任何淘汰策略
// 在表满时都必须牺牲某个键，而 lockout 这一层没有信息区分「受害者的 1 次失败」
// 与「攻击者的 1 次失败」——两者长得完全一样。
//
// 现有加固把成本抬到了：**每猜一次要灌满一整表**（默认 4096 次请求），且
// 只在 IP 维度被管理员关掉时可行（开着时灌水者自己先被 IP 锁拦住）。
// 真正的解法在前置层——nginx 对登录端点按源限速，让「每轮 4096 次」不可行。
// 这条边界写在 docs/ARCHITECTURE.md 第七节，运维建议一并在那里。
//
// 本用例存在的意义：它是这条边界的**可执行文档**。哪天有人改了淘汰策略以为
// 顺手修好了它，这里会告诉他并没有。
func TestKnownLimit_灌满整表仍可稀释账号锁(t *testing.T) {
	g, now := newTestGuard()
	cfg := g.Config()
	cfg.IPEnabled = false // 前提：管理员关掉了 IP 维度（NAT 后办公网的常见运维动作）
	g.mu.Lock()
	g.cfg = cfg
	g.mu.Unlock()

	for round := 0; round < 10; round++ {
		if locked := g.Fail(ctx, "victim", ""); len(locked) > 0 {
			t.Fatalf("第 %d 轮就锁定了——如果这条用例开始失败，说明这个已知边界被真正修好了，"+
				"请把它改成正向断言并更新 docs/ARCHITECTURE.md 第七节", round)
		}
		*now = now.Add(time.Second)
		for i := 0; i < maxFailKeys; i++ {
			g.Fail(ctx, fmt.Sprintf("spam-%03d-%06d", round, i), "")
		}
		*now = now.Add(time.Second)
	}
	if _, hit := g.Check("victim", ""); hit {
		t.Fatal("victim 竟被锁上了（同上：边界已修好，请更新用例与文档）")
	}
}
