package knock

// 去重缓存的规模基准与洪泛行为（wave9）。
//
// ★定位：**防回归 + 证明一个已修的攻击面**，不是容量承诺。
// 口径：纯内存操作，无网络无 IO；数字随机器变化，看的是**随表大小的增长趋势**。
//
// 修的是什么：Seen 此前每次调用都遍历整个 map 做惰性清理，而 map 无上界。
// SPA 是免认证的公网 UDP 口，nonce 去重又排在验签之前——不需要任何有效令牌就能
// 同时撑大表和触发全表扫描，成本 O(N²)，而 spa.Serve 是单 goroutine。

import (
	"fmt"
	"testing"
	"time"
)

// benchSeenAtSize 在表里已有 n 条**未过期**记录时，量一次 Seen 的成本。
// 改造前这个数字随 n 线性增长（每次都全扫）；改造后应基本持平。
func benchSeenAtSize(b *testing.B, n int) {
	c := NewCache()
	for i := 0; i < n; i++ {
		c.Seen(fmt.Sprintf("n:pre%08d", i), time.Hour) // 长 TTL：不会被清理掉
	}
	if got, _ := c.Stats(); got != n {
		b.Fatalf("预置失败：表里 %d 条，期望 %d", got, n)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Seen(fmt.Sprintf("n:bench%08d", i), time.Hour)
	}
}

func BenchmarkSeen_表内100条(b *testing.B)   { benchSeenAtSize(b, 100) }
func BenchmarkSeen_表内10000条(b *testing.B) { benchSeenAtSize(b, 10000) }
func BenchmarkSeen_表内50000条(b *testing.B) { benchSeenAtSize(b, 50000) }

// 表满时必须 fail-closed（当作重放拒绝），而不是无限增长。
//
// ★方向是刻意的：宁可在洪泛期间拒掉新敲门，也不能因为记不下而放过一次真重放
// ——放过重放等于一次性敲门令牌失效，那是比"这段时间敲不开门"严重得多的后果。
func TestSeen表满时fail_closed而不是无限增长(t *testing.T) {
	c := NewCache()
	for i := 0; i < maxEntries+1000; i++ {
		c.Seen(fmt.Sprintf("n:flood%08d", i), time.Hour)
	}
	entries, rejected := c.Stats()
	if entries > maxEntries {
		t.Fatalf("表突破了上界：%d > %d——洪泛可以把内存吃到 OOM", entries, maxEntries)
	}
	if rejected == 0 {
		t.Fatal("表满时没有计数被拒次数——正在被洪泛这件事应当可观测")
	}
	// 满了之后，新 key 一律当"已见过"拒掉。
	if !c.Seen("n:another", time.Hour) {
		t.Fatal("表满后仍在接受新条目")
	}
}

// 摊销清理不能破坏过期语义：表里残留的过期条目**必须**被当作"没见过"。
//
// ★改造前靠「每次先全扫」保证表里没有过期项；改成摊销后表里会有残留，
// 查找时若不判过期，一个早该失效的 key 会被当成重放，把正常敲门挡在门外。
func TestSeen残留的过期条目不算重放(t *testing.T) {
	c := NewCache()
	if c.Seen("n:short", 10*time.Millisecond) {
		t.Fatal("首次不该判重放")
	}
	time.Sleep(30 * time.Millisecond)
	// 此时距上次 sweep 远不到 sweepEvery，条目仍在表里但已过期。
	if c.Seen("n:short", time.Hour) {
		t.Fatal("已过期的条目被当成重放了——摊销清理漏判了过期，正常敲门会被误拒")
	}
}

// 窗口内的真重放照旧拒绝（改造不能把去重本身弄丢）。
func TestSeen窗口内重放仍被拒(t *testing.T) {
	c := NewCache()
	if c.Seen("j:tok-1", time.Hour) {
		t.Fatal("首次不该判重放")
	}
	if !c.Seen("j:tok-1", time.Hour) {
		t.Fatal("窗口内的重放必须被拒——放过它等于一次性敲门令牌失效")
	}
}

// 表满与真重放必须分得开：归因方向相反。
func TestSeen表满与真重放分得开(t *testing.T) {
	c := NewCache()
	// 真重放：同一个 key 第二次。
	c.Seen("j:tok", time.Hour)
	if seen, full := c.SeenOrFull("j:tok", time.Hour); !seen || full {
		t.Fatalf("窗口内重放应 seen=true full=false，实得 %v/%v", seen, full)
	}
	// 表满：新 key 被拒，且要报出 full。
	for i := 0; i < maxEntries+10; i++ {
		c.Seen(fmt.Sprintf("n:f%08d", i), time.Hour)
	}
	seen, full := c.SeenOrFull("n:brandnew", time.Hour)
	if !seen || !full {
		t.Fatalf("表满应 seen=true full=true，实得 %v/%v——"+
			"分不开的话，一个正常用户会因为别人在洪泛而被记成重放者", seen, full)
	}
}
