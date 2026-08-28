package spa

// Allowlist 的并发读基准（wave9）。
//
// ★定位：防回归，不是容量承诺。口径：纯内存 + 锁竞争，无 IO；
// 并发度由 GOMAXPROCS 决定，绝对值随机器与核数变化，看的是**串行 vs 并行的差**。
//
// 为什么测这里：proxy.handle 每条隧道连接要摸这把锁三次
// （Allowed 两次——放行判定 + track 之后的复核，Touch 一次），
// 而 Allowed 是**纯读**（判过期但不删，回收由 Reap 单独做）。
// 用独占锁的话，N 条并发连接的放行判定完全串行。

import (
	"fmt"
	"testing"
	"time"
)

func seedAllowlist(n int) *Allowlist {
	al := NewAllowlist()
	for i := 0; i < n; i++ {
		al.Allow(fmt.Sprintf("10.8.%d.%d", i/256, i%256), fmt.Sprintf("user%04d", i), "user", time.Hour)
	}
	return al
}

// 并发读：模拟多条隧道连接同时做放行判定。
func benchAllowedParallel(b *testing.B, n int) {
	al := seedAllowlist(n)
	ip := "10.8.0.1"
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, ok := al.Allowed(ip); !ok {
				b.Fatal("应命中放行窗口")
			}
		}
	})
}

func BenchmarkAllowedParallel_100会话(b *testing.B)  { benchAllowedParallel(b, 100) }
func BenchmarkAllowedParallel_1000会话(b *testing.B) { benchAllowedParallel(b, 1000) }

// 单线程读作为对照：这条基本不受锁类型影响，用来把「锁竞争」与「查表本身」分开。
func BenchmarkAllowedSerial_1000会话(b *testing.B) {
	al := seedAllowlist(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		al.Allowed("10.8.0.1")
	}
}
