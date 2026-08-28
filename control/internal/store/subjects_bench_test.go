package store

// SubjectIndex 的规模基准（wave9，NFR-PERF-06 的第一个测量点）。
//
// ★定位：**防回归，不是容量承诺。**
// 这些数字是「在某台开发机、某个目录形状、modernc 纯 Go SQLite 上跑出来的」，
// 不构成任何并发/容量/时延规格——项目对「测了但不能当承诺」有既定表述法
// （对照 gateway_metrics 的采集三态、reachprobe 的 RTT），这里沿用：先写口径，
// 再给数字，绝不写成「达标」。
//
// 口径（读者最容易误以为的三件事，逐条写清）：
//   - 测的是**一次 SubjectIndex 调用**的库读 + 内存合并，不是一次登录、
//     不是一次网关轮询。真实轮询里它只是其中一项（另有 Users()、posture 扫描等）。
//   - 用的是 modernc 纯 Go SQLite（本项目免 CGO），与 CGO 版性能特征不同。
//   - 库是**刚建好、刚写完**的：无碎片、页缓存全热。生产上的冷库会更慢。
//
// 为什么选这里作为第一个测量点：它是控制面唯一一处随目录规模增长、
// 又同时出现在三条热路径上的读——网关策略轮询（G 台 × 每 15s）、客户端剖面、
// 以及**未启用二因子账号**的登录（已注册 passkey/TOTP 的账号在 secondFactor
// 里先行 return，根本走不到它——基准 fixture 因此刻意不绑二因子，
// 绑了会测出一条与结论相反的平线）。

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// seedDirectory 播一个 n 人、深度 depth 的目录，外加 g 个静态用户组。
// 返回 store。组织树按 depth 层链式展开（每层一个节点），用户平均分布在叶子上——
// 物化路径越深，buildSubjectIndex 的祖先链拆分越贵。
func seedDirectory(tb testing.TB, n, depth, g int) *SQLiteStore {
	tb.Helper()
	st, err := OpenSQLite(filepath.Join(tb.TempDir(), "bench.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { st.Close() })
	ctx := context.Background()

	parent := ""
	var leaf string
	for d := 0; d < depth; d++ {
		o, err := st.SaveOrgUnit(ctx, Org{Name: fmt.Sprintf("层%d", d), ParentID: parent})
		if err != nil {
			tb.Fatal(err)
		}
		parent, leaf = o.ID, o.ID
	}

	gids := make([]string, 0, g)
	for i := 0; i < g; i++ {
		grp, err := st.SaveUserGroup(ctx, UserGroup{Name: fmt.Sprintf("组%d", i), Kind: GroupKindStatic})
		if err != nil {
			tb.Fatal(err)
		}
		gids = append(gids, grp.ID)
	}

	for i := 0; i < n; i++ {
		acct := fmt.Sprintf("bench.user%05d", i)
		if _, err := st.CreateUser(ctx, DirUser{
			Name: acct, Account: acct, OrgID: leaf, Status: "active",
		}); err != nil {
			tb.Fatal(err)
		}
		if g > 0 {
			if err := st.SetUserGroups(ctx, acct, []string{gids[i%g]}); err != nil {
				tb.Fatal(err)
			}
		}
	}
	return st
}

func benchSubjectIndex(b *testing.B, n, depth, g int) {
	st := seedDirectory(b, n, depth, g)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix, err := st.SubjectIndex(ctx)
		if err != nil {
			b.Fatal(err)
		}
		// 用一下结果，防止编译器把整次调用优化掉。
		if len(ix.OrgAccounts)+len(ix.GroupAccounts) < 0 {
			b.Fatal("unreachable")
		}
	}
}

// 三档规模。100 是演示站量级，1000 是一家中型企业，5000 是本项目文档里
// 讨论「网关数 × 用户数相乘」时用的那个数。
func BenchmarkSubjectIndex_100用户(b *testing.B)  { benchSubjectIndex(b, 100, 3, 5) }
func BenchmarkSubjectIndex_1000用户(b *testing.B) { benchSubjectIndex(b, 1000, 3, 5) }
func BenchmarkSubjectIndex_5000用户(b *testing.B) { benchSubjectIndex(b, 5000, 3, 5) }

// 组织树深度的影响：buildSubjectIndex 对每个账号按物化路径拆祖先链，
// 成本随「深度 × 账号数」增长。同样 1000 人，深度 3 与深度 10 的差值就是这一项。
func BenchmarkSubjectIndex_1000用户深10层(b *testing.B) { benchSubjectIndex(b, 1000, 10, 5) }

// Users() 的规模基准。口径同上。
//
// ★为什么单独测它：handleGatewayPolicy 每轮（G 台网关 × 每 15s）都调一次
// Users()，而它只用得到 u.Account 与 u.Status 两个字段——目录树、用户组、
// 成员关系、身份源计数、每组织成员数全部算出来后丢弃。这条基准就是
// 「白付了多少」的量。
func benchUsers(b *testing.B, n, depth, g int) {
	st := seedDirectory(b, n, depth, g)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bundle, err := st.Users(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if len(bundle.Users) < 0 {
			b.Fatal("unreachable")
		}
	}
}

func BenchmarkUsers_100用户(b *testing.B)  { benchUsers(b, 100, 3, 5) }
func BenchmarkUsers_1000用户(b *testing.B) { benchUsers(b, 1000, 3, 5) }
func BenchmarkUsers_5000用户(b *testing.B) { benchUsers(b, 5000, 3, 5) }

// BlockedAccounts 是 handleGatewayPolicy 真正需要的那一小块（wave9 新增）。
// 与 BenchmarkUsers_* 并排看，差值就是每轮每台网关白付的成本。
func benchBlockedAccounts(b *testing.B, n, depth, g int) {
	st := seedDirectory(b, n, depth, g)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acc, err := st.BlockedAccounts(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if len(acc) < 0 {
			b.Fatal("unreachable")
		}
	}
}

func BenchmarkBlockedAccounts_1000用户(b *testing.B) { benchBlockedAccounts(b, 1000, 3, 5) }
func BenchmarkBlockedAccounts_5000用户(b *testing.B) { benchBlockedAccounts(b, 5000, 3, 5) }
