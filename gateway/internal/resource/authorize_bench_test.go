package resource

// Authorize 的规模基准（wave9）。
//
// ★定位：防回归，不是容量承诺。口径：纯 CPU，无 IO；看的是**随主体清单长度的
// 增长趋势**，绝对值随机器变化。
//
// 为什么测这里：Authorize 每条隧道连接执行一次（proxy.handle 的前导分支），
// 而 AllowUsers 的长度**由控制面的组织授权展开决定**——一条授权给根组织的资源，
// 在 5000 人目录下会带着 5000 个账号下发（见 api.expandForGateway）。
// 判定是线性扫 + strings.EqualFold，两者相乘就是每条连接的固定开销。

import (
	"fmt"
	"testing"
)

func resWithUsers(n int) Resource {
	users := make([]string, n)
	for i := range users {
		users[i] = fmt.Sprintf("org.user%05d", i)
	}
	return Resource{ID: "res-git", Backend: "10.0.0.1:22", AllowUsers: users}
}

func benchAuthorize(b *testing.B, n int, user string) {
	r := New("10.0.0.9:22")
	r.Replace([]Resource{resWithUsers(n)})
	// ★从 Lookup 取，而不是把原始 Resource 传回去——这才是真实调用路径
	// （proxy.handle 是先 reg.Lookup(rid) 再 reg.Authorize(user, role, res)），
	// 也只有这份带着 Replace 时预计算的查找表。传原始值测到的是回落路径。
	res, ok := r.Lookup("res-git")
	if !ok {
		b.Fatal("Lookup 失败")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Authorize(user, "user", res)
	}
}

// benchAuthorizeLinear 走回落（线性扫）路径，作为对照。
func benchAuthorizeLinear(b *testing.B, n int, user string) {
	r := New("10.0.0.9:22")
	res := resWithUsers(n) // 不经 Replace：没有预计算表
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Authorize(user, "user", res)
	}
}

func BenchmarkAuthorize线性_5000人命中末位(b *testing.B) { benchAuthorizeLinear(b, 5000, "org.user04999") }
func BenchmarkAuthorize线性_5000人不命中(b *testing.B)  { benchAuthorizeLinear(b, 5000, "outsider") }

// 命中在最前：早退出，成本与规模无关。
func BenchmarkAuthorize_1000人命中首位(b *testing.B) { benchAuthorize(b, 1000, "org.user00000") }

// 命中在最后：最坏的"允许"路径。
func BenchmarkAuthorize_1000人命中末位(b *testing.B) { benchAuthorize(b, 1000, "org.user00999") }
func BenchmarkAuthorize_5000人命中末位(b *testing.B) { benchAuthorize(b, 5000, "org.user04999") }

// 不命中：必然全扫。★这正是**被拒绝**的路径——也就是未授权者反复拨号时
// 网关每次要付的成本，攻击者可以刻意触发。
func BenchmarkAuthorize_1000人不命中(b *testing.B) { benchAuthorize(b, 1000, "outsider") }
func BenchmarkAuthorize_5000人不命中(b *testing.B) { benchAuthorize(b, 5000, "outsider") }
