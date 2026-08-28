package resource

// 预计算查找表与线性扫必须**同真同假**（wave9）。
//
// ★引入第二条判定路径就是引入一个可能与第一条不一致的地方，而这里判的是
// 「谁能访问哪条资源」——不一致不会报错，只会静默放行或静默拒绝。
// 这条用例把两条路径并排跑，任何组合上分歧即失败。

import (
	"fmt"
	"testing"
)

func TestAuthorize两条路径同真同假(t *testing.T) {
	cases := []struct {
		name string
		res  Resource
		user string
		role string
	}{
		{"两维皆空即不限", Resource{ID: "r", Backend: "b"}, "anyone", "user"},
		{"仅角色命中", Resource{ID: "r", Backend: "b", AllowRoles: []string{"admin"}}, "x", "admin"},
		{"仅角色不命中", Resource{ID: "r", Backend: "b", AllowRoles: []string{"admin"}}, "x", "user"},
		{"用户命中", Resource{ID: "r", Backend: "b", AllowUsers: []string{"zhang.wei"}}, "zhang.wei", "user"},
		{"用户不命中", Resource{ID: "r", Backend: "b", AllowUsers: []string{"zhang.wei"}}, "li.fang", "user"},
		{"否决压过允许", Resource{ID: "r", Backend: "b",
			AllowUsers: []string{"zhang.wei"}, DenyUsers: []string{"zhang.wei"}}, "zhang.wei", "user"},
		{"否决压过角色", Resource{ID: "r", Backend: "b",
			AllowRoles: []string{"admin"}, DenyUsers: []string{"boss"}}, "boss", "admin"},
		{"否决压过两维皆空", Resource{ID: "r", Backend: "b", DenyUsers: []string{"boss"}}, "boss", "user"},
		{"大小写不敏感·用户", Resource{ID: "r", Backend: "b", AllowUsers: []string{"Zhang.Wei"}}, "zhang.wei", "user"},
		{"大小写不敏感·角色", Resource{ID: "r", Backend: "b", AllowRoles: []string{"Admin"}}, "x", "ADMIN"},
		{"大小写不敏感·否决", Resource{ID: "r", Backend: "b", DenyUsers: []string{"BOSS"}}, "boss", "user"},
		{"首尾空白", Resource{ID: "r", Backend: "b", AllowUsers: []string{" zhang.wei "}}, "zhang.wei", "user"},
		{"中文账号", Resource{ID: "r", Backend: "b", AllowUsers: []string{"张伟"}}, "张伟", "user"},
		{"哨兵拒全体", Resource{ID: "r", Backend: "b", AllowUsers: []string{"\x00deny-all"}}, "anyone", "user"},
		{"空用户名", Resource{ID: "r", Backend: "b", AllowUsers: []string{"a"}}, "", "user"},
		{"角色为空串", Resource{ID: "r", Backend: "b", AllowRoles: []string{"admin"}}, "x", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := New("def:22")
			linear := r.Authorize(c.user, c.role, c.res) // 未经 Replace = 回落线性扫
			r.Replace([]Resource{c.res})
			indexed, ok := r.Lookup("r")
			if !ok {
				t.Fatal("Lookup 失败")
			}
			if got := r.Authorize(c.user, c.role, indexed); got != linear {
				t.Fatalf("两条判定路径分歧：线性=%v 查表=%v（user=%q role=%q）——"+
					"分歧不会报错，只会静默放行或静默拒绝", linear, got, c.user, c.role)
			}
		})
	}
}

// 随机组合的对照：固定种子的伪随机，覆盖上面表格想不到的组合。
func TestAuthorize两条路径随机对照(t *testing.T) {
	pool := []string{"a", "B", "zhang.wei", "Zhang.Wei", " c ", "张伟", "", "admin", "user"}
	seed := uint32(2166136261)
	next := func(n int) int { // xorshift，避免依赖 math/rand 的默认源
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		return int(seed>>1) % n
	}
	for i := 0; i < 400; i++ {
		res := Resource{ID: "r", Backend: "b"}
		for j := next(4); j > 0; j-- {
			res.AllowUsers = append(res.AllowUsers, pool[next(len(pool))])
		}
		for j := next(3); j > 0; j-- {
			res.AllowRoles = append(res.AllowRoles, pool[next(len(pool))])
		}
		for j := next(3); j > 0; j-- {
			res.DenyUsers = append(res.DenyUsers, pool[next(len(pool))])
		}
		user, role := pool[next(len(pool))], pool[next(len(pool))]

		r := New("def:22")
		linear := r.Authorize(user, role, res)
		r.Replace([]Resource{res})
		indexed, _ := r.Lookup("r")
		if got := r.Authorize(user, role, indexed); got != linear {
			t.Fatalf("第 %d 组分歧：线性=%v 查表=%v\nres=%+v\nuser=%q role=%q",
				i, linear, got, res, user, role)
		}
	}
}

// 预计算表必须随 Replace 更新：改了授权名单，下一轮就该生效。
func TestAuthorize查找表随Replace更新(t *testing.T) {
	r := New("def:22")
	r.Replace([]Resource{{ID: "r", Backend: "b", AllowUsers: []string{"zhang.wei"}}})
	res, _ := r.Lookup("r")
	if !r.Authorize("zhang.wei", "user", res) {
		t.Fatal("首轮应放行")
	}
	// 控制面把他移出授权名单。
	r.Replace([]Resource{{ID: "r", Backend: "b", AllowUsers: []string{"li.fang"}}})
	res2, _ := r.Lookup("r")
	if r.Authorize("zhang.wei", "user", res2) {
		t.Fatal("撤权后仍放行——预计算表没随 Replace 重建，撤权失效")
	}
}

// 主体清单越长，判定成本不该跟着涨（这条是上面基准的断言化表述）。
func TestAuthorize成本不随名单长度增长(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过")
	}
	small := testing.Benchmark(func(b *testing.B) { benchAuthorize(b, 100, "outsider") })
	large := testing.Benchmark(func(b *testing.B) { benchAuthorize(b, 5000, "outsider") })
	// 50 倍的名单长度，耗时不该涨到 5 倍以上（留足抖动余量；线性实现会涨约 50 倍）。
	if large.NsPerOp() > small.NsPerOp()*5+50 {
		t.Fatalf("判定成本随名单长度显著增长：100 人 %d ns/op → 5000 人 %d ns/op——"+
			"退回线性扫了。AllowUsers 的长度由控制面的组织授权展开决定，"+
			"一条授权给根组织的资源会带着全组织的账号下发",
			small.NsPerOp(), large.NsPerOp())
	}
	fmt.Printf("授权判定：100 人 %d ns/op，5000 人 %d ns/op\n", small.NsPerOp(), large.NsPerOp())
}
