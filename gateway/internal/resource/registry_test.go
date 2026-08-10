package resource

import "testing"

// 否决名单是网关侧「风险降权」的执行方：控制面算好谁不许碰哪个资源，网关只机械比对。
//
// ★DenyUsers 必须**先于**一切允许来源判定。控制面下发时会把有效期内的 JIT 授予并进
// AllowUsers，若先判允许，一张审批单就能让被降权的终端照样打开高敏资源——
// 而那恰恰是最该收缩的时刻。
func TestAuthorizeDenyUsersWinsOverAllow(t *testing.T) {
	r := New("")
	cases := []struct {
		name string
		res  Resource
		user string
		role string
		want bool
	}{
		{
			name: "否决压过点名授权（JIT 授予就是这样并进 AllowUsers 的）",
			res:  Resource{ID: "fin", AllowUsers: []string{"li.fang"}, DenyUsers: []string{"li.fang"}},
			user: "li.fang", role: "user", want: false,
		},
		{
			name: "否决压过角色授权",
			res:  Resource{ID: "fin", AllowRoles: []string{"user"}, DenyUsers: []string{"li.fang"}},
			user: "li.fang", role: "user", want: false,
		},
		{
			// ★这一条是"降权而非全断"的关键：没设 ACL 的资源（两维皆空 = 不限）
			// 也必须能被否决，否则绝大多数资源根本收缩不了。
			name: "否决对「不限」资源同样生效",
			res:  Resource{ID: "fin", DenyUsers: []string{"li.fang"}},
			user: "li.fang", role: "user", want: false,
		},
		{
			name: "不在否决名单里的人不受影响（降权只针对被判定的账号）",
			res:  Resource{ID: "fin", AllowRoles: []string{"user"}, DenyUsers: []string{"li.fang"}},
			user: "wang.qiang", role: "user", want: true,
		},
		{
			name: "否决按账号大小写不敏感比对（与 AllowUsers 同口径）",
			res:  Resource{ID: "fin", DenyUsers: []string{"li.fang"}},
			user: "Li.Fang", role: "user", want: false,
		},
		{
			// 回归：旧控制面不下发 denyUsers → 空切片 → 行为与改造前逐字节一致。
			name: "空否决名单不改变既有判定",
			res:  Resource{ID: "oa", AllowRoles: []string{"user"}},
			user: "li.fang", role: "user", want: true,
		},
		{
			name: "空否决名单下越权仍被拒",
			res:  Resource{ID: "fin", AllowRoles: []string{"admin"}},
			user: "li.fang", role: "user", want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := r.Authorize(c.user, c.role, c.res); got != c.want {
				t.Fatalf("Authorize(%s,%s,%+v) = %v，want %v", c.user, c.role, c.res, got, c.want)
			}
		})
	}
}

// 降权只摘高敏资源：同一个被否决的账号，普通资源（控制面不下发 denyUsers）照常放行。
// 这是「优先降权而非终止会话」在数据面的可观测形态。
func TestAuthorizeDegradeIsPartialNotTotal(t *testing.T) {
	r := New("")
	high := Resource{ID: "fin", Backend: "10.20.3.21:443", AllowRoles: []string{"user"}, DenyUsers: []string{"li.fang"}}
	normal := Resource{ID: "oa", Backend: "10.20.1.10:8080", AllowRoles: []string{"user"}}
	r.Replace([]Resource{high, normal})

	if r.Authorize("li.fang", "user", high) {
		t.Fatal("高敏资源应被否决")
	}
	if !r.Authorize("li.fang", "user", normal) {
		t.Fatal("★降权不是全断：普通资源必须仍可访问")
	}
	// 注册表本身不做任何推导——它不知道"高敏"是什么，只认下发来的名单
	if got, ok := r.Lookup("fin"); !ok || len(got.DenyUsers) != 1 {
		t.Fatalf("Replace 应原样保留 denyUsers：%+v", got)
	}
}
