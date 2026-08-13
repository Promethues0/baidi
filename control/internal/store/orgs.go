package store

import (
	"errors"
	"sort"
	"strings"
)

// ── 组织与用户组领域（PRD ch6 FR-USER 系列）──
//
// ★为什么这是地基：在此之前「组织」只存在于 Memory 种子里——策略中心那棵
// 四部门的树是硬编码常量，users 表连"这个人属于哪个部门"都没有一列。于是
// 「按组织授权 / 按组织统计 / 按组织继承策略」全都只能编数字，页面看着是真的。
//
// 三张表：
//   org_units          邻接表（parent_id）+ 冗余物化路径 path
//   user_groups        用户组；kind 决定成员从哪来（见 GroupKind*）
//   user_group_members static 组的显式成员，按 **account** 存
//                      （account 是令牌主体，也是将来「按组授权」唯一能对齐的键；
//                       按 user id 存的话改账号名就对不上任何鉴权侧的判定）
// users.org_id 指向 org_units.id（补列 + 回填，见 backfillOrgUnits）。

var (
	// ErrOrgHasChildren 组织下还有子部门，拒删。
	ErrOrgHasChildren = errors.New("该组织下还有子部门，请先移走或删除子部门")
	// ErrOrgHasMembers 组织下还有用户，拒删。
	// ★刻意不做「级联把成员置空」：组织维度正是策略与统计的分组键，
	// 一批用户静默变成"无归属"等于静默丢掉他们的策略归属，且没有任何报错。
	ErrOrgHasMembers = errors.New("该组织下还有用户，请先把用户移到其他组织")
	// ErrOrgCycle 把节点的父设成了它自己或它的后代。邻接表允许写进去，
	// 但之后任何一次树遍历都会无限递归——所以在写入期拒绝，不靠读取期兜底。
	ErrOrgCycle = errors.New("父组织不能是它自己或它的后代")
	// ErrOrgNotFound 组织不存在。
	ErrOrgNotFound = errors.New("组织不存在")
	// ErrGroupNotFound 用户组不存在。
	ErrGroupNotFound = errors.New("用户组不存在")
	// ErrGroupExists 同名用户组已存在（名称大小写/空格规范化后比对）。
	// 角色组的名称就是它的成员判据，重名会让同一批人分裂成两个组。
	ErrGroupExists = errors.New("同名用户组已存在")
	// ErrGroupDerived 角色组的成员由用户展示角色派生，不接受显式成员写入。
	ErrGroupDerived = errors.New("角色组的成员由用户角色派生，不能直接编辑成员")
	// ErrGroupExternal 外部目录组按登录刷新，不接受手工编辑（改了也会被下次登录冲掉）。
	ErrGroupExternal = errors.New("外部目录组由认证源按登录刷新，不能手工编辑或改名")
	// ErrUnknownAccount 成员清单里有库中不存在的账号。
	// ★不静默丢弃：拼错一个账号就少一个人有权限，而界面上看不出任何异常。
	ErrUnknownAccount = errors.New("成员账号在用户目录中不存在")
	// ErrOrgInAuthPolicy / ErrGroupInAuthPolicy 主体仍被认证策略的适用范围引用，拒删。
	//
	// ★为什么这一条必须拦：删掉被引用的组织/用户组，绑在它上面的策略立刻
	// **静默失效**——covers() 恒 false，那条「一律二次认证」再也命中不了任何人，
	// 而页面上策略还在、只是"生效账号 0"，登录行为无声地从双因素退回单因素。
	// 这是放松安全的方向，和对象库「被引用拒删」同一条纪律。
	//
	// 刻意**不**拦资源授权（resources.allow_orgs/allow_groups）的引用：那个方向是
	// fail-closed 的（展开为空 → 下发哨兵 → 谁也连不上），管理员立刻会收到报障，
	// 与"悄悄少了一道认证"性质不同。
	ErrOrgInAuthPolicy   = errors.New("该组织仍被认证策略的适用范围引用，请先解除绑定再删除")
	ErrGroupInAuthPolicy = errors.New("该用户组仍被认证策略的适用范围引用，请先解除绑定再删除")
)

// 用户组类型。kind 不是装饰性标签，它决定 GroupMembers 从哪里取成员：
//   - static：成员显式存在 user_group_members，管理员维护；
//   - role  ：成员 = 展示角色（users.roles）里含该组名的用户，只读派生。
//
// 角色组把既有的扁平 roles 字段桥进组维度：不引入第二套角色数据，
// 也就不会出现「组里加了人、roles 里没加」这种两份真相不一致的情况。
const (
	GroupKindStatic = "static"
	GroupKindRole   = "role"
	// GroupKindExternal 外部目录派生组（wave7 行动 2）：成员由该账号每次外部登录时
	// 按认证源返回的组清单刷新（BindExternalUser）。★ValidGroupKind 刻意不含它：
	// 该类组不可经 API 创建/改名/改成员——手工编辑会在下一次登录被静默冲掉，
	// 那种"改了又变回去"比直接拒绝难查得多。
	GroupKindExternal = "external"
)

// ValidGroupKind 报告 kind 取值是否合法。
func ValidGroupKind(k string) bool { return k == GroupKindStatic || k == GroupKindRole }

// Org 一个组织单元（部门）。
type Org struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ParentID string `json:"parentId"`
	// Path 物化路径，形如 /root/dev/（含首尾斜杠）。环检测与子树查询都依赖它：
	// 后代的 path 必然含 "/<祖先 id>/"，一次字符串包含判断即可，无需递归查库。
	Path      string `json:"path"`
	Sort      int    `json:"sort"`
	CreatedAt string `json:"createdAt"`
	// Members 直属成员数（读取时实算，写入时忽略）。树上的子树合计由 buildOrgTree 累加。
	Members int `json:"members"`
}

// UserGroup 一个用户组。
type UserGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"` // static | role
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
	// Members 成员数（读取时实算：static 数成员表，role 数命中该角色的用户）。
	Members int `json:"members"`
}

// normAccount 账号规范化（去首尾空格 + 小写），与登录链路 Credential 的口径一致。
// 组成员按规范化账号存，避免 "Alice" 与 "alice" 被当成两个人。
func normAccount(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// buildOrgTree 由扁平组织行构建展示树。
//
// Members 是**子树**成员数（含各级后代），不是直属数——只算直属的话，
// 上层部门永远显示 0，看树的人会以为整个大区没有人。
//
// 两处刻意的兜底：
//   - 父指针指向不存在的行（并发删除/历史脏数据）时该节点提升为根。宁可树上
//     多一个顶层节点，也不能让一批用户连同他们的部门从树上静默消失。
//   - visited 防环。写入期已拒环（ErrOrgCycle），这里只是让读取路径在脏数据下
//     退化成"少画几条边"，而不是把控制面卡死在无限递归里。
func buildOrgTree(orgs []Org) []OrgUnit {
	sorted := append([]Org(nil), orgs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Sort != sorted[j].Sort {
			return sorted[i].Sort < sorted[j].Sort
		}
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].ID < sorted[j].ID
	})
	byID := make(map[string]Org, len(sorted))
	for _, o := range sorted {
		byID[o.ID] = o
	}
	kids := map[string][]string{}
	var roots []string
	for _, o := range sorted {
		if _, ok := byID[o.ParentID]; ok && o.ParentID != o.ID {
			kids[o.ParentID] = append(kids[o.ParentID], o.ID)
			continue
		}
		roots = append(roots, o.ID)
	}
	visited := map[string]bool{}
	var build func(id string) OrgUnit
	build = func(id string) OrgUnit {
		o := byID[id]
		n := OrgUnit{Key: o.ID, Title: o.Name, Members: o.Members}
		if visited[id] {
			return n
		}
		visited[id] = true
		for _, cid := range kids[id] {
			c := build(cid)
			n.Members += c.Members
			n.Children = append(n.Children, c)
		}
		return n
	}
	out := []OrgUnit{}
	for _, id := range roots {
		out = append(out, build(id))
	}
	// 成环的脏数据会让环里的每个节点都"有父"，于是一个根都选不出来、整棵树空掉——
	// 静默丢光所有部门比多画一个顶层节点危险得多。凡是从根出发没走到的节点，
	// 在这里被提升为根补画出来。
	for _, o := range sorted {
		if !visited[o.ID] {
			out = append(out, build(o.ID))
		}
	}
	return out
}

// toPolicyTree 把组织树映射成策略继承树节点，标注哪些节点定义了自定义策略覆盖。
// 策略中心的继承可视化就靠 HasCustom 区分「自己定了」与「继承父级」。
func toPolicyTree(units []OrgUnit, custom map[string]bool) []OrgNode {
	out := []OrgNode{}
	for _, u := range units {
		n := OrgNode{Key: u.Key, Title: u.Title, Members: u.Members, HasCustom: custom[u.Key]}
		if len(u.Children) > 0 {
			n.Children = toPolicyTree(u.Children, custom)
		}
		out = append(out, n)
	}
	return out
}
