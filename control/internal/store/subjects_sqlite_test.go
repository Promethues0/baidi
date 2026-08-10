package store

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
)

// 种子组织树：root ─┬ dev（zhang.wei / chen.jing）
//
//	├ sales（li.fang / wang.qiang）
//	├ cs（zhao.min / liu.yang）
//	├ ext（ext.zhou）
//	└ sec（admin）
//
// 见 backfillOrgUnits。

// accountsOf 断言用的小工具：主体展开成账号集合。
func accountsOf(ix SubjectIndex, res Resource) map[string]bool {
	out := map[string]bool{}
	for _, a := range ix.SubjectAccounts(res) {
		out[a] = true
	}
	return out
}

// 子树继承：授权给上级组织即涵盖其全部后代组织的用户。
// 这是 AllowOrgs 与 AllowUsers 唯一的语义差别，也是最容易被实现漏掉的一条。
func TestSubjectIndexOrgSubtreeInheritance(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	ix, err := s.SubjectIndex(ctx)
	if err != nil {
		t.Fatalf("SubjectIndex: %v", err)
	}
	// 直属：dev 只覆盖研发部两人
	dev := accountsOf(ix, Resource{AllowOrgs: []string{"dev"}})
	for _, a := range []string{"zhang.wei", "chen.jing"} {
		if !dev[a] {
			t.Errorf("授权 dev 应覆盖 %s，实得 %v", a, dev)
		}
	}
	if dev["li.fang"] {
		t.Errorf("授权 dev 不该覆盖销售部的 li.fang，实得 %v", dev)
	}
	// 子树：root 覆盖全部下级部门的人
	root := accountsOf(ix, Resource{AllowOrgs: []string{"root"}})
	for _, a := range []string{"zhang.wei", "chen.jing", "li.fang", "wang.qiang", "zhao.min", "liu.yang", "ext.zhou", "admin"} {
		if !root[a] {
			t.Errorf("授权根组织应覆盖后代组织的 %s（子树继承），实得 %v", a, root)
		}
	}
	// 多级子树：在 dev 下再挂一层，新层的人必须同时被 dev 与 root 覆盖
	team, err := s.SaveOrgUnit(ctx, Org{Name: "内核组", ParentID: "dev"})
	if err != nil {
		t.Fatalf("SaveOrgUnit: %v", err)
	}
	if err := s.SetUserOrg(ctx, "u6", team.ID); err != nil { // u6 = chen.jing
		t.Fatalf("SetUserOrg: %v", err)
	}
	ix, err = s.SubjectIndex(ctx)
	if err != nil {
		t.Fatalf("SubjectIndex: %v", err)
	}
	for _, orgID := range []string{team.ID, "dev", "root"} {
		if got := accountsOf(ix, Resource{AllowOrgs: []string{orgID}}); !got["chen.jing"] {
			t.Errorf("授权 %s 应覆盖二级子部门里的 chen.jing，实得 %v", orgID, got)
		}
	}
}

// 把人移出组织后立刻失去覆盖：展开是每次现算的，不带缓存。
// ★撤权与生效之间不能有窗口——这正是"不缓存"那条注释要守住的性质。
func TestSubjectIndexRecomputedOnMembershipChange(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	res := Resource{ID: "oa", AllowOrgs: []string{"dev"}}

	ix, _ := s.SubjectIndex(ctx)
	if !ix.SubjectAllows(res, "zhang.wei") {
		t.Fatal("改动前 zhang.wei 应在 dev 组织内")
	}
	// 移到销售部 → 立即失去 dev 授权、获得 sales 授权
	if err := s.SetUserOrg(ctx, "u1", "sales"); err != nil {
		t.Fatalf("SetUserOrg: %v", err)
	}
	ix, _ = s.SubjectIndex(ctx)
	if ix.SubjectAllows(res, "zhang.wei") {
		t.Error("移出 dev 后必须立即失去授权（展开不缓存）")
	}
	if !ix.SubjectAllows(Resource{AllowOrgs: []string{"sales"}}, "zhang.wei") {
		t.Error("移入 sales 后应立即被 sales 覆盖")
	}
	// 清空归属 → 任何组织都覆盖不到他
	if err := s.SetUserOrg(ctx, "u1", ""); err != nil {
		t.Fatalf("SetUserOrg 清空: %v", err)
	}
	ix, _ = s.SubjectIndex(ctx)
	if ix.SubjectAllows(Resource{AllowOrgs: []string{"root"}}, "zhang.wei") {
		t.Error("无组织归属的账号不该被任何组织主体覆盖（含根组织）")
	}
}

// 用户组维度：static 组按显式成员，role 组按 users.roles 派生，两种都要能展开。
func TestSubjectIndexGroups(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	g, err := s.SaveUserGroup(ctx, UserGroup{Name: "运维值班", Kind: GroupKindStatic})
	if err != nil {
		t.Fatalf("SaveUserGroup: %v", err)
	}
	if err := s.SetGroupMembers(ctx, g.ID, []string{"Li.Fang", "liu.yang"}); err != nil {
		t.Fatalf("SetGroupMembers: %v", err)
	}
	rg, err := s.SaveUserGroup(ctx, UserGroup{Name: "研发", Kind: GroupKindRole})
	if err != nil {
		t.Fatalf("SaveUserGroup(role): %v", err)
	}

	ix, err := s.SubjectIndex(ctx)
	if err != nil {
		t.Fatalf("SubjectIndex: %v", err)
	}
	// 账号大小写在展开时已规范化——组成员写 "Li.Fang"，令牌主体是 "li.fang"，
	// 不统一规范化就会出现"组里明明有他却没权限"。
	if got := ix.SubjectAccounts(Resource{AllowGroups: []string{g.ID}}); !reflect.DeepEqual(got, []string{"li.fang", "liu.yang"}) {
		t.Errorf("static 组展开应为 [li.fang liu.yang]（规范化+排序），实得 %v", got)
	}
	// 角色组的成员是派生的：users.roles 含"研发"的人
	rolegrp := accountsOf(ix, Resource{AllowGroups: []string{rg.ID}})
	for _, a := range []string{"zhang.wei", "chen.jing"} {
		if !rolegrp[a] {
			t.Errorf("角色组「研发」应派生出 %s，实得 %v", a, rolegrp)
		}
	}
	// 多主体求并：组织 ∪ 用户组
	both := accountsOf(ix, Resource{AllowOrgs: []string{"dev"}, AllowGroups: []string{g.ID}})
	for _, a := range []string{"zhang.wei", "chen.jing", "li.fang", "liu.yang"} {
		if !both[a] {
			t.Errorf("组织 ∪ 用户组应覆盖 %s，实得 %v", a, both)
		}
	}
}

// 未设主体维度时 SubjectAllows 恒假，且不受索引内容影响——
// 这是「空 AllowOrgs/AllowGroups 行为与改造前完全一致」的判据之一。
func TestSubjectIndexEmptySubjectsNeverAllow(t *testing.T) {
	s := openTestStore(t)
	ix, err := s.SubjectIndex(context.Background())
	if err != nil {
		t.Fatalf("SubjectIndex: %v", err)
	}
	res := Resource{ID: "oa", AllowRoles: []string{"admin"}}
	for _, acct := range []string{"zhang.wei", "admin", "li.fang", ""} {
		if ix.SubjectAllows(res, acct) {
			t.Errorf("未设组织/用户组主体时 %q 不该被主体维度放行", acct)
		}
	}
	if got := ix.SubjectAccounts(res); len(got) != 0 {
		t.Errorf("未设主体的资源展开应为空，实得 %v", got)
	}
}

// 落库往返：四个主体维度都要能存能读，且空值读回来是空而不是 null 语义的坑。
func TestResourceSubjectsRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	in := Resource{ID: "r-sub", Name: "组织授权资源", Backend: "10.20.9.1:443",
		AllowRoles: []string{"user"}, AllowUsers: []string{"li.fang"},
		AllowGroups: []string{"grp-a"}, AllowOrgs: []string{"dev", "cs"}}
	if err := s.SaveResource(ctx, in); err != nil {
		t.Fatalf("SaveResource: %v", err)
	}
	rs, err := s.Resources(ctx)
	if err != nil {
		t.Fatalf("Resources: %v", err)
	}
	var got Resource
	for _, r := range rs {
		if r.ID == "r-sub" {
			got = r
		}
	}
	if !reflect.DeepEqual(got.AllowOrgs, []string{"dev", "cs"}) || !reflect.DeepEqual(got.AllowGroups, []string{"grp-a"}) {
		t.Fatalf("主体列往返不一致：%+v", got)
	}
	if !got.Restricted() {
		t.Error("设了主体的资源必须判定为受限")
	}
	// 种子资源（改造前建的行）读回来应是空切片，语义与改造前完全一致
	for _, r := range rs {
		if r.ID != "oa" {
			continue
		}
		if len(r.AllowOrgs) != 0 || len(r.AllowGroups) != 0 {
			t.Errorf("既有资源的新维度应为空，实得 %+v", r)
		}
	}
}

// 补列回填：既有库（列不存在）升级后，两列必须是 '[]' 而不是 NULL。
// ★addColumnIfMissing 只加列不填值——apps.resource_id 就这么静默断过。
func TestBackfillResourceSubjectsFillsLegacyRows(t *testing.T) {
	s := openTestStore(t)
	// 模拟"旧库"：把两列打回 NULL，再跑一次回填
	if _, err := s.db.Exec(`UPDATE resources SET allow_groups=NULL, allow_orgs=NULL`); err != nil {
		t.Fatalf("造旧数据: %v", err)
	}
	var nulls int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM resources WHERE allow_groups IS NULL OR allow_orgs IS NULL`).Scan(&nulls); err != nil {
		t.Fatalf("count: %v", err)
	}
	if nulls == 0 {
		t.Fatal("测试前置失败：没有造出 NULL 行")
	}
	if err := s.backfillResourceSubjects(); err != nil {
		t.Fatalf("backfillResourceSubjects: %v", err)
	}
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM resources WHERE allow_groups IS NULL OR allow_orgs IS NULL`).Scan(&nulls); err != nil {
		t.Fatalf("count: %v", err)
	}
	if nulls != 0 {
		t.Errorf("回填后仍有 %d 行为 NULL", nulls)
	}
	var g, o sql.NullString
	if err := s.db.QueryRow(`SELECT allow_groups, allow_orgs FROM resources LIMIT 1`).Scan(&g, &o); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if g.String != "[]" || o.String != "[]" {
		t.Errorf("回填值应为空数组 '[]'，实得 %q/%q", g.String, o.String)
	}
	// 回填后读出来仍是空切片 = 语义与改造前一致
	rs, err := s.Resources(context.Background())
	if err != nil {
		t.Fatalf("Resources: %v", err)
	}
	for _, r := range rs {
		if len(r.AllowOrgs) != 0 || len(r.AllowGroups) != 0 || r.Restricted() != (len(r.AllowRoles) > 0 || len(r.AllowUsers) > 0) {
			t.Errorf("回填后 %s 的行为应与改造前一致，实得 %+v", r.ID, r)
		}
	}
}

// orgPathIDs 是子树语义的唯一来源，单独钉住它的边界形态。
func TestOrgPathIDs(t *testing.T) {
	cases := map[string][]string{
		"/root/dev/team/": {"root", "dev", "team"},
		"/root/":          {"root"},
		"/":               {},
		"":                {},
	}
	for in, want := range cases {
		if got := orgPathIDs(in); !reflect.DeepEqual(got, want) {
			t.Errorf("orgPathIDs(%q) = %v, want %v", in, got, want)
		}
	}
}
