package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// openTestStore 复用 credential_test.go 的 helper。

// orgByID 从扁平清单里挑一条，找不到即 fatal。
func orgByID(t *testing.T, orgs []Org, id string) Org {
	t.Helper()
	for _, o := range orgs {
		if o.ID == id {
			return o
		}
	}
	t.Fatalf("组织 %s 不在清单里: %+v", id, orgs)
	return Org{}
}

// 回填：种子里那 4 个部门（+ 根 + admin 的安全运营）建成真实行，
// 既有用户按 org_key 挂到对应 org_id。
func TestBackfillOrgUnitsFromSeed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	orgs, err := s.OrgUnits(ctx)
	if err != nil {
		t.Fatalf("OrgUnits: %v", err)
	}
	for _, id := range []string{"root", "dev", "sales", "cs", "ext"} {
		o := orgByID(t, orgs, id)
		if id != "root" && o.ParentID != "root" {
			t.Errorf("%s 的父应为 root，得到 %q", id, o.ParentID)
		}
	}
	// admin 的 org_key=sec 不在种子树里，回填时应被补建为根的子部门——
	// 否则这批人回填完仍无归属，组织树上凭空少几个人。
	sec := orgByID(t, orgs, "sec")
	if sec.Name != "安全运营" || sec.ParentID != "root" {
		t.Errorf("sec 应补建为 root 下的「安全运营」，得到 %+v", sec)
	}
	// 物化路径
	if dev := orgByID(t, orgs, "dev"); dev.Path != "/root/dev/" {
		t.Errorf("dev.path 应为 /root/dev/，得到 %q", dev.Path)
	}

	b, err := s.Users(ctx)
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	want := map[string]string{"zhang.wei": "dev", "li.fang": "sales", "zhao.min": "cs", "ext.zhou": "ext", "admin": "sec"}
	got := map[string]string{}
	for _, u := range b.Users {
		got[u.Account] = u.OrgID
	}
	for acct, org := range want {
		if got[acct] != org {
			t.Errorf("%s 的 orgId 应回填为 %s，得到 %q", acct, org, got[acct])
		}
	}
	// 直属成员数：研发部 2 人（zhang.wei / chen.jing）
	if dev := orgByID(t, orgs, "dev"); dev.Members != 2 {
		t.Errorf("dev 直属成员应为 2，得到 %d", dev.Members)
	}
}

// 回填幂等：重开同一个库（等于再跑一次 migrate+回填）不重复建部门，
// 且管理员删掉的部门不会被下次启动安静地复活。
func TestBackfillOrgUnitsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "org.db")
	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open#1: %v", err)
	}
	ctx := context.Background()
	first, _ := s1.OrgUnits(ctx)
	// 删一个空部门（先把客服中心的人挪走）。
	// ★刻意不用 ext：种子策略 ap-ext-strict 的适用范围绑着它，现在会被拒删守卫拦下
	// （见 TestDeleteOrgUnitRefusedWhenAuthPolicyReferencesIt）。
	users, _ := s1.Users(ctx)
	for _, u := range users.Users {
		if u.OrgID == "cs" {
			if err := s1.SetUserOrg(ctx, u.ID, "dev"); err != nil {
				t.Fatalf("SetUserOrg: %v", err)
			}
		}
	}
	if err := s1.DeleteOrgUnit(ctx, "cs"); err != nil {
		t.Fatalf("DeleteOrgUnit(cs): %v", err)
	}
	s1.Close()

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open#2: %v", err)
	}
	defer s2.Close()
	second, _ := s2.OrgUnits(ctx)
	if len(second) != len(first)-1 {
		t.Fatalf("重开后组织数应为 %d（删掉 cs），得到 %d：回填重复建部门或复活了已删部门", len(first)-1, len(second))
	}
	for _, o := range second {
		if o.ID == "cs" {
			t.Fatal("已删除的部门 cs 被下次启动的回填复活了")
		}
	}
}

// 既有库（补列迁移场景）：库里已有用户、但没有组织表数据也没有回填标记时，
// 下次启动必须把部门建出来并把人挂上去——补列只加列不填值正是历史上静默断链的成因。
func TestBackfillOrgUnitsOnLegacyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open#1: %v", err)
	}
	ctx := context.Background()
	// 把库退回「本轮之前」的形态：无组织行、无归属、无回填标记（org_id 列留着，
	// 补列本身是幂等的；这里模拟的正是"列有了、值全是 NULL"那一刻）。
	for _, q := range []string{
		`DELETE FROM org_units`,
		`UPDATE users SET org_id=NULL`,
		`DELETE FROM settings WHERE k='` + orgBackfillMarker + `'`,
	} {
		if _, err := s1.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("退回旧形态 %q: %v", q, err)
		}
	}
	s1.Close()

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open#2: %v", err)
	}
	defer s2.Close()
	orgs, _ := s2.OrgUnits(ctx)
	if len(orgs) == 0 {
		t.Fatal("既有库重启后组织表仍为空：补列没有配回填")
	}
	b, _ := s2.Users(ctx)
	for _, u := range b.Users {
		if u.OrgID == "" {
			t.Errorf("既有用户 %s 未被回填组织归属", u.Account)
		}
	}
}

// 组织 CRUD：新建 / 改名 / 改父（子树 path 级联重写）。
func TestOrgCRUDAndPathCascade(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	a, err := s.SaveOrgUnit(ctx, Org{Name: "华东大区", ParentID: "root", Sort: 1})
	if err != nil {
		t.Fatalf("新建华东: %v", err)
	}
	b, err := s.SaveOrgUnit(ctx, Org{Name: "杭州分部", ParentID: a.ID})
	if err != nil {
		t.Fatalf("新建杭州: %v", err)
	}
	c, err := s.SaveOrgUnit(ctx, Org{Name: "滨江组", ParentID: b.ID})
	if err != nil {
		t.Fatalf("新建滨江: %v", err)
	}
	if c.Path != "/root/"+a.ID+"/"+b.ID+"/"+c.ID+"/" {
		t.Fatalf("滨江组 path 不对: %q", c.Path)
	}
	// 把杭州分部挪到 root 下 → 它与它的后代 path 都要跟着改
	if _, err := s.SaveOrgUnit(ctx, Org{ID: b.ID, Name: "杭州分部", ParentID: "root"}); err != nil {
		t.Fatalf("改父: %v", err)
	}
	orgs, _ := s.OrgUnits(ctx)
	if got := orgByID(t, orgs, b.ID).Path; got != "/root/"+b.ID+"/" {
		t.Errorf("杭州分部 path 应随改父更新，得到 %q", got)
	}
	if got := orgByID(t, orgs, c.ID).Path; got != "/root/"+b.ID+"/"+c.ID+"/" {
		t.Errorf("子树 path 未级联重写，滨江组仍是 %q", got)
	}
	// 改名保留创建时间
	renamed, err := s.SaveOrgUnit(ctx, Org{ID: a.ID, Name: "华东区", ParentID: "root"})
	if err != nil || renamed.Name != "华东区" || renamed.CreatedAt != a.CreatedAt {
		t.Fatalf("改名应保留 createdAt: %+v %v", renamed, err)
	}
}

// 环形父子必须被拒绝：父设成自己、父设成自己的后代（含隔代）。
func TestOrgCycleRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.SaveOrgUnit(ctx, Org{Name: "A", ParentID: "root"})
	b, _ := s.SaveOrgUnit(ctx, Org{Name: "B", ParentID: a.ID})
	c, _ := s.SaveOrgUnit(ctx, Org{Name: "C", ParentID: b.ID})

	if _, err := s.SaveOrgUnit(ctx, Org{ID: a.ID, Name: "A", ParentID: a.ID}); !errors.Is(err, ErrOrgCycle) {
		t.Errorf("父设成自己应回 ErrOrgCycle，得到 %v", err)
	}
	if _, err := s.SaveOrgUnit(ctx, Org{ID: a.ID, Name: "A", ParentID: b.ID}); !errors.Is(err, ErrOrgCycle) {
		t.Errorf("父设成直接子节点应回 ErrOrgCycle，得到 %v", err)
	}
	if _, err := s.SaveOrgUnit(ctx, Org{ID: a.ID, Name: "A", ParentID: c.ID}); !errors.Is(err, ErrOrgCycle) {
		t.Errorf("父设成隔代后代应回 ErrOrgCycle，得到 %v", err)
	}
	// 拒绝之后树仍然可以正常构建（没写进去一个环）
	orgs, _ := s.OrgUnits(ctx)
	if got := orgByID(t, orgs, a.ID).ParentID; got != "root" {
		t.Errorf("被拒的改父不应落库，A 的父仍应是 root，得到 %q", got)
	}
	if len(buildOrgTree(orgs)) == 0 {
		t.Error("组织树应能正常构建")
	}
}

// 删除守卫：有子部门拒删、有成员拒删；两者都清掉后可删。
func TestDeleteOrgGuards(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.DeleteOrgUnit(ctx, "root"); !errors.Is(err, ErrOrgHasChildren) {
		t.Errorf("有子部门应回 ErrOrgHasChildren，得到 %v", err)
	}
	if err := s.DeleteOrgUnit(ctx, "dev"); !errors.Is(err, ErrOrgHasMembers) {
		t.Errorf("有成员应回 ErrOrgHasMembers，得到 %v", err)
	}
	empty, _ := s.SaveOrgUnit(ctx, Org{Name: "空部门", ParentID: "root"})
	if err := s.DeleteOrgUnit(ctx, empty.ID); err != nil {
		t.Fatalf("空部门应可删: %v", err)
	}
	if err := s.DeleteOrgUnit(ctx, empty.ID); !errors.Is(err, ErrOrgNotFound) {
		t.Errorf("重复删应回 ErrOrgNotFound，得到 %v", err)
	}
	// 不存在的父
	if _, err := s.SaveOrgUnit(ctx, Org{Name: "孤儿", ParentID: "nope"}); !errors.Is(err, ErrOrgNotFound) {
		t.Errorf("父不存在应回 ErrOrgNotFound，得到 %v", err)
	}
}

// 删除守卫（认证策略引用）：被策略适用范围绑着的组织/用户组拒删。
//
// 少了这道闸，删组织/组的那一刻绑在它上面的二次认证策略就静默失效——
// 页面上策略还在、只是"生效账号 0"，登录行为无声地退回单因素。
func TestDeleteOrgUnitRefusedWhenAuthPolicyReferencesIt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// 种子策略 ap-ext-strict 的适用范围是 ScopeOrgs=["ext"]；先把外包部门腾空，
	// 让"有成员"这道旧闸不再是拒绝的原因。
	users, _ := s.Users(ctx)
	for _, u := range users.Users {
		if u.OrgID == "ext" {
			if err := s.SetUserOrg(ctx, u.ID, "dev"); err != nil {
				t.Fatalf("SetUserOrg: %v", err)
			}
		}
	}
	if err := s.DeleteOrgUnit(ctx, "ext"); !errors.Is(err, ErrOrgInAuthPolicy) {
		t.Fatalf("被认证策略引用的组织应回 ErrOrgInAuthPolicy，得到 %v", err)
	}
	if _, err := s.OrgUnits(ctx); err != nil {
		t.Fatalf("OrgUnits: %v", err)
	}
	orgs, _ := s.OrgUnits(ctx)
	orgByID(t, orgs, "ext") // 拒删之后组织必须还在

	// 解除绑定后可删（守卫不是死锁：改掉策略范围就放行）
	pols, err := s.AuthPolicies(ctx)
	if err != nil {
		t.Fatalf("AuthPolicies: %v", err)
	}
	for _, p := range pols {
		if len(p.ScopeOrgs) == 0 {
			continue
		}
		p.ScopeOrgs = []string{"dev"}
		if _, err := s.SaveAuthPolicy(ctx, p); err != nil {
			t.Fatalf("改策略范围: %v", err)
		}
	}
	if err := s.DeleteOrgUnit(ctx, "ext"); err != nil {
		t.Fatalf("解除引用后应可删: %v", err)
	}
}

func TestDeleteUserGroupRefusedWhenAuthPolicyReferencesIt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	g, err := s.SaveUserGroup(ctx, UserGroup{Name: "外包协作组", Kind: GroupKindStatic})
	if err != nil {
		t.Fatalf("建组: %v", err)
	}
	if _, err := s.SaveAuthPolicy(ctx, AuthPolicy{
		Name: "外包协作组 · 一律二次认证", Directory: "local", Priority: 20, Enabled: true,
		PC: AuthMethodSet{Primary: "local"}, Mobile: AuthMethodSet{Primary: "local"},
		ScopeGroups: []string{g.ID}, Enhance: EnhanceRule{Always: true},
	}); err != nil {
		t.Fatalf("存策略: %v", err)
	}
	if err := s.DeleteUserGroup(ctx, g.ID); !errors.Is(err, ErrGroupInAuthPolicy) {
		t.Fatalf("被认证策略引用的用户组应回 ErrGroupInAuthPolicy，得到 %v", err)
	}
	gs, _ := s.UserGroups(ctx)
	found := false
	for _, x := range gs {
		if x.ID == g.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("拒删之后用户组不应消失")
	}
}

// 用户组：static 显式成员 CRUD + 重名拒绝 + 未知账号整批拒绝。
func TestUserGroupsStatic(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	g, err := s.SaveUserGroup(ctx, UserGroup{Name: "高敏访问组", Kind: GroupKindStatic, Description: "财务系统白名单"})
	if err != nil {
		t.Fatalf("建组: %v", err)
	}
	if _, err := s.SaveUserGroup(ctx, UserGroup{Name: " 高敏访问组 ", Kind: GroupKindStatic}); !errors.Is(err, ErrGroupExists) {
		t.Errorf("重名（规范化后）应拒绝，得到 %v", err)
	}
	if err := s.SetGroupMembers(ctx, g.ID, []string{"li.fang", "LI.FANG", "zhang.wei"}); err != nil {
		t.Fatalf("设成员: %v", err)
	}
	mem, _ := s.GroupMembers(ctx, g.ID)
	if len(mem) != 2 {
		t.Fatalf("大小写重复应去重成 2 人，得到 %v", mem)
	}
	// 未知账号整批拒绝：拼错一个账号就少一个人有权限，界面上看不出异常
	if err := s.SetGroupMembers(ctx, g.ID, []string{"li.fang", "typo.user"}); !errors.Is(err, ErrUnknownAccount) {
		t.Errorf("未知账号应回 ErrUnknownAccount，得到 %v", err)
	}
	if after, _ := s.GroupMembers(ctx, g.ID); len(after) != 2 {
		t.Errorf("整批拒绝后成员不应被改动，得到 %v", after)
	}
	gs, _ := s.UserGroups(ctx)
	if len(gs) != 1 || gs[0].Members != 2 {
		t.Fatalf("组清单成员数应实算为 2: %+v", gs)
	}
	if err := s.DeleteUserGroup(ctx, g.ID); err != nil {
		t.Fatalf("删组: %v", err)
	}
	if err := s.DeleteUserGroup(ctx, g.ID); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("重复删应回 ErrGroupNotFound，得到 %v", err)
	}
}

// 角色组：成员由 users.roles 派生、只读；显式写入被拒。
func TestUserGroupsRoleDerived(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	g, err := s.SaveUserGroup(ctx, UserGroup{Name: "研发", Kind: GroupKindRole})
	if err != nil {
		t.Fatalf("建角色组: %v", err)
	}
	mem, err := s.GroupMembers(ctx, g.ID)
	if err != nil {
		t.Fatalf("GroupMembers: %v", err)
	}
	// 种子里 roles 含「研发」的是 zhang.wei 与 chen.jing
	if len(mem) != 2 {
		t.Fatalf("角色组应派生出 2 名成员，得到 %v", mem)
	}
	if err := s.SetGroupMembers(ctx, g.ID, []string{"li.fang"}); !errors.Is(err, ErrGroupDerived) {
		t.Errorf("角色组显式写成员应回 ErrGroupDerived，得到 %v", err)
	}
	if err := s.SetUserGroups(ctx, "li.fang", []string{g.ID}); !errors.Is(err, ErrGroupDerived) {
		t.Errorf("从用户侧挂进角色组也应拒绝，得到 %v", err)
	}
	// 反向索引里角色组的派生归属要出现
	m, _ := s.GroupMemberships(ctx)
	if len(m["zhang.wei"]) != 1 || m["zhang.wei"][0] != g.ID {
		t.Errorf("zhang.wei 应派生归属角色组，得到 %v", m["zhang.wei"])
	}
}

// 用户侧写入：改组织归属 + 改所属 static 组，读回时 Users() 带上。
func TestSetUserOrgAndGroups(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	g, _ := s.SaveUserGroup(ctx, UserGroup{Name: "值班组", Kind: GroupKindStatic})
	b, _ := s.Users(ctx)
	var target DirUser
	for _, u := range b.Users {
		if u.Account == "li.fang" {
			target = u
		}
	}
	if err := s.SetUserOrg(ctx, target.ID, "dev"); err != nil {
		t.Fatalf("SetUserOrg: %v", err)
	}
	if err := s.SetUserGroups(ctx, "li.fang", []string{g.ID}); err != nil {
		t.Fatalf("SetUserGroups: %v", err)
	}
	b2, _ := s.Users(ctx)
	for _, u := range b2.Users {
		if u.Account != "li.fang" {
			continue
		}
		if u.OrgID != "dev" || u.Org != "研发部" || u.OrgKey != "dev" {
			t.Errorf("展示用 org/orgKey 应跟随组织表，得到 %+v", u)
		}
		if len(u.GroupIDs) != 1 || u.GroupIDs[0] != g.ID {
			t.Errorf("所属组应为 %s，得到 %v", g.ID, u.GroupIDs)
		}
	}
	if len(b2.Groups) != 1 {
		t.Errorf("用户目录应带上用户组目录，得到 %+v", b2.Groups)
	}
	// 不存在的组织拒绝
	if err := s.SetUserOrg(ctx, target.ID, "nope"); !errors.Is(err, ErrOrgNotFound) {
		t.Errorf("不存在的组织应回 ErrOrgNotFound，得到 %v", err)
	}
}

// 新建用户带组织与组：落库并读回。组织不存在时整体拒绝。
func TestCreateUserWithOrgAndGroups(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	g, _ := s.SaveUserGroup(ctx, UserGroup{Name: "新人组", Kind: GroupKindStatic})

	u, err := s.CreateUser(ctx, DirUser{Name: "钱七", Account: "qian.qi", OrgID: "sales", GroupIDs: []string{g.ID}})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Org != "销售部" || u.OrgKey != "sales" {
		t.Errorf("新建用户的展示组织应对齐组织表，得到 %+v", u)
	}
	mem, _ := s.GroupMembers(ctx, g.ID)
	if len(mem) != 1 || mem[0] != "qian.qi" {
		t.Errorf("新建用户应已入组，得到 %v", mem)
	}
	if _, err := s.CreateUser(ctx, DirUser{Name: "错组织", Account: "bad.org", OrgID: "nope"}); !errors.Is(err, ErrOrgNotFound) {
		t.Errorf("组织不存在应回 ErrOrgNotFound，得到 %v", err)
	}
}

// PolicyBundle 的组织树来自库而不是种子：改了库，树跟着变；
// 种子树里那批硬编码 key（east/south/contractor）不该再出现。
func TestPolicyBundleTreeFromDB(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	pb, err := s.PolicyBundle(ctx)
	if err != nil {
		t.Fatalf("PolicyBundle: %v", err)
	}
	keys := map[string]OrgNode{}
	var walk func(ns []OrgNode)
	walk = func(ns []OrgNode) {
		for _, n := range ns {
			keys[n.Key] = n
			walk(n.Children)
		}
	}
	walk(pb.Tree)
	for _, seedKey := range []string{"east", "south", "east-sales", "contractor"} {
		if _, ok := keys[seedKey]; ok {
			t.Errorf("策略树仍含种子节点 %s：PolicyBundle 没有脱种子", seedKey)
		}
	}
	if _, ok := keys["dev"]; !ok {
		t.Fatalf("策略树应含库里的 dev 部门: %+v", keys)
	}
	// 根节点人数 = 子树合计（种子 7 用户 + admin = 8，全部有归属）
	if root := keys["root"]; root.Members != 8 {
		t.Errorf("根节点应显示子树合计 8 人，得到 %d", root.Members)
	}
	if keys["dev"].HasCustom {
		t.Error("尚未保存覆盖时 dev 不应标记 hasCustom")
	}
	// 新建部门 + 给它存一份策略覆盖 → 树上立刻反映
	n, _ := s.SaveOrgUnit(ctx, Org{Name: "风控组", ParentID: "root"})
	if err := s.SavePolicyOverride(ctx, n.ID, "风控组", "{}", 3); err != nil {
		t.Fatalf("SavePolicyOverride: %v", err)
	}
	pb2, _ := s.PolicyBundle(ctx)
	keys = map[string]OrgNode{}
	walk(pb2.Tree)
	if got, ok := keys[n.ID]; !ok || !got.HasCustom {
		t.Errorf("新建部门与它的策略覆盖应出现在树上，得到 %+v", got)
	}
	// List 维持既有行为（仍是演示清单）
	if len(pb2.List) == 0 {
		t.Error("策略清单 List 应维持既有行为")
	}
}

// buildOrgTree 的两处兜底：父指针悬空的节点提升为根、脏数据成环时不无限递归。
func TestBuildOrgTreeDefensive(t *testing.T) {
	orphan := buildOrgTree([]Org{{ID: "x", Name: "孤儿部", ParentID: "ghost", Members: 3}})
	if len(orphan) != 1 || orphan[0].Key != "x" || orphan[0].Members != 3 {
		t.Fatalf("父不存在的节点应提升为根而不是消失: %+v", orphan)
	}
	cyc := buildOrgTree([]Org{
		{ID: "a", Name: "A", ParentID: "b", Members: 1},
		{ID: "b", Name: "B", ParentID: "a", Members: 1},
	})
	if len(cyc) == 0 {
		t.Fatal("成环的脏数据应退化成少画几条边，而不是空树/死循环")
	}
}
