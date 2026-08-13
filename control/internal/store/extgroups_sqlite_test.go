package store

// 外部身份组/属性消费（wave7 行动 2）。回归背景：采集侧（LDAP GroupAttr /
// OIDC groups claim）与承接侧（allow_groups / ScopeGroups / SubjectIndex）都真，
// BindExternalUser 却在"已绑定"分支提前返回——组到手即弃，「按 AD 安全组授权」
// 整条链断在最后一跳。

import (
	"context"
	"path/filepath"
	"testing"
)

func openExtStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "ext.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func bind(t *testing.T, st *SQLiteStore, src string, ext ExternalIdentity) Credential {
	t.Helper()
	c, err := st.BindExternalUser(context.Background(), src, ext)
	if err != nil {
		t.Fatalf("BindExternalUser: %v", err)
	}
	return c
}

func groupsOf(t *testing.T, st *SQLiteStore, account string) map[string]string {
	t.Helper()
	idx, err := st.SubjectIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{} // group id → 是否含该账号（"1"）
	for gid, accs := range idx.GroupAccounts {
		for _, a := range accs {
			if a == account {
				names[gid] = "1"
			}
		}
	}
	return names
}

func TestExternalGroupsFlowIntoSubjectIndex(t *testing.T) {
	st := openExtStore(t)
	ctx := context.Background()

	c := bind(t, st, "src-ad", ExternalIdentity{
		Subject: "dn=alice", Username: "alice.ext", DisplayName: "Alice",
		Email: "Alice@Corp.Example", Groups: []string{"研发部", "VPN-Users"},
	})

	// 组已建（kind=external）且 SubjectIndex 展开含此人。
	got := groupsOf(t, st, c.Account)
	gid研发 := extGroupID("src-ad", "研发部")
	if got[gid研发] != "1" || got[extGroupID("src-ad", "VPN-Users")] != "1" {
		t.Fatalf("外部组应进 SubjectIndex 展开，实得 %v", got)
	}
	gs, err := st.UserGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kindOf := map[string]string{}
	for _, g := range gs {
		kindOf[g.ID] = g.Kind
	}
	if kindOf[gid研发] != GroupKindExternal {
		t.Fatalf("外部组 kind 应为 external，实得 %q", kindOf[gid研发])
	}
	// 邮箱落库（规范化小写）。
	ub, _ := st.Users(ctx)
	for _, u := range ub.Users {
		if u.Account == c.Account && u.Email != "alice@corp.example" {
			t.Errorf("邮箱应规范化落库，实得 %q", u.Email)
		}
	}
}

// 再登录：组清单收敛到本次返回值；改名/移除的组失去该成员；显示名与邮箱刷新。
func TestExternalGroupsConvergeOnRelogin(t *testing.T) {
	st := openExtStore(t)
	base := ExternalIdentity{Subject: "dn=bob", Username: "bob.ext", DisplayName: "Bob",
		Groups: []string{"OldGroup", "Keep"}}
	c := bind(t, st, "src-ad", base)

	// 手工把此人放进一个 static 组：刷新绝不能碰它。
	if _, err := st.SaveUserGroup(context.Background(), UserGroup{ID: "grp-manual", Name: "手工组", Kind: GroupKindStatic}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGroupMembers(context.Background(), "grp-manual", []string{c.Account}); err != nil {
		t.Fatal(err)
	}

	// 第二次登录：OldGroup 没了、New 来了；显示名与邮箱变了。
	base.Groups = []string{"Keep", "New"}
	base.DisplayName = "Bob Wang"
	base.Email = "bob@corp.example"
	c2 := bind(t, st, "src-ad", base)
	if c2.Account != c.Account {
		t.Fatalf("同 subject 应回同一账号：%s vs %s", c.Account, c2.Account)
	}
	if c2.Name != "Bob Wang" {
		t.Errorf("返回的凭据应带刷新后的显示名，实得 %q", c2.Name)
	}

	got := groupsOf(t, st, c.Account)
	if got[extGroupID("src-ad", "OldGroup")] == "1" {
		t.Error("已移出的外部组不该再含该成员")
	}
	if got[extGroupID("src-ad", "Keep")] != "1" || got[extGroupID("src-ad", "New")] != "1" {
		t.Errorf("新组清单应生效：%v", got)
	}
	if got["grp-manual"] != "1" {
		t.Error("★static 组成员绝不能被外部刷新冲掉")
	}
}

// 双源隔离：同名组两个 id；A 源刷新不碰 B 源的成员。
func TestExternalGroupsSourceIsolation(t *testing.T) {
	st := openExtStore(t)
	c := bind(t, st, "src-a", ExternalIdentity{Subject: "s1", Username: "dual.user", Groups: []string{"admins"}})
	// 同一账号（同 subject 不可能跨源；模拟同名组即可）：B 源另一个人也有 admins 组。
	c2 := bind(t, st, "src-b", ExternalIdentity{Subject: "s2", Username: "other.user", Groups: []string{"admins"}})

	ga, gb := extGroupID("src-a", "admins"), extGroupID("src-b", "admins")
	if ga == gb {
		t.Fatalf("两个源的同名组必须是两个组：%s", ga)
	}
	// A 源用户下次登录组清空：只影响 A 源的组。
	bind(t, st, "src-a", ExternalIdentity{Subject: "s1", Username: "dual.user", Groups: nil})
	if got := groupsOf(t, st, c.Account); got[ga] == "1" {
		t.Error("A 源清空后其组不应再含该成员")
	}
	if got := groupsOf(t, st, c2.Account); got[gb] != "1" {
		t.Error("B 源的成员不该被 A 源的刷新波及")
	}
}

// 外部组只读：改名/改成员两条路都被拒——手工编辑会被下次登录静默冲掉，
// "改了又变回去"比直接拒绝难查得多。
func TestExternalGroupsReadOnly(t *testing.T) {
	st := openExtStore(t)
	c := bind(t, st, "src-ad", ExternalIdentity{Subject: "s", Username: "ro.user", Groups: []string{"G"}})
	gid := extGroupID("src-ad", "G")

	if _, err := st.SaveUserGroup(context.Background(), UserGroup{ID: gid, Name: "改名", Kind: GroupKindStatic}); err == nil {
		t.Fatal("改外部组应被拒")
	}
	if err := st.SetGroupMembers(context.Background(), gid, []string{c.Account}); err == nil {
		t.Fatal("改外部组成员应被拒")
	}
	// 资源授权引用外部组：validateSubjectRefs 走 UserGroups——组在清单里即可引用。
	found := false
	gs, _ := st.UserGroups(context.Background())
	for _, g := range gs {
		if g.ID == gid {
			found = true
		}
	}
	if !found {
		t.Fatal("外部组应出现在组清单里（供授权引用与页面展示）")
	}
}
