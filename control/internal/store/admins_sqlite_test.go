package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// 管理员分级分权（三权分立）的库层：内置角色建齐、既有管理员回填成超管、
// 防自锁三条路（降权/撤销/禁用）、自定义角色的权限收缩、System 来自库而非种子。

// soleRoot 把 admin 之外的超管统统降成审计管理员，制造"只剩一名超管"的局面。
// 种子里 zhang.wei 的展示角色含「管理员」，roleFromDisplay 会把他判成 role=admin，
// 于是回填后库里有两名超管——不先收敛，防自锁用例测的就不是最后一名。
func soleRoot(t *testing.T, s *SQLiteStore) {
	t.Helper()
	ctx := context.Background()
	b, err := s.System(ctx)
	if err != nil {
		t.Fatalf("System: %v", err)
	}
	for _, a := range b.Admins {
		if a.Power == PowerRoot && a.Account != "admin" {
			if err := s.SetAdminRole(ctx, a.Account, "audit"); err != nil {
				t.Fatalf("收敛超管 %s: %v", a.Account, err)
			}
		}
	}
}

// secondRoot 造一名额外的超管，用于解开「最后一名超管」的防自锁闸。
func secondRoot(t *testing.T, s *SQLiteStore) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, DirUser{
		Name: "备用超管", Account: "root2", Status: "active", Role: "admin", AdminRole: "root",
	}); err != nil {
		t.Fatalf("建第二名超管: %v", err)
	}
}

// 内置四角色建齐，且 scope_json 与代码里的 PowerPerms 一致（不是配置里另写一份）。
func TestBuiltinAdminRolesSeeded(t *testing.T) {
	s := openTestStore(t)
	roles, err := s.AdminRoles(context.Background())
	if err != nil {
		t.Fatalf("AdminRoles: %v", err)
	}
	byKey := map[string]AdminRole{}
	for _, r := range roles {
		byKey[r.Key] = r
	}
	for _, b := range BuiltinAdminRoles() {
		got, ok := byKey[b.Key]
		if !ok {
			t.Fatalf("内置角色 %s 未建", b.Key)
		}
		if !got.Builtin || got.Power != b.Power {
			t.Errorf("%s builtin/power 不对: %+v", b.Key, got)
		}
		want := PowerPerms(b.Power)
		if len(got.Perms) != len(want) || (len(want) > 0 && got.Perms[0] != want[0]) {
			t.Errorf("%s 权限键应为 %v，得到 %v", b.Key, want, got.Perms)
		}
	}
	// 三权互不越权：安全管理员读不到审计，审计管理员改不了策略。
	if byKey["security"].Allows(PermAudit) {
		t.Error("安全管理员不应持有审计权")
	}
	if byKey["audit"].Allows(PermSecurity) || byKey["audit"].Allows(PermSystem) {
		t.Error("审计管理员只应有审计权")
	}
	if !byKey["root"].Allows(PermAdmins) || !byKey["root"].Allows(PermAudit) {
		t.Error("超管应持有全部权限")
	}
}

// ★回填：升级后既有 role='admin' 的账号必须自动落到超管，否则所有人被锁在门外
// （requirePerm fail-closed 403，而"给自己分配角色"本身也需要管理员权限）。
func TestBackfillAdminRoleKeepsExistingAdminInCharge(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	role, ok, err := s.AdminRoleFor(ctx, "admin")
	if err != nil || !ok {
		t.Fatalf("种子 admin 应有角色: ok=%v err=%v", ok, err)
	}
	if role.Power != PowerRoot || !role.Allows(PermAdmins) {
		t.Fatalf("种子 admin 应回填为超管，得到 %+v", role)
	}

	// 模拟"补列迁移刚跑完"的既有库：列有了、值是空的、一次性标记未落。
	if _, err := s.db.Exec(`UPDATE users SET admin_role='' WHERE role='admin'`); err != nil {
		t.Fatalf("造场景: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM settings WHERE k=?`, adminRoleBackfillMarker); err != nil {
		t.Fatalf("清标记: %v", err)
	}
	if _, ok, _ := s.AdminRoleFor(ctx, "admin"); ok {
		t.Fatal("造场景后 admin 不应有角色（否则本用例没在测回填）")
	}
	if err := s.backfillAdminRoles(ctx); err != nil {
		t.Fatalf("backfillAdminRoles: %v", err)
	}
	role, ok, err = s.AdminRoleFor(ctx, "admin")
	if err != nil || !ok || role.Power != PowerRoot {
		t.Fatalf("回填后 admin 应重回超管，得到 %+v ok=%v err=%v", role, ok, err)
	}

	// 一次性：标记落下之后，再出现"是管理员但没角色"的异常行不得被静默提权成超管。
	if _, err := s.db.Exec(`UPDATE users SET admin_role='' WHERE role='admin'`); err != nil {
		t.Fatalf("造第二次场景: %v", err)
	}
	if err := s.backfillAdminRoles(ctx); err != nil {
		t.Fatalf("backfillAdminRoles 第二次: %v", err)
	}
	if _, ok, _ := s.AdminRoleFor(ctx, "admin"); ok {
		t.Error("标记已落，回填不应再次执行（否则任何异常行重启即提权到超管）")
	}
}

// 防自锁：最后一名超管不可降权 / 不可撤销 / 不可禁用；有了第二名之后才放行。
func TestLastRootAdminCannotBeDemotedRemovedOrDisabled(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	soleRoot(t, s)

	if err := s.SetAdminRole(ctx, "admin", "audit"); !errors.Is(err, ErrLastRootAdmin) {
		t.Errorf("降走最后一名超管应 ErrLastRootAdmin，得到 %v", err)
	}
	if err := s.RemoveAdmin(ctx, "admin"); !errors.Is(err, ErrLastRootAdmin) {
		t.Errorf("撤销最后一名超管应 ErrLastRootAdmin，得到 %v", err)
	}
	if err := s.SetUserStatus(ctx, "u-admin", "disabled"); !errors.Is(err, ErrLastRootAdmin) {
		t.Errorf("禁用最后一名超管应 ErrLastRootAdmin，得到 %v", err)
	}
	// 三次拒绝后权限一字未动
	if role, ok, _ := s.AdminRoleFor(ctx, "admin"); !ok || role.Power != PowerRoot {
		t.Fatalf("拒绝后 admin 仍应是超管，得到 %+v ok=%v", role, ok)
	}

	secondRoot(t, s)
	if err := s.SetAdminRole(ctx, "admin", "audit"); err != nil {
		t.Fatalf("有第二名超管后应可降权，得到 %v", err)
	}
	role, ok, _ := s.AdminRoleFor(ctx, "admin")
	if !ok || role.Power != PowerAudit {
		t.Fatalf("降权后应是审计管理员，得到 %+v", role)
	}
	// 现在 root2 成了最后一名超管，同样受保护
	if err := s.RemoveAdmin(ctx, "root2"); !errors.Is(err, ErrLastRootAdmin) {
		t.Errorf("root2 成为最后一名后应受保护，得到 %v", err)
	}
}

// 已禁用的超管不算数：留着一个登不进来的 root 当"还有超管"等于自锁没被拦住。
func TestDisabledRootDoesNotCountAsRemainingRoot(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	soleRoot(t, s)
	secondRoot(t, s)
	if err := s.SetUserStatus(ctx, "u-admin", "disabled"); err != nil {
		t.Fatalf("有两名超管时应可禁用其一: %v", err)
	}
	// 此刻可登录的超管只剩 root2
	if err := s.RemoveAdmin(ctx, "root2"); !errors.Is(err, ErrLastRootAdmin) {
		t.Errorf("被禁用的 admin 不应被算作剩余超管，得到 %v", err)
	}
}

// 自定义角色只能在三权内收缩：`*` 与 admins 一律拒绝（否则等于自造一个不叫 root 的超管，
// 「最后一个 root」的计数就绕过去了）。内置角色不可改不可删；有成员的角色不可删。
func TestCustomAdminRoleConstraints(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	for _, bad := range [][]string{{PermAll}, {PermAdmins}, {"security", PermAll}, {}, {"nope"}} {
		if _, err := s.SaveAdminRole(ctx, AdminRole{Key: "x", Name: "越权角色", Perms: bad}); !errors.Is(err, ErrAdminRolePerm) {
			t.Errorf("权限 %v 应被拒，得到 %v", bad, err)
		}
	}
	if _, err := s.SaveAdminRole(ctx, AdminRole{Key: "root", Name: "改内置", Perms: []string{PermAudit}}); !errors.Is(err, ErrAdminRoleBuiltin) {
		t.Errorf("内置角色应拒改，得到 %v", err)
	}
	if err := s.DeleteAdminRole(ctx, "audit"); !errors.Is(err, ErrAdminRoleBuiltin) {
		t.Errorf("内置角色应拒删，得到 %v", err)
	}

	saved, err := s.SaveAdminRole(ctx, AdminRole{Key: "east-op", Name: "华东运维组", Perms: []string{PermSystem, PermAudit}})
	if err != nil {
		t.Fatalf("建自定义角色: %v", err)
	}
	if saved.Power != PowerCustom || len(saved.Perms) != 2 {
		t.Fatalf("自定义角色落地不对: %+v", saved)
	}
	// 角色的权限键真的被 Allows 消费（scope_json 不是摆设）
	got, ok, err := func() (AdminRole, bool, error) {
		secondRoot(t, s)
		if err := s.SetAdminRole(ctx, "root2", "east-op"); err != nil {
			return AdminRole{}, false, err
		}
		return s.AdminRoleFor(ctx, "root2")
	}()
	if err != nil || !ok {
		t.Fatalf("改派自定义角色: ok=%v err=%v", ok, err)
	}
	if !got.Allows(PermSystem) || !got.Allows(PermAudit) || got.Allows(PermSecurity) || got.Allows(PermAdmins) {
		t.Errorf("自定义角色权限判定不对: %+v", got)
	}
	if err := s.DeleteAdminRole(ctx, "east-op"); !errors.Is(err, ErrAdminRoleInUse) {
		t.Errorf("有成员的角色应拒删，得到 %v", err)
	}
	if err := s.RemoveAdmin(ctx, "root2"); err != nil {
		t.Fatalf("撤销非超管应放行: %v", err)
	}
	if err := s.DeleteAdminRole(ctx, "east-op"); err != nil {
		t.Errorf("无成员后应可删，得到 %v", err)
	}
	if _, ok, _ := s.AdminRoleFor(ctx, "root2"); ok {
		t.Error("撤销后不应再解析出管理员角色")
	}
}

// System 全部来自库：角色表 + users 表；集群如实回"未部署"，不再有三个假节点。
func TestSystemBundleComesFromDBNotSeed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	b, err := s.System(ctx)
	if err != nil {
		t.Fatalf("System: %v", err)
	}
	if len(b.Roles) != len(BuiltinAdminRoles()) {
		t.Fatalf("角色数应等于内置四角色，得到 %d", len(b.Roles))
	}
	var a AdminAccount
	for _, x := range b.Admins {
		if x.Account == "admin" {
			a = x
		}
	}
	if a.Account == "" {
		t.Fatalf("管理员清单里应有种子 admin，得到 %+v", b.Admins)
	}
	if a.RoleKey != "root" || a.Power != PowerRoot {
		t.Errorf("admin 角色不对: %+v", a)
	}
	if a.TwoFA || a.Auth != "本地口令" {
		t.Errorf("未注册 passkey 的账号不应显示已开启二次认证: %+v", a)
	}
	// 集群状态已从 SystemBundle 移出（改由 api 层的 standby.ClusterView 承载，
	// 真读 standby_nodes 表）：这里不再有可断言的集群字段，
	// 三态断言在 api 包的 TestClusterViewThreeStates。

	// 库里新增的管理员必须出现在响应里（种子是常量，不会随库变）
	secondRoot(t, s)
	if err := s.SetAdminRole(ctx, "root2", "audit"); err != nil {
		t.Fatalf("改派: %v", err)
	}
	b2, err := s.System(ctx)
	if err != nil {
		t.Fatalf("System 二次: %v", err)
	}
	found := false
	for _, x := range b2.Admins {
		if x.Account == "root2" {
			found = true
			if x.RoleName != "审计管理员" {
				t.Errorf("root2 角色名应随库变，得到 %q", x.RoleName)
			}
		}
	}
	if !found {
		t.Error("新建管理员未出现在 System 响应里（说明这一页仍在吃种子）")
	}
	wantAudit := 0
	for _, x := range b2.Admins {
		if x.RoleKey == "audit" {
			wantAudit++
		}
	}
	for _, r := range b2.Roles {
		if r.Key == "audit" && r.Members != wantAudit {
			t.Errorf("审计角色成员数应实算为 %d，得到 %d", wantAudit, r.Members)
		}
	}
}

// TestSeedHasExactlyOneRoot 钉住「全新库只有一名超级管理员」。
//
// ★这条守卫当初该有而没有，缺了它的代价是：种子循环用 roleFromDisplay 从**中文展示标签**
// 「管理员」推出权威角色 role=admin，于是种子用户 zhang.wei 成了 role=admin，
// 再被 ensureAdminRoles 的 root 回填升成 admin_role='root'——
// **每一台按 deploy.sh 装出来的机器上都有第二把超管钥匙，口令是公开的 baidi@123**。
// 2026-09-04 在演示站实测：zhang.wei / baidi@123 登录 → /auth/me 回 adminRole.perms=["*"]
// → GET /audit 与 GET /system 均 200。
//
// 它活得久是因为**四条用例把它当成预期行为钉住了**（store/idle_test.go 的
// 「zhang.wei 应标记为管理员」、api 侧三条闲置治理用例、以及 soleRoot 脚手架的注释）。
// 那几处现在都改成显式造管理员夹具，这条则从正面把不变式钉死。
//
// 断言两层：数量为 1（防再冒出第二把钥匙），以及那一个必须是 admin
// （防有人"修"成把 root 给了别人而不是 admin）。
func TestSeedHasExactlyOneRoot(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rows, err := s.db.QueryContext(ctx,
		`SELECT account, role FROM users WHERE admin_role='root' ORDER BY account`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var roots []string
	for rows.Next() {
		var acct, role string
		if err := rows.Scan(&acct, &role); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, acct+"(role="+role+")")
	}
	if len(roots) != 1 || roots[0] != "admin(role=admin)" {
		t.Fatalf("全新库必须**只有** admin 一名超级管理员，实得 %v。\n"+
			"多出来的每一把钥匙都持有公开的种子口令 baidi@123，且活过了 BAIDI_SEED_MUST_CHANGE\n"+
			"（那条只保证「谁先登谁改」，拦不住知道公开口令的人抢先改成自己的）。", roots)
	}

	// 反面：权威角色绝不许从展示标签推导。zhang.wei 的展示标签含「管理员」，
	// 它是给页面看的中文数据、管理员随时可改；拿它当鉴权判据等于把提权入口
	// 开在一个谁都不会当成安全面的字段上（同 requirePerm 那条「判定点是权限键、不是页面文案」）。
	var roles, role string
	if err := s.db.QueryRowContext(ctx,
		`SELECT roles, role FROM users WHERE account='zhang.wei'`).Scan(&roles, &role); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(roles, "管理员") {
		t.Skip("种子数据已变：zhang.wei 的展示标签不再含「管理员」，这条反面断言失去意义")
	}
	if role != "user" {
		t.Fatalf("展示标签含「管理员」的种子用户，其权威角色必须仍是 user，实得 %q", role)
	}
}
