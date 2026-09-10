package store

import (
	"context"
	"testing"

	"baidi.dev/control/internal/auth"
)

// bindExtUser 建一个外部认证源并绑一个外部身份，返回该账号名。
func bindExtUser(t *testing.T, s *SQLiteStore, srcID, account string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := s.SaveAuthSource(ctx, AuthSourceRec{
		ID: srcID, Name: "测试目录 " + srcID, Kind: "ldap", Enabled: true, Config: "{}",
	}); err != nil {
		t.Fatalf("建认证源失败：%v", err)
	}
	cred, err := s.BindExternalUser(ctx, srcID, ExternalIdentity{
		Subject: "cn=" + account + ",dc=corp", Username: account, DisplayName: account,
	})
	if err != nil {
		t.Fatalf("绑定外部身份失败：%v", err)
	}
	if cred.PassHash != "" {
		t.Fatalf("建号那一刻 pass_hash 就该是空的（不变式：外部账号恒无本地口令），实得 %q", cred.PassHash)
	}
	return account
}

// TestExternalAccountNeverGetsSeedPassword 外部目录账号在任意多次重启后都不得获得本地口令。
//
// 这条用例钉的是一个真实存在过的冒充通道：ensureCredentials 的 pass_hash 回填此前
// 每次启动都无条件跑，判据 `pass_hash=''` 同时命中「史前迁移库的本地用户」与
// 「外部目录账号」两种互斥语义，于是控制面每重启一次，全体 LDAP/AD/RADIUS/OIDC
// 账号都获得可用的公开口令 baidi@123；叠加门户「先本地、后外部」，知道外部用户名
// 的人即可冒充他登录，且全程不触达外部认证源、审计里是一次正常的本地登录。
//
// ★变异检查（实跑过，逐条对应到具体用例——三处修复各有一条能把它变红的变异）：
//  1. 去掉 ② 的 NOT EXISTS 子句 → TestLegacyDatabaseWithExistingExternalUsersNotPoisoned 变红。
//     **本用例对这条变异是绿的**，别指望它：openTestStore 已经跑过一次 OpenSQLite，
//     标记早落下了，于是这里的外部账号是被"一次性"挡住的，NOT EXISTS 根本没被走到。
//     那条子句真正承重的是另一个场景——**已配置 LDAP 的存量库升级**（无标记 + 已有
//     外部账号），也就是所有现役部署的形态，必须由那条专门的用例来钉。
//  2. 去掉 ② 的一次性标记 → TestOrphanExternalAccountNotRepoisoned 变红。
//  3. 去掉 ① 的清理段 → TestPoisonedExternalCredentialGetsCleaned 变红。
func TestExternalAccountNeverGetsSeedPassword(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	acct := bindExtUser(t, s, "src-ldap", "alice")

	// 连跑三次，模拟三次进程启动。
	for i := 1; i <= 3; i++ {
		if err := s.ensureCredentials(); err != nil {
			t.Fatalf("第 %d 次 ensureCredentials：%v", i, err)
		}
		cred, found, err := s.Credential(ctx, acct)
		if err != nil || !found {
			t.Fatalf("第 %d 次重读凭据：found=%v err=%v", i, found, err)
		}
		if cred.PassHash != "" {
			verdict := "非种子口令"
			if auth.VerifyPassword(cred.PassHash, seedPassword) {
				verdict = "而且就是公开的 " + seedPassword + "——任何知道用户名的人都能冒充他登录"
			}
			t.Fatalf("第 %d 次重启后外部账号 %s 被写入了本地口令（%s）。"+
				"外部账号 pass_hash 必须恒空，否则 api.guardLocalCredentialForAdmin "+
				"（判据就是 PassHash==\"\"）会一并失效，外部账号可被提为管理员", i, acct, verdict)
		}
	}
}

// TestPoisonedExternalCredentialGetsCleaned 已被污染的存量库要在启动时清回来。
//
// 光"以后不再下毒"不够：任何在修复前跑过一次的部署，库里已经躺着一批可用的
// 公开口令，而管理员没有任何手段发现它们是被回填出来的（页面上与本地账号同形）。
func TestPoisonedExternalCredentialGetsCleaned(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	acct := bindExtUser(t, s, "src-ad", "bob")

	// 手工复现旧版行为：把种子口令哈希直接写进外部账号。
	hash, err := auth.HashPassword(seedPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET pass_hash=? WHERE account=?`, hash, acct); err != nil {
		t.Fatal(err)
	}
	// 前置断言：污染确实生效了（否则后面的"清干净了"是空断言）。
	if cred, _, _ := s.Credential(ctx, acct); !auth.VerifyPassword(cred.PassHash, seedPassword) {
		t.Fatal("前置条件不成立：污染没写进去，本用例证明不了任何事")
	}

	if err := s.ensureCredentials(); err != nil {
		t.Fatalf("ensureCredentials：%v", err)
	}
	cred, found, err := s.Credential(ctx, acct)
	if err != nil || !found {
		t.Fatalf("重读凭据：found=%v err=%v", found, err)
	}
	if cred.PassHash != "" {
		t.Fatalf("升级后必须清掉外部账号上的出厂口令，实得 %q", cred.PassHash)
	}
}

// TestDeliberateLocalPasswordForExternalUserSurvives 管理员刻意为外部账号重置的本地口令不得被清掉。
//
// 那是 guardLocalCredentialForAdmin 明写的补救路径（"如需让他管理系统，请先为他
// 重置一个本地口令，再来提权"）。清理段的判据因此必须是「绑定 ∩ 口令恰为出厂口令」
// 的交集——只看绑定就会把这条正当配置一起抹掉，且抹掉之后那个管理员再也登不进管理台。
func TestDeliberateLocalPasswordForExternalUserSurvives(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	acct := bindExtUser(t, s, "src-oidc", "carol")

	hash, err := auth.HashPassword("Str0ng-Passphrase!42")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET pass_hash=? WHERE account=?`, hash, acct); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureCredentials(); err != nil {
		t.Fatalf("ensureCredentials：%v", err)
	}
	cred, _, _ := s.Credential(ctx, acct)
	if !auth.VerifyPassword(cred.PassHash, "Str0ng-Passphrase!42") {
		t.Fatalf("管理员刻意设置的本地口令被清掉了（那是提权前的必经补救路径），实得 %q", cred.PassHash)
	}
}

// TestOrphanExternalAccountNotRepoisoned 认证源被删除后，孤儿外部账号不得在下次启动被重新下毒。
//
// DeleteAuthSource 会连带删 auth_source_bindings，于是「按绑定排除」这一道判据对
// 孤儿账号失效——一次性标记是这条路上唯一挡得住的东西。
func TestOrphanExternalAccountNotRepoisoned(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	acct := bindExtUser(t, s, "src-gone", "dave")

	// 第一次启动（此时绑定还在，账号被正确排除）。
	if err := s.ensureCredentials(); err != nil {
		t.Fatal(err)
	}
	// 管理员删掉认证源 → 绑定行随之消失，账号成为孤儿。
	if err := s.DeleteAuthSource(ctx, "src-gone"); err != nil {
		t.Fatalf("删除认证源：%v", err)
	}
	var binds int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM auth_source_bindings`).Scan(&binds); err != nil {
		t.Fatal(err)
	}
	if binds != 0 {
		t.Fatalf("前置条件不成立：删源后绑定行应清空，实得 %d 行——本用例要验的孤儿形态没造出来", binds)
	}

	// 第二次启动：一次性标记已落，回填不得再跑。
	if err := s.ensureCredentials(); err != nil {
		t.Fatal(err)
	}
	cred, found, err := s.Credential(ctx, acct)
	if err != nil || !found {
		t.Fatalf("重读凭据：found=%v err=%v", found, err)
	}
	if cred.PassHash != "" {
		t.Fatalf("认证源删除后的孤儿账号 %s 在下次启动被重新写入本地口令 %q——"+
			"一次性标记没起作用，冒充通道原样保留", acct, cred.PassHash)
	}
}

// TestLegacyLocalUserStillBackfilledOnce 史前迁移库的本地用户仍要被补一次，且只补一次。
//
// 这是回填原本要解决的真问题（迁移后无人能登录），修复不能把它一起砍掉。
func TestLegacyLocalUserStillBackfilledOnce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// 模拟「这个库从没被新版二进制打开过」：openTestStore 已经跑过一次 OpenSQLite，
	// 标记早就落下了，不清掉的话下面造出来的行根本不是"史前行"，用例会验空。
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM settings WHERE k=?`, legacyPassHashMarker); err != nil {
		t.Fatal(err)
	}

	// 造一个"史前"本地行：有账号、无口令、无外部绑定。
	if err := s.insertUser(DirUser{
		ID: "u-legacy", Name: "史前用户", Account: "legacy.user", Org: "研发", OrgKey: "dev",
		Device: "—", IP: "—", Auth: "口令", LastLogin: "—", Status: "active", Risk: "none",
		Roles: []string{"研发"}, Role: "user", PassHash: "",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureCredentials(); err != nil {
		t.Fatal(err)
	}
	cred, found, err := s.Credential(ctx, "legacy.user")
	if err != nil || !found {
		t.Fatalf("重读凭据：found=%v err=%v", found, err)
	}
	if !auth.VerifyPassword(cred.PassHash, seedPassword) {
		t.Fatalf("史前本地用户必须被补一次 demo 口令（否则迁移后无人能登录），实得 %q", cred.PassHash)
	}

	// 再造一个：标记已落，这次不该再补——否则"重启即获得公开口令"的形态原样还在。
	if err := s.insertUser(DirUser{
		ID: "u-later", Name: "后来的行", Account: "later.user", Org: "研发", OrgKey: "dev",
		Device: "—", IP: "—", Auth: "口令", LastLogin: "—", Status: "active", Risk: "none",
		Roles: []string{"研发"}, Role: "user", PassHash: "",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureCredentials(); err != nil {
		t.Fatal(err)
	}
	later, _, _ := s.Credential(ctx, "later.user")
	if later.PassHash != "" {
		t.Fatalf("一次性标记落下之后新出现的空口令行不得再被回填（那等于"+
			"任何能造出该形态的路径都变成「重启即拿到公开口令」），实得 %q", later.PassHash)
	}
}

// TestLegacyDatabaseWithExistingExternalUsersNotPoisoned 已配置认证源的存量库升级时，
// 那唯一一次回填也不得打中外部账号。
//
// ★这是 NOT EXISTS 子句唯一承重的场景，也是**所有现役部署的真实形态**：库里既没有
// 一次性标记（老二进制没写过），又已经躺着一批外部目录账号。少了那条子句，升级后
// 第一次启动就会把公开口令发给全体外部用户——一次性标记挡不住它，因为那一次正是
// 允许跑的那一次。
func TestLegacyDatabaseWithExistingExternalUsersNotPoisoned(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	acct := bindExtUser(t, s, "src-legacy", "erin")

	// 模拟"老二进制建的库"：标记不存在，而外部账号已经绑好了。
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM settings WHERE k=?`, legacyPassHashMarker); err != nil {
		t.Fatal(err)
	}
	var markers int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM settings WHERE k=?`, legacyPassHashMarker).Scan(&markers); err != nil {
		t.Fatal(err)
	}
	if markers != 0 {
		t.Fatalf("前置条件不成立：标记没删掉（实得 %d 行），本用例会退化成验一次性标记而不是验 NOT EXISTS", markers)
	}

	if err := s.ensureCredentials(); err != nil {
		t.Fatalf("ensureCredentials：%v", err)
	}
	cred, found, err := s.Credential(ctx, acct)
	if err != nil || !found {
		t.Fatalf("重读凭据：found=%v err=%v", found, err)
	}
	if cred.PassHash != "" {
		t.Fatalf("存量库升级时那唯一一次回填打中了外部账号 %s（实得 %q）——"+
			"这正是升级那一刻把公开口令发给全体 LDAP/AD 用户的路径", acct, cred.PassHash)
	}
}
