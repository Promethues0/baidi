package store

import (
	"context"
	"database/sql"
	"testing"

	"baidi.dev/control/internal/auth"
)

// 策略往返：新增的适用范围、可信网段、工作时段都要能原样存取
// （少存一个字段的症状是"界面上配了、判定时不生效"，与本轮要消灭的形态同类）。
func TestSaveAuthPolicyRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	in := AuthPolicy{
		Name: "研发 · 加严", Directory: "local", Priority: 7, Enabled: true,
		Secondary: []string{"totp"},
		ScopeOrgs: []string{"dev"}, ScopeGroups: []string{"g-oncall"},
		Exempt: ExemptRule{TrustedNetwork: true, Networks: []string{"10.8.0.0/16"}, TrustedDevice: true},
		Enhance: EnhanceRule{
			Always: true, WeakPwd: true, OffHours: true,
			WorkStart: "08:30", WorkEnd: "20:00", WorkDays: []int{1, 2, 3, 4, 5, 6},
		},
	}
	saved, err := s.SaveAuthPolicy(ctx, in)
	if err != nil {
		t.Fatalf("SaveAuthPolicy: %v", err)
	}
	pols, err := s.AuthPolicies(ctx)
	if err != nil {
		t.Fatalf("AuthPolicies: %v", err)
	}
	var got AuthPolicy
	for _, p := range pols {
		if p.ID == saved.ID {
			got = p
		}
	}
	if got.ID == "" {
		t.Fatal("存进去的策略没读回来")
	}
	if len(got.ScopeOrgs) != 1 || got.ScopeOrgs[0] != "dev" ||
		len(got.ScopeGroups) != 1 || got.ScopeGroups[0] != "g-oncall" {
		t.Errorf("适用范围没存住: %+v", got)
	}
	if len(got.Exempt.Networks) != 1 || got.Exempt.Networks[0] != "10.8.0.0/16" {
		t.Errorf("可信网段没存住: %+v", got.Exempt)
	}
	if got.Enhance.WorkStart != "08:30" || got.Enhance.WorkEnd != "20:00" || len(got.Enhance.WorkDays) != 6 {
		t.Errorf("工作时段没存住: %+v", got.Enhance)
	}
	if !got.Enhance.Always || !got.Enhance.WeakPwd || !got.Enhance.OffHours || !got.Exempt.TrustedDevice {
		t.Errorf("开关没存住: %+v / %+v", got.Enhance, got.Exempt)
	}
}

// 补列回填：既有库升级后 scope_orgs/scope_groups 必须是 '[]' 而不是 NULL，
// 且**库里已经为 true 的两个冻结开关要被清掉**——否则界面上会永久留着
// 「打开了但永远不会生效」的勾，正是本轮要消灭的形态。
func TestBackfillAuthPolicyScopeOnLegacyDB(t *testing.T) {
	s := openTestStore(t)

	// 造"旧库"：两列打回 NULL，并把冻结开关塞成 true（旧版本允许这么存）。
	if _, err := s.db.Exec(`UPDATE auth_policies SET scope_orgs=NULL, scope_groups=NULL,
	  enhance=json_set(enhance,'$.geoAnomaly',json('true')),
	  exempt=json_set(exempt,'$.winDomain',json('true'))`); err != nil {
		t.Fatalf("造旧数据: %v", err)
	}
	var dirty int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth_policies
	  WHERE scope_orgs IS NULL OR json_extract(enhance,'$.geoAnomaly')=1`).Scan(&dirty); err != nil {
		t.Fatalf("count: %v", err)
	}
	if dirty == 0 {
		t.Fatal("测试前置失败：没造出旧数据")
	}

	if err := s.backfillAuthPolicyScope(); err != nil {
		t.Fatalf("backfillAuthPolicyScope: %v", err)
	}
	pols, err := s.AuthPolicies(context.Background())
	if err != nil {
		t.Fatalf("AuthPolicies: %v", err)
	}
	for _, p := range pols {
		if p.ScopeOrgs == nil || p.ScopeGroups == nil {
			t.Errorf("%s 的适用范围回填后仍为 nil", p.ID)
		}
		if p.Enhance.GeoAnomaly || p.Exempt.WinDomain {
			t.Errorf("%s 的冻结开关没被清掉：判不了的规则不该留在库里显示为已启用", p.ID)
		}
		// 回填不该顺手动掉别的字段。哨兵换成 PC.Secondary——原来用的是 PC.Primary，
		// 而那个字段已随 wave8 行动 13-② 摘除（它在本策略模型里是同义反复，
		// 且零消费方，见 store/authpolicy.go 顶部注释）。
		if len(p.Secondary) == 0 {
			t.Errorf("%s 的二次认证方式被回填弄丢了", p.ID)
		}
	}
}

// 口令强度补列：既有行只能回填成 unknown。
//
// ★这条是「补列必须配回填」里语义最要紧的一次：库里只有 bcrypt 哈希，明文不可得。
// 回填 strong → 「弱密码要求二次认证」对全部存量账号静默失效；回填 weak → 全体存量
// 账号无端被抬到二次认证。unknown 如实表达"判不了"，且不命中弱密码规则。
func TestBackfillPwStrengthOnLegacyDB(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.db.Exec(`UPDATE users SET pw_strength=NULL`); err != nil {
		t.Fatalf("造旧数据: %v", err)
	}
	if err := s.backfillPwStrength(); err != nil {
		t.Fatalf("backfillPwStrength: %v", err)
	}
	var nulls int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE pw_strength IS NULL OR pw_strength=''`).Scan(&nulls); err != nil {
		t.Fatalf("count: %v", err)
	}
	if nulls != 0 {
		t.Fatalf("回填后仍有 %d 行为空", nulls)
	}
	cred, ok, err := s.Credential(ctx, "li.fang")
	if err != nil || !ok {
		t.Fatalf("Credential: %v %v", err, ok)
	}
	if cred.PwStrength != auth.PwUnknown {
		t.Fatalf("存量行只能是 unknown，实得 %q", cred.PwStrength)
	}
}

// 种子账号的口令强度**如实判定**：baidi@123 就是弱口令。
// 谎报成 strong 会让「弱密码」规则从首启起就是摆设。
func TestSeedUsersCarryHonestPwStrength(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, acct := range []string{"admin", "li.fang"} {
		cred, ok, err := s.Credential(ctx, acct)
		if err != nil || !ok {
			t.Fatalf("Credential(%s): %v %v", acct, err, ok)
		}
		if cred.PwStrength != auth.PwWeak {
			t.Errorf("种子口令 baidi@123 应判弱，%s 实得 %q", acct, cred.PwStrength)
		}
	}
}

// 改密即更新强度标记：登录链路消费的就是这一刻的结论。
func TestSetUserPasswordUpdatesStrength(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	cred, _, _ := s.Credential(ctx, "li.fang")
	hash, _ := auth.HashPassword("Kx9#mqrtvz")
	if err := s.SetUserPassword(ctx, cred.ID, hash, false, auth.PasswordStrength("li.fang", "Kx9#mqrtvz")); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	after, _, _ := s.Credential(ctx, "li.fang")
	if after.PwStrength != auth.PwStrong {
		t.Fatalf("改成强口令后标记应为 strong，实得 %q", after.PwStrength)
	}
	// 传空强度 = 调用方没判过 → 落 unknown，不许假装是强口令
	if err := s.SetUserPassword(ctx, cred.ID, hash, false, ""); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if after, _, _ := s.Credential(ctx, "li.fang"); after.PwStrength != auth.PwUnknown {
		t.Fatalf("未判定的强度应落 unknown，实得 %q", after.PwStrength)
	}
}

// one_click 列已冻结：读写路径都不再碰它，但旧库里的值不该影响任何行为。
func TestOneClickColumnFrozen(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec(`UPDATE auth_policies SET one_click=1`); err != nil {
		t.Fatalf("写冻结列: %v", err)
	}
	if _, err := s.AuthPolicies(context.Background()); err != nil {
		t.Fatalf("读策略不该受冻结列影响: %v", err)
	}
	var v sql.NullInt64
	if err := s.db.QueryRow(`SELECT one_click FROM auth_policies LIMIT 1`).Scan(&v); err != nil {
		t.Fatalf("列应仍在（旧库可直接启动）: %v", err)
	}
}

// TestLegacyPcMobileColumnsMerge 旧库里分别配在 pc / mobile 两列上的方式必须合并读出。
//
// ★这条钉的是"合并"本身。只读 pc 列的话，一条历史策略里**只配在移动端**的
// 二次认证方式会在升级那一刻静默消失——策略还在、开关不见了，而它正是
// AuthPolicy.Secondary 的唯一执行语义（不接受 legacy 演示验证码回落）的开关。
func TestLegacyPcMobileColumnsMerge(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO auth_policies
(id,name,directory,is_default,scope,priority,enabled,pc,mobile,exempt,enhance,scope_orgs,scope_groups,authz_apps,updated_at)
VALUES('ap-legacy','历史策略','local',0,'',50,1,?,?,'{}','{}','[]','[]','','')`,
		`{"primary":"local","secondary":[]}`,
		`{"primary":"local","secondary":["totp"]}`); err != nil {
		t.Fatalf("插历史行: %v", err)
	}
	pols, err := s.AuthPolicies(ctx)
	if err != nil {
		t.Fatalf("读策略: %v", err)
	}
	for _, p := range pols {
		if p.ID != "ap-legacy" {
			continue
		}
		if len(p.Secondary) != 1 || p.Secondary[0] != "totp" {
			t.Fatalf("只配在 mobile 列上的方式必须合并读出，得到 %v", p.Secondary)
		}
		return
	}
	t.Fatal("找不到历史策略行")
}
