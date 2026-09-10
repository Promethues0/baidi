package store

import (
	"context"
	"testing"

	"baidi.dev/control/internal/auth"
)

// ── wave11 行动 8-③：SetExternalPwStrength 的三条 WHERE 各挡一种错法 ──

// pwStrengthOf 直接读库里那一列（不经 Credential 的 COALESCE，好区分"空"与"unknown"）。
func pwStrengthOf(t *testing.T, s *SQLiteStore, account string) string {
	t.Helper()
	var v string
	if err := s.db.QueryRow(
		`SELECT COALESCE(pw_strength,'') FROM users WHERE lower(trim(account))=?`, account).Scan(&v); err != nil {
		t.Fatalf("读 %s 的 pw_strength 失败：%v", account, err)
	}
	return v
}

// bindOne 建一个外部绑定账号，返回它的白帝账号名。
func bindOne(t *testing.T, s *SQLiteStore, srcID, user string) string {
	t.Helper()
	cred, err := s.BindExternalUser(context.Background(), srcID, ExternalIdentity{
		Subject: "CN=" + user + ",DC=ex,DC=com", Username: user, DisplayName: user,
	})
	if err != nil {
		t.Fatalf("绑定外部身份失败：%v", err)
	}
	return cred.Account
}

// TestSetExternalPwStrengthOnlyTouchesBoundAccounts 只允许改**有外部绑定**的行。
//
// 少了 EXISTS(auth_source_bindings) 那道守卫，一次传错账号名就会让某个纯本地账号的
// 强度标记被外部口令的判定结果覆盖——而本地那一列是自助改密/建号那一刻算出来的，
// 覆盖之后既无人察觉，「弱密码」规则对那个人也就按了另一把口令在判。
//
// 变异实跑：删掉那行 EXISTS 子句 → 种子本地账号 li.fang 的标记被改成 weak，本用例变红。
//
// ★写的方向必须是 weak（收紧）、且前置把该账号置成 strong：第一轮把用例写成
// 「置 weak 后比对是否没变」时**变异逃逸了**——种子口令 baidi@123 本来就判 weak，
// 断言等于「weak 还是 weak」，两种实现给出同一个答案。反过来写 strong 也逃逸：
// 那时最后一条 WHERE（本地口令仍标 weak 就不放宽）自己把更新挡住了，
// 挡住它的不是本用例要钉的那道守卫。
func TestSetExternalPwStrengthOnlyTouchesBoundAccounts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// li.fang 是种子本地账号，没有任何外部绑定。先置成 strong，让"被误改成 weak"看得出来。
	if _, err := s.db.Exec(`UPDATE users SET pw_strength=? WHERE account='li.fang'`, auth.PwStrong); err != nil {
		t.Fatalf("前置置位失败：%v", err)
	}
	if err := s.SetExternalPwStrength(ctx, "li.fang", auth.PwWeak); err != nil {
		t.Fatalf("SetExternalPwStrength: %v", err)
	}
	if got := pwStrengthOf(t, s, "li.fang"); got != auth.PwStrong {
		t.Fatalf("纯本地账号的强度标记不该被外部路径改动：strong → %q", got)
	}
}

// TestSetExternalPwStrengthMatchesAccountCaseInsensitively 账号匹配与 Credential 同口径。
//
// 大小写/空白不归一的话，一次登录会静默更新 0 行——没有任何人看 RowsAffected，
// 表现就是"改了半天，「弱密码」规则还是不命中"。
func TestSetExternalPwStrengthMatchesAccountCaseInsensitively(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	acct := bindOne(t, s, "src-ad", "casey")

	if err := s.SetExternalPwStrength(ctx, "  "+upperFirst(acct)+"  ", auth.PwWeak); err != nil {
		t.Fatalf("SetExternalPwStrength: %v", err)
	}
	if got := pwStrengthOf(t, s, acct); got != auth.PwWeak {
		t.Fatalf("大小写/空白应被归一后匹配上，得到 %q", got)
	}
}

// TestSetExternalPwStrengthTightensOnly 双凭据账号上只收紧不放宽；纯外部账号双向更新。
func TestSetExternalPwStrengthTightensOnly(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// ① 纯外部账号（pass_hash 恒空）：weak → strong 必须真的更新。
	pure := bindOne(t, s, "src-ad", "pure")
	if err := s.SetExternalPwStrength(ctx, pure, auth.PwWeak); err != nil {
		t.Fatalf("落 weak 失败：%v", err)
	}
	if err := s.SetExternalPwStrength(ctx, pure, auth.PwStrong); err != nil {
		t.Fatalf("落 strong 失败：%v", err)
	}
	if got := pwStrengthOf(t, s, pure); got != auth.PwStrong {
		t.Fatalf("纯外部账号应双向更新（否则用户在目录侧改强之后永远清不掉 weak），得到 %q", got)
	}

	// ② 同时持本地口令哈希的账号：weak 不许被 strong 覆盖。
	dual := bindOne(t, s, "src-ad", "dual")
	cred, ok, err := s.Credential(ctx, dual)
	if err != nil || !ok {
		t.Fatalf("读 %s 失败：ok=%v err=%v", dual, ok, err)
	}
	hash, herr := auth.HashPassword("baidi@123")
	if herr != nil {
		t.Fatalf("造哈希失败：%v", herr)
	}
	if err := s.SetUserPassword(ctx, cred.ID, hash, true, auth.PwWeak); err != nil {
		t.Fatalf("重置本地口令失败：%v", err)
	}
	if err := s.SetExternalPwStrength(ctx, dual, auth.PwStrong); err != nil {
		t.Fatalf("SetExternalPwStrength: %v", err)
	}
	if got := pwStrengthOf(t, s, dual); got != auth.PwWeak {
		t.Fatalf("弱本地口令仍然可用时不得把标记放宽，得到 %q", got)
	}
	// 而 weak 方向永远畅通（收紧不受任何条件限制）。
	if err := s.SetExternalPwStrength(ctx, dual, auth.PwWeak); err != nil {
		t.Fatalf("SetExternalPwStrength: %v", err)
	}
	if got := pwStrengthOf(t, s, dual); got != auth.PwWeak {
		t.Fatalf("收紧方向必须无条件生效，得到 %q", got)
	}
}

// TestSetExternalPwStrengthRejectsUnknown 只收判得出来的两态。
//
// 放 unknown 进来就等于允许"认证成功了却把标记擦回未知"——一次静默的降级，
// 而 unknown 恰好是「弱密码」规则不命中的那个值。
func TestSetExternalPwStrengthRejectsUnknown(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	acct := bindOne(t, s, "src-ad", "unk")
	if err := s.SetExternalPwStrength(ctx, acct, auth.PwWeak); err != nil {
		t.Fatalf("落 weak 失败：%v", err)
	}
	for _, bad := range []string{auth.PwUnknown, "", "Weak", "STRONG"} {
		if err := s.SetExternalPwStrength(ctx, acct, bad); err == nil {
			t.Fatalf("强度标记 %q 应被拒收", bad)
		}
	}
	if got := pwStrengthOf(t, s, acct); got != auth.PwWeak {
		t.Fatalf("被拒的调用不该改动任何东西，得到 %q", got)
	}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 32
	}
	return string(b)
}
