package api

import (
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
)

// 口令复杂度必须在自助改密这一步强制——它是全流程唯一能强制它的时点。
//
// ★BAIDI_SEED_MUST_CHANGE 默认为 1，每一次标准部署的第一个动作就是管理员把公开的
// 种子口令 baidi@123 换掉。而此前这里只查 len>=8：超管口令可以被改成 `12345678`
// （命中内置弱口令表、被 PasswordWeakness 判 weak），接口回 200、页面提示「修改成功」，
// 没有任何一处告诉他这是弱口令。而那个 weak 标记的唯一后果，是当且仅当有一条开着
// weakPwd 的认证策略覆盖该账号时抬一次二次认证——种子里的本地默认策略并没有开它。
// 于是「弱口令」在标准部署里从头到尾没有任何执行方：判定器算得好好的、连中文原因
// 都备好了（PasswordWeakness 的第二个返回值），全仓零消费方。
func TestChangePasswordRejectsWeak(t *testing.T) {
	f := newIsoFixture(t)
	try := func(pw string) (int, map[string]any) {
		return doJSON(t, f.h, "POST", "/api/v1/auth/password", adminToken(),
			map[string]any{"old": "baidi@123", "new": pw})
	}
	weak := []struct{ pw, why string }{
		{"12345678", "命中常见弱口令表"},
		// ★预期原因跟随判定器的**判定顺序**（strength.go：弱口令表 → 含账号名 →
		//   长度 → 字符种类 → 连续重复）。顺序本身合理：先给最明确的那个原因。
		{"admin123", "命中常见弱口令表"},        // 它同时含账号名，但弱口令表先命中
		{"myadminpass", "口令中包含账号名"},     // 不在弱口令表里，才轮到账号名这条
		{"Aa1!aa", "长度不足 10 位"},
		{"aaaaaaaaaaaa", "字符种类不足"},        // 只有小写，字符种类先于连续重复命中
		{"abcdefghijk", "字符种类不足"},
	}
	for _, c := range weak {
		code, out := try(c.pw)
		if code != http.StatusBadRequest {
			t.Errorf("弱口令 %q 应被拒（%s），实得 %d: %v", c.pw, c.why, code, out)
			continue
		}
		// 拒绝理由要**原样带出判定器算出的那句中文**，否则用户只能反复试
		msg, _ := out["error"].(map[string]any)["message"].(string)
		if !strings.Contains(msg, c.why) {
			t.Errorf("拒绝 %q 时理由应含 %q，实得：%s", c.pw, c.why, msg)
		}
	}

	// 判据与落库用的 PasswordStrength 必须同源——不能出现「存进去判强、拦的时候判弱」
	for _, pw := range []string{"Tr0ub4dor&3xK", "correct horse battery staple"} {
		if weak, why := auth.PasswordWeakness("admin", pw); weak {
			t.Fatalf("用例前提不成立：%q 本应判强，实得弱（%s）", pw, why)
		}
		if s := auth.PasswordStrength("admin", pw); s != auth.PwStrong {
			t.Errorf("PasswordWeakness 与 PasswordStrength 判定不一致：%q → %s", pw, s)
		}
	}
}
