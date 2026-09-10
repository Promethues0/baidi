package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/authpolicy"
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

// ── wave11 行动 8-③：外部目录账号的口令强度标记 ──
//
// 被修的坏形态：`users.pw_strength` 只有「自助改密」与「建号/重置口令」两个写值方，
// 而外部目录账号两条都走不到（BindExternalUser 写 pass_hash=''，pw_strength 停在
// 补列回填的 unknown 上、此后永不更新）。于是认证策略里那条「弱密码 → 要求二次认证」
// 对**全部**外部账号恒不命中，而策略页上它显示为「已启用」——PRD FR-AUTH-21 原文
// 要求这条规则判的正是第三方认证服务器用户的登录口令。
//
// 判据在「外部认证成功那一刻」才拿得到（明文由客户端提交、白帝拿它去 bind），
// 所以写值点只能在 finishExternalAuth 里。★只落强度标记，绝不落外部口令的任何形式。

// extStrengthEnv 起一台带真实 SQLite 的 Server + 一个总是认证成功的假口令源。
// 返回登录用的闭包：跑一次完整的 authenticateExternal（含准入闸、绑定、强度落库）。
func extStrengthEnv(t *testing.T, user string) (*Server, func(password string) store.Credential) {
	t.Helper()
	s, _, _ := newFailServer(t)
	ctx := context.Background()

	aw, _ := s.store.(store.AuthSourceStore)
	if aw == nil {
		t.Fatal("需要 SQLite 后端")
	}
	// admitPolicy 留空 = auto（存量语义），这条用例关心的不是准入闸。
	rec := store.AuthSourceRec{ID: "src-ad", Name: "总部 AD", Kind: "ad", Enabled: true, Config: `{"host":"dc01"}`}
	if _, err := aw.SaveAuthSource(ctx, rec); err != nil {
		t.Fatalf("存认证源失败：%v", err)
	}
	id := ident(user, user+"@ex.com")
	s.testPasswordAuth = func(store.AuthSourceRec) (authsrc.PasswordAuthenticator, error) {
		return fakePwAuth{id: id}, nil
	}
	return s, func(password string) store.Credential {
		t.Helper()
		ext, err := s.authenticateExternal(
			httptest.NewRequest(http.MethodPost, "/api/v1/portal/login", nil), user, password, "")
		if err != nil || !ext.Hit {
			t.Fatalf("外部登录应成功：hit=%v err=%v", ext.Hit, err)
		}
		// ★重读完整行而不是用 ext.Cred：UserBySubject / BindExternalUser 回的是窄 SELECT，
		//   里面根本没有 pw_strength——用它断言的话，修好没修好都读到空串。
		cred, ok, cerr := s.store.Credential(context.Background(), ext.Cred.Account)
		if cerr != nil || !ok {
			t.Fatalf("重读账号 %q 失败：ok=%v err=%v", ext.Cred.Account, ok, cerr)
		}
		return cred
	}
}

// TestExternalLoginRecordsPwStrength 外部口令认证成功即落强度标记，弱/强两向都验。
//
// 变异实跑：把 finishExternalAuth 末尾那行 s.noteExternalPwStrength 删掉 →
// 两个子用例都拿到 "unknown"（正是改造前的形态），本用例变红。
func TestExternalLoginRecordsPwStrength(t *testing.T) {
	t.Run("弱口令落 weak", func(t *testing.T) {
		_, login := extStrengthEnv(t, "weakguy")
		// "abc123" 命中内置弱口令表。
		if got := login("abc123").PwStrength; got != auth.PwWeak {
			t.Fatalf("外部弱口令应落 %q，得到 %q——「弱密码」规则对外部账号又恒不命中了",
				auth.PwWeak, got)
		}
	})
	t.Run("强口令落 strong", func(t *testing.T) {
		_, login := extStrengthEnv(t, "strongguy")
		if got := login("Tq7#vLm2wZx9").PwStrength; got != auth.PwStrong {
			t.Fatalf("外部强口令应落 %q，得到 %q", auth.PwStrong, got)
		}
	})
}

// TestExternalPwStrengthDrivesWeakPwdRule 落下的标记真能让「弱密码」规则命中。
//
// ★只断言库里那一列是不够的：这一列的存在意义就是喂给 authpolicy 的 WeakPwd 判据，
// 两者对不上（比如落成 "Weak"）时库里看着有值、规则照样永远不响。
func TestExternalPwStrengthDrivesWeakPwdRule(t *testing.T) {
	_, login := extStrengthEnv(t, "weakrule")
	cred := login("abc123")

	pol := store.AuthPolicy{
		ID: "p1", Name: "AD 默认策略", Directory: "ad", IsDefault: true, Enabled: true, Priority: 10,
		Enhance: store.EnhanceRule{WeakPwd: true},
	}
	d := authpolicy.Evaluate([]store.AuthPolicy{pol}, authpolicy.Input{
		Account: cred.Account, Directory: "ad", PwStrength: cred.PwStrength,
	})
	if !d.RequireMFA {
		t.Fatalf("弱口令的外部账号应被要求二次认证，得到 %+v（pw_strength=%q）", d, cred.PwStrength)
	}
}

// TestExternalPwStrengthNeverStoresPassword 强度标记之外，一个字节都不许落。
//
// ★这是本条改动的安全底线：外部账号 pass_hash 恒空是一道闸（认证源被停用后账号
// 不会退回成"某个本地口令也能登录"），而 guardLocalCredentialForAdmin 判「是不是
// 外部账号」用的正是 PassHash == ""——把外部口令的哈希填进去，那道守卫整个失效。
func TestExternalPwStrengthNeverStoresPassword(t *testing.T) {
	_, login := extStrengthEnv(t, "nohash")
	cred := login("Tq7#vLm2wZx9")
	if cred.PassHash != "" {
		t.Fatalf("外部账号的 pass_hash 必须恒空，得到 %q——外部口令绝不落库（明文或哈希都不行）", cred.PassHash)
	}
	// 反向再确认一次：那把外部口令不能当本地口令用。
	if auth.VerifyPassword(cred.PassHash, "Tq7#vLm2wZx9") {
		t.Fatal("外部口令变成了可用的本地口令——这正是 BindExternalUser 注释里那条闸要防的事")
	}
}

// TestExternalStrongPwKeepsWeakLocalMarker 双凭据账号上，强度标记只收紧不放宽。
//
// 场景是 guardLocalCredentialForAdmin 给出的那条补救路径走完之后的形态：管理员为一个
// 外部绑定账号重置过**本地**口令，于是它同时持有两把口令。此时用外部那把强口令把标记
// 刷成 strong，等于让一把仍然可用的弱本地口令从「弱密码」规则的视野里消失（fail-open），
// 而页面上完全看不出来。
//
// 变异实跑：把 SetExternalPwStrength 的 `? OR COALESCE(pass_hash,'')='' OR …` 那一整段
// WHERE 条件删掉 → 标记被刷成 strong，本用例变红。
func TestExternalStrongPwKeepsWeakLocalMarker(t *testing.T) {
	s, login := extStrengthEnv(t, "dualcred")
	ctx := context.Background()
	cred := login("abc123") // 先建号，顺带落一个 weak
	if cred.PwStrength != auth.PwWeak {
		t.Fatalf("前置条件不成立：应先落 weak，得到 %q", cred.PwStrength)
	}
	// 管理员给他重置一个**弱**本地口令（历史库里完全可能，口令闸是后加的）。
	hash, err := auth.HashPassword("baidi@123")
	if err != nil {
		t.Fatalf("造哈希失败：%v", err)
	}
	if err := s.writer.SetUserPassword(ctx, cred.ID, hash, true, auth.PwWeak); err != nil {
		t.Fatalf("重置本地口令失败：%v", err)
	}
	// 他这次用外部那把强口令登录。
	after := login("Tq7#vLm2wZx9")
	if after.PwStrength != auth.PwWeak {
		t.Fatalf("同时持有弱本地口令时不得把标记放宽成 %q——那把弱口令仍然能登录", after.PwStrength)
	}
	// 纯外部账号（pass_hash 恒空）则必须双向如实更新，否则用户在目录侧把口令改强之后
	// 白帝这边永远停在 weak 且无人能清。
	_, pure := extStrengthEnv(t, "pureext")
	if got := pure("abc123").PwStrength; got != auth.PwWeak {
		t.Fatalf("纯外部账号首次应落 weak，得到 %q", got)
	}
	if got := pure("Tq7#vLm2wZx9").PwStrength; got != auth.PwStrong {
		t.Fatalf("纯外部账号改强后应更新为 %q，得到 %q", auth.PwStrong, got)
	}
}
