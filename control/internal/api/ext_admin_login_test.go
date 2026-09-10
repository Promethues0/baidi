package api

// 外部认证换会话闸（externalSessionCredential）+ 改派角色守卫的 fail-closed。
//
// ★背景：guardLocalCredentialForAdmin 的 400 文案给出的补救路径「先为他重置一个本地口令，
// 再来提权」走完之后，账号同时持有外部绑定 + 本地口令 + role=admin。此前门户口令路径与
// OIDC 两处签发都原样 Sign(Role: cred.Role)——凭 RADIUS/LDAP 口令或走一遍 IdP 就是一张
// role=admin 的完整会话，管理台「只验本地口令」的收敛被整个绕开。另外 ext.Cred 来自
// UserBySubject 的窄 SELECT，没有 must_change_pw，首登强制改密对外部路径形同虚设。
//
// 三条路（门户口令 / OIDC 回调 / OIDC 交接票据换会话）必须过同一道闸，本文件逐条钉住；
// 每条用例都做过变异（去掉闸里的 admin 判定 → 红；admins.go 改回 err == nil && found → 红）。

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/totp"
	"baidi.dev/control/internal/webauthnx"
)

// promoteViaRemedyPath 照守卫文案走补救路径：重置本地口令（置首登改密）→ 提升为管理员。
func promoteViaRemedyPath(t *testing.T, h http.Handler, account, roleKey string) {
	t.Helper()
	id := idOf(t, h, account)
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+id+"/password", adminToken(),
		map[string]any{"password": "Kx7!mQrTw9Zp"}); code != http.StatusOK {
		t.Fatalf("重置本地口令 http %d: %v", code, out)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/admins", adminToken(),
		map[string]any{"account": account, "roleKey": roleKey}); code != http.StatusOK {
		t.Fatalf("有本地口令后提权应 200，got %d %v", code, out)
	}
}

// assertAdminExtDenyAudited 闸拒绝时必须落一条 category=auth / verdict=deny 的审计，且点名「本地口令」。
func assertAdminExtDenyAudited(t *testing.T, h http.Handler, account string) {
	t.Helper()
	code, aout := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读审计 %d", code)
	}
	for _, raw := range aout["logs"].([]any) {
		e := raw.(map[string]any)
		if e["user"] == account && e["category"] == "auth" && e["verdict"] == "deny" &&
			strings.Contains(str(e["event"]), "管理员只接受本地口令") {
			return
		}
	}
	t.Errorf("闸拒绝管理员经外部源换会话时应落 auth/deny 审计，未找到")
}

// TestExtBoundAdminCannotLoginViaExternalSource 门户口令路径：外部绑定账号拿到本地口令并被
// 提权后，凭 RADIUS 口令登门户不得换到任何令牌；不计爆破锁定；本地口令路径不受影响。
func TestExtBoundAdminCannotLoginViaExternalSource(t *testing.T) {
	s, h, _ := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "s3cret", nil)

	if out := portalLoginRaw(t, h, "zhou", "pw"); out["ok"] != true {
		t.Fatalf("首登应成功：%v", out)
	}
	promoteViaRemedyPath(t, h, "zhou", "security")

	// ★凭 RADIUS 口令登门户：必须被拒，且拿不到任何令牌（完整的、受限的都不行）
	out := portalLoginRaw(t, h, "zhou", "pw")
	if out["ok"] == true || out["token"] != nil {
		t.Fatalf("管理员账号凭外部源口令不得换到会话令牌：%v", out)
	}
	reason, _ := out["reason"].(string)
	if !strings.Contains(reason, "管理员") || !strings.Contains(reason, "本地口令") {
		t.Errorf("拒绝文案要说清原因与下一步（改用本地口令），got %q", reason)
	}
	if n := len(s.lockout.Active()); n != 0 {
		t.Errorf("外部口令是对的，不该计入爆破锁定，却有 %d 条", n)
	}
	assertAdminExtDenyAudited(t, h, "zhou")

	// 对照：本地口令走本地哈希路径，不该撞上管理员闸（种子策略「外包人员 · 一律二次认证」
	// 可能把它抬成 needEnroll——那是策略在起作用，与本闸无关；只断言不是本闸拒的）。
	o2 := portalLoginRaw(t, h, "zhou", "Kx7!mQrTw9Zp")
	if r2, _ := o2["reason"].(string); strings.Contains(r2, "管理员只接受本地口令") {
		t.Fatalf("本地口令路径不该被管理员闸拒：%v", o2)
	}
	if o2["ok"] != true && o2["needEnroll"] != true {
		t.Fatalf("本地口令登录应通过口令校验（受限改密或策略抬升二次认证）：%v", o2)
	}
}

// TestExtLoginSeesMustChangePw 门户口令路径：普通外部用户被重置本地口令后，凭外部口令登录
// 必须看到 users 行上的 must_change_pw（受限改密令牌），而不是窄 SELECT 里恒 false 的那份。
func TestExtLoginSeesMustChangePw(t *testing.T) {
	_, h, _ := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "s3cret", nil)
	if out := portalLoginRaw(t, h, "zhou", "pw"); out["ok"] != true || out["mustChangePassword"] == true {
		t.Fatalf("无本地口令的外部账号首登应得完整会话：%v", out)
	}
	id := idOf(t, h, "zhou")
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+id+"/password", adminToken(),
		map[string]any{"password": "Kx7!mQrTw9Zp"}); code != http.StatusOK {
		t.Fatalf("重置本地口令 http %d: %v", code, out)
	}
	out := portalLoginRaw(t, h, "zhou", "pw")
	if out["ok"] != true {
		t.Fatalf("普通外部用户凭外部口令仍应认证通过：%v", out)
	}
	if out["mustChangePassword"] != true {
		t.Fatalf("外部登录路径看不到 must_change_pw：%v", out)
	}
	// 受限令牌调业务端点必须 403（它只够改口令）。
	tok, _ := out["token"].(string)
	if code, _ := doJSON(t, h, "GET", "/api/v1/portal/apps", tok, nil); code != http.StatusForbidden {
		t.Errorf("首登改密受限令牌调业务端点应 403，实得 %d", code)
	}
}

// oidcCallbackLocation 走一遍 authorize → callback，返回 302 的 Location 解析结果。
func oidcCallbackLocation(t *testing.T, h http.Handler, stub *stubOIDC) *url.URL {
	t.Helper()
	getRaw(t, h, "/api/v1/auth/oidc/oidc-1/authorize")
	rec := getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?state="+url.QueryEscape(stub.state)+"&code=good-code")
	if rec.Code != http.StatusFound {
		t.Fatalf("callback 应 302，实得 %d %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location 解析失败：%v", err)
	}
	return u
}

// oidcGrant 走完 OIDC 回调并要求拿到交接票据。
func oidcGrant(t *testing.T, h http.Handler, stub *stubOIDC) string {
	t.Helper()
	u := oidcCallbackLocation(t, h, stub)
	g := u.Query().Get("oidcGrant")
	if g == "" {
		t.Fatalf("应带交接票据，实得 %s", u.String())
	}
	return g
}

// TestOIDCBoundAdminRejectedAtCallback OIDC 回调：已被提权的外部绑定账号走一遍 IdP，
// 回调阶段就要拒（连交接票据都不签），文案与门户口令路径同款。
func TestOIDCBoundAdminRejectedAtCallback(t *testing.T) {
	h, _, stub := oidcFixture(t)
	// 首登建号 + 换到 user 会话（对照：此刻他是普通外部用户，一切正常）。
	grant := oidcGrant(t, h, stub)
	if code, out := doJSON(t, h, "POST", "/api/v1/auth/oidc/session", "", map[string]any{"ticket": grant}); code != http.StatusOK || out["role"] != "user" {
		t.Fatalf("首登交接应成功且 role=user：%d %v", code, out)
	}
	promoteViaRemedyPath(t, h, "ext.oidc.user", "security")

	u := oidcCallbackLocation(t, h, stub)
	if g := u.Query().Get("oidcGrant"); g != "" {
		t.Fatalf("管理员账号经 OIDC 认证不得拿到交接票据，却拿到了：%s", u.String())
	}
	msg := u.Query().Get("oidcError")
	if !strings.Contains(msg, "管理员") || !strings.Contains(msg, "本地口令") {
		t.Errorf("拒绝文案要说清原因与下一步（改用本地口令），got %q", msg)
	}
	assertAdminExtDenyAudited(t, h, "ext.oidc.user")
}

// TestOIDCSessionExchangeRechecksAdminRole OIDC 交接票据换会话：票据签出时是 user，
// 60s 窗口内被提权——换会话那一刻必须按**重读的行**再判一次，票据里的角色快照不算数。
func TestOIDCSessionExchangeRechecksAdminRole(t *testing.T) {
	h, _, stub := oidcFixture(t)
	// 先让账号存在（首登），再拿一张尚未兑换的交接票据。
	oidcGrant(t, h, stub)
	grant := oidcGrant(t, h, stub)
	promoteViaRemedyPath(t, h, "ext.oidc.user", "security")

	code, out := doJSON(t, h, "POST", "/api/v1/auth/oidc/session", "", map[string]any{"ticket": grant})
	if code != http.StatusForbidden {
		t.Fatalf("提权后兑换交接票据应 403，实得 %d %v", code, out)
	}
	if out["token"] != nil {
		t.Fatalf("不得签出任何令牌：%v", out)
	}
	msg := errMsgOf(out)
	if !strings.Contains(msg, "管理员") || !strings.Contains(msg, "本地口令") {
		t.Errorf("拒绝文案要说清原因与下一步，got %q", msg)
	}
	assertAdminExtDenyAudited(t, h, "ext.oidc.user")
}

// TestOIDCSessionHonorsMustChangePw OIDC 交接换会话：普通外部用户被重置过本地口令后，
// 走一遍 IdP 拿到的必须是受限改密令牌（与门户口令路径同一处理），不是完整会话。
func TestOIDCSessionHonorsMustChangePw(t *testing.T) {
	h, _, stub := oidcFixture(t)
	oidcGrant(t, h, stub) // 首登建号
	id := idOf(t, h, "ext.oidc.user")
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+id+"/password", adminToken(),
		map[string]any{"password": "Kx7!mQrTw9Zp"}); code != http.StatusOK {
		t.Fatalf("重置本地口令 http %d: %v", code, out)
	}
	grant := oidcGrant(t, h, stub)
	code, out := doJSON(t, h, "POST", "/api/v1/auth/oidc/session", "", map[string]any{"ticket": grant})
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("普通外部用户交接仍应成功：%d %v", code, out)
	}
	if out["mustChangePassword"] != true {
		t.Fatalf("OIDC 路径看不到 must_change_pw，直接签了完整会话：%v", out)
	}
	tok, _ := out["token"].(string)
	if code, _ := doJSON(t, h, "GET", "/api/v1/portal/apps", tok, nil); code != http.StatusForbidden {
		t.Errorf("首登改密受限令牌调业务端点应 403，实得 %d", code)
	}
}

// usersUnreadableStore 让「用户目录」这一次读失败，其余读原样透传（管理员角色照读得到，
// 所以 requirePerm 能过——考的是守卫，不是权限闸）。
type usersUnreadableStore struct {
	store.Store
}

func (usersUnreadableStore) Users(context.Context) (store.UserDirBundle, error) {
	return store.UserDirBundle{}, errors.New("database is locked")
}

// TestSetAdminRoleFailsClosedWhenDirectoryUnreadable 改派角色：目录读失败必须 500 且**不提权**。
// 此前 `err == nil && found { guard }` 在读失败时跳过守卫直接 SetAdminRole——一次库抖动
// 就让「外部目录账号不得提升为管理员」消失。不存在的账号回 404。
func TestSetAdminRoleFailsClosedWhenDirectoryUnreadable(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "flaky-dir.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(usersUnreadableStore{Store: st}, st, testKeys, "test", t.TempDir(), nil, nil, true)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())
	ctx := context.Background()

	code, out := doJSON(t, h, "PUT", "/api/v1/admins/li.fang/role", adminToken(), map[string]any{"roleKey": "audit"})
	if code != http.StatusInternalServerError {
		t.Fatalf("目录读失败时改派角色应 500（fail-closed），实得 %d %v", code, out)
	}
	if _, found, err := st.AdminRoleFor(ctx, "li.fang"); err != nil || found {
		t.Fatalf("目录读失败时不得提权：found=%v err=%v", found, err)
	}

	// 目录读得到、账号不存在 → 404（不是静默 200，也不是 500）。
	h2 := newTestServer(t)
	if code, out := doJSON(t, h2, "PUT", "/api/v1/admins/nobody.here/role", adminToken(),
		map[string]any{"roleKey": "audit"}); code != http.StatusNotFound {
		t.Fatalf("不存在的账号改派角色应 404，实得 %d %v", code, out)
	}
}

// ── 二次认证与闸的先后顺序（wave10 复审发现 1）────────────────────────────────
//
// ★上一轮复审的探针实证：把 externalSessionCredential 整体挪到「签 60s 交接票据」
// 之前（即 secondFactor **之后**），`go test ./internal/api/` 仍然全绿——因为原有
// 三条用例的账号都没注册二次因子，secondFactor 直接 done=false，闸放前放后结果相同。
// 而那样一挪，**已注册 TOTP 的外部绑定管理员**走一遍 IdP 就能拿到 oidcTotp 票据，
// 再 POST /api/v1/auth/totp 换到 role=admin 的 8h 完整会话令牌：handleTotpLogin 是
// 自己按 store.Credential 签令牌的，它不认识这道闸。
//
// 下面两条把那个探针固化：判据是**回调/口令那一回合就没有票据流出**。

// resetLocalPw 管理员为某账号重置本地口令（顺带置上 must_change_pw）。
func resetLocalPw(t *testing.T, h http.Handler, account, pw string) {
	t.Helper()
	id := idOf(t, h, account)
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+id+"/password", adminToken(),
		map[string]any{"password": pw}); code != http.StatusOK {
		t.Fatalf("重置本地口令 http %d: %v", code, out)
	}
}

// enrollTotp 给持 tok 的账号注册并确认 TOTP，返回密钥原文。
//
// ★确认码取 **now-1 步**：ConsumeTotpCounter 是单调递增的（同一步长的码只能成功一次，
// 更早的步长也不接受），把确认消费在更早那一步上，后面的登录回合才有可用的步长。
// 反过来先用 now 确认的话，紧接着的登录只能等下一个 30s 窗口——一条会卡半分钟的用例
// 等于一条会被人加 t.Skip 的用例。
func enrollTotp(t *testing.T, h http.Handler, tok string) string {
	t.Helper()
	code, enr := doJSON(t, h, "POST", "/api/v1/totp/enroll", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("totp enroll http %d: %v", code, enr)
	}
	sec, _ := enr["secret"].(string)
	if sec == "" {
		t.Fatalf("enroll 应回显密钥一次：%v", enr)
	}
	cc, err := totp.Code(sec, time.Now().Add(-totp.Period*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/totp/confirm", tok, map[string]any{"code": cc}); code != http.StatusOK {
		t.Fatalf("totp confirm http %d: %v", code, out)
	}
	return sec
}

// totpSecondRound 走完 TOTP 登录第二回合（ticket + 当前步长的码）。
func totpSecondRound(t *testing.T, h http.Handler, ticket, sec string) map[string]any {
	t.Helper()
	cc, err := totp.Code(sec, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	code, out := doJSON(t, h, "POST", "/api/v1/auth/totp", "", map[string]any{"ticket": ticket, "code": cc})
	if code != http.StatusOK {
		t.Fatalf("totp 第二回合 http %d: %v", code, out)
	}
	return out
}

// promoteWithTotpEnrolled 把一个已注册 TOTP 的外部绑定账号走完补救路径提成管理员：
// 重置本地口令 → 本地口令登录（过 TOTP 第二回合）→ 清掉 must_change_pw → POST /admins。
//
// ★must_change_pw 必须先清掉，否则**变异跑**里第二回合拿到的会是受限改密令牌而不是
// 完整会话，用例就没法断言"闸一挪就能换到 role=admin 的 8h 令牌"这件事。
func promoteWithTotpEnrolled(t *testing.T, h http.Handler, account, sec, roleKey string) {
	t.Helper()
	const localPw, newPw = "Kx7!mQrTw9Zp", "Zx9#tLmQ7vRb"
	resetLocalPw(t, h, account, localPw)
	out := portalLoginRaw(t, h, account, localPw)
	if out["needTotp"] != true {
		t.Fatalf("已确认 TOTP 的账号本地登录应被要求验证码：%v", out)
	}
	tk, _ := out["ticket"].(string)
	out = totpSecondRound(t, h, tk, sec)
	if out["mustChangePassword"] != true {
		t.Fatalf("刚被重置口令，第二回合应回受限改密令牌：%v", out)
	}
	pwTok, _ := out["token"].(string)
	if code, o := doJSON(t, h, "POST", "/api/v1/auth/password", pwTok,
		map[string]any{"old": localPw, "new": newPw}); code != http.StatusOK || o["ok"] != true {
		t.Fatalf("受限令牌改密应成功：%d %v", code, o)
	}
	if code, o := doJSON(t, h, "POST", "/api/v1/admins", adminToken(),
		map[string]any{"account": account, "roleKey": roleKey, "password": testStrongPw}); code != http.StatusOK {
		t.Fatalf("有本地口令后提权应 200，got %d %v", code, o)
	}
}

// TestOIDCAdminWithTotpDeniedBeforeSecondFactor 已注册 TOTP 的外部绑定管理员走一遍 IdP：
// 必须在**回调阶段**就被拒——连 oidcTotp 票据都不许流出，更谈不上拿它去换会话。
//
// 变异（本轨核心交付）：把 oidc_login.go 里那段 externalSessionCredential 挪到
// secondFactor 之后（签交接票据那一行前面），本用例当场红：Location 会带上 oidcTotp。
func TestOIDCAdminWithTotpDeniedBeforeSecondFactor(t *testing.T) {
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	h, _, stub := oidcFixture(t)

	// 首登建号并换到 user 会话（此刻他还只是个普通外部用户）。
	grant := oidcGrant(t, h, stub)
	code, out := doJSON(t, h, "POST", "/api/v1/auth/oidc/session", "", map[string]any{"ticket": grant})
	if code != http.StatusOK || out["role"] != "user" {
		t.Fatalf("首登交接应成功且 role=user：%d %v", code, out)
	}
	userTok, _ := out["token"].(string)
	sec := enrollTotp(t, h, userTok)
	promoteWithTotpEnrolled(t, h, "ext.oidc.user", sec, "security")

	u := oidcCallbackLocation(t, h, stub)
	q := u.Query()
	for _, k := range []string{"oidcGrant", "oidcTotp", "oidcTicket"} {
		if v := q.Get(k); v != "" {
			t.Fatalf("管理员经 OIDC 认证不得拿到任何票据，却拿到了 %s=%s（%s）", k, v, u.String())
		}
	}
	msg := q.Get("oidcError")
	if !strings.Contains(msg, "管理员") || !strings.Contains(msg, "本地口令") {
		t.Errorf("拒绝文案要说清原因与下一步（改用本地口令），got %q", msg)
	}
	assertAdminExtDenyAudited(t, h, "ext.oidc.user")

	// 没有票据可用，/auth/totp 这条路本身也换不到任何令牌（空票据 = 401，不泄露账号状态）。
	if code, out := doJSON(t, h, "POST", "/api/v1/auth/totp", "",
		map[string]any{"ticket": "", "code": "000000"}); code != http.StatusUnauthorized || out["token"] != nil {
		t.Fatalf("无票据不得换到令牌：%d %v", code, out)
	}
}

// TestExtPasswordAdminWithTotpDeniedBeforeSecondFactor 门户口令路径（RADIUS）同构：
// 已注册 TOTP 的外部绑定管理员用**外部口令**登门户，必须在闸那里就拒——
// 拿不到 mfaTicket，needTotp 也不许出现。
func TestExtPasswordAdminWithTotpDeniedBeforeSecondFactor(t *testing.T) {
	s, h, _ := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "s3cret", nil)

	out := portalLoginRaw(t, h, "zhou", "pw") // 首登建号
	if out["ok"] != true {
		t.Fatalf("首登应成功：%v", out)
	}
	userTok, _ := out["token"].(string)
	sec := enrollTotp(t, h, userTok)
	promoteWithTotpEnrolled(t, h, "zhou", sec, "security")

	out = portalLoginRaw(t, h, "zhou", "pw")
	if out["ok"] == true || out["token"] != nil || out["ticket"] != nil || out["needTotp"] == true {
		t.Fatalf("管理员凭外部源口令不得拿到令牌或二次认证票据：%v", out)
	}
	reason, _ := out["reason"].(string)
	if !strings.Contains(reason, "管理员") || !strings.Contains(reason, "本地口令") {
		t.Errorf("拒绝文案要说清原因与下一步，got %q", reason)
	}
	if n := len(s.lockout.Active()); n != 0 {
		t.Errorf("外部口令是对的，不该计入爆破锁定，却有 %d 条", n)
	}
	assertAdminExtDenyAudited(t, h, "zhou")
}

// ── 闸排在 BindExternalUser 之后（wave10 复审发现 2）──────────────────────────

// TestExtAdminProfileNotRewrittenOnDeny 被拒的那次外部认证，**一个字段都不许改**。
//
// ★改造前：闸只拦会话，而它排在 BindExternalUser 之后——refreshExternalProfile 已经按
// IdP 的应答把这名管理员的显示名/邮箱写掉、并按应答增删了他的外部组归属。控制 IdP/AD
// 的人由此能把某管理员移出一个「一律二次认证」的用户组，等于替他的**本地**登录降了一档
// 策略要求；「认证被拒」不等于"这次登录什么都没改动"。
//
// 变异：删掉 oidc_login.go 里 BindExternalUser 之前那段 `bound && cur.Role == "admin"`，
// 本用例当场红（name/email/groups 三项全被外部目录改写）。
func TestExtAdminProfileNotRewrittenOnDeny(t *testing.T) {
	h, _, stub := oidcFixture(t)
	oidcGrant(t, h, stub) // 首登建号
	promoteViaRemedyPath(t, h, "ext.oidc.user", "security")

	before := dirUserOf(t, h, "ext.oidc.user")

	// IdP 这一侧改口：换个显示名、塞个邮箱、再塞一个外部组。
	stub.identity.DisplayName = "被外部目录改写的名字"
	stub.identity.Email = "attacker@evil.example"
	stub.identity.Groups = []string{"everyone"}

	u := oidcCallbackLocation(t, h, stub)
	if g := u.Query().Get("oidcGrant"); g != "" {
		t.Fatalf("管理员账号不得拿到交接票据：%s", u.String())
	}

	after := dirUserOf(t, h, "ext.oidc.user")
	if after["name"] != before["name"] {
		t.Errorf("被拒的外部登录改写了管理员显示名：%v → %v", before["name"], after["name"])
	}
	if after["email"] != before["email"] {
		t.Errorf("被拒的外部登录改写了管理员邮箱：%v → %v", before["email"], after["email"])
	}
	if g1, g2 := groupsOf(before), groupsOf(after); g1 != g2 {
		t.Errorf("被拒的外部登录改写了管理员的用户组归属：%q → %q", g1, g2)
	}
}

// dirUserOf 取目录里某账号那一行（原样的 JSON map）。
func dirUserOf(t *testing.T, h http.Handler, account string) map[string]any {
	t.Helper()
	_, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	for _, raw := range out["users"].([]any) {
		u := raw.(map[string]any)
		if u["account"] == account {
			return u
		}
	}
	t.Fatalf("目录里没有 %s", account)
	return nil
}

// groupsOf 把用户组归属压成一个可比较的字符串（顺序由后端固定，直接拼即可）。
func groupsOf(u map[string]any) string {
	gs, _ := u["groups"].([]any)
	parts := make([]string, 0, len(gs))
	for _, g := range gs {
		parts = append(parts, str(g))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// ── 首登强制改密把外部用户卡死（wave10 复审发现 3）────────────────────────────

// TestExtRoundPwResetSkipsOldPassword 外部认证回合签出的受限改密令牌免填旧口令；
// 本地回合照旧追问。
//
// ★改造前：管理员为外部绑定账号重置本地口令（那正是 guardLocalCredentialForAdmin 给出的
// 补救路径）会置上 must_change_pw，该用户随后凭**外部**口令登录，拿到受限令牌却被要求
// 填「旧口令」——那是管理员刚设的本地口令，他多半不知道；每试错一次 handleChangePassword
// 都调 noteLoginFailure，账号维与 IP 维防爆破很快打满，连本来能用的外部登录也一起进不去。
//
// 变异：把 handleChangePassword 里的 skipOld 恒置 false（或去掉 extAuth.mark），
// 本用例第一段当场红（免填旧口令那次回「旧口令错误」）。
func TestExtRoundPwResetSkipsOldPassword(t *testing.T) {
	const localPw, newPw = "Kx7!mQrTw9Zp", "Zx9#tLmQ7vRb"
	_, h, _ := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "s3cret", nil)
	if out := portalLoginRaw(t, h, "zhou", "pw"); out["ok"] != true {
		t.Fatalf("首登应成功：%v", out)
	}
	resetLocalPw(t, h, "zhou", localPw)

	// ① 凭外部口令登录 → 受限改密令牌，且当面说清"本次无需再填旧口令"。
	out := portalLoginRaw(t, h, "zhou", "pw")
	if out["mustChangePassword"] != true {
		t.Fatalf("外部登录应看到 must_change_pw：%v", out)
	}
	if out["skipOldPassword"] != true {
		t.Fatalf("外部认证回合签出的受限令牌应免填旧口令（前端据此收起输入框）：%v", out)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "无需再填写旧口令") {
		t.Errorf("文案要说清本次不用填旧口令，got %q", reason)
	}
	pwTok, _ := out["token"].(string)
	if code, o := doJSON(t, h, "POST", "/api/v1/auth/password", pwTok,
		map[string]any{"new": newPw}); code != http.StatusOK || o["ok"] != true {
		t.Fatalf("外部回合改密不填旧口令应成功：%d %v", code, o)
	}
	// 改完就走出了受限态：再登一次是完整会话。
	if o := portalLoginRaw(t, h, "zhou", "pw"); o["ok"] != true || o["mustChangePassword"] == true {
		t.Fatalf("改密后外部登录应拿到完整会话：%v", o)
	}

	// ② 对照：本地口令回合**照旧**追问旧口令（这条松了的话，会话被盗 = 可直接改密）。
	h2 := newTestServer(t)
	resetLocalPw(t, h2, "li.fang", localPw)
	o2 := portalLoginRaw(t, h2, "li.fang", localPw)
	if o2["mustChangePassword"] != true {
		t.Fatalf("本地重置后登录应进受限改密态：%v", o2)
	}
	if o2["skipOldPassword"] != nil {
		t.Fatalf("本地回合不得免填旧口令：%v", o2)
	}
	localTok, _ := o2["token"].(string)
	if code, o := doJSON(t, h2, "POST", "/api/v1/auth/password", localTok,
		map[string]any{"new": newPw}); code != http.StatusOK || o["ok"] != false {
		t.Fatalf("本地回合不填旧口令应被拒：%d %v", code, o)
	}
	if code, o := doJSON(t, h2, "POST", "/api/v1/auth/password", localTok,
		map[string]any{"old": localPw, "new": newPw}); code != http.StatusOK || o["ok"] != true {
		t.Fatalf("本地回合填对旧口令应成功：%d %v", code, o)
	}
}

// TestExtPasswordAdminProfileNotRewrittenOnDeny 口令路径（LDAP/AD/RADIUS 共用
// finishExternalAuth）上的同一条：被拒的那次外部认证不许改写管理员的目录属性。
//
// ★用 testPasswordAuth 注入缝而不是真跑一台目录服务器，为的是让「外部目录这次改口了」
// 成为一个可控输入——真服务器的应答里 DisplayName/Email/Groups 是固定的，
// 改写发生了也看不出来，这条用例就会变成一条永远绿的用例。
//
// 变异：删掉 login_authsrc.go 里 BindExternalUser 之前那段 `bound && cur.Role == "admin"`，
// 本用例当场红——而 TestExtBoundAdminCannotLoginViaExternalSource 仍然是绿的
// （签发前那道闸照样把会话拒了），两条用例覆盖的正是不同的东西。
func TestExtPasswordAdminProfileNotRewrittenOnDeny(t *testing.T) {
	s, h := newPlainServer(t)
	aw, _ := s.store.(store.AuthSourceStore)
	if aw == nil {
		t.Fatal("需要 SQLite 后端")
	}
	if _, err := aw.SaveAuthSource(context.Background(), admitSrc(store.AdmitAuto, nil, nil)); err != nil {
		t.Fatalf("存认证源失败：%v", err)
	}
	id := ident("extguy", "extguy@ex.com")
	s.testPasswordAuth = func(store.AuthSourceRec) (authsrc.PasswordAuthenticator, error) {
		return fakePwAuth{id: id}, nil
	}

	// 首登建号。**刻意不断言 out["ok"]**：该源的目录默认策略可能把这一次抬成
	// needEnroll（工作时段之外），而账号在 BindExternalUser 那一步就已经建好了——
	// 用例要的是"目录里有这一行"，不是"这一次登录拿到了令牌"。
	portalLoginRaw(t, h, "extguy", "pw")
	dirUserOf(t, h, "extguy") // 建号了才谈得上后面的改写
	promoteViaRemedyPath(t, h, "extguy", "security")
	before := dirUserOf(t, h, "extguy")

	// 外部目录这一侧改口。
	id = authsrc.Identity{
		Subject: id.Subject, Username: id.Username,
		DisplayName: "被外部目录改写的名字", Email: "attacker@evil.example",
		Groups: []string{"everyone"},
	}

	out := portalLoginRaw(t, h, "extguy", "pw")
	if out["ok"] == true || out["token"] != nil {
		t.Fatalf("管理员凭外部源口令不得换到会话：%v", out)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "管理员") || !strings.Contains(reason, "本地口令") {
		t.Errorf("拒绝文案要说清原因与下一步，got %q", reason)
	}

	after := dirUserOf(t, h, "extguy")
	if after["name"] != before["name"] {
		t.Errorf("被拒的外部登录改写了管理员显示名：%v → %v", before["name"], after["name"])
	}
	if after["email"] != before["email"] {
		t.Errorf("被拒的外部登录改写了管理员邮箱：%v → %v", before["email"], after["email"])
	}
	if g1, g2 := groupsOf(before), groupsOf(after); g1 != g2 {
		t.Errorf("被拒的外部登录改写了管理员的用户组归属：%q → %q", g1, g2)
	}
}

// ── extAuthRounds 这套机制的三处位置约束（wave10 复盘：只有一处有用例）───────────
//
// 三处约束分别是：① 免填旧口令的条件里那半 `c.Use == auth.UsePwReset`；
// ② externalSessionCredential 的「读不到账号一律不签」；③ mark 必须登记在闸之后。
// 上一轮只有 TestExtRoundPwResetSkipsOldPassword 覆盖了「标记生效」这件事本身——
// 三处约束各自删掉，整包 74s 全绿。下面逐条钉住。

// TestFullSessionTokenNeverSkipsOldPassword 免填旧口令的条件是**两个**且缺一不可：
// 受限改密令牌 + 本回合由外部认证源认过。删掉前半（只判 extAuth.active）之后，
// **任何持该账号完整 8h 会话令牌的人**，在该账号一次外部登录后的 18 分钟窗口内，
// 都能不填旧口令直接改掉本地口令——而"旧口令"正是这条路上防「会话被盗后被改密」的唯一一道。
//
// 变异：把 handleChangePassword 里的 skipOld 改成只判 s.extAuth.active(c.Sub)，
// 本用例第 ① 段当场红（完整会话令牌不填旧口令也改成了）。
func TestFullSessionTokenNeverSkipsOldPassword(t *testing.T) {
	const localPw, newPw = "Kx7!mQrTw9Zp", "Zx9#tLmQ7vRb"
	_, h, st := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "s3cret", nil)
	ctx := context.Background()

	// 外部登录一次：拿到**完整会话令牌**，同时该账号进入 18 分钟外部认证回合窗口。
	out := portalLoginRaw(t, h, "zhou", "pw")
	if out["ok"] != true || out["mustChangePassword"] == true {
		t.Fatalf("首登应拿到完整会话令牌：%v", out)
	}
	sessTok, _ := out["token"].(string)
	// 管理员随后给他设了本地口令（补救路径的常规动作），于是这个账号有了本地口令哈希。
	resetLocalPw(t, h, "zhou", localPw)

	// ① 完整会话令牌 + 窗口内：不填旧口令必须被拒，且口令一个字节都不许变。
	code, o := doJSON(t, h, "POST", "/api/v1/auth/password", sessTok, map[string]any{"new": newPw})
	if code != http.StatusOK || o["ok"] != false {
		t.Fatalf("完整会话令牌不填旧口令改密必须失败（会话被盗即可改密）：%d %v", code, o)
	}
	if reason, _ := o["reason"].(string); !strings.Contains(reason, "旧口令") {
		t.Errorf("失败原因应说是旧口令那一关，得到 %q", reason)
	}
	cred, found, err := st.Credential(ctx, "zhou")
	if err != nil || !found {
		t.Fatalf("读账号失败：found=%v err=%v", found, err)
	}
	if !auth.VerifyPassword(cred.PassHash, localPw) || auth.VerifyPassword(cred.PassHash, newPw) {
		t.Fatalf("被拒的那次改密竟然改掉了本地口令哈希")
	}

	// ② 对照：**同一个窗口内**，受限改密令牌走同一个端点就免填旧口令——
	// 证明上面那次失败是 `c.Use` 那半条件挡的，不是窗口过期或标记根本没登记。
	out = portalLoginRaw(t, h, "zhou", "pw")
	if out["mustChangePassword"] != true || out["skipOldPassword"] != true {
		t.Fatalf("同一窗口内的受限改密令牌应免填旧口令：%v", out)
	}
	pwTok, _ := out["token"].(string)
	if code, o := doJSON(t, h, "POST", "/api/v1/auth/password", pwTok,
		map[string]any{"new": newPw}); code != http.StatusOK || o["ok"] != true {
		t.Fatalf("受限令牌免填旧口令改密应成功：%d %v", code, o)
	}
}

// TestOIDCSessionRefusesDeletedAccount 交接票据换会话：60s 窗口内被删号的账号一律不签。
//
// ★改造前 externalSessionCredential 的 !found 分支「视为不受限」：那 60 秒里被删掉的账号
// 仍能换到一张 8h 会话令牌，且 Sub 指向一个已不存在的账号——审计里那个人此后做的每件事
// 都归到一个目录里查不到的主体上，而删号的管理员以为席位与权限已经收回。
//
// 变异：把 !found 分支改回「返回 Role=user 的凭据与 nil error」，本用例当场红（换到了令牌）。
func TestOIDCSessionRefusesDeletedAccount(t *testing.T) {
	h, _, stub := oidcFixture(t)
	oidcGrant(t, h, stub) // 首登建号
	grant := oidcGrant(t, h, stub)

	id := idOf(t, h, "ext.oidc.user")
	if code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+id, adminToken(), nil); code != http.StatusOK {
		t.Fatalf("删号 http %d：%v", code, out)
	}

	code, out := doJSON(t, h, "POST", "/api/v1/auth/oidc/session", "", map[string]any{"ticket": grant})
	if out["token"] != nil {
		t.Fatalf("被删掉的账号不得换到会话令牌：%v", out)
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("读不到账号应 fail-closed（500 账号状态复查失败），实得 %d %v", code, out)
	}
}

// credFlakyStore 让**指定账号**那一次 Credential 重读失败，其余读原样透传。
//
// ★嵌的是 *store.SQLiteStore 而不是 store.Store 接口：登录链路要经 s.store 断言出
// authSourceStore（AuthSources / UserBySubject / BindExternalUser），而那几个方法
// 不在 store.Store 里——嵌接口的话外部认证会整段静默跳过，用例就变成一条永远绿的用例。
type credFlakyStore struct {
	*store.SQLiteStore
	mu          sync.Mutex
	failAccount string
}

func (c *credFlakyStore) fail(account string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failAccount = account
}

func (c *credFlakyStore) Credential(ctx context.Context, account string) (store.Credential, bool, error) {
	c.mu.Lock()
	fa := c.failAccount
	c.mu.Unlock()
	if fa != "" && strings.EqualFold(strings.TrimSpace(account), fa) {
		return store.Credential{}, false, errors.New("database is locked")
	}
	return c.SQLiteStore.Credential(ctx, account)
}

// TestExtRoundMarkedOnlyAfterGate 登记点必须在闸之后：被拒/判不了的那一回合
// **不是一次可用的认证回合**，不得留下"免填旧口令"这个标记。
//
// ★怎么在端到端上制造出"闸拦下了"：让签发前那道闸（externalSessionCredential）重读账号
// 失败即可——它对读不到一律 fail-closed。用外部账号那一行（li.fang@<源 id>，与本地
// li.fang 撞名后加了来源后缀）作为失败目标，正好与 handlePortalLogin 开头那次本地校验
// （读的是 li.fang）分得开，不必按"第几次调用"去猜。
//
// 变异：把 handlePortalLogin 里的 s.extAuth.mark(cred.Account) 挪到
// externalSessionCredential 之前，本用例第 ① 段当场红（被拒的那回合也打上了标记）。
func TestExtRoundMarkedOnlyAfterGate(t *testing.T) {
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	raw, err := store.OpenSQLite(filepath.Join(t.TempDir(), "extmark.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	flaky := &credFlakyStore{SQLiteStore: raw}
	s := New(flaky, raw, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	host, port := startRadiusSrv(t, "s3cret", map[string]string{"li.fang": "radius-pw"}, true)
	srcID := saveRadiusSource(t, h, host, port, "s3cret", nil)
	extAccount := "li.fang@" + srcID // 与本地 li.fang 撞名 → 加来源后缀（BindExternalUser）

	// ① 认证通过、账号也建好了，但签发前那道闸重读失败 → 500，且**不得**留下标记。
	flaky.fail(extAccount)
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "",
		map[string]string{"username": "li.fang", "password": "radius-pw"})
	if code != http.StatusInternalServerError {
		t.Fatalf("重读账号失败应 fail-closed 500，实得 %d %v", code, out)
	}
	if out["token"] != nil {
		t.Fatalf("闸没过却签了令牌：%v", out)
	}
	// 账号确实建出来了 = 这一回合真的走到了闸那一步（否则本用例会空转成永远绿）。
	if _, found, err := raw.Credential(context.Background(), extAccount); err != nil || !found {
		t.Fatalf("夹具没走到闸那一步：外部账号 %s 未建号（found=%v err=%v）", extAccount, found, err)
	}
	if s.extAuth.active(extAccount) {
		t.Fatalf("被闸拒下的那一回合不得登记成一次可用的外部认证回合（它会替后续的受限改密免掉旧口令）")
	}

	// ② 对照：闸放行的那一回合照常登记——证明上面那个 false 不是"这套机制在本夹具里根本没接"。
	flaky.fail("")
	if o := portalLoginRaw(t, h, "li.fang", "radius-pw"); o["ok"] != true {
		t.Fatalf("解除故障后外部登录应成功：%v", o)
	}
	if !s.extAuth.active(extAccount) {
		t.Fatalf("正常通过的外部认证回合应登记标记")
	}
}

// ── 二次认证第二回合的纵深：半程票据带上第一因子来路（wave10 复审 1b）────────────
//
// ★上一轮留下的口子：signMfaTicket 只收 account，handleTotpLogin 与
// handleWebauthnLoginFinish 都是「拿票据换账号 → 重读 users 行 → 按**当下**的 role
// 签 8h 完整令牌」，两者都不知道这一回合的第一因子来自哪里。于是「管理员的认证权不外包」
// 在这条腿上只剩**顺序**在守（闸排在 secondFactor 之前）——顺序一旦被挪动，
// 一名注册了 TOTP 的外部绑定管理员走一遍 IdP 就是一张 role=admin 的完整会话。
//
// 下面两条用例**不依赖那个顺序**：直接伪造一张"外部认证源刚认过"的半程票据
// （那正是闸被挪到 secondFactor 之后时真实会流出的那张），要求第二回合自己拦住。

// TestMfaTotpRoundRefusesExternalAdmin TOTP 第二回合：票据说第一因子来自外部认证源、
// 而账号是管理员 → 403，不签任何令牌；不可判定（旧票据无 dir）同向拒；本地那一回合照常。
func TestMfaTotpRoundRefusesExternalAdmin(t *testing.T) {
	s, h, _ := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "s3cret", nil)
	out := portalLoginRaw(t, h, "zhou", "pw") // 首登建号
	if out["ok"] != true {
		t.Fatalf("首登应成功：%v", out)
	}
	userTok, _ := out["token"].(string)
	sec := enrollTotp(t, h, userTok)
	promoteWithTotpEnrolled(t, h, "zhou", sec, "security") // 本地口令改成 newPw，并提成管理员

	post := func(ticket string, at time.Time) (int, map[string]any) {
		cc, err := totp.Code(sec, at)
		if err != nil {
			t.Fatal(err)
		}
		return doJSON(t, h, "POST", "/api/v1/auth/totp", "", map[string]any{"ticket": ticket, "code": cc})
	}

	// ① 票据自称来自 radius 目录：拒。**验证码是对的**——拦的不是码，是这条路。
	code, o := post(s.signMfaTicket("zhou", "radius"), time.Now())
	if code != http.StatusForbidden || o["token"] != nil {
		t.Fatalf("外部第一因子 + 管理员账号必须 403 且不签令牌：%d %v", code, o)
	}
	if msg := errMsgOf(o); !strings.Contains(msg, "管理员") || !strings.Contains(msg, "本地口令") {
		t.Errorf("拒绝文案要与另外两条路逐字同源，得到 %q", msg)
	}
	assertAdminExtDenyAudited(t, h, "zhou")

	// ② dir 为空（升级那一刻尚在飞行的旧票据）= 不可判定 → 同向拒（fail-closed）。
	if code, o := post(s.signMfaTicket("zhou", ""), time.Now()); code != http.StatusForbidden || o["token"] != nil {
		t.Fatalf("不可判定的第一因子应按外部处理（fail-closed）：%d %v", code, o)
	}

	// ③ 不计入爆破锁定：外部那边的凭据是对的，用户什么都没做错。
	//
	// ★判据必须能分辨「拒绝时偷偷记了一次失败」。Active() 只列**已经锁定**的条目，
	// 而上面才拒了 2 次、阈值是 5——只看它的话，在 denyExternalMfaAdmin 里插一行
	// s.noteLoginFailure(r, account) 本用例照绿（实测过）。所以这里把被拒的那一回合
	// **打满阈值次**，再要求账号仍未被锁定：一次都不许计，才是这条闸的语义。
	thr := s.lockout.Config().Threshold
	for i := 0; i < thr; i++ {
		if code, o := post(s.signMfaTicket("zhou", "radius"), time.Now()); code != http.StatusForbidden {
			t.Fatalf("第 %d 次被闸拒应仍是 403，得到 %d %v", i+1, code, o)
		}
	}
	if n := len(s.lockout.Active()); n != 0 {
		t.Errorf("这道闸不该计入爆破锁定（已连拒 %d 次，阈值 %d），却有 %d 条：%+v",
			thr, thr, n, s.lockout.Active())
	}

	// ④ 对照：**真走一遍本地口令登录**（管理员的正常姿态）——第二回合照常换到完整会话。
	// 这一段同时是 ③ 的第二道判据：若上面那些拒绝各记了一次失败，账号维与 IP 维都已锁死，
	// 这里的 /portal/login 会回 403（portalLoginRaw 当场 Fatal），而不只是少一条 Active()。
	// 这条同时钉住"纵深没有把管理员锁在 TOTP 外面"。
	out = portalLoginRaw(t, h, "zhou", "Zx9#tLmQ7vRb")
	if out["needTotp"] != true {
		t.Fatalf("已确认 TOTP 的管理员本地登录应被要求验证码：%v", out)
	}
	tk, _ := out["ticket"].(string)
	// 用**下一步长**的码：同一步长的码在上面 promoteWithTotpEnrolled 那一回合已被消费
	// （store.ConsumeTotpCounter 单调递增，同码只能成功一次）。
	code, o = post(tk, time.Now().Add(totp.Period*time.Second))
	if code != http.StatusOK || o["ok"] != true || o["token"] == nil {
		t.Fatalf("本地口令那一回合应照常换到完整会话：%d %v", code, o)
	}
	if o["role"] != "admin" {
		t.Errorf("本地路径上管理员就该拿到 admin 会话，得到 %v", o["role"])
	}
}

// TestMfaWebauthnRoundRefusesExternalAdmin passkey 第二回合：同一道闸、同一个函数
// （denyExternalMfaAdmin），排在断言校验之前。
//
// ★这里必须配一个 RP（webauthnx.New），否则 handleWebauthnLoginFinish 第一行就 503，
// 用例会变成"什么都没测到却是绿的"。断言本身不需要造——闸排在 consumeChallenge 之前，
// 拿一个空 body 就能分辨出三种结局：403（本闸）/ 400（走到了 challenge 那一步）。
func TestMfaWebauthnRoundRefusesExternalAdmin(t *testing.T) {
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "wafinish.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	rp, err := webauthnx.New("localhost", "http://localhost", "白帝")
	if err != nil {
		t.Fatalf("构造 RP 失败：%v", err)
	}
	s := New(st, st, testKeys, "test", t.TempDir(), rp, nil, true)
	t.Cleanup(s.Close)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	finish := func(ticket string) (int, map[string]any) {
		return doJSON(t, h, "POST", "/api/v1/webauthn/login/finish", "", map[string]any{"ticket": ticket})
	}

	// ① 管理员 + 外部第一因子：403，且是本闸的那句话（不是"断言校验失败"）。
	code, o := finish(s.signMfaTicket("admin", "oidc"))
	if code != http.StatusForbidden {
		t.Fatalf("外部第一因子 + 管理员账号必须 403，得到 %d %v", code, o)
	}
	if msg := errMsgOf(o); !strings.Contains(msg, "管理员") || !strings.Contains(msg, "本地口令") {
		t.Errorf("拒绝文案要与另外两条路逐字同源，得到 %q", msg)
	}
	assertAdminExtDenyAudited(t, h, "admin")

	// ② 对照 A：同一个管理员、第一因子是本地口令 → 本闸不管，流程照常走到 challenge 那一步。
	if code, o := finish(s.signMfaTicket("admin", "local")); code == http.StatusForbidden {
		t.Fatalf("本地第一因子的管理员不该被本闸拦下：%d %v", code, o)
	}
	// ③ 对照 B：外部第一因子但**不是管理员** → 本闸同样不管（外部用户走 passkey 是正常业务）。
	if code, o := finish(s.signMfaTicket("li.fang", "oidc")); code == http.StatusForbidden {
		t.Fatalf("外部第一因子的普通用户不该被本闸拦下：%d %v", code, o)
	}
}

// ── 半程票据里那份 dir 的**真实接线**（本轨行动 1）────────────────────────────────
//
// ★上面四条纵深用例（TestMfa*RoundRefusesExternalAdmin）全都用 s.signMfaTicket(...)
// **直接伪造票据**——它们测的是「法官」（denyExternalMfaAdmin 拿到 dir 之后判得对不对），
// 从没测过「证据从哪来」。实证：把 webauthn.go 里 secondFactor 的两处
// `s.signMfaTicket(account, lc.Directory)` 改成写死 "local"，整个 api 包全绿。
//
// 后果是纵深整层无声失效：每张半程票据都自称 local → denyExternalMfaAdmin 第一行
// 就 return false。而纵深层的**全部存在意义**正是「顺序（闸排在 secondFactor 之前）
// 被重构挪动时仍然拦得住」——顺序与接线会在同一次重构里一起没掉，
// 那时四条纵深用例照绿、一名注册了 TOTP/passkey 的外部绑定管理员走一遍 IdP
// 就是一张 role=admin 的 8h 会话。
//
// 下面两条只断言**真实登录链路签出的那张票据**里的 dir，一条覆盖 TOTP 分支、
// 一条覆盖 passkey 分支（两处 signMfaTicket 各一）；每条各取一次外部目录与一次本地，
// 单向断言（只测 radius）会被"写死 radius"这种反向变异漏掉。

// mfaTicketDir 解出半程票据里的第一因子目录（测试直接验签，不经任何 handler）。
func mfaTicketDir(t *testing.T, ticket string) string {
	t.Helper()
	if ticket == "" {
		t.Fatal("这一回合根本没签出半程票据")
	}
	c, err := testKeys.Verify(ticket)
	if err != nil {
		t.Fatalf("半程票据验签失败：%v", err)
	}
	if c.Role != "mfa" {
		t.Fatalf("半程票据的 role 应是 mfa，得到 %q", c.Role)
	}
	return c.Dir
}

// TestMfaTicketCarriesFirstFactorDirectory TOTP 分支：needTotp 那张票据里的 dir
// 必须是**本回合真正认出这个人的那个目录**，不是常量。
//
// 变异（本条的交付判据）：把 webauthn.go 里 needTotp 分支的
// `s.signMfaTicket(account, lc.Directory)` 改成 `s.signMfaTicket(account, "local")`
// → 第 ① 段当场红（radius 那一回合的票据自称 local）。
func TestMfaTicketCarriesFirstFactorDirectory(t *testing.T) {
	const localPw = "Kx7!mQrTw9Zp"
	_, h, _ := newRadiusAPI(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "s3cret", nil)

	// 用**非管理员**外部绑定账号：顺序闸只拦管理员，普通外部用户走 TOTP 是正常业务，
	// 这一回合才会真的签出票据（拿管理员做夹具的话闸会先把这条路掐掉，什么都验不到）。
	out := portalLoginRaw(t, h, "zhou", "pw") // 首登建号
	if out["ok"] != true {
		t.Fatalf("首登应成功：%v", out)
	}
	userTok, _ := out["token"].(string)
	enrollTotp(t, h, userTok) // 本条只看票据里的 dir，不进第二回合，密钥用不上

	// ① 外部口令那一回合：dir 必须是该源的 kind（RADIUS）。
	out = portalLoginRaw(t, h, "zhou", "pw")
	if out["needTotp"] != true {
		t.Fatalf("已确认 TOTP 的账号登录应被要求验证码：%v", out)
	}
	tk, _ := out["ticket"].(string)
	if d := mfaTicketDir(t, tk); d != "radius" {
		t.Fatalf("外部认证回合签出的半程票据应记 dir=radius，得到 %q——"+
			"第二回合的纵深闸（denyExternalMfaAdmin）唯一的判据就是它", d)
	}

	// ② 本地口令那一回合：同一个账号、同一个分支，dir 必须是 local。
	// 这一段与 ① 成对，缺了它「写死 radius」这类反向变异就漏过去了。
	resetLocalPw(t, h, "zhou", localPw)
	out = portalLoginRaw(t, h, "zhou", localPw)
	if out["needTotp"] != true {
		t.Fatalf("本地口令回合也应被要求验证码：%v", out)
	}
	tk, _ = out["ticket"].(string)
	if d := mfaTicketDir(t, tk); d != string(authsrc.KindLocal) {
		t.Fatalf("本地口令回合签出的半程票据应记 dir=local，得到 %q——"+
			"记错成外部会让管理员在本地路径上也被纵深闸拦死", d)
	}
}

// newRadiusAPIRP 与 newRadiusAPI 同款，只多配一个 RP（passkey 分支要 webauthnEnabled()
// 为真才走得到，否则 secondFactor 连 WebauthnCredentialCount 都不查，用例会空转成永远绿）。
func newRadiusAPIRP(t *testing.T) (*Server, http.Handler, *store.SQLiteStore) {
	t.Helper()
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "radius-rp.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	rp, err := webauthnx.New("localhost", "http://localhost", "白帝")
	if err != nil {
		t.Fatalf("构造 RP 失败：%v", err)
	}
	s := New(st, st, testKeys, "test", t.TempDir(), rp, nil, true)
	t.Cleanup(s.Close)
	return s, auth.Middleware(testKeys, s.IsOpen)(s.Routes()), st
}

// TestMfaTicketCarriesDirectoryOnPasskeyBranch passkey 分支同款：needWebauthn 那张票据
// 里的 dir 同样必须来自 lc。两处 signMfaTicket 是并排的两行，只钉住一处的话，
// 另一处被"顺手简化"成常量时全包仍绿。
//
// 变异：把 needWebauthn 分支的 lc.Directory 改成写死 "local" → 第 ① 段当场红。
func TestMfaTicketCarriesDirectoryOnPasskeyBranch(t *testing.T) {
	const localPw = "Kx7!mQrTw9Zp"
	_, h, st := newRadiusAPIRP(t)
	host, port := startRadiusSrv(t, "s3cret", map[string]string{"zhou": "pw"}, true)
	saveRadiusSource(t, h, host, port, "s3cret", nil)
	ctx := context.Background()

	out := portalLoginRaw(t, h, "zhou", "pw") // 首登建号
	if out["ok"] != true {
		t.Fatalf("首登应成功：%v", out)
	}
	// 直接落一条 passkey 凭据：本条用例要的只是「该账号已注册 passkey」这个事实
	// （secondFactor 读的是 WebauthnCredentialCount），不是一次真的认证器仪式。
	cred, found, err := st.Credential(ctx, "zhou")
	if err != nil || !found {
		t.Fatalf("外部账号应已建号：found=%v err=%v", found, err)
	}
	if _, err := st.SaveWebauthnCredential(ctx, store.WebauthnCredential{
		UserID: cred.ID, Account: "zhou", CredentialID: "cred-zhou-1",
		PublicKey: "cHVibGljLWtleQ", Transports: `["internal"]`, Name: "Touch ID",
	}); err != nil {
		t.Fatalf("落 passkey 凭据：%v", err)
	}

	// ① 外部口令那一回合 → needWebauthn，票据里的 dir 必须是 radius。
	out = portalLoginRaw(t, h, "zhou", "pw")
	if out["needWebauthn"] != true {
		t.Fatalf("已注册 passkey 的账号登录应强制断言：%v", out)
	}
	tk, _ := out["ticket"].(string)
	if d := mfaTicketDir(t, tk); d != "radius" {
		t.Fatalf("外部认证回合的 passkey 半程票据应记 dir=radius，得到 %q", d)
	}

	// ② 本地口令那一回合 → dir=local。
	resetLocalPw(t, h, "zhou", localPw)
	out = portalLoginRaw(t, h, "zhou", localPw)
	if out["needWebauthn"] != true {
		t.Fatalf("本地口令回合也应强制断言：%v", out)
	}
	tk, _ = out["ticket"].(string)
	if d := mfaTicketDir(t, tk); d != string(authsrc.KindLocal) {
		t.Fatalf("本地口令回合的 passkey 半程票据应记 dir=local，得到 %q", d)
	}
}

// ── 纵深闸的 fail-closed 分支（本轨行动 2）──────────────────────────────────────
//
// ★denyExternalMfaAdmin 的注释把「读不到账号也拒」写成一条**独立**的安全决策
// （与 externalSessionCredential 的 !found 同向），但它此前零用例：把那个分支改成
// `return false` 放行，整包全绿。今天危害为零，因为下游会各自再读一次账号并同样
// fail-closed（handleTotpLogin 的 store.Credential、handleWebauthnLoginFinish 的
// webauthnUserFor 都回 500）；可那是**下游的**纪律，一旦下游改写（例如把重读结果
// 缓存进票据、或把 500 降级成"按未注册处理"），这条就无声消失，而它的名字仍写在注释里。

// TestMfaGateFailsClosedWhenCredentialUnreadable 两条第二回合路径：账号重读失败时
// 一律 500 且不签任何令牌——不是"读不到就当他不是管理员"。
//
// 变异：把 denyExternalMfaAdmin 里 `if err != nil || !found` 的分支体换成 `return false`
// → 两段各自当场红（TOTP 那条变 401「该账号未启用 TOTP」，
// webauthn 那条变 400「挑战」——都不再是本闸的 500）。
func TestMfaGateFailsClosedWhenCredentialUnreadable(t *testing.T) {
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	raw, err := store.OpenSQLite(filepath.Join(t.TempDir(), "mfagate.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	flaky := &credFlakyStore{SQLiteStore: raw}
	rp, rerr := webauthnx.New("localhost", "http://localhost", "白帝")
	if rerr != nil {
		t.Fatalf("构造 RP 失败：%v", rerr)
	}
	s := New(flaky, raw, testKeys, "test", t.TempDir(), rp, nil, true)
	t.Cleanup(s.Close)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	// 目标账号真实存在（种子里的 li.fang）——考的是"读失败"，不是"账号不存在"。
	flaky.fail("li.fang")

	// ① TOTP 第二回合：500，不签令牌。
	code, out := doJSON(t, h, "POST", "/api/v1/auth/totp", "",
		map[string]any{"ticket": s.signMfaTicket("li.fang", "radius"), "code": "000000"})
	// ★两段都用 Errorf 不用 Fatalf：它们是**两条**独立路径（totp.go 与 webauthn.go
	// 各有一个调用点），第一段 Fatal 掉的话，第二段在变异跑里根本不会执行，
	// 于是"只有一条路径接了这道闸"这种半覆盖会被读成全绿。
	if code != http.StatusInternalServerError {
		t.Errorf("重读账号失败时 TOTP 第二回合应 fail-closed 500，实得 %d %v", code, out)
	}
	if out["token"] != nil {
		t.Errorf("闸没判出结论却签了令牌：%v", out)
	}

	// ② passkey 第二回合：同一道闸、同一个函数，同样 500。
	code, out = doJSON(t, h, "POST", "/api/v1/webauthn/login/finish", "",
		map[string]any{"ticket": s.signMfaTicket("li.fang", "oidc")})
	if code != http.StatusInternalServerError {
		t.Errorf("重读账号失败时 passkey 第二回合应 fail-closed 500，实得 %d %v", code, out)
	}
	if out["token"] != nil {
		t.Errorf("闸没判出结论却签了令牌：%v", out)
	}

	// ③ 对照：解除故障后同一张票据不再撞 500（证明上面两次 500 是本闸给的，
	// 不是这套夹具里什么都跑不通）。li.fang 不是管理员 → 闸放行 → 各自走到下游的判定。
	flaky.fail("")
	if code, out := doJSON(t, h, "POST", "/api/v1/auth/totp", "",
		map[string]any{"ticket": s.signMfaTicket("li.fang", "radius"), "code": "000000"}); code == http.StatusInternalServerError {
		t.Fatalf("解除故障后不该再是 500：%d %v", code, out)
	}
}
