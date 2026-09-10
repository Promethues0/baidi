package api

// 认证加严配置的防自锁闸（PRD FR-ADMIN-20，并 FR-ADMIN-16/17）端到端。
//
// # 改造前
//
// 一条 `enhance.always + secondary:["totp"]` 的本地默认策略保存下去，就把**全部管理员**
// 永久挡在管理台之外：handleAdminLogin 与 handlePortalLogin 走同一个 secondFactor，
// 一个都没注册第二因子的账号拿到的是 needEnroll；而注册入口（/totp/enroll、webauthn 注册）
// 都走 requireUser——**要先登录**。保存回 200、策略卡显示「已启用」，
// 下一次登录起整套系统只能停服改库。
//
// # 这一组用例钉住的
//
//	① 会把最后一名管理员挡在门外的保存/删除 → 409，且**不落库**；
//	② 已注册可用第二因子的管理员算"进得来"；
//	③ 只读审计的管理员**不算**（登得进来但改不动这条策略，救不了场）；
//	④ 没有本地口令的管理员**不算**（管理台只验本地 bcrypt）；
//	⑤ 差分而非绝对：改动之前就已经锁死时不拦，否则把修好它的那次编辑一起拦掉；
//	⑥ 登录侧被挡住时给的补救路径**真实存在**（不再是"联系管理员协助录入"）。

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// lockoutFixture 与 totpFixture 同款：把 secret 盒主密钥指进临时目录
// （用例要给管理员注册 TOTP，否则首次 Seal 会在包目录落密钥文件）。
func lockoutFixture(t *testing.T) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "lockout.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), st
}

// sessionFor 造一张**账号口径正确**的会话令牌。
// ★不能用 adminToken()：它的 Name 是显示名「安全管理员」，而 TOTP 注册按 claims.Name 取账号。
func sessionFor(account, role string) string {
	return testKeys.Sign(auth.Claims{Sub: account, Role: role, Name: account}, tokenTTL)
}

// lockingDefault 一条覆盖本地目录全体、一律二次认证、只收 TOTP 的默认策略。
// 三样缺一不可：directory=local（管理台登录的目录）、isDefault（谁都匹配得上）、
// secondary 非空（legacy 演示验证码回落因此不成立）。
func lockingDefault() map[string]any {
	return map[string]any{
		"id": "ap-local-default", "name": "本地目录 · 默认策略", "directory": "local",
		"isDefault": true, "enabled": true, "priority": 100,
		"secondary": []string{"totp"},
		"enhance":   map[string]any{"always": true},
	}
}

func saveAuthPolicy(t *testing.T, h http.Handler, body map[string]any) (int, map[string]any) {
	t.Helper()
	return doJSON(t, h, "POST", "/api/v1/authpolicy", adminToken(), body)
}

// policyByID 从 GET /authpolicy 里点查一条策略（用来断言"到底落库没有"）。
func policyByID(t *testing.T, h http.Handler, id string) map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/authpolicy", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /authpolicy http %d", code)
	}
	list, _ := out["policies"].([]any)
	for _, it := range list {
		p, _ := it.(map[string]any)
		if p["id"] == id {
			return p
		}
	}
	return nil
}

func alwaysOn(p map[string]any) bool {
	e, _ := p["enhance"].(map[string]any)
	on, _ := e["always"].(bool)
	return on
}

// enrollTotpFor 给某个**账号**注册并确认 TOTP（复用 ext_admin_login_test.go 的 enrollTotp，
// 只多做一件事：按账号造一张口径正确的会话令牌）。
func enrollTotpFor(t *testing.T, h http.Handler, account string) {
	t.Helper()
	enrollTotp(t, h, sessionFor(account, "admin"))
}

// ① 会锁死全体管理员的保存必须 409，而且一个字节都不许落库。
func TestSaveAuthPolicyRefusedWhenItLocksOutEveryAdmin(t *testing.T) {
	h, _ := lockoutFixture(t)

	code, out := saveAuthPolicy(t, h, lockingDefault())
	if code != http.StatusConflict {
		t.Fatalf("这条策略会把唯一的管理员永久挡在管理台外，必须 409；实得 http %d：%v", code, out)
	}
	msg := errMsg(out)
	// 拒绝要说清「谁会被挡住」与「怎么办」——笼统的"不允许"会让管理员反复换写法试。
	for _, want := range []string{"admin", "TOTP", "适用范围"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("拒绝文案缺少「%s」：%s", want, msg)
		}
	}
	// ★补救路径必须真实存在：白帝没有"管理员代为录入认证器"这个入口。
	if strings.Contains(msg, "协助录入") {
		t.Fatalf("拒绝文案指向了一条不存在的补救路径：%s", msg)
	}

	// 落库了没有——409 之后策略必须原样不动，否则"拒绝"只是句话。
	if p := policyByID(t, h, "ap-local-default"); p == nil || alwaysOn(p) {
		t.Fatalf("被拒的策略不该落库，实得 %v", p)
	}
	// 反面证据：管理台仍然登得进去。
	code, login := doJSON(t, h, "POST", "/api/v1/auth/login", "",
		map[string]string{"username": "admin", "password": "baidi@123"})
	if code != http.StatusOK || login["token"] == nil {
		t.Fatalf("拒绝之后管理台必须照常登得进去，实得 http %d：%v", code, login)
	}
}

// ② 管理员注册了 TOTP 之后，同一条策略就该存得下去——闸只拦"没人进得来"，不拦加严本身。
func TestSaveAuthPolicyAllowedOnceAdminHasTotp(t *testing.T) {
	h, _ := lockoutFixture(t)
	if code, out := saveAuthPolicy(t, h, lockingDefault()); code != http.StatusConflict {
		t.Fatalf("前置：未注册第二因子时应被拒，实得 http %d：%v", code, out)
	}
	enrollTotpFor(t, h, "admin")
	if code, out := saveAuthPolicy(t, h, lockingDefault()); code != http.StatusOK {
		t.Fatalf("管理员已注册 TOTP，加严策略必须存得下去；实得 http %d：%v", code, out)
	}
	if p := policyByID(t, h, "ap-local-default"); p == nil || !alwaysOn(p) {
		t.Fatalf("放行之后策略应真的落库，实得 %v", p)
	}
}

// ③ 只读审计的管理员登得进来也解不开这条策略——把他数进去等于给一个假的安全垫。
func TestLockoutGuardIgnoresAdminsWithoutSecurityPerm(t *testing.T) {
	h, _ := lockoutFixture(t)
	if code, out := doJSON(t, h, "POST", "/api/v1/admins", adminToken(), map[string]string{
		"account": "aud1", "name": "审计员", "roleKey": "audit", "password": "Auditor#2026x",
	}); code != http.StatusCreated {
		t.Fatalf("建审计管理员 http %d：%v", code, out)
	}
	enrollTotpFor(t, h, "aud1") // 他有可用的第二因子，登得进管理台

	code, out := saveAuthPolicy(t, h, lockingDefault())
	if code != http.StatusConflict {
		t.Fatalf("唯一还进得来的是审计管理员（无 security 权，改不动认证策略），必须仍判自锁；实得 http %d：%v", code, out)
	}
	if msg := errMsg(out); strings.Contains(msg, "aud1") {
		t.Fatalf("审计管理员不该被算进「还进得来的人」，文案却点了他的名：%s", msg)
	}
}

// ④ 没有本地口令的管理员登不进管理台（只验本地 bcrypt），同样不算数。
//
// ★这一格构造得直白些：直接把 admin 的 pass_hash 清空。它对应的真实形态是
// 「外部目录账号被提成管理员」——guardLocalCredentialForAdmin 现在拦着这条路，
// 但那道守卫是后来补的，存量库里可能已经有这样的行，而它在管理员表里看起来一切正常。
func TestLockoutGuardIgnoresAdminsWithoutLocalPassword(t *testing.T) {
	h, st := lockoutFixture(t)
	ctx := context.Background()

	// 再造一名持 security 权、有本地口令、没有第二因子的管理员。
	if code, out := doJSON(t, h, "POST", "/api/v1/admins", adminToken(), map[string]string{
		"account": "sec1", "name": "安全员", "roleKey": "security", "password": "Security#2026x",
	}); code != http.StatusCreated {
		t.Fatalf("建安全管理员 http %d：%v", code, out)
	}
	// 超管注册 TOTP（本来永远进得来），再把他的本地口令抹掉。
	enrollTotpFor(t, h, "admin")
	users, err := st.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var adminID string
	for _, u := range users.Users {
		if u.Account == "admin" {
			adminID = u.ID
		}
	}
	if adminID == "" {
		t.Fatal("种子里应有 admin")
	}
	if err := st.SetUserPassword(ctx, adminID, "", false, auth.PwUnknown); err != nil {
		t.Fatal(err)
	}

	code, out := saveAuthPolicy(t, h, lockingDefault())
	if code != http.StatusConflict {
		t.Fatalf("唯一带第二因子的超管已经没有本地口令、登不进管理台，必须仍判自锁；实得 http %d：%v", code, out)
	}
	if msg := errMsg(out); strings.Contains(msg, "admin、") || !strings.Contains(msg, "sec1") {
		t.Fatalf("文案里「还进得来的人」应只剩 sec1，实得：%s", msg)
	}
}

// ⑤ 删除同样过闸：删掉一条宽松的定向策略，被它命中的账号会回落到更严的默认策略。
func TestDeleteAuthPolicyRefusedWhenFallbackLocksOut(t *testing.T) {
	h, _ := lockoutFixture(t)

	// 一个含 admin 的用户组，用来给他挂一条更优先的宽松策略。
	code, gout := doJSON(t, h, "POST", "/api/v1/groups", adminToken(),
		map[string]any{"name": "运维组", "kind": "static"})
	if code != http.StatusOK {
		t.Fatalf("建组 http %d：%v", code, gout)
	}
	g, _ := gout["group"].(map[string]any)
	gid, _ := g["id"].(string)
	if code, out := doJSON(t, h, "PUT", "/api/v1/groups/"+gid+"/members", adminToken(),
		map[string]any{"accounts": []string{"admin"}}); code != http.StatusOK {
		t.Fatalf("设成员 http %d：%v", code, out)
	}

	// 宽松定向策略（优先级 10，压过默认的 100）→ admin 由它命中，不要求二次认证。
	if code, out := saveAuthPolicy(t, h, map[string]any{
		"id": "ap-ops-relaxed", "name": "运维组 · 不加严", "directory": "local",
		"enabled": true, "priority": 10, "scopeGroups": []string{gid},
	}); code != http.StatusOK {
		t.Fatalf("保存宽松定向策略 http %d：%v", code, out)
	}
	// 有它兜着，严格默认策略这时是存得下去的。
	if code, out := saveAuthPolicy(t, h, lockingDefault()); code != http.StatusOK {
		t.Fatalf("有定向策略兜底时严格默认策略应可保存；实得 http %d：%v", code, out)
	}

	// 删掉兜底那条 → admin 回落到严格默认策略 → 没人进得来。
	code, out := doJSON(t, h, "DELETE", "/api/v1/authpolicy/ap-ops-relaxed", adminToken(), nil)
	if code != http.StatusConflict {
		t.Fatalf("删掉兜底策略会让管理员回落到严格默认策略，必须 409；实得 http %d：%v", code, out)
	}
	if p := policyByID(t, h, "ap-ops-relaxed"); p == nil {
		t.Fatal("被拒的删除不该真的删掉")
	}
}

// ⑥ 差分而非绝对：改动之前就已经没人进得来时不拦——否则把唯一能修好它的那次编辑也拦掉。
func TestLockoutGuardIsDifferentialNotAbsolute(t *testing.T) {
	h, st := lockoutFixture(t)
	ctx := context.Background()

	// 绕过闸直接落一条锁死全员的策略，模拟"本闸上线之前保存的存量配置"。
	locking := store.AuthPolicy{
		ID: "ap-local-default", Name: "本地目录 · 默认策略", Directory: "local", IsDefault: true,
		Priority: 100, Enabled: true, Secondary: []string{"totp"},
		Enhance: store.EnhanceRule{Always: true},
	}
	if _, err := st.SaveAuthPolicy(ctx, locking); err != nil {
		t.Fatal(err)
	}

	// 此刻已经没人登得进管理台。**与本次改动无关的**另一条策略仍必须存得下去：
	// 绝对判定会把它一起拒掉，而修复往往要好几步。
	if code, out := saveAuthPolicy(t, h, map[string]any{
		"id": "ap-other", "name": "外部目录加严", "directory": "local",
		"enabled": true, "priority": 20, "scopeOrgs": []string{"ext"},
		"enhance": map[string]any{"always": true}, "secondary": []string{"totp"},
	}); code != http.StatusOK {
		t.Fatalf("改动前就已锁死时，闸不该再拦别的编辑（否则修不回来）；实得 http %d：%v", code, out)
	}

	// 把锁死那条改回宽松同样必须放行——这才是真正的出路。
	fix := lockingDefault()
	fix["enhance"] = map[string]any{"always": false}
	if code, out := saveAuthPolicy(t, h, fix); code != http.StatusOK {
		t.Fatalf("把锁死的策略改回去必须放行；实得 http %d：%v", code, out)
	}
}

// ⑦ 被策略挡在门外时给的补救路径必须**真实存在**：
// 白帝没有"管理员代为录入认证器"的入口，门户「安全设置」也在同一堵墙后面。
func TestEnrollDeadEndNoteGivesARealPath(t *testing.T) {
	h, st := lockoutFixture(t)
	ctx := context.Background()
	if _, err := st.SaveAuthPolicy(ctx, store.AuthPolicy{
		ID: "ap-local-default", Name: "本地目录 · 默认策略", Directory: "local", IsDefault: true,
		Priority: 100, Enabled: true, Secondary: []string{"totp"},
		Enhance: store.EnhanceRule{Always: true},
	}); err != nil {
		t.Fatal(err)
	}

	out := loginResp(t, h, "li.fang")
	if out["needEnroll"] != true {
		t.Fatalf("该账号既无 passkey 也无 TOTP，策略点名了方式 → 应回 needEnroll，实得 %v", out)
	}
	reason, _ := out["reason"].(string)
	for _, want := range []string{"要求先登录", "管理员无法代你录入认证器", "安全策略"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("补救路径文案缺少「%s」：%s", want, reason)
		}
	}
	// 旧文案里的两条死路不许回来。
	for _, bad := range []string{"协助录入", "请先在门户「安全设置」里绑定后再登录"} {
		if strings.Contains(reason, bad) {
			t.Fatalf("文案又指回了不存在的路（%s）：%s", bad, reason)
		}
	}
	// 裸 IP 部署（RP 未配置）下必须点名 passkey 用不了，否则用户会去查"为什么点了没反应"。
	if !strings.Contains(reason, "RP ID") {
		t.Fatalf("未配置 WebAuthn RP 时应说明 passkey 不可用：%s", reason)
	}
}

// ⑧ 裸 IP 部署（未配置 WebAuthn RP）下，只注册过 passkey 的管理员**不算**有第二因子：
// secondFactor 的第一步整个包在 `if s.webauthnEnabled()` 里，RP 没配时那一步根本不跑。
// 把它数成"有"，闸就会放过一条真会锁死他的策略——而演示站正是这个形态。
func TestLockoutGuardIgnoresPasskeyWhenRPNotConfigured(t *testing.T) {
	h, st := lockoutFixture(t)
	ctx := context.Background()

	users, err := st.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var adminID string
	for _, u := range users.Users {
		if u.Account == "admin" {
			adminID = u.ID
		}
	}
	if _, err := st.SaveWebauthnCredential(ctx, store.WebauthnCredential{
		UserID: adminID, Account: "admin", CredentialID: "cred-1",
		PublicKey: "cG9j", Name: "Touch ID",
	}); err != nil {
		t.Fatal(err)
	}
	// 前置：测试栈的 rp 为 nil（New(…, nil, nil, true)），即"未配置 RP"。
	if code, out := saveAuthPolicy(t, h, lockingDefault()); code != http.StatusConflict {
		t.Fatalf("RP 未配置时 passkey 用不上，管理员仍会被挡住，必须 409；实得 http %d：%v", code, out)
	}
}

// ⑨ 新建策略不填优先级时，闸必须按**落库后**的那个值（50）求值。
// 拿未归一的 0 去算，它会排在所有已有策略之前，闸看到的适用策略与登录时真正生效的那条
// 不是同一条——方向是**过度拒绝**：一条其实不会生效的加严策略把保存挡住，
// 而管理员在页面上看不出任何理由。
func TestLockoutGuardEvaluatesNormalizedPriority(t *testing.T) {
	h, _ := lockoutFixture(t)

	code, gout := doJSON(t, h, "POST", "/api/v1/groups", adminToken(),
		map[string]any{"name": "运维组", "kind": "static"})
	if code != http.StatusOK {
		t.Fatalf("建组 http %d：%v", code, gout)
	}
	g, _ := gout["group"].(map[string]any)
	gid, _ := g["id"].(string)
	if code, out := doJSON(t, h, "PUT", "/api/v1/groups/"+gid+"/members", adminToken(),
		map[string]any{"accounts": []string{"admin"}}); code != http.StatusOK {
		t.Fatalf("设成员 http %d：%v", code, out)
	}
	// 优先级 30 的宽松策略：admin 由它命中。
	if code, out := saveAuthPolicy(t, h, map[string]any{
		"id": "ap-ops-relaxed", "name": "运维组 · 不加严", "directory": "local",
		"enabled": true, "priority": 30, "scopeGroups": []string{gid},
	}); code != http.StatusOK {
		t.Fatalf("保存宽松策略 http %d：%v", code, out)
	}
	// 新策略**不填优先级**，同样圈住 admin。落库后是 50，压不过上面那条 30。
	code, out := saveAuthPolicy(t, h, map[string]any{
		"name": "运维组 · 一律二次认证", "directory": "local", "enabled": true,
		"scopeGroups": []string{gid},
		"enhance":     map[string]any{"always": true}, "secondary": []string{"totp"},
	})
	if code != http.StatusOK {
		t.Fatalf("缺省优先级落库是 50、压不过既有的 30，这条策略对 admin 不生效，应放行；实得 http %d：%v", code, out)
	}
}
