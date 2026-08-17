package api

// TOTP 二次认证（wave7 行动 4）。算法本体在 internal/totp（RFC 官方向量钉住）；
// 这里测**编排**：注册→确认→登录强制→防重放，以及三条硬边界——
// 确认码不能在登录页重用、mfa 票据不是会话令牌、冻结方式保存即拒。

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/totp"
)

// totpFixture 测试栈；把 secret 盒主密钥指进临时目录（否则首次 Seal 会在包目录落密钥文件）。
func totpFixture(t *testing.T) http.Handler {
	t.Helper()
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	return newTestServer(t)
}

// loginResp 门户口令登录一回合（不断言必然拿到 token——TOTP 开启后拿到的是 needTotp）。
func loginResp(t *testing.T, h http.Handler, user string) map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "",
		map[string]string{"username": user, "password": "baidi@123"})
	if code != http.StatusOK {
		t.Fatalf("portal login http %d", code)
	}
	return out
}

func TestTotpFullFlow(t *testing.T) {
	h := totpFixture(t)

	// 0) 未注册：单因素直接放行
	out := loginResp(t, h, "li.fang")
	tok, _ := out["token"].(string)
	if tok == "" {
		t.Fatalf("未注册 TOTP 应单因素放行，实得 %v", out)
	}

	// 1) 注册：密钥只在本响应回显一次
	code, enr := doJSON(t, h, "POST", "/api/v1/totp/enroll", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("enroll http %d", code)
	}
	sec, _ := enr["secret"].(string)
	uri, _ := enr["uri"].(string)
	if sec == "" || !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("应回显密钥与 otpauth URI，实得 %v", enr)
	}

	// 2) 未确认不参与判定：登录仍单因素（点了注册没扫码，不锁死）
	if out := loginResp(t, h, "li.fang"); out["token"] == nil {
		t.Fatalf("未确认的注册不该抬二次认证，实得 %v", out)
	}

	// 3) 确认转正
	now := time.Now()
	confirmCode, err := totp.Code(sec, now)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/totp/confirm", tok,
		map[string]string{"code": confirmCode}); code != http.StatusOK {
		t.Fatalf("confirm http %d %v", code, out)
	}
	if _, st := doJSON(t, h, "GET", "/api/v1/totp", tok, nil); st["confirmed"] != true {
		t.Fatalf("确认后状态应 confirmed，实得 %v", st)
	}

	// 4) 从此登录强制 TOTP：拿到 needTotp+票据而不是令牌，legacy 演示码对本账号不可达
	out = loginResp(t, h, "li.fang")
	if out["needTotp"] != true || out["token"] != nil {
		t.Fatalf("已确认 TOTP 应强制验证码，实得 %v", out)
	}
	ticket, _ := out["ticket"].(string)
	if ticket == "" {
		t.Fatal("应携带 mfa 票据")
	}
	// ★legacy 123456 不再放行（此前裸 IP 演示站唯一的"二因子"）
	_, byp := doJSON(t, h, "POST", "/api/v1/portal/login", "",
		map[string]string{"username": "li.fang", "password": "baidi@123", "mfaCode": "123456"})
	if byp["token"] != nil {
		t.Fatalf("演示验证码不得绕过 TOTP，实得 %v", byp)
	}
	if byp["needTotp"] != true {
		t.Fatalf("应仍要求 TOTP，实得 %v", byp)
	}

	// 5) ★确认码不能在登录页重用（确认那步已消费该计数器）
	code, out = doJSON(t, h, "POST", "/api/v1/auth/totp", "",
		map[string]string{"ticket": ticket, "code": confirmCode})
	if code != http.StatusUnauthorized {
		t.Fatalf("确认码重用应 401，实得 %d %v", code, out)
	}

	// 6) 下一步长的码完成登录（+30s 在 ±1 步漂移窗内，且计数器 > 确认码的）
	nextCode, _ := totp.Code(sec, now.Add(totp.Period*time.Second))
	code, out = doJSON(t, h, "POST", "/api/v1/auth/totp", "",
		map[string]string{"ticket": ticket, "code": nextCode})
	if code != http.StatusOK || out["token"] == nil {
		t.Fatalf("正确验证码应发令牌，实得 %d %v", code, out)
	}
	sessTok, _ := out["token"].(string)
	if c, _ := doJSON(t, h, "GET", "/api/v1/portal/apps", sessTok, nil); c != http.StatusOK {
		t.Fatalf("会话令牌应可用，实得 %d", c)
	}

	// 7) ★同一个码第二次必拒（防重放：截获一次性码无用）
	if code, _ := doJSON(t, h, "POST", "/api/v1/auth/totp", "",
		map[string]string{"ticket": ticket, "code": nextCode}); code != http.StatusUnauthorized {
		t.Fatalf("同码二用应 401，实得 %d", code)
	}

	// 8) ★mfa 票据不是会话令牌：当 Bearer 调业务端点必须 403
	if code, _ := doJSON(t, h, "GET", "/api/v1/portal/apps", ticket, nil); code != http.StatusForbidden {
		t.Fatalf("mfa 票据当 Bearer 应 403，实得 %d", code)
	}
}

func TestTotpLoginRejects(t *testing.T) {
	h := totpFixture(t)
	tok, _ := loginResp(t, h, "li.fang")["token"].(string)
	code, enr := doJSON(t, h, "POST", "/api/v1/totp/enroll", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("enroll http %d", code)
	}
	sec := enr["secret"].(string)
	cc, _ := totp.Code(sec, time.Now())
	if code, _ := doJSON(t, h, "POST", "/api/v1/totp/confirm", tok, map[string]string{"code": cc}); code != http.StatusOK {
		t.Fatal("confirm 应成功")
	}
	ticket, _ := loginResp(t, h, "li.fang")["ticket"].(string)

	// 错码 → 401
	if code, _ := doJSON(t, h, "POST", "/api/v1/auth/totp", "",
		map[string]string{"ticket": ticket, "code": "000000"}); code != http.StatusUnauthorized {
		t.Fatalf("错码应 401，实得 %d", code)
	}
	// 会话令牌冒充 mfa 票据 → 401（verifyMfaTicket 只认 role=mfa）
	if code, _ := doJSON(t, h, "POST", "/api/v1/auth/totp", "",
		map[string]string{"ticket": userToken("li.fang"), "code": "123456"}); code != http.StatusUnauthorized {
		t.Fatalf("会话令牌当票据应 401，实得 %d", code)
	}
}

func TestTotpDisable(t *testing.T) {
	h := totpFixture(t)
	tok, _ := loginResp(t, h, "li.fang")["token"].(string)
	_, enr := doJSON(t, h, "POST", "/api/v1/totp/enroll", tok, nil)
	sec := enr["secret"].(string)
	now := time.Now()
	cc, _ := totp.Code(sec, now)
	if code, _ := doJSON(t, h, "POST", "/api/v1/totp/confirm", tok, map[string]string{"code": cc}); code != http.StatusOK {
		t.Fatal("confirm 应成功")
	}

	// 已生效的注册：不带码/带错码解绑 → 403（会话被劫持不等于拿到认证器）
	if code, _ := doJSON(t, h, "POST", "/api/v1/totp/disable", tok, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("无码解绑应 403，实得 %d", code)
	}
	// 出示下一步长的有效码 → 解绑成功，登录回到单因素
	next, _ := totp.Code(sec, now.Add(totp.Period*time.Second))
	if code, out := doJSON(t, h, "POST", "/api/v1/totp/disable", tok, map[string]string{"code": next}); code != http.StatusOK {
		t.Fatalf("解绑应成功，实得 %d %v", code, out)
	}
	if out := loginResp(t, h, "li.fang"); out["token"] == nil {
		t.Fatalf("解绑后应回到单因素，实得 %v", out)
	}
}

// 管理员重置 TOTP（helpdesk：用户丢了认证器，没有自助恢复码）。
// 收口与重置口令同款：普通用户目标要 PermSecurity；管理员目标抬到 PermAdmins。
func TestAdminResetTotp(t *testing.T) {
	h := totpFixture(t)

	// 给 li.fang 启用 TOTP
	tok, _ := loginResp(t, h, "li.fang")["token"].(string)
	_, enr := doJSON(t, h, "POST", "/api/v1/totp/enroll", tok, nil)
	sec := enr["secret"].(string)
	cc, _ := totp.Code(sec, time.Now())
	if code, _ := doJSON(t, h, "POST", "/api/v1/totp/confirm", tok, map[string]string{"code": cc}); code != http.StatusOK {
		t.Fatal("confirm 应成功")
	}
	if out := loginResp(t, h, "li.fang"); out["needTotp"] != true {
		t.Fatal("确认后登录应强制 TOTP")
	}

	// 普通用户令牌不能重置 → 403
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/users/u2/totp", userToken("wang.qiang"), nil); code != http.StatusForbidden {
		t.Fatal("普通用户不得重置他人 TOTP")
	}

	// root 重置 → 回到口令单因素
	if code, out := doJSON(t, h, "DELETE", "/api/v1/users/u2/totp", adminToken(), nil); code != http.StatusOK || out["removed"] != true {
		t.Fatalf("root 重置应成功，实得 %d %v", code, out)
	}
	if out := loginResp(t, h, "li.fang"); out["token"] == nil {
		t.Fatalf("重置后应回到单因素，实得 %v", out)
	}

	// ★目标是管理员时门槛抬到 PermAdmins：security 角色的管理员给 root 挂上 TOTP 后
	// 不能再由 security 清掉（能清 root 的二因子 + 能重置口令 = 全权接管，两道必须同门槛）。
	_, atok := doJSON(t, h, "POST", "/api/v1/auth/login", "",
		map[string]string{"username": "admin", "password": "baidi@123"})
	rootTok, _ := atok["token"].(string)
	if rootTok == "" {
		t.Fatalf("root 登录失败：%v", atok)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/admins", rootTok,
		map[string]string{"account": "sec.op", "name": "安全专员", "roleKey": "security", "password": "baidi@123456"}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("建 security 管理员失败 %d %v", code, out)
	}
	// root 自己注册 TOTP
	_, renr := doJSON(t, h, "POST", "/api/v1/totp/enroll", rootTok, nil)
	rsec := renr["secret"].(string)
	rcc, _ := totp.Code(rsec, time.Now())
	if code, _ := doJSON(t, h, "POST", "/api/v1/totp/confirm", rootTok, map[string]string{"code": rcc}); code != http.StatusOK {
		t.Fatal("root confirm 应成功")
	}
	// 查 root 的用户 id
	_, dir := doJSON(t, h, "GET", "/api/v1/users", rootTok, nil)
	rootID := ""
	for _, u := range dir["users"].([]any) {
		um := u.(map[string]any)
		if um["account"] == "admin" {
			rootID, _ = um["id"].(string)
		}
	}
	if rootID == "" {
		t.Fatal("找不到 root 的用户 id")
	}
	secTok := testKeys.Sign(auth.Claims{Sub: "sec.op", Role: "admin", Name: "sec.op"}, tokenTTL)
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/users/"+rootID+"/totp", secTok, nil); code != http.StatusForbidden {
		t.Fatalf("security 管理员清 root 的 TOTP 应 403（PermAdmins 门槛），实得 %d", code)
	}
	if code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+rootID+"/totp", rootTok, nil); code != http.StatusOK || out["removed"] != true {
		t.Fatalf("root 自清应成功，实得 %d %v", code, out)
	}
}

// 冻结的二次认证方式保存即拒（能力声明与校验同源）。
func TestSaveAuthPolicyRejectsFrozenMethods(t *testing.T) {
	h := totpFixture(t)
	body := map[string]any{
		"name": "测试策略", "directory": "local", "isDefault": false, "enabled": true,
		"pc":        map[string]any{"primary": "local", "secondary": []string{"sms"}},
		"mobile":    map[string]any{"primary": "local", "secondary": []string{}},
		"scopeOrgs": []string{"ext"}, "scopeGroups": []string{},
	}
	code, out := doJSON(t, h, "POST", "/api/v1/authpolicy", adminToken(), body)
	msg := ""
	if e, ok := out["error"].(map[string]any); ok {
		msg, _ = e["message"].(string)
	}
	if code != http.StatusBadRequest || !strings.Contains(msg, "不可选用") {
		t.Fatalf("sms 应保存即拒，实得 %d %v", code, out)
	}
	// totp 是真实现，应可保存
	body["pc"] = map[string]any{"primary": "local", "secondary": []string{"totp"}}
	if code, out := doJSON(t, h, "POST", "/api/v1/authpolicy", adminToken(), body); code != http.StatusOK {
		t.Fatalf("totp 应可保存，实得 %d %v", code, out)
	}
}

// GET /authpolicy 下发方式能力声明（前端置灰的数据源）。
func TestAuthPolicyMethodsCapabilities(t *testing.T) {
	h := totpFixture(t)
	code, out := doJSON(t, h, "GET", "/api/v1/authpolicy", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("http %d", code)
	}
	ms, _ := out["methods"].([]any)
	if len(ms) == 0 {
		t.Fatal("应下发 methods 能力声明")
	}
	avail := map[string]bool{}
	for _, m := range ms {
		mm := m.(map[string]any)
		avail[mm["key"].(string)] = mm["available"] == true
	}
	if !avail["totp"] || avail["sms"] || avail["radius"] || avail["cert"] || avail["http"] {
		t.Fatalf("只有 totp 可用，实得 %v", avail)
	}
}

// 迁移清洗：存量策略里未实现的方式被剔除，真实现的保留（store 层）。
func TestCleanFrozenSecondaryMethods(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "clean.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// 种子灌入后所有策略应已不含冻结方式（种子本身干净 + 清洗幂等）
	pols, err := st.AuthPolicies(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pols {
		for _, m := range append(p.PC.Secondary, p.Mobile.Secondary...) {
			if m != "totp" {
				t.Fatalf("策略 %s 残留冻结方式 %s", p.ID, m)
			}
		}
	}
}
