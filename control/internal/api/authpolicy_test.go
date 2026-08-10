package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/webauthnx"
)

// 认证策略脱 config-only 的端到端回归：策略在**登录链路**上真实生效，
// 而不是"表里有、页面看得见、登录时没人读"。
//
// 覆盖：每条真接线规则的命中/未命中、豁免命中时不要求、策略关闭回到基线、
// 判定写审计，以及最要紧的一条——**已注册 passkey 的账号不会被任何策略削弱**。

// policyEnv 起一套带真实 SQLite 的服务端；rp 非 nil 时 WebAuthn 已配置（走 needEnroll/needWebauthn 分支），
// nil 时回落 legacy 演示验证码路径（needMfa），后者更便于断言"要不要二次认证"这件事本身。
func policyEnv(t *testing.T, rp *webauthnx.RP) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), rp, nil, true)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), st
}

// loginFrom 以指定源 IP / 设备指纹发起门户登录（源 IP 与指纹都是策略判定的输入）。
func policyLogin(t *testing.T, h http.Handler, user, pw, remoteAddr, deviceID, mfaCode string) map[string]any {
	t.Helper()
	body := map[string]string{"username": user, "password": pw}
	if deviceID != "" {
		body["deviceId"] = deviceID
	}
	if mfaCode != "" {
		body["mfaCode"] = mfaCode
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("encode: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/v1/portal/login", &buf)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("portal login http %d: %s", rec.Code, rec.Body.String())
	}
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// savePolicy 保存一条策略（admin），返回 HTTP 状态码与响应体。
func savePolicy(t *testing.T, h http.Handler, p store.AuthPolicy) (int, map[string]any) {
	t.Helper()
	return doJSON(t, h, "POST", "/api/v1/authpolicy", adminToken(), p)
}

// vendorPolicy 一条绑在用户组上的加严策略（由调用方按需改写）。
func vendorPolicy(mut func(*store.AuthPolicy)) store.AuthPolicy {
	p := store.AuthPolicy{
		ID: "ap-test-vendor", Name: "外包协作 · 加严", Directory: "local", Priority: 5, Enabled: true,
		Scope: "外包协作组", PC: store.AuthMethodSet{Primary: "local"}, Mobile: store.AuthMethodSet{Primary: "local"},
		ScopeGroups: []string{"g-test-vendor"},
	}
	if mut != nil {
		mut(&p)
	}
	return p
}

// putVendorGroup 建一个用户组并把 li.fang 放进去（策略的适用范围据此匹配）。
func putVendorGroup(t *testing.T, h http.Handler) {
	t.Helper()
	adm := adminToken()
	if code, _ := doJSON(t, h, "POST", "/api/v1/groups", adm, map[string]any{
		"id": "g-test-vendor", "name": "外包协作组", "kind": "static"}); code != http.StatusOK {
		t.Fatalf("建用户组失败: %d", code)
	}
	if code, _ := doJSON(t, h, "PUT", "/api/v1/groups/g-test-vendor/members", adm,
		map[string]any{"accounts": []string{"li.fang"}}); code != http.StatusOK {
		t.Fatalf("设置组成员失败: %d", code)
	}
}

// auditHas 断言审计里存在一条满足条件的记录（判定必须留痕，否则"为什么要 MFA"无从回答）。
func auditHas(t *testing.T, st *store.SQLiteStore, category, contains string) bool {
	t.Helper()
	b, err := st.Audit(context.Background())
	if err != nil {
		t.Fatalf("读审计: %v", err)
	}
	for _, e := range b.Logs {
		if e.Category == category && strings.Contains(e.Event, contains) {
			return true
		}
	}
	return false
}

// ── 规则命中 / 未命中 / 策略关闭 ──

func TestPolicyAlwaysRuleDrivesStepUp(t *testing.T) {
	h, st := policyEnv(t, nil)
	putVendorGroup(t, h)

	// 基线：策略还没建，登录不需要二次认证。
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", ""); out["ok"] != true {
		t.Fatalf("基线应直接登录成功: %v", out)
	}

	if code, out := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) { p.Enhance.Always = true })); code != http.StatusOK {
		t.Fatalf("保存策略失败: %d %v", code, out)
	}
	out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", "")
	if out["needMfa"] != true {
		t.Fatalf("策略范围内账号应被要求二次认证: %v", out)
	}
	if r, _ := out["reason"].(string); !strings.Contains(r, "一律二次认证") || !strings.Contains(r, "外包协作 · 加严") {
		t.Fatalf("提示要说清是哪条策略哪条原因: %q", r)
	}
	if !auditHas(t, st, "auth", "要求二次认证") {
		t.Fatal("决策结果必须写审计（category=auth）")
	}

	// 组外账号不受影响（同一条策略，另一个人）。
	if out := policyLogin(t, h, "wang.qiang", "baidi@123", "203.0.113.7:5000", "", ""); out["ok"] != true {
		t.Fatalf("范围外账号不应被加严: %v", out)
	}

	// 策略停用 → 回到基线。
	if code, _ := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always, p.Enabled = true, false
	})); code != http.StatusOK {
		t.Fatal("停用策略保存失败")
	}
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", ""); out["ok"] != true {
		t.Fatalf("策略停用后应回到基线: %v", out)
	}
}

func TestPolicyOffHoursRule(t *testing.T) {
	h, _ := policyEnv(t, nil)
	putVendorGroup(t, h)

	// 工作时段覆盖全周全天 → 永远不算非工作时段（未命中）。
	if code, _ := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) {
		p.Enhance.OffHours = true
		p.Enhance.WorkStart, p.Enhance.WorkEnd = "00:00", "23:59"
		p.Enhance.WorkDays = []int{1, 2, 3, 4, 5, 6, 7}
	})); code != http.StatusOK {
		t.Fatal("保存策略失败")
	}
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", ""); out["ok"] != true {
		t.Fatalf("工作时段内不应要求二次认证: %v", out)
	}

	// 命中一侧不能写死某个钟点（测试跑在任意时刻），改用"工作日"这一维：
	// 「工作日=周一至周五」与「工作日=周六周日」两条配置对同一时刻必然一真一假。
	// 判定用的是服务器当前时间，因此这条断言与真实日期无关却仍然是真判定。
	weekdayPolicy := vendorPolicy(func(p *store.AuthPolicy) {
		p.Enhance.OffHours = true
		p.Enhance.WorkStart, p.Enhance.WorkEnd = "00:00", "23:59"
		p.Enhance.WorkDays = []int{1, 2, 3, 4, 5}
	})
	weekendPolicy := vendorPolicy(func(p *store.AuthPolicy) {
		p.Enhance.OffHours = true
		p.Enhance.WorkStart, p.Enhance.WorkEnd = "00:00", "23:59"
		p.Enhance.WorkDays = []int{6, 7}
	})
	if code, _ := savePolicy(t, h, weekdayPolicy); code != http.StatusOK {
		t.Fatal("保存策略失败")
	}
	a := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", "")["needMfa"] == true
	if code, _ := savePolicy(t, h, weekendPolicy); code != http.StatusOK {
		t.Fatal("保存策略失败")
	}
	b := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", "")["needMfa"] == true
	if a == b {
		t.Fatalf("「工作日=周一至周五」与「工作日=周末」两条配置必然一真一假，实测都为 %v", a)
	}
}

func TestPolicyTrustedNetworkExempts(t *testing.T) {
	h, st := policyEnv(t, nil)
	putVendorGroup(t, h)
	if code, out := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always = true
		p.Exempt.TrustedNetwork = true
		p.Exempt.Networks = []string{"10.8.0.0/16"}
	})); code != http.StatusOK {
		t.Fatalf("保存策略失败: %d %v", code, out)
	}

	// 内网来源：命中增强条件但被豁免 → 直接放行，且豁免这件事要留痕。
	if out := policyLogin(t, h, "li.fang", "baidi@123", "10.8.2.31:6000", "", ""); out["ok"] != true {
		t.Fatalf("可信网络应豁免二次认证: %v", out)
	}
	if !auditHas(t, st, "auth", "豁免二次认证") {
		t.Fatal("豁免也是一次发生过的判定，必须留痕")
	}
	// 网段外来源：照常要求二次认证。
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", ""); out["needMfa"] != true {
		t.Fatalf("网段外来源不应被豁免: %v", out)
	}
}

func TestPolicyTrustedDeviceExempts(t *testing.T) {
	h, _ := policyEnv(t, nil)
	putVendorGroup(t, h)

	// 先以合规终端上报一次 posture（策略尚未建立，登录不受阻）——这台设备就此"已登记"。
	sess, _ := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", "")["token"].(string)
	if sess == "" {
		t.Fatal("基线登录应拿到会话令牌")
	}
	code, verdict := doJSON(t, h, "POST", "/api/v1/posture", sess, map[string]any{
		"platform": "macOS", "os": "macOS 15.1", "clientVersion": "0.1.0", "device": "FP-MAC-TEST",
		"checks": []map[string]any{
			{"key": "disk_encrypted", "label": "磁盘已加密", "ok": true, "value": "on"},
			{"key": "sys_integrity", "label": "系统完整性保护开启", "ok": true, "value": "on"},
			{"key": "firewall_on", "label": "系统防火墙启用", "ok": true, "value": "on"},
			{"key": "os_version", "label": "系统版本合规", "ok": true, "value": "15.1"},
			{"key": "edr_online", "label": "EDR 终端防护在线", "ok": true, "value": "on"},
			{"key": "client_version", "label": "客户端为最新版本", "ok": true, "value": "0.1.0"},
		}})
	if code != http.StatusOK || verdict["verdict"] != "allow" {
		t.Fatalf("posture 上报应判定 allow: %d %v", code, verdict)
	}

	if code, _ := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always = true
		p.Exempt.TrustedDevice = true
	})); code != http.StatusOK {
		t.Fatal("保存策略失败")
	}
	// ★上报过 ≠ 授信：默认绑定方式是「审批绑定」，这台设备此刻是 pending。
	// 改造前这里只看"曾上报过 posture"，于是任何终端上报一次就自动拿到免二次认证资格，
	// 管理员在终端管理页的批准/吊销对登录链路毫无影响。现在两处同源（trusted_devices.status）。
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "FP-MAC-TEST", ""); out["needMfa"] != true {
		t.Fatalf("pending 设备（尚未批准）不应被豁免: %v", out)
	}

	// 管理员批准该终端后才豁免。
	approveDevice(t, h, "li.fang", "FP-MAC-TEST")
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "FP-MAC-TEST", ""); out["ok"] != true {
		t.Fatalf("授信终端应被豁免: %v", out)
	}
	// 吊销之后立刻失去豁免（同一条 status 判据，不需要用户重新登录以外的任何操作）。
	revokeDevice(t, h, "li.fang", "FP-MAC-TEST", "设备遗失")
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "FP-MAC-TEST", ""); out["needMfa"] != true {
		t.Fatalf("已吊销设备不应被豁免: %v", out)
	}
	approveDevice(t, h, "li.fang", "FP-MAC-TEST")
	// 换一台从没上报过的设备（以及浏览器登录不带指纹）→ 不豁免。
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "FP-OTHER", ""); out["needMfa"] != true {
		t.Fatalf("未登记设备不应被豁免: %v", out)
	}
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", ""); out["needMfa"] != true {
		t.Fatalf("不带指纹（浏览器登录）不应被豁免: %v", out)
	}
}

// 弱密码规则：强度在改密那一刻判定并落库，登录链路消费这个标记。
func TestPolicyWeakPasswordRule(t *testing.T) {
	h, _ := policyEnv(t, nil)
	adm := adminToken()
	putVendorGroup(t, h)
	if code, _ := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) { p.Enhance.WeakPwd = true })); code != http.StatusOK {
		t.Fatal("保存策略失败")
	}

	// 种子口令 baidi@123 是弱口令（不足 10 位且在常见弱口令表里）→ 命中。
	if out := policyLogin(t, h, "li.fang", "baidi@123", "203.0.113.7:5000", "", ""); out["needMfa"] != true {
		t.Fatalf("弱口令账号应被要求二次认证: %v", out)
	}

	// 管理员重置成一把强口令 → 强度标记随之更新，同一条策略不再命中。
	if code, _ := doJSON(t, h, "POST", "/api/v1/users/u2/password", adm,
		map[string]string{"password": "Kx9#mqrtvz"}); code != http.StatusOK {
		t.Fatal("重置口令失败")
	}
	out := policyLogin(t, h, "li.fang", "Kx9#mqrtvz", "203.0.113.7:5000", "", "")
	// 管理员重置会置首登改密：认证已过（没有 needMfa），只是令牌被降级。
	if out["needMfa"] == true {
		t.Fatalf("强口令不应再命中弱密码规则: %v", out)
	}
	if out["mustChangePassword"] != true {
		t.Fatalf("管理员重置后应走首登改密: %v", out)
	}
}

// ★最要紧的一条：已注册 passkey 的账号，任何策略配置都不能把它降级成单因素。
// 策略只能加强，不能削弱——豁免规则压制的只是策略性增强要求。
func TestRegisteredPasskeyNeverWeakenedByPolicy(t *testing.T) {
	rp, err := webauthnx.New("localhost", "http://localhost:5193", "白帝测试")
	if err != nil || rp == nil {
		t.Fatalf("构造 RP: %v", err)
	}
	h, st := policyEnv(t, rp)
	putVendorGroup(t, h)
	ctx := context.Background()

	cred, _, _ := st.Credential(ctx, "li.fang")
	if _, err := st.SaveWebauthnCredential(ctx, store.WebauthnCredential{
		UserID: cred.ID, Account: "li.fang", CredentialID: "cred-li-1",
		PublicKey: "cHVibGljLWtleQ", Transports: `["internal"]`, Name: "Touch ID",
	}); err != nil {
		t.Fatalf("落 passkey 凭据: %v", err)
	}

	// 一条"什么都豁免"的策略：可信网络 + 授信终端全开，且源 IP 正好在网段内。
	if code, out := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always = true
		p.Exempt.TrustedNetwork, p.Exempt.Networks = true, []string{"10.8.0.0/16"}
		p.Exempt.TrustedDevice = true
	})); code != http.StatusOK {
		t.Fatalf("保存策略失败: %d %v", code, out)
	}
	out := policyLogin(t, h, "li.fang", "baidi@123", "10.8.2.31:6000", "FP-MAC-TEST", "")
	if out["needWebauthn"] != true || out["ok"] == true {
		t.Fatalf("已注册 passkey 的账号必须强制断言，豁免规则不得削弱它: %v", out)
	}
	if out["ticket"] == "" {
		t.Fatal("强制断言应下发一次性票据")
	}

	// 连策略都删掉，强制断言依旧（这条与策略无关，是账号自身的强认证因子）。
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/authpolicy/ap-test-vendor", adminToken(), nil); code != http.StatusOK {
		t.Fatal("删除策略失败")
	}
	if out := policyLogin(t, h, "li.fang", "baidi@123", "10.8.2.31:6000", "FP-MAC-TEST", ""); out["needWebauthn"] != true {
		t.Fatalf("无策略时也应强制断言: %v", out)
	}
}

// 判不了的规则既不可保存、也在能力清单里明确标注不可用（不是静默无效）。
func TestFrozenRulesRejectedOnSave(t *testing.T) {
	h, _ := policyEnv(t, nil)
	putVendorGroup(t, h)

	cases := []struct {
		name     string
		mut      func(*store.AuthPolicy)
		contains string
	}{
		{"异地登录", func(p *store.AuthPolicy) { p.Enhance.GeoAnomaly = true }, "IP 地理库"},
		{"Windows 域", func(p *store.AuthPolicy) { p.Exempt.WinDomain = true }, "域校验"},
		{"可信网络空网段", func(p *store.AuthPolicy) { p.Exempt.TrustedNetwork = true }, "至少配置一个网段"},
		{"非默认策略无范围", func(p *store.AuthPolicy) { p.ScopeGroups = nil }, "必须绑定适用范围"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := savePolicy(t, h, vendorPolicy(c.mut))
			if code != http.StatusBadRequest {
				t.Fatalf("应 400 拒绝，got %d %v", code, out)
			}
			errObj, _ := out["error"].(map[string]any)
			if msg, _ := errObj["message"].(string); !strings.Contains(msg, c.contains) {
				t.Fatalf("拒绝原因应说清问题: %v", out)
			}
		})
	}

	// 能力清单随策略一起下发，前端据此置灰并显示原因。
	code, out := doJSON(t, h, "GET", "/api/v1/authpolicy", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读策略失败: %d", code)
	}
	caps, _ := out["capabilities"].([]any)
	if len(caps) == 0 {
		t.Fatal("响应应带能力声明（置灰与保存校验必须同源）")
	}
	frozen := 0
	for _, c := range caps {
		m, _ := c.(map[string]any)
		if m["available"] == false {
			frozen++
			if r, _ := m["reason"].(string); r == "" {
				t.Errorf("%v 不可用却没说原因", m["key"])
			}
		}
		if e, _ := m["effect"].(string); e == "" {
			t.Errorf("%v 缺少生效说明", m["key"])
		}
	}
	if frozen != 2 {
		t.Fatalf("当前应恰有 2 条不可用规则（异地登录 / Windows 域），实为 %d", frozen)
	}
}

// 种子策略里不能躺着"配了不生效"的开关（冻结规则一律为关；可信网络必配网段）。
func TestSeedPoliciesHaveNoDeadSwitches(t *testing.T) {
	_, st := policyEnv(t, nil)
	pols, err := st.AuthPolicies(context.Background())
	if err != nil {
		t.Fatalf("读策略: %v", err)
	}
	if len(pols) == 0 {
		t.Fatal("种子应至少有一条策略")
	}
	for _, p := range pols {
		if p.Enhance.GeoAnomaly || p.Exempt.WinDomain {
			t.Errorf("种子策略 %s 打开了已冻结的规则", p.ID)
		}
		if p.Exempt.TrustedNetwork && len(p.Exempt.Networks) == 0 {
			t.Errorf("种子策略 %s 开了可信网络却没配网段（永远不会命中）", p.ID)
		}
		if !p.IsDefault && len(p.ScopeOrgs)+len(p.ScopeGroups) == 0 {
			t.Errorf("种子策略 %s 是非默认策略却没绑定适用范围（匹配不到任何账号）", p.ID)
		}
	}
}

// ── 用户目录候选：必须是登录链路真会给出的取值 ──
//
// 控制台的「所属用户目录」下拉此前接在 GET /api/v1/authsrc 的演示种子上
// （恒定只有 local 与 ad），而登录链路把 Directory 置成**真实认证源的 kind**。
// 于是管理员真配一个 LDAP/OIDC 源之后，那批人登录时一条策略都匹配不到
// （Match 按目录先筛一刀），而策略页上根本选不出 ldap/oidc——配不出、也修不了。
func TestAuthDirectoriesComeFromRealSources(t *testing.T) {
	h, _ := policyEnv(t, nil)
	adm := adminToken()

	dirs := func() map[string]map[string]any {
		code, out := doJSON(t, h, "GET", "/api/v1/authpolicy", adm, nil)
		if code != http.StatusOK {
			t.Fatalf("读策略 http %d: %v", code, out)
		}
		list, _ := out["directories"].([]any)
		if len(list) == 0 {
			t.Fatal("响应应带用户目录候选（下拉与保存校验必须同源）")
		}
		m := map[string]map[string]any{}
		for _, d := range list {
			dm := mapOf(t, d)
			m[dm["key"].(string)] = dm
		}
		return m
	}

	// 只有本地源时：本地目录恒在；种子策略用到的 ad 保留（否则一编辑就被自己的校验拒掉），
	// 但如实标注"当前没有已配置的认证源"。
	before := dirs()
	if _, ok := before["local"]; !ok {
		t.Error("本地目录必须恒在候选里")
	}
	if d, ok := before["ad"]; !ok {
		t.Error("存量策略用到的目录必须保留在候选里，否则管理员编辑不了它")
	} else if d["configured"] != false {
		t.Error("没有已配置 AD 源时 ad 目录应标为 configured=false")
	}
	if _, ok := before["ldap"]; ok {
		t.Error("没配 LDAP 源时不该凭空出现 ldap 目录")
	}

	// 真配一个 LDAP 源 → ldap 目录立刻出现在候选里，并标为已配置
	if code, out := doJSON(t, h, "POST", "/api/v1/authsrc/sources", adm, map[string]any{
		"name": "研发 LDAP", "kind": "ldap", "enabled": true,
		"config": `{"url":"ldap://127.0.0.1:389","baseDn":"dc=corp,dc=local"}`,
	}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("建 LDAP 源 http %d: %v", code, out)
	}
	after := dirs()
	d, ok := after["ldap"]
	if !ok {
		t.Fatal("配了 LDAP 源之后 ldap 必须出现在目录候选里——否则永远绑不出一条能命中的策略")
	}
	if d["configured"] != true {
		t.Errorf("已配置的源对应的目录应 configured=true: %v", d)
	}
	if srcs, _ := d["sources"].([]any); len(srcs) != 1 || srcs[0] != "研发 LDAP" {
		t.Errorf("目录应回带认证源名，便于认出这条策略管的是哪个源: %v", d["sources"])
	}

	// 现在这条 ldap 策略存得进去（此前保存都无从谈起，因为选不出这个目录）
	putVendorGroup(t, h)
	if code, out := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) {
		p.ID, p.Directory = "ap-test-ldap", "ldap"
	})); code != http.StatusOK {
		t.Fatalf("绑真实 LDAP 目录的策略应存得进去，得到 %d %v", code, out)
	}
	// 而拼错的目录一律拒：存进去也永远匹配不到任何账号
	code, out := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) {
		p.ID, p.Directory = "ap-test-typo", "ldaps"
	}))
	if code != http.StatusBadRequest {
		t.Fatalf("不存在的用户目录应 400，得到 %d %v", code, out)
	}
}

// 适用范围引用的组织/用户组必须真实存在——与资源授权的 validateSubjects 同一条纪律。
// 拼错一个 id：covers() 恒 false，策略页上"绑好了"、登录时一次都不命中，
// 而且是**放松**方向（该二次认证的人静默走了单因素）。
func TestAuthPolicyScopeRefsValidatedOnSave(t *testing.T) {
	h, _ := policyEnv(t, nil)
	putVendorGroup(t, h)

	for _, c := range []struct {
		name     string
		mut      func(*store.AuthPolicy)
		contains string
	}{
		{"组织不存在", func(p *store.AuthPolicy) {
			p.ScopeGroups, p.ScopeOrgs = nil, []string{"no-such-org"}
		}, "授权组织 no-such-org 不存在"},
		{"用户组不存在", func(p *store.AuthPolicy) {
			p.ScopeGroups = []string{"g-typo"}
		}, "授权用户组 g-typo 不存在"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := savePolicy(t, h, vendorPolicy(c.mut))
			if code != http.StatusBadRequest {
				t.Fatalf("应 400 拒绝，得到 %d %v", code, out)
			}
			errObj, _ := out["error"].(map[string]any)
			if msg, _ := errObj["message"].(string); !strings.Contains(msg, c.contains) {
				t.Fatalf("拒绝原因应指名道姓: %v", out)
			}
		})
	}
	// 真实存在的范围照常存得进去
	if code, out := savePolicy(t, h, vendorPolicy(func(p *store.AuthPolicy) {
		p.ScopeOrgs = []string{"dev"}
	})); code != http.StatusOK {
		t.Fatalf("真实存在的范围应放行，得到 %d %v", code, out)
	}
}

// 删除守卫在 REST 层的表现：被认证策略引用的组织/用户组回 409（不是 500、不是静默成功）。
func TestDeleteSubjectReferencedByAuthPolicyIs409(t *testing.T) {
	h, _ := policyEnv(t, nil)
	adm := adminToken()
	putVendorGroup(t, h)
	if code, out := savePolicy(t, h, vendorPolicy(nil)); code != http.StatusOK {
		t.Fatalf("存策略 http %d: %v", code, out)
	}
	code, out := doJSON(t, h, "DELETE", "/api/v1/groups/g-test-vendor", adm, nil)
	if code != http.StatusConflict {
		t.Fatalf("被策略引用的用户组应 409，得到 %d %v", code, out)
	}
	// 组还在，策略也还在（拒删不能是"删一半"）
	if code, out := doJSON(t, h, "GET", "/api/v1/groups", adm, nil); code != http.StatusOK ||
		!strings.Contains(jsonStr(t, out), "g-test-vendor") {
		t.Fatalf("拒删之后用户组应还在: %d %v", code, out)
	}
}

// jsonStr 把响应体重新序列化成字符串，便于做"含某个 id"这类粗粒度断言。
func jsonStr(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
