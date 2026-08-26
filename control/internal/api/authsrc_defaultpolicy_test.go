package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/authpolicy"
	"baidi.dev/control/internal/store"
)

// FR-AUTH-10（P0）：接入一个用户目录后，系统必须为它自动生成默认认证策略。
//
// ★不生成的后果是一条彻底静默的认证降级：登录链路把 Directory 置成该源的 kind，
// 而 authpolicy.Match 第一刀按目录筛 —— 库里一条该目录的策略都没有 → Evaluate 返回
// 零值 Decision → 二次认证要求为零，且 secondFactor 在零值分支两个 case 都不进，
// **审计里连「本次未要求二次认证」都没有**。而认证策略页只按「已有策略」分组渲染，
// 接了 LDAP 之后页面上根本不多出这一栏，管理员看到的与接入前一模一样。
func TestSaveAuthSourceCreatesDirectoryDefaultPolicy(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()

	before := map[string]bool{}
	pols, err := f.st.AuthPolicies(ctx)
	if err != nil {
		t.Fatalf("读策略: %v", err)
	}
	for _, p := range pols {
		before[strings.ToLower(p.Directory)] = true
	}
	if before["ldap"] {
		t.Skip("种子里已有 ldap 策略，本用例的前提不成立")
	}

	code, out := doJSON(t, f.h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
		"name": "总部 LDAP", "kind": "ldap", "enabled": true, "priority": 10,
		"config": map[string]any{"host": "ldap.corp.internal", "port": 389, "baseDn": "dc=corp,dc=internal"},
	})
	if code != http.StatusOK {
		t.Fatalf("保存认证源应成功，实得 %d: %v", code, out)
	}
	if out["policyCreated"] != true {
		t.Errorf("回执应告知已自动生成默认策略（管理员据此知道去哪里调整），实得 %v", out["policyCreated"])
	}

	pols, err = f.st.AuthPolicies(ctx)
	if err != nil {
		t.Fatalf("读策略: %v", err)
	}
	var def *store.AuthPolicy
	for i := range pols {
		if strings.EqualFold(pols[i].Directory, "ldap") {
			def = &pols[i]
		}
	}
	if def == nil {
		t.Fatal("接入 ldap 源后必须存在该目录的策略 —— 否则该目录用户登录时 Match 找不到、" +
			"Evaluate 返回零值、二次认证要求为零，且一条审计都不写")
	}
	if !def.IsDefault || !def.Enabled {
		t.Errorf("自动生成的应是**启用中的默认策略**，实得 isDefault=%v enabled=%v", def.IsDefault, def.Enabled)
	}
	// ★行为判据：该目录的登录必须能匹配到策略（不再落进零值分支）。
	if _, ok := authpolicy.Match(pols, authpolicy.Input{Account: "someone", Directory: "ldap"}); !ok {
		t.Error("该目录的登录仍匹配不到任何策略 —— 自动生成等于没生成")
	}
	// ★同种子里 local 那条的纪律：不替管理员做加严决策。自动生成的策略
	//   判定行为与"没有策略"一致，这条修复改变的是**可见性**而不是强度。
	if def.Enhance.Always || def.Enhance.WeakPwd || def.Enhance.OffHours {
		t.Error("自动生成的默认策略不得开启增强规则：那是替管理员做加严决策，" +
			"接入一条 LDAP 就把全目录抬到二次认证会打穿正在用的登录流程")
	}
	for _, m := range def.Secondary {
		if m != "totp" {
			t.Errorf("Secondary 只许出现真实现的方式，实得 %q（sms/radius/cert/http 均已冻结）", m)
		}
	}
}

// 重复保存同一个源、或再接一条同 kind 的源，都不该重复建策略
// （一个 kind 就是一个用户目录，多条 LDAP 源共享同一份策略）。
func TestDefaultPolicyNotDuplicated(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()
	mk := func(name string) map[string]any {
		return map[string]any{
			"name": name, "kind": "ldap", "enabled": true, "priority": 10,
			"config": map[string]any{"host": "x.internal", "port": 389, "baseDn": "dc=x"},
		}
	}
	if code, out := doJSON(t, f.h, "POST", "/api/v1/authsrc/sources", adminToken(), mk("源一")); code != http.StatusOK {
		t.Fatalf("首个源应成功 %d: %v", code, out)
	}
	code, out := doJSON(t, f.h, "POST", "/api/v1/authsrc/sources", adminToken(), mk("源二"))
	if code != http.StatusOK {
		t.Fatalf("第二个源应成功 %d: %v", code, out)
	}
	if out["policyCreated"] == true {
		t.Error("同一目录的第二个源不该再建一条默认策略")
	}
	pols, _ := f.st.AuthPolicies(ctx)
	n := 0
	for _, p := range pols {
		if strings.EqualFold(p.Directory, "ldap") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("ldap 目录应恰有 1 条策略，实得 %d", n)
	}
}
