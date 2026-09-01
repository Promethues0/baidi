package api

import (
	"net/http"
	"strings"
	"testing"
)

// 多认证域部署下，**本地口令输错**必须照常计入防爆破并落审计（FR-AUTH-09 + FR-MON-14/17）。
//
// ★缺陷原样：`routeDirectory` 在「启用中的外部源 ≥2 且未指定 directory」时回
// errAmbiguousDirectory，门户登录在这条分支上直接 return——不计锁定、不写审计。
// 那个豁免的本意是放过「合法外部用户忘了选域」，但它对**本地口令账号**同样生效：
//
//	部署一旦接了两个外部源（PRD FR-USER-01 正要求多目录并存），攻击者对
//	/portal/login 反复提交 {username: admin, password: 猜的} 且不带 directory，
//	每一次都从那里 return——账号维与 IP 维的计数一次不加、审计一条不写；
//	而口令一旦**猜对**，代码根本不进这个 if 块，直接登录成功。
//	响应差异构成一个干净的口令预言机，且整段爆破在「用户状态」「爆破锁定 IP」
//	两张表与审计中心里恒不可见。
//
// 收口后的不变式：**一次输错的本地口令算不算数，不该随部署接了几个认证源而改变。**
func TestLocalPasswordFailureCountedWithMultipleDirectories(t *testing.T) {
	h := newTestServer(t)

	// 接两个外部源 → 未指定 directory 时进入 ambiguous 分支。
	for _, s := range []struct{ id, name string }{{"ad1", "总部 AD"}, {"ldap2", "供应商 LDAP"}} {
		if code, out := doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
			"id": s.id, "name": s.name, "kind": "ad", "enabled": true,
			"config": map[string]any{"host": "dc.example", "baseDn": "DC=x"},
		}); code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("建认证源 %s http %d: %v", s.id, code, out)
		}
	}

	// 对**本地口令账号** li.fang 连续猜错口令、不带 directory。
	//
	// ★循环要容忍「锁定生效后进门锁直接 403」——那正是这条修复要达到的效果：
	//   计数生效之后，第 N 次尝试会被 loginGateLocked 在最前面拦掉。
	//   把 403 当失败会让这个测试在**修好的实现上**变红。
	const tries = 8
	sawLocalReason, gated := false, false
	for i := 0; i < tries; i++ {
		code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{
			"username": "li.fang", "password": "wrong-guess",
		})
		if code == http.StatusForbidden || code == http.StatusTooManyRequests {
			gated = true // 进门锁已生效
			break
		}
		if code != http.StatusOK {
			t.Fatalf("第 %d 次应回 200 + ok:false 或被进门锁拦下，得到 %d", i+1, code)
		}
		if out["ok"] == true {
			t.Fatalf("第 %d 次不该放行", i+1)
		}
		// 仍然把候选带回去（他可能确实是域账号打错了地方），但话要说清。
		if strings.Contains(str(out["reason"]), "口令错误") {
			sawLocalReason = true
		}
	}
	if !sawLocalReason {
		t.Fatal("本地账号口令错误时要说实话：候选下拉里根本没有「本地目录」这一项，" +
			"让他去选一个不存在的选项，他永远看不到「口令错了」这句话")
	}
	if !gated {
		t.Fatalf("连续 %d 次本地口令错误后，进门锁应当已经把后续尝试挡在最前面", tries)
	}

	// ① 账号维锁定必须已经生效——爆破在这一路上不再隐形。
	code, out := doJSON(t, h, "GET", "/api/v1/security/lockouts", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET lockouts http %d", code)
	}
	locks, _ := out["lockouts"].([]any)
	hit := false
	for _, raw := range locks {
		m, _ := raw.(map[string]any)
		if strings.Contains(str(m["key"]), "li.fang") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("连续 %d 次本地口令错误后应出现锁定记录，实得 %v —— "+
			"说明多认证域部署下这条爆破路径依然不计数（口令预言机仍然成立）", tries, out["lockouts"])
	}

	// ② 审计里查得到——管理员在控制台上要能看见正在发生的爆破。
	code, aud := doJSON(t, h, "GET", "/api/v1/audit?category=auth&q=本地口令错误", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET audit http %d", code)
	}
	if total, _ := aud["total"].(float64); int(total) == 0 {
		t.Fatal("这类失败必须落审计：否则审计中心对整段爆破恒为空")
	}
}

// 反向：**外部**账号（本地没有口令哈希）忘了选域时，原来的豁免必须还在——
// 他什么都没输错，计进去连申诉机会都没有。
func TestExternalUserMissingDirectoryStillExempt(t *testing.T) {
	h := newTestServer(t)
	for _, s := range []struct{ id, name string }{{"ad1", "总部 AD"}, {"ldap2", "供应商 LDAP"}} {
		doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
			"id": s.id, "name": s.name, "kind": "ad", "enabled": true,
			"config": map[string]any{"host": "dc.example", "baseDn": "DC=x"},
		})
	}
	const tries = 8
	for i := 0; i < tries; i++ {
		doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{
			"username": "someone.external", "password": "whatever",
		})
	}
	_, out := doJSON(t, h, "GET", "/api/v1/security/lockouts", adminToken(), nil)
	for _, raw := range out["lockouts"].([]any) {
		m, _ := raw.(map[string]any)
		if strings.Contains(str(m["key"]), "someone.external") {
			t.Fatalf("本地目录里根本没有这个账号，他只是没选域——不该计入锁定：%v", m)
		}
	}
}
