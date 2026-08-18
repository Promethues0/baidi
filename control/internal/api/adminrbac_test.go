package api

import (
	"net/http"
	"testing"

	"baidi.dev/control/internal/auth"
)

// 三权分立的**执行方**回归：requirePerm 真的挂在端点上。
//
// 每一条都是「能做的 2xx / 不能做的 403」两向断言——只测拒绝的话，
// 一个把所有人都拒掉的实现也能全绿，而那同样是坏的。

// adminTokenFor 以指定账号签一张 admin 会话令牌（角色不在令牌里，由库现算）。
func adminTokenFor(account string) string {
	return testKeys.Sign(auth.Claims{Sub: account, Role: "admin", Name: account}, tokenTTL)
}

// makeAdmin 用超管身份建一名指定角色的管理员，返回其会话令牌。
func makeAdmin(t *testing.T, h http.Handler, account, roleKey string) string {
	t.Helper()
	code, out := doJSON(t, h, "POST", "/api/v1/admins", adminToken(), map[string]any{
		"account": account, "name": account, "roleKey": roleKey,
	})
	if code != http.StatusCreated {
		t.Fatalf("建 %s 管理员 http %d: %v", roleKey, code, out)
	}
	return adminTokenFor(account)
}

// 三类角色 × 四个面的权限矩阵。
func TestAdminPowerSeparationMatrix(t *testing.T) {
	h := newTestServer(t)
	sysTok := makeAdmin(t, h, "sys.admin", "system")
	secTok := makeAdmin(t, h, "sec.admin", "security")
	audTok := makeAdmin(t, h, "aud.admin", "audit")
	rootTok := adminToken() // 种子 admin，回填为超管

	type probe struct {
		name         string
		method, path string
		body         any
		bodyPerRole  map[string]any // 需要唯一入参时按角色区分
		allowed      map[string]bool
	}
	cases := []probe{
		{
			name: "读全量审计（审计权）", method: "GET", path: "/api/v1/audit",
			allowed: map[string]bool{"root": true, "audit": true},
		},
		{
			name: "审计防篡改链校验（审计权）", method: "GET", path: "/api/v1/audit/verify",
			allowed: map[string]bool{"root": true, "audit": true},
		},
		{
			name: "新建用户（安全权）", method: "POST", path: "/api/v1/users",
			bodyPerRole: map[string]any{
				"root":     map[string]any{"name": "u-root", "account": "probe.root"},
				"system":   map[string]any{"name": "u-sys", "account": "probe.sys"},
				"security": map[string]any{"name": "u-sec", "account": "probe.sec"},
				"audit":    map[string]any{"name": "u-aud", "account": "probe.aud"},
			},
			allowed: map[string]bool{"root": true, "security": true},
		},
		{
			name: "新建组织（安全权）", method: "POST", path: "/api/v1/orgs",
			bodyPerRole: map[string]any{
				"root":     map[string]any{"name": "探针部-root"},
				"system":   map[string]any{"name": "探针部-sys"},
				"security": map[string]any{"name": "探针部-sec"},
				"audit":    map[string]any{"name": "探针部-aud"},
			},
			allowed: map[string]bool{"root": true, "security": true},
		},
		{
			name: "运维体检（系统权）", method: "GET", path: "/api/v1/diag",
			allowed: map[string]bool{"root": true, "system": true},
		},
		{
			name: "保存地址对象（系统权）", method: "POST", path: "/api/v1/objects/addr",
			bodyPerRole: map[string]any{
				"root":     map[string]any{"name": "探针-root", "kind": "ip", "value": "10.9.0.1"},
				"system":   map[string]any{"name": "探针-sys", "kind": "ip", "value": "10.9.0.2"},
				"security": map[string]any{"name": "探针-sec", "kind": "ip", "value": "10.9.0.3"},
				"audit":    map[string]any{"name": "探针-aud", "kind": "ip", "value": "10.9.0.4"},
			},
			allowed: map[string]bool{"root": true, "system": true},
		},
		{
			name: "分派管理员角色（管理员权，仅超管）", method: "PUT", path: "/api/v1/admins/aud.admin/role",
			body:    map[string]any{"roleKey": "audit"},
			allowed: map[string]bool{"root": true},
		},
	}

	toks := map[string]string{"root": rootTok, "system": sysTok, "security": secTok, "audit": audTok}
	for _, c := range cases {
		for _, role := range []string{"root", "system", "security", "audit"} {
			body := c.body
			if c.bodyPerRole != nil {
				body = c.bodyPerRole[role]
			}
			code, out := doJSON(t, h, c.method, c.path, toks[role], body)
			if c.allowed[role] {
				if code != http.StatusOK && code != http.StatusCreated {
					t.Errorf("%s：%s 角色应放行，得到 %d %v", c.name, role, code, out)
				}
				continue
			}
			if code != http.StatusForbidden {
				t.Errorf("%s：%s 角色应 403，得到 %d %v", c.name, role, code, out)
			}
		}
	}
}

// 安全管理员改得了策略、读不到审计；审计管理员反过来。这两条是三权分立的核心断言。
func TestSecurityAdminCannotReadAuditAndAuditAdminCannotWrite(t *testing.T) {
	h := newTestServer(t)
	secTok := makeAdmin(t, h, "sec2.admin", "security")
	audTok := makeAdmin(t, h, "aud2.admin", "audit")

	// 安全管理员：能存认证策略
	code, out := doJSON(t, h, "POST", "/api/v1/authpolicy", secTok, map[string]any{
		"name": "探针策略", "directory": "local", "enabled": true,
		"secondary": []string{},
		"scopeOrgs": []string{"dev"},
	})
	if code != http.StatusOK {
		t.Errorf("安全管理员应能存认证策略，得到 %d %v", code, out)
	}
	// 安全管理员：读不到审计（含导出）
	for _, p := range []string{"/api/v1/audit", "/api/v1/audit/verify", "/api/v1/audit/export"} {
		if code, out := doJSON(t, h, "GET", p, secTok, nil); code != http.StatusForbidden {
			t.Errorf("安全管理员读 %s 应 403，得到 %d %v", p, code, out)
		}
	}
	// 审计管理员：读得到审计
	if code, out := doJSON(t, h, "GET", "/api/v1/audit", audTok, nil); code != http.StatusOK {
		t.Errorf("审计管理员应能读审计，得到 %d %v", code, out)
	}
	// 审计管理员：改不了策略、改不了用户状态、动不了管理员
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/authpolicy", map[string]any{"name": "越权策略", "directory": "local"}},
		{"POST", "/api/v1/users/u1/status", map[string]any{"status": "disabled"}},
		{"POST", "/api/v1/security/baselines", map[string]any{"name": "越权基线"}},
		{"POST", "/api/v1/admins", map[string]any{"account": "x.y", "roleKey": "root"}},
		{"DELETE", "/api/v1/admins/sec2.admin", nil},
	} {
		if code, out := doJSON(t, h, c.method, c.path, audTok, c.body); code != http.StatusForbidden {
			t.Errorf("审计管理员 %s %s 应 403，得到 %d %v", c.method, c.path, code, out)
		}
	}
}

// 回填保证：升级后既有 admin 账号（种子 admin）仍能全权操作三个面。
func TestBackfilledAdminKeepsFullPower(t *testing.T) {
	h := newTestServer(t)
	tok := adminToken()
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/audit", nil},
		{"GET", "/api/v1/diag", nil},
		{"GET", "/api/v1/system", nil},
		{"POST", "/api/v1/orgs", map[string]any{"name": "回填探针部"}},
		{"POST", "/api/v1/admins", map[string]any{"account": "backfill.probe", "roleKey": "system"}},
	} {
		code, out := doJSON(t, h, c.method, c.path, tok, c.body)
		if code != http.StatusOK && code != http.StatusCreated {
			t.Errorf("回填后的超管 %s %s 应放行，得到 %d %v", c.method, c.path, code, out)
		}
	}
}

// 未分配角色的 admin 令牌 fail-closed：不是"查不到就当有权"。
// **读端点同样现算**：requireAdmin 也要过 AdminRoleFor，否则读面停在令牌快照上。
func TestAdminWithoutRoleIsDeniedNotAllowed(t *testing.T) {
	h := newTestServer(t)
	// 目录里根本不存在这个账号 → AdminRoleFor 找不到角色
	ghost := adminTokenFor("ghost.admin")
	for _, p := range []string{
		"/api/v1/audit", "/api/v1/diag", // requirePerm 端点
		"/api/v1/system", "/api/v1/users", "/api/v1/online", "/api/v1/orgs", // 只挂 requireAdmin 的读端点
	} {
		if code, out := doJSON(t, h, "GET", p, ghost, nil); code != http.StatusForbidden {
			t.Errorf("无角色的 admin 令牌访问 %s 应 403，得到 %d %v", p, code, out)
		}
	}
}

// 撤销管理员身份后，**读端点也立刻失效**——不是等 8h 令牌自然过期。
//
// 这条钉住的是"角色现算不进令牌"这条性质在读面的兑现：被撤销的人手里那张令牌
// 仍然合法（role=admin 是签发那一刻的事实），但目录里他已经不是管理员了，
// 用户目录 / 在线会话（账号 + 源 IP + 网关）/ 管理员清单一律不该再读得到。
func TestRemovedAdminLosesReadEndpointsImmediately(t *testing.T) {
	h := newTestServer(t)
	tok := makeAdmin(t, h, "revoke.me", "system")

	reads := []string{"/api/v1/users", "/api/v1/online", "/api/v1/system", "/api/v1/userstate", "/api/v1/groups"}
	for _, p := range reads {
		if code, out := doJSON(t, h, "GET", p, tok, nil); code != http.StatusOK {
			t.Fatalf("撤销前 %s 应 200，得到 %d %v", p, code, out)
		}
	}
	if code, out := doJSON(t, h, "DELETE", "/api/v1/admins/revoke.me", adminToken(), nil); code != http.StatusOK {
		t.Fatalf("撤销管理员 http %d: %v", code, out)
	}
	// 同一张（尚未过期的）令牌，撤销后一条都读不到
	for _, p := range reads {
		if code, out := doJSON(t, h, "GET", p, tok, nil); code != http.StatusForbidden {
			t.Errorf("撤销后 %s 应 403（令牌未过期但目录里已不是管理员），得到 %d %v", p, code, out)
		}
	}
}

// 安全管理员不得重置管理员账号的口令：那是一次请求打穿三权分立的最短路径
// （重置成自己知道的口令 → 用目标账号登录 → 拿到目标的全部权限）。
func TestSecurityAdminCannotResetAdminPassword(t *testing.T) {
	h := newTestServer(t)
	secTok := makeAdmin(t, h, "sec5.admin", "security")
	makeAdmin(t, h, "aud5.admin", "audit")
	audID := userIDOf(t, h, "aud5.admin")

	// 普通用户的口令仍归安全管理员管（这条是"没把闸修成一刀切"的证据）
	if code, out := doJSON(t, h, "POST", "/api/v1/users/u2/password", secTok,
		map[string]any{"password": "Normal@2026x"}); code != http.StatusOK {
		t.Fatalf("安全管理员重置普通用户口令应放行，得到 %d %v", code, out)
	}
	// 超管账号
	if code, out := doJSON(t, h, "POST", "/api/v1/users/u-admin/password", secTok,
		map[string]any{"password": "Attacker@2026x"}); code != http.StatusForbidden {
		t.Errorf("安全管理员重置超管口令应 403，得到 %d %v", code, out)
	}
	// 另一权的管理员账号
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+audID+"/password", secTok,
		map[string]any{"password": "Attacker@2026x"}); code != http.StatusForbidden {
		t.Errorf("安全管理员重置审计管理员口令应 403，得到 %d %v", code, out)
	}
	// 拒绝必须是真拒绝：超管的原口令仍然有效，新口令登不进去
	if code, out := doJSON(t, h, "POST", "/api/v1/auth/login", "",
		map[string]any{"username": "admin", "password": "Attacker@2026x"}); code == http.StatusOK && out["ok"] == true {
		t.Fatal("被拒的重置竟然生效了：攻击者口令能登录超管")
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/auth/login", "",
		map[string]any{"username": "admin", "password": seedInitialPassword}); code != http.StatusOK || out["ok"] != true {
		t.Fatalf("超管原口令应仍可登录，得到 %d %v", code, out)
	}
	// 持 admins 权的超管照常可以重置管理员口令（应急重置不能被这道闸堵死）
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+audID+"/password", adminToken(),
		map[string]any{"password": "Reset@2026x"}); code != http.StatusOK {
		t.Errorf("超管重置管理员口令应放行，得到 %d %v", code, out)
	}
}

// 安全管理员不得禁用/锁定另外两权的管理员：
// store.SetUserStatus 的防自锁只保护「最后一名可登录超管」，管不到 audit/system。
func TestSecurityAdminCannotDisableOtherPowerAdmins(t *testing.T) {
	h := newTestServer(t)
	secTok := makeAdmin(t, h, "sec6.admin", "security")
	makeAdmin(t, h, "aud6.admin", "audit")
	makeAdmin(t, h, "sys6.admin", "system")
	audID, sysID := userIDOf(t, h, "aud6.admin"), userIDOf(t, h, "sys6.admin")

	// 普通用户照常
	if code, out := doJSON(t, h, "POST", "/api/v1/users/u2/status", secTok,
		map[string]any{"status": "disabled"}); code != http.StatusOK {
		t.Fatalf("安全管理员禁用普通用户应放行，得到 %d %v", code, out)
	}
	for _, id := range []string{audID, sysID, "u-admin"} {
		for _, st := range []string{"disabled", "locked"} {
			if code, out := doJSON(t, h, "POST", "/api/v1/users/"+id+"/status", secTok,
				map[string]any{"status": st}); code != http.StatusForbidden {
				t.Errorf("安全管理员把管理员 %s 置「%s」应 403，得到 %d %v", id, st, code, out)
			}
		}
	}
	// 拒绝之后审计管理员仍读得到审计（"定策略的人关不掉看自己痕迹的人"）
	if code, out := doJSON(t, h, "GET", "/api/v1/audit", adminTokenFor("aud6.admin"), nil); code != http.StatusOK {
		t.Errorf("审计管理员应仍可读审计，得到 %d %v", code, out)
	}
	// 超管仍可禁用管理员（正常的人事变动不能被这道闸堵死）
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+audID+"/status", adminToken(),
		map[string]any{"status": "disabled"}); code != http.StatusOK {
		t.Errorf("超管禁用管理员应放行，得到 %d %v", code, out)
	}
}

// 访问者目录与对象库是管理配置，不对普通登录用户开放（这两条此前一道闸都没有：
// 门户里的任何账号都能拉走全量账号清单与内网地址对象）。
func TestDirectoryAndObjectsRequireAdmin(t *testing.T) {
	h := newTestServer(t)
	tok := userToken("li.fang")
	for _, p := range []string{"/api/v1/users", "/api/v1/objects"} {
		if code, out := doJSON(t, h, "GET", p, tok, nil); code != http.StatusForbidden {
			t.Errorf("普通用户读 %s 应 403，得到 %d %v", p, code, out)
		}
		if code, out := doJSON(t, h, "GET", p, adminToken(), nil); code != http.StatusOK {
			t.Errorf("管理员读 %s 应 200，得到 %d %v", p, code, out)
		}
	}
}

// userIDOf 按账号查目录用户 id。
func userIDOf(t *testing.T, h http.Handler, account string) string {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /users http %d: %v", code, out)
	}
	users, _ := out["users"].([]any)
	for _, u := range users {
		m := mapOf(t, u)
		if m["account"] == account {
			return m["id"].(string)
		}
	}
	t.Fatalf("目录里找不到账号 %s", account)
	return ""
}

// 防自锁在 REST 层的表现：最后一名超管降权/撤销/禁用都回 409，不是 500 也不是静默成功。
func TestLastRootAdminGuardOverREST(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()
	// 种子里 zhang.wei 展示角色含「管理员」，回填后也是超管——先收敛掉，
	// 否则测的不是"最后一名"。
	if code, out := doJSON(t, h, "PUT", "/api/v1/admins/zhang.wei/role", adm,
		map[string]any{"roleKey": "audit"}); code != http.StatusOK {
		t.Fatalf("收敛 zhang.wei http %d: %v", code, out)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"PUT", "/api/v1/admins/admin/role", map[string]any{"roleKey": "audit"}},
		{"DELETE", "/api/v1/admins/admin", nil},
		{"POST", "/api/v1/users/u-admin/status", map[string]any{"status": "disabled"}},
	} {
		code, out := doJSON(t, h, c.method, c.path, adm, c.body)
		if code != http.StatusConflict {
			t.Errorf("%s %s 应 409（防自锁），得到 %d %v", c.method, c.path, code, out)
		}
	}
	// 拒绝之后自己仍是超管（能继续管权限）
	if code, out := doJSON(t, h, "POST", "/api/v1/admins", adm,
		map[string]any{"account": "still.root", "roleKey": "system"}); code != http.StatusCreated {
		t.Fatalf("防自锁拒绝后超管应仍可管权限，得到 %d %v", code, out)
	}
}

// GET /api/v1/system 的内容来自库：新建的管理员出现在响应里，集群如实回未部署。
func TestSystemEndpointReflectsDatabase(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()
	makeAdmin(t, h, "sys3.admin", "system")

	code, out := doJSON(t, h, "GET", "/api/v1/system", adm, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /system http %d: %v", code, out)
	}
	admins, _ := out["admins"].([]any)
	found := false
	for _, a := range admins {
		m := mapOf(t, a)
		if m["account"] == "sys3.admin" {
			found = true
			if m["roleKey"] != "system" || m["roleName"] != "系统管理员" {
				t.Errorf("新建管理员的角色回显不对: %v", m)
			}
		}
		// 种子里那八个编造的管理员账号不该再出现
		if m["account"] == "ops.li" || m["account"] == "sec.zheng" || m["account"] == "aud.zhouji" {
			t.Errorf("种子管理员 %v 仍在响应里（这一页还在吃种子）", m["account"])
		}
	}
	if !found {
		t.Error("刚建的管理员不在 /system 响应里")
	}
	cluster := mapOf(t, out["cluster"])
	if cluster["deployed"] != false {
		t.Errorf("集群未实现，deployed 应为 false，得到 %v", cluster["deployed"])
	}
	if n, _ := cluster["distNodes"].([]any); len(n) != 0 {
		t.Errorf("集群节点应为空，得到 %v", n)
	}
	roles, _ := out["roles"].([]any)
	if len(roles) < 4 {
		t.Errorf("应下发内置四角色，得到 %d", len(roles))
	}
}

// POST /api/v1/users 这条路只建普通用户：请求体里带 role=admin 也不得造出管理员。
// 否则持安全权的管理员一次请求即可给自己造超管，三权分立当场失效。
func TestCreateUserCannotMintAdmin(t *testing.T) {
	h := newTestServer(t)
	secTok := makeAdmin(t, h, "sec4.admin", "security")
	code, out := doJSON(t, h, "POST", "/api/v1/users", secTok, map[string]any{
		"name": "提权尝试", "account": "escalate.me", "role": "admin",
	})
	if code != http.StatusCreated {
		t.Fatalf("建普通用户应成功，得到 %d %v", code, out)
	}
	// 新账号拿 admin 令牌也没有任何管理员角色 → 全面 403
	tok := adminTokenFor("escalate.me")
	for _, p := range []string{"/api/v1/audit", "/api/v1/diag"} {
		if code, _ := doJSON(t, h, "GET", p, tok, nil); code != http.StatusForbidden {
			t.Errorf("经 /users 建的账号不应有任何管理员权限，%s 得到 %d", p, code)
		}
	}
	// /system 里也不该出现它
	_, sys := doJSON(t, h, "GET", "/api/v1/system", adminToken(), nil)
	admins, _ := sys["admins"].([]any)
	for _, a := range admins {
		if mapOf(t, a)["account"] == "escalate.me" {
			t.Error("POST /users 造出了管理员账号")
		}
	}
}
