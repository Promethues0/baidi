package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// ── 组织/用户组授权：控制面两个判定点的同构测试 ──
//
// 这是本特性的核心风险点。控制面把「组织/用户组」展开成账号后并进 AllowUsers 下发网关，
// 而客户端剖面自己算一遍可达性。两处若分叉：
//   - 剖面窄、网关宽 → 「审批/授权批了却连不上」（用户看不到任何报错）；
//   - 剖面宽、网关窄 → 流量被接管进隧道再被拒，表现成"时通时不通"。
//
// 故每个场景都**同时**断言两侧，且必须同真同假。

// gatewayAuthorize 逐字复刻数据面 gateway/internal/resource.(*Registry).Authorize。
//
// ★为什么是复刻而不是 import：control 与 gateway 是两个独立 module（Go 版本都不同），
// 测试不可能链进真网关代码。复刻的代价是"网关改了这里没跟着改"，故此处刻意只有三行、
// 与源实现逐句对应；网关那份的语义（都空=不限、EqualFold 比对）是本测试的全部前提。
func gatewayAuthorize(user, role string, allowUsers, allowRoles []string) bool {
	hit := func(ss []string, v string) bool {
		for _, s := range ss {
			if strings.EqualFold(s, v) {
				return true
			}
		}
		return false
	}
	if len(allowUsers) > 0 && hit(allowUsers, user) {
		return true
	}
	if len(allowRoles) > 0 && hit(allowRoles, role) {
		return true
	}
	return len(allowUsers) == 0 && len(allowRoles) == 0
}

// isoFixture 一套能同时驱动两个判定点的环境：真 SQLite + 路由 handler + Server 本体。
type isoFixture struct {
	t  *testing.T
	st *store.SQLiteStore
	s  *Server
	h  http.Handler
}

func newIsoFixture(t *testing.T) *isoFixture {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "iso.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	return &isoFixture{t: t, st: st, s: s, h: auth.Middleware(testKeys, s.IsOpen)(s.Routes())}
}

// saveResource 经真实管理端点落一条资源（顺带覆盖主体存在性校验）。
func (f *isoFixture) saveResource(res map[string]any) (int, map[string]any) {
	f.t.Helper()
	return doJSON(f.t, f.h, "POST", "/api/v1/resources", adminToken(), res)
}

// gwAllow 拉一次网关策略，返回该资源下发的 allowUsers / allowRoles。
func (f *isoFixture) gwAllow(resID string) (users, roles []string, found bool) {
	f.t.Helper()
	code, out := doJSON(f.t, f.h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if code != http.StatusOK {
		f.t.Fatalf("gateways/policy http %d", code)
	}
	arr, _ := out["resources"].([]any)
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok || m["id"] != resID {
			continue
		}
		if m["allowGroups"] != nil || m["allowOrgs"] != nil {
			f.t.Fatalf("下发给网关的资源不该带组织/用户组字段（数据面不做策略推导）：%v", m)
		}
		return strSlice(m["allowUsers"]), strSlice(m["allowRoles"]), true
	}
	return nil, nil, false
}

func strSlice(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// profileHasRoute 剖面里该应用是否既标记可访问、又真的排出了 resmap 与路由。
// 只看 Accessible 是不够的：真正决定"点开能不能用"的是 resmap + routes 那两条。
func (f *isoFixture) profileHasRoute(user, role, appID, backend, resID string, apps store.AppBundle) bool {
	f.t.Helper()
	rs, err := f.st.Resources(context.Background())
	if err != nil {
		f.t.Fatalf("Resources: %v", err)
	}
	p := f.s.buildProfile(context.Background(), user, role, apps, rs)
	a, ok := findApp(p, appID)
	if !ok || !a.Accessible {
		return false
	}
	if p.Resmap[backend] != resID {
		return false
	}
	host, _, _ := strings.Cut(backend, ":")
	return hasRoute(p.Routes, host+"/32")
}

// isoApps 一个桥接到 r-org 资源的应用。
func isoApps() store.AppBundle {
	return store.AppBundle{Apps: []store.App{
		{ID: "app-org", Name: "组织授权应用", Addr: "10.20.8.8:8080", Mode: "web",
			Category: "office", Status: "running", ResourceID: "r-org"},
	}}
}

// ★核心用例：用户**仅因所属组织**被授权（没有角色、没有点名账号）。
// 剖面必须排出路由，网关策略里该账号必须在允许集合内——两者同真。
func TestOrgSubjectIsomorphicProfileAndGatewayPolicy(t *testing.T) {
	f := newIsoFixture(t)
	// chen.jing(u6) 属研发部 dev，角色 user；资源只授权给**根组织**（靠子树继承覆盖到他）
	code, out := f.saveResource(map[string]any{
		"id": "r-org", "name": "组织授权资源", "backend": "10.20.8.8:8080",
		"allowRoles": []string{}, "allowUsers": []string{}, "allowOrgs": []string{"root"},
	})
	if code != http.StatusOK {
		t.Fatalf("保存资源 http %d: %v", code, out)
	}

	users, roles, found := f.gwAllow("r-org")
	if !found {
		t.Fatal("资源未下发给网关")
	}
	gwOK := gatewayAuthorize("chen.jing", "user", users, roles)
	profOK := f.profileHasRoute("chen.jing", "user", "app-org", "10.20.8.8:8080", "r-org", isoApps())
	if !gwOK || !profOK {
		t.Fatalf("仅因组织被授权的用户两侧都应放行：网关=%v 剖面=%v（下发 allowUsers=%v）", gwOK, profOK, users)
	}

	// 不在该组织树内的账号：两侧同时为假。构造一个无组织归属的外部账号。
	if err := f.st.SetUserOrg(context.Background(), "u2", ""); err != nil { // u2 = li.fang
		t.Fatalf("SetUserOrg: %v", err)
	}
	users, roles, _ = f.gwAllow("r-org")
	gwOK = gatewayAuthorize("li.fang", "user", users, roles)
	profOK = f.profileHasRoute("li.fang", "user", "app-org", "10.20.8.8:8080", "r-org", isoApps())
	if gwOK || profOK {
		t.Fatalf("无组织归属的账号两侧都应拒绝：网关=%v 剖面=%v（下发 allowUsers=%v）", gwOK, profOK, users)
	}
}

// 用户从组织移出后**立即**失去访问：展开是每次下发现算的，不缓存。
// 两侧必须同时翻假——只翻一侧就是「控制台看着已撤权、隧道还通着」或反过来。
func TestOrgSubjectRevokedImmediatelyOnMoveOut(t *testing.T) {
	f := newIsoFixture(t)
	code, _ := f.saveResource(map[string]any{
		"id": "r-org", "name": "研发专用", "backend": "10.20.8.8:8080",
		"allowOrgs": []string{"dev"},
	})
	if code != http.StatusOK {
		t.Fatalf("保存资源 http %d", code)
	}
	users, roles, _ := f.gwAllow("r-org")
	if !gatewayAuthorize("zhang.wei", "user", users, roles) ||
		!f.profileHasRoute("zhang.wei", "user", "app-org", "10.20.8.8:8080", "r-org", isoApps()) {
		t.Fatalf("前置失败：dev 成员本应两侧放行（allowUsers=%v）", users)
	}

	// 移出研发部 → 下一次下发/下一次拉剖面即失效
	if err := f.st.SetUserOrg(context.Background(), "u1", "sales"); err != nil {
		t.Fatalf("SetUserOrg: %v", err)
	}
	users, roles, _ = f.gwAllow("r-org")
	gwOK := gatewayAuthorize("zhang.wei", "user", users, roles)
	profOK := f.profileHasRoute("zhang.wei", "user", "app-org", "10.20.8.8:8080", "r-org", isoApps())
	if gwOK || profOK {
		t.Fatalf("移出组织后两侧都应立即失效：网关=%v 剖面=%v（下发 allowUsers=%v）", gwOK, profOK, users)
	}
}

// 用户组维度同构（含从组里移除后立即失效）。
func TestGroupSubjectIsomorphic(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()
	g, err := f.st.SaveUserGroup(ctx, store.UserGroup{Name: "外包审计", Kind: store.GroupKindStatic})
	if err != nil {
		t.Fatalf("SaveUserGroup: %v", err)
	}
	if err := f.st.SetGroupMembers(ctx, g.ID, []string{"wang.qiang"}); err != nil {
		t.Fatalf("SetGroupMembers: %v", err)
	}
	code, out := f.saveResource(map[string]any{
		"id": "r-org", "name": "按组授权", "backend": "10.20.8.8:8080",
		"allowGroups": []string{g.ID},
	})
	if code != http.StatusOK {
		t.Fatalf("保存资源 http %d: %v", code, out)
	}
	users, roles, _ := f.gwAllow("r-org")
	if !gatewayAuthorize("wang.qiang", "user", users, roles) ||
		!f.profileHasRoute("wang.qiang", "user", "app-org", "10.20.8.8:8080", "r-org", isoApps()) {
		t.Fatalf("组成员两侧都应放行（allowUsers=%v）", users)
	}
	// 清空成员 → 两侧同时失效，且资源**不得**退化成"对所有人开放"
	if err := f.st.SetGroupMembers(ctx, g.ID, nil); err != nil {
		t.Fatalf("SetGroupMembers 清空: %v", err)
	}
	users, roles, _ = f.gwAllow("r-org")
	for _, acct := range []string{"wang.qiang", "li.fang", "chen.jing"} {
		if gatewayAuthorize(acct, "user", users, roles) {
			t.Errorf("清空组成员后 %s 不该被网关放行（allowUsers=%v）", acct, users)
		}
		if f.profileHasRoute(acct, "user", "app-org", "10.20.8.8:8080", "r-org", isoApps()) {
			t.Errorf("清空组成员后 %s 的剖面不该排出路由", acct)
		}
	}
}

// ★空主体集不得在网关侧退化成「不限」。
// 只按组织授权、而那个组织一个人都没有时，展开结果为空；若原样下发，网关看到
// AllowUsers/AllowRoles 双空 = 对所有人开放——与控制面判定方向完全相反。
// 哨兵账号（store.DenyAllSubject）就是为这一步存在的。
func TestEmptySubjectExpansionStaysDenyAll(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()
	empty, err := f.st.SaveOrgUnit(ctx, store.Org{Name: "新建空部门", ParentID: "root"})
	if err != nil {
		t.Fatalf("SaveOrgUnit: %v", err)
	}
	code, _ := f.saveResource(map[string]any{
		"id": "r-org", "name": "空部门授权", "backend": "10.20.8.8:8080",
		"allowOrgs": []string{empty.ID},
	})
	if code != http.StatusOK {
		t.Fatalf("保存资源 http %d", code)
	}
	users, roles, _ := f.gwAllow("r-org")
	if len(users) != 1 || users[0] != store.DenyAllSubject {
		t.Fatalf("空展开必须且只下发哨兵（否则网关侧退化成「不限」= 全员放行），实得 %q", users)
	}
	// 目录里**每一个**真实账号都必须被两侧同时拒绝。逐个跑而不是抽样：
	// 哨兵之所以安全，靠的正是"没有任何真实账号能等于它"。
	b, err := f.st.Users(ctx)
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	for _, u := range b.Users {
		role := "user"
		if u.Role == "admin" {
			role = "admin"
		}
		if gatewayAuthorize(u.Account, role, users, roles) {
			t.Errorf("成员为空的组织授权不该放行 %q（allowUsers=%q）", u.Account, users)
		}
		if f.profileHasRoute(u.Account, role, "app-org", "10.20.8.8:8080", "r-org", isoApps()) {
			t.Errorf("成员为空的组织授权不该给 %q 排出路由", u.Account)
		}
	}
}

// 回归：不设组织/用户组时行为与改造前**完全一致**——
// 下发内容不含哨兵、四维全空即不限、只设角色即按角色判定。
func TestNoSubjectsBehavesExactlyAsBefore(t *testing.T) {
	f := newIsoFixture(t)
	// ① 四维全空 = 不限（含展开后也不能凭空多出条目）
	code, _ := f.saveResource(map[string]any{"id": "r-open", "name": "全开", "backend": "10.20.8.9:80"})
	if code != http.StatusOK {
		t.Fatalf("保存资源 http %d", code)
	}
	users, roles, found := f.gwAllow("r-open")
	if !found {
		t.Fatal("资源未下发")
	}
	if len(users) != 0 || len(roles) != 0 {
		t.Fatalf("无主体资源的下发应保持空清单，实得 users=%v roles=%v", users, roles)
	}
	if !gatewayAuthorize("anyone", "user", users, roles) {
		t.Error("四维全空应对所有人开放")
	}
	// ② 只设角色：与改造前逐字一致
	code, _ = f.saveResource(map[string]any{
		"id": "r-role", "name": "仅角色", "backend": "10.20.8.10:80", "allowRoles": []string{"admin"},
	})
	if code != http.StatusOK {
		t.Fatalf("保存资源 http %d", code)
	}
	users, roles, _ = f.gwAllow("r-role")
	if len(users) != 0 {
		t.Fatalf("仅设角色时不该出现任何账号条目（含哨兵），实得 %v", users)
	}
	if !gatewayAuthorize("admin", "admin", users, roles) || gatewayAuthorize("li.fang", "user", users, roles) {
		t.Error("仅角色授权的判定与改造前不一致")
	}
	// ③ 种子资源（finance 仅 admin）在剖面侧同样保持原判定
	if f.profileHasRoute("li.fang", "user", "a2", "10.20.3.21:443", "finance", store.AppBundle{Apps: []store.App{
		{ID: "a2", Name: "财务", Addr: "10.20.3.21:443", Mode: "web", Category: "finance", Status: "running", ResourceID: "finance"},
	}}) {
		t.Error("种子资源 finance 对 user 的判定应保持不变（不可访问）")
	}
}

// 拼错的组织/用户组 id 必须被拒绝落库。
// ★静默接受的后果：资源列表上那个标签看着完全正常，整批人却永远拿不到权限。
func TestSaveResourceRejectsUnknownSubjects(t *testing.T) {
	f := newIsoFixture(t)
	code, out := f.saveResource(map[string]any{
		"id": "r-bad", "backend": "10.20.8.8:80", "allowOrgs": []string{"no-such-org"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("未知组织应 400，实得 %d: %v", code, out)
	}
	code, out = f.saveResource(map[string]any{
		"id": "r-bad", "backend": "10.20.8.8:80", "allowGroups": []string{"no-such-group"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("未知用户组应 400，实得 %d: %v", code, out)
	}
}

// 资源清单端点要把主体候选（含**已展开**的账号）一并给控制台：
// 控制台显示的"生效账号数"必须与网关实际放行的那批人同源，不能让浏览器自己走组织树。
func TestResourcesEndpointExposesExpandedSubjects(t *testing.T) {
	f := newIsoFixture(t)
	code, out := doJSON(f.t, f.h, "GET", "/api/v1/resources", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /resources http %d", code)
	}
	orgs, _ := out["orgs"].([]any)
	if len(orgs) == 0 {
		t.Fatal("资源清单应带组织候选")
	}
	var rootAccounts []string
	for _, it := range orgs {
		m, _ := it.(map[string]any)
		if m["id"] == "root" {
			rootAccounts = strSlice(m["accounts"])
		}
	}
	// 根组织的 accounts 必须是**子树展开后**的全量，而不是直属成员（直属为 0 人）
	if len(rootAccounts) < 7 {
		t.Fatalf("根组织的 accounts 应为子树展开结果（≥7 人），实得 %v", rootAccounts)
	}
	if _, ok := out["groups"]; !ok {
		t.Error("资源清单应带用户组候选")
	}
}
