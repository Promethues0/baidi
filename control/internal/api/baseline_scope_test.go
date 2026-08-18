package api

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// ── wave8 行动 13-④：安全基线的适用范围（结构化 + 真接进判定）──
//
// 被修的坏形态：BaselinePolicy 有一个**自由文本** Scope（种子里写着「个人 BYOD 设备」
// 「财务系统 / OA / 代码仓库」），页面把它当筛选条件渲染在每条基线下面，
// 而 risk.Evaluate 从不读它——那条「个人设备灰度基线」实际对**全体终端**生效。
// 同批摘掉的还有 Type（上线准入 / 应用防护）：同样无人读，且与 Disposal 的真实行为矛盾。
//
// 现在范围是 ScopeOrgs/ScopeGroups，判定点 api.baselinesInScope，
// 展开与资源授权 / 认证策略共用 store.SubjectIndex。

// clearBaselines 删光种子基线，让用例只面对自己建的那一条。
func clearBaselines(t *testing.T, h http.Handler) {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/security", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读安全中心 %d", code)
	}
	for _, it := range out["baselines"].([]any) {
		id := str(it.(map[string]any)["id"])
		if c, _ := doJSON(t, h, "DELETE", "/api/v1/security/baselines/"+id, adminToken(), nil); c != http.StatusOK {
			t.Fatalf("删基线 %s: %d", id, c)
		}
	}
}

// blockBaseline 一条必然判失败的 block 基线（磁盘未加密），可指定适用范围。
func blockBaseline(name string, orgs, groups []string) map[string]any {
	return map[string]any{
		"name": name, "disposal": "block", "status": "enabled",
		"scopeOrgs": orgs, "scopeGroups": groups,
		"platforms": []string{"Windows", "macOS", "Linux"},
		"checks": []map[string]any{
			{"key": "disk_encrypted", "label": "磁盘已加密", "platform": "All",
				"expect": "FileVault / BitLocker = On", "severity": "high"},
		},
	}
}

// degradeBaseline 一条必然判失败的 degrade 基线（防火墙未开），可指定适用范围。
func degradeBaseline(name string, orgs, groups []string) map[string]any {
	return map[string]any{
		"name": name, "disposal": "degrade", "status": "enabled",
		"scopeOrgs": orgs, "scopeGroups": groups,
		"platforms": []string{"Windows", "macOS", "Linux"},
		"checks": []map[string]any{
			{"key": "firewall_on", "label": "系统防火墙启用", "platform": "All",
				"expect": "firewall = enabled", "severity": "medium"},
		},
	}
}

// reportUnencrypted 以 account 身份上报一台「磁盘未加密 + 防火墙未开」的终端，返回判定处置。
func reportUnencrypted(t *testing.T, h http.Handler, account string) string {
	t.Helper()
	code, out := doJSON(t, h, "POST", "/api/v1/posture", userToken(account), map[string]any{
		"device": "dev-" + account, "platform": "macOS", "os": "macOS 14.5", "clientVersion": "0.9.0",
		"checks": []map[string]any{
			{"key": "disk_encrypted", "label": "磁盘已加密", "ok": false, "value": "FileVault=Off"},
			{"key": "firewall_on", "label": "系统防火墙启用", "ok": false, "value": "off"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("%s 上报 posture http %d: %v", account, code, out)
	}
	d := str(out["verdict"])
	if d == "" {
		t.Fatalf("上报应回判定：%v", out)
	}
	return d
}

// TestBaselineScopeIsRealJudgment 范围内的人被判、范围外的人不被判。
//
// ★这是本项被修坏形态的**可执行判据**：改造前不论范围写什么，两个人都会被判 block。
func TestBaselineScopeIsRealJudgment(t *testing.T) {
	h := newTestServer(t)
	clearBaselines(t, h)
	putVendorGroup(t, h) // g-test-vendor = { li.fang }

	code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(),
		blockBaseline("外包终端加密基线", nil, []string{"g-test-vendor"}))
	if code != http.StatusOK {
		t.Fatalf("建基线失败 %d: %v", code, out)
	}

	if got := reportUnencrypted(t, h, "li.fang"); got != "block" {
		t.Fatalf("li.fang 在适用范围内，磁盘未加密应判 block，实得 %q", got)
	}
	// wang.qiang 不在 g-test-vendor 里：这条基线对他不成立，同样的上报应放行。
	if got := reportUnencrypted(t, h, "wang.qiang"); got != "allow" {
		t.Fatalf("wang.qiang 不在适用范围内，不该被这条基线判到，实得 %q——"+
			"范围如果不真进判定，页面上那栏就只是装饰", got)
	}
}

// TestBaselineWithoutScopeAppliesToEveryone 两栏都空 = 对全体生效（存量行为不变）。
//
// ★这条是回填的正确性判据：既有库的基线回填成空数组，升级后判定必须与升级前逐字一致。
func TestBaselineWithoutScopeAppliesToEveryone(t *testing.T) {
	h := newTestServer(t)
	clearBaselines(t, h)
	if code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(),
		blockBaseline("全员加密基线", nil, nil)); code != http.StatusOK {
		t.Fatalf("建基线失败 %d: %v", code, out)
	}
	for _, u := range []string{"li.fang", "wang.qiang"} {
		if got := reportUnencrypted(t, h, u); got != "block" {
			t.Fatalf("未限定范围应对全体生效，%s 实得 %q", u, got)
		}
	}
}

// TestBaselineScopeRefsMustExist 引用不存在的组织/用户组，保存即拒。
//
// ★不拦的话，引用一个已删组织的基线**对谁都不生效**，而页面照常显示「已启用 · 阻断」。
// 与资源授权、认证策略共用同一处 validateSubjectRefs。
func TestBaselineScopeRefsMustExist(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(),
		blockBaseline("引用了幽灵组", nil, []string{"g-does-not-exist"}))
	if code != http.StatusBadRequest {
		t.Fatalf("引用不存在的用户组应 400，实得 %d: %v", code, out)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(),
		blockBaseline("引用了幽灵部门", []string{"org-nope"}, nil)); code != http.StatusBadRequest {
		t.Fatalf("引用不存在的组织应 400，实得 %d: %v", code, out)
	}
}

// TestBaselineScopeRoundTrip 范围能存能读、缺省是空数组而不是 null。
func TestBaselineScopeRoundTrip(t *testing.T) {
	h := newTestServer(t)
	clearBaselines(t, h)
	putVendorGroup(t, h)
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(),
		blockBaseline("回环", nil, []string{"g-test-vendor"})); code != http.StatusOK {
		t.Fatal("建基线失败")
	}
	code, out := doJSON(t, h, "GET", "/api/v1/security", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读安全中心 %d", code)
	}
	arr, _ := out["baselines"].([]any)
	if len(arr) != 1 {
		t.Fatalf("应只剩一条，实得 %d", len(arr))
	}
	b := arr[0].(map[string]any)
	if _, ok := b["type"]; ok {
		t.Error("type 已摘除，不该再出现在下发里——无人读的分类会被当成判据")
	}
	gs, _ := b["scopeGroups"].([]any)
	if len(gs) != 1 || str(gs[0]) != "g-test-vendor" {
		t.Fatalf("scopeGroups 应回环，实得 %v", b["scopeGroups"])
	}
	if b["scopeOrgs"] == nil {
		t.Error("空范围应是 []，不能是 null——前端对 null 会渲染成「未配置」而不是「对全体生效」")
	}
	// 范围选择器的候选必须随页面一起下发，否则管理员只能凭 id 手填。
	if _, ok := out["groups"].([]any); !ok {
		t.Error("/security 应下发 groups 候选（与资源授权、认证策略同一处 subjectOptions）")
	}
	if _, ok := out["orgs"].([]any); !ok {
		t.Error("/security 应下发 orgs 候选")
	}
}

// TestBaselineScopeCoversOrgSubtree 授权给父部门 = 覆盖它的全部后代部门。
//
// ★子树是 CLAUDE.md 里写死的语义，展开只有一处实现（store.SubjectIndex）。
// 只按"直属"匹配的话，管理员把基线配在「研发中心」上，新建的「研发中心/前端组」
// 里的人全都不受这条基线管——而页面上那条基线看起来覆盖整个中心。
func TestBaselineScopeCoversOrgSubtree(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()
	clearBaselines(t, h)

	// 研发部（种子 dev）下新建一个子部门，把 li.fang 挪进去。
	code, out := doJSON(t, h, "POST", "/api/v1/orgs", adm, map[string]any{"name": "前端组", "parentId": "dev"})
	if code != http.StatusOK {
		t.Fatalf("建子部门 %d: %v", code, out)
	}
	child := str(mapOf(t, out["org"])["id"])
	li := userIDOf(t, h, "li.fang")
	if code, out := doJSON(t, h, "PUT", "/api/v1/users/"+li+"/membership", adm,
		map[string]any{"orgId": child}); code != http.StatusOK {
		t.Fatalf("挪人进子部门 %d: %v", code, out)
	}
	// wang.qiang 留在销售部，作为「范围外」的对照。

	// 基线只授给**父部门** dev。
	if code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adm,
		blockBaseline("研发中心加密基线", []string{"dev"}, nil)); code != http.StatusOK {
		t.Fatalf("建基线 %d: %v", code, out)
	}
	if got := reportUnencrypted(t, h, "li.fang"); got != "block" {
		t.Fatalf("li.fang 在 dev 的子部门里，父部门的基线应覆盖到他（含子树），实得 %q", got)
	}
	if got := reportUnencrypted(t, h, "wang.qiang"); got != "allow" {
		t.Fatalf("wang.qiang 在销售部，不该被研发中心的基线判到，实得 %q", got)
	}
}

// TestBaselineMixedScopedAndGlobal 一条限定范围 + 一条全体：范围外的人仍受全体那条管。
//
// ★这条用例是 M2 变异（把"两栏都空"当成"谁也不覆盖"）的唯一判据。只有全体基线时
// baselinesInScope 会走「没有任何基线配了范围」的快路径直接返回，验不出空范围的语义；
// 必须让两种基线**同时存在**，才走得到逐条判定那段。
func TestBaselineMixedScopedAndGlobal(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()
	clearBaselines(t, h)
	putVendorGroup(t, h) // g-test-vendor = { li.fang }

	if code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adm,
		blockBaseline("外包终端加密基线", nil, []string{"g-test-vendor"})); code != http.StatusOK {
		t.Fatalf("建限定基线 %d: %v", code, out)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adm,
		degradeBaseline("全员防火墙基线", nil, nil)); code != http.StatusOK {
		t.Fatalf("建全体基线 %d: %v", code, out)
	}

	// li.fang 两条都命中 → 取最严的 block。
	if got := reportUnencrypted(t, h, "li.fang"); got != "block" {
		t.Fatalf("li.fang 两条基线都适用，应按最严的判 block，实得 %q", got)
	}
	// wang.qiang 只命中全体那条 → degrade。
	// block 说明范围没生效（限定基线管到了范围外的人）；
	// allow 说明"两栏都空"被当成了"谁也不覆盖"，全体基线整个失效——
	// 后者是升级那一刻全系统基线集体静默失灵，比前者更严重。
	if got := reportUnencrypted(t, h, "wang.qiang"); got != "degrade" {
		t.Fatalf("wang.qiang 只应命中全体基线（degrade），实得 %q："+
			"block = 限定范围没生效；allow = 空范围被当成不覆盖任何人（全体基线集体失效）", got)
	}
}

// ixFailStore 让 SubjectIndex 恒失败的 store 包装（其余全部透传）。
type ixFailStore struct{ store.Store }

func (ixFailStore) SubjectIndex(context.Context) (store.SubjectIndex, error) {
	return store.SubjectIndex{}, errors.New("注入故障：展开索引读不到")
}

// TestBaselineScopeReadFailureKeepsAllBaselines 展开索引读不到时**保留全部基线**。
//
// ★方向是刻意的：基线是安全闸门，一次读失败不该让全体终端瞬间"合规"。
// 清空（fail-open）那种写法在测试里与"范围过滤生效了"完全同形——库一抖，
// block 基线集体失灵，页面上一切正常。这条用例是那个方向的唯一守卫。
func TestBaselineScopeReadFailureKeepsAllBaselines(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	// 先用正常 store 建好数据（含一条只对 g-test-vendor 生效的 block 基线）。
	ok := auth.Middleware(testKeys, New(st, st, testKeys, "test", t.TempDir(), nil, nil, true).IsOpen)(
		New(st, st, testKeys, "test", t.TempDir(), nil, nil, true).Routes())
	clearBaselines(t, ok)
	putVendorGroup(t, ok)
	if code, out := doJSON(t, ok, "POST", "/api/v1/security/baselines", adminToken(),
		blockBaseline("外包终端加密基线", nil, []string{"g-test-vendor"})); code != http.StatusOK {
		t.Fatalf("建基线 %d: %v", code, out)
	}

	// 换成展开索引恒失败的 store：范围外的 wang.qiang 也应被判到（宁可误伤不可误放）。
	bad := New(ixFailStore{st}, st, testKeys, "test", t.TempDir(), nil, nil, true)
	h := auth.Middleware(testKeys, bad.IsOpen)(bad.Routes())
	if got := reportUnencrypted(t, h, "wang.qiang"); got != "block" {
		t.Fatalf("展开索引读不到时应保留全部基线（fail-closed），实得 %q——"+
			"清空即全体终端瞬间合规，且页面上看不出任何异常", got)
	}
}
