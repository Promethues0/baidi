package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// 闲置账号治理策略（PRD FR-MON-19）与自动锁定（PRD 验收 905 行）的回归。
//
// ★改造前的形态：阈值只从 URL 参数 `?days=` 取，管理员在页面上调过的值不落库
// （刷新一次、换台机器、或后台任务——那时根本没有 URL——都回到写死的 90 天）；
// `autoLockEnabled` 这个 PRD 数据模型里明列的字段整项不存在，于是
// 「若开启自动锁定，Then 该账号被自动锁定」**没有任何执行方**：
// 闲置治理必须有人记得点进那一页手工选、手工点，而页面上看不出这个区别。

// newTestServerWithSrv 同 newTestServerWithStore，另回 *Server——
// 自动锁定循环是后台入口，没有 HTTP 端点，只能直接调 RunIdleAutoLock。
func newTestServerWithSrv(t *testing.T) (http.Handler, *Server) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "idle.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), s
}

// setIdlePolicy 存一份策略（走真实 HTTP，顺带覆盖入口校验）。
func setIdlePolicy(t *testing.T, h http.Handler, days int, auto bool) (int, map[string]any) {
	t.Helper()
	return doJSON(t, h, "PUT", "/api/v1/users/idle/policy", adminToken(),
		map[string]any{"thresholdDays": days, "autoLock": auto})
}

func TestIdlePolicyPersistsAndDrivesIdentification(t *testing.T) {
	h := newTestServer(t)

	// 出厂值：90 天 + **不自动锁定**。
	code, out := doJSON(t, h, "GET", "/api/v1/users/idle/policy", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET 策略 http %d", code)
	}
	p, _ := out["policy"].(map[string]any)
	if p["thresholdDays"].(float64) != float64(store.DefaultIdleDays) {
		t.Fatalf("出厂阈值应为 %d，got %v", store.DefaultIdleDays, p["thresholdDays"])
	}
	if p["autoLock"].(bool) {
		t.Fatal("出厂必须是不自动锁定：开着它升级一次，后台任务会按一份管理员没同意过的阈值批量锁人")
	}

	// 存一份 30 天，然后**不带 ?days=** 拉清单：阈值必须来自库。
	if code, out := setIdlePolicy(t, h, 30, false); code != http.StatusOK {
		t.Fatalf("保存策略 http %d: %v", code, out)
	}
	code, out = doJSON(t, h, "GET", "/api/v1/users/idle", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET 闲置清单 http %d", code)
	}
	if days, _ := out["days"].(float64); int(days) != 30 {
		t.Fatalf("识别阈值应取落库策略 30 天，got %v —— 说明它又回落到了写死的默认值", out["days"])
	}
	if _, ok := out["policy"].(map[string]any); !ok {
		t.Fatal("闲置清单应带回当前策略：页面得知道系统会不会自己动手")
	}

	// `?days=` 只是预览覆盖，不改策略。
	_, out = doJSON(t, h, "GET", "/api/v1/users/idle?days=200", adminToken(), nil)
	if days, _ := out["days"].(float64); int(days) != 200 {
		t.Fatalf("?days= 应作为预览覆盖生效，got %v", out["days"])
	}
	_, out = doJSON(t, h, "GET", "/api/v1/users/idle/policy", adminToken(), nil)
	if p, _ := out["policy"].(map[string]any); p["thresholdDays"].(float64) != 30 {
		t.Fatalf("预览不该改动落库策略，got %v", p["thresholdDays"])
	}
}

// 入口校验与执行层同一份判据：放行一个执行层必然夹掉的值 = 管理员拿到 200
// 而实际生效的是另一个数（CLAUDE.md「入口比实现宽」）。
func TestIdlePolicyRejectsOutOfRange(t *testing.T) {
	h := newTestServer(t)
	for _, days := range []int{0, 1, store.MinIdleDays - 1, store.MaxIdleDays + 1} {
		if code, out := setIdlePolicy(t, h, days, false); code != http.StatusBadRequest {
			t.Fatalf("阈值 %d 应被拒（400），got %d %v", days, code, out)
		}
	}
	for _, days := range []int{store.MinIdleDays, 90, store.MaxIdleDays} {
		if code, _ := setIdlePolicy(t, h, days, false); code != http.StatusOK {
			t.Fatalf("阈值 %d 应被接受，got %d", days, code)
		}
	}
	// 写权限：审计管理员改不了（与批量锁定同权 PermSecurity）。
	audTok := makeAdmin(t, h, "aud.idle", "audit")
	if code, _ := doJSON(t, h, "PUT", "/api/v1/users/idle/policy", audTok,
		map[string]any{"thresholdDays": 30, "autoLock": true}); code != http.StatusForbidden {
		t.Fatalf("审计管理员不该改得动闲置策略，got %d", code)
	}
}

// 自动锁定的**执行方**回归：四向断言。
func TestIdleAutoLockOnlyRunsWhenEnabled(t *testing.T) {
	h, srv := newTestServerWithSrv(t)
	ctx := t.Context()
	makeIdleAdminFixture(t, h, "zhang.wei") // 见该函数注释：这个身份以前是白拿缺陷的副作用

	// 种子里 30 天阈值命中 4 个 active 账号，其中 zhang.wei 已被夹具提成管理员。
	// ① 开关关着：跑一轮，一个都不该动。
	if code, _ := setIdlePolicy(t, h, 30, false); code != http.StatusOK {
		t.Fatal("保存策略失败")
	}
	srv.RunIdleAutoLock(ctx)
	if got := statusOf(t, h, "li.fang"); got != "active" {
		t.Fatalf("自动锁定未开启时不该锁人，li.fang 现在是 %q", got)
	}

	// ② 打开开关后再跑：普通闲置账号被锁。
	if code, out := setIdlePolicy(t, h, 30, true); code != http.StatusOK {
		t.Fatalf("保存策略 http %d: %v", code, out)
	}
	srv.RunIdleAutoLock(ctx)
	if got := statusOf(t, h, "li.fang"); got != "locked" {
		t.Fatalf("开启自动锁定后闲置账号应被锁定，li.fang 现在是 %q —— PRD 905 行的验收就是这一句", got)
	}

	// ③ 管理员账号**永不处置**：那条路径上没有调用方可以比对 PermAdmins，
	//    而一个能自己锁管理员的定时任务，最坏能把系统锁到没人登得进去。
	if got := statusOf(t, h, "zhang.wei"); got != "active" {
		t.Fatalf("自动锁定不该处置管理员账号，zhang.wei 现在是 %q", got)
	}

	// ④ 数据面联动与手工锁定**结果一致**：被自动锁定的账号出现在网关撤销名单里，
	//    下一轮策略轮询即撤窗断隧道。
	//
	//    ★这条断言的边界要说清楚，免得它看起来比实际证明的更多：
	//    `handleGatewayPolicy` 会把目录里 disabled/locked 的账号**动态并入**撤销名单
	//    （见 api.go 的 blockedAccounts 那一段），所以只要账号被锁上，它就会出现在
	//    名单里——`lockIdleAccount` 里那次 `s.revoked` 写入对**已锁账号**这一路是
	//    冗余的纵深，删掉它这条断言照样绿（实测变异逃逸过）。
	//    这里断言的是管理员真正关心的那件事：自动锁定与手工锁定的**可观测结果相同**，
	//    不是"某一行内存写入执行过"。
	if !revokedUsers(t, h)["li.fang"] {
		t.Fatal("被自动锁定的账号必须出现在网关撤销名单里，否则人被锁了隧道还通着")
	}

	// ⑤ 关掉开关后下一轮就停手（**不能靠重启才生效**）。
	//
	//    反向断言必须是确定的：把刚被锁的那个账号解回 active——它是已经证明过
	//    「本轮会被锁」的那一个，于是"没被再锁一次"只能是开关起了作用。
	//    ★刻意不用另一个种子账号 + t.Skip：依赖种子形态的跳过会让整包在
	//    「自动锁定根本停不下来」时照样全绿（wave8 行动 1 的复核实测过这种逃逸）。
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+idOf(t, h, "li.fang")+"/status",
		adminToken(), map[string]any{"status": "active"}); code != http.StatusOK {
		t.Fatalf("解锁 li.fang http %d: %v", code, out)
	}
	if got := statusOf(t, h, "li.fang"); got != "active" {
		t.Fatalf("前置条件没成立：li.fang 应已解回 active，实为 %q", got)
	}
	if code, _ := setIdlePolicy(t, h, 30, false); code != http.StatusOK {
		t.Fatal("关闭策略失败")
	}
	srv.RunIdleAutoLock(ctx)
	if got := statusOf(t, h, "li.fang"); got != "active" {
		t.Fatalf("关掉自动锁定后下一轮就必须停手，li.fang 又被锁成了 %q", got)
	}
}

// idOf 取某账号的目录 id。
func idOf(t *testing.T, h http.Handler, account string) string {
	t.Helper()
	_, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	for _, raw := range out["users"].([]any) {
		u := raw.(map[string]any)
		if u["account"] == account {
			return u["id"].(string)
		}
	}
	t.Fatalf("目录里没有 %s", account)
	return ""
}
