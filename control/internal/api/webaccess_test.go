package api

// wave11 行动 14：接入策略覆盖 B/S 取票路径 + 七层会话进「在线用户」页。
//
// 改造前的两个洞：
//   ① 接入策略两条 P0 只挂在敲门令牌上，浏览器不敲门 → 「同时在线设备上限 = 0
//      （PRD 原文：禁止登录）」封不住 B/S：隧道全断，所有人照样从门户点开 Web 应用。
//   ② 网关心跳只报 SPA 放行表里的隧道会话 → 一个整天用浏览器访问 OA 的人
//      在「在线用户」页上根本不存在，既数不到也点不到「强制下线」。

import (
	"net/http"
	"testing"
	"time"

	"baidi.dev/control/internal/store"
)

// ── ① 接入策略在 B/S 上的执行方 ──

// 「同时在线设备上限 = 0」必须同时挡住敲门与取票。
//
// 变异实测：把 handleWebTicket 里的 accessWebGate 调用删掉 → 本条红（取票仍回 200）。
func TestWebTicketBlockedByZeroDeviceLimit(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)
	// 先确认这条路本来是通的，否则下面那个 403 可能来自别的原因。
	if code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
		map[string]string{"appId": "a1"}); code != http.StatusOK {
		t.Fatalf("前置：有权限时应能取票，得 %d %v", code, out)
	}
	setAccessPolicy(t, h, map[string]any{
		"deviceLimitEnabled": true, "maxDevices": 0, "idleEnabled": false, "idleMinutes": 480,
	})
	code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
		map[string]string{"appId": "a1"})
	if code != http.StatusForbidden {
		t.Fatalf("★上限 0 = 禁止接入，浏览器这条路同样要挡住，得 %d %v", code, out)
	}
	msg := errMsg(out)
	if !hasSub(msg, "0") || !hasSub(msg, "禁止接入") {
		t.Fatalf("拒绝文案必须点名是哪条策略把人挡住的，得 %q", msg)
	}
	// 敲门那条路的行为完全不变（同一条策略、同一个语义）。
	if code, _ := knockAs(t, h, "li.fang", "d1"); code != http.StatusForbidden {
		t.Fatalf("敲门也应被同一条策略挡住，得 %d", code)
	}
}

// 「上限 N 台（N>0）」**不**作用于浏览器——如实不生效，而不是拿源 IP 当设备指纹。
//
// ★这一条钉的是一个刻意的取舍：浏览器没有设备指纹，任何编出来的键都会给出假答案
// （同 NAT 出口两人共用一个名额 = 拒绝服务；换网络就多一个名额 = 上限形同虚设），
// 更糟的是它会与 C/S 抢同一个名额池，一次网页访问就能把一台正在用的终端挤下线。
// 策略页当面写明「上限 N 只统计 C/S 客户端」，这条用例是那句话的可执行版本。
func TestWebTicketNotCountedAgainstDeviceQuota(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)
	setAccessPolicy(t, h, map[string]any{
		"deviceLimitEnabled": true, "maxDevices": 1, "idleEnabled": false, "idleMinutes": 480,
	})
	// 先用掉唯一的名额（C/S 一台终端在线）。
	if code, _ := knockAs(t, h, "li.fang", "d1"); code != http.StatusOK {
		t.Fatal("前置：第一台终端应能接入")
	}
	if code, _ := knockAs(t, h, "li.fang", "d2"); code != http.StatusForbidden {
		t.Fatal("前置：第二台终端应被上限挡住")
	}
	// 浏览器不受这一档约束：取票照常，且**不占用**那个名额。
	if code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
		map[string]string{"appId": "a1"}); code != http.StatusOK {
		t.Fatalf("★上限 N 台只统计 C/S，浏览器取票不该被它挡住，得 %d %v", code, out)
	}
	if code, _ := knockAs(t, h, "li.fang", "d1"); code != http.StatusOK {
		t.Fatal("★浏览器接入不得占用 C/S 名额，否则原本在线的那台会被挤掉")
	}
}

// 策略页必须说得出 B/S 的覆盖面：哪几台网关在真的执行超时注销、哪几台没回报。
//
// ★「已启用 · N 分钟」这句话在页面上对全体接入形态说，而一台还没升级的网关
// 上的浏览器接入根本不会被注销——回执（网关报回来它在执行几秒）是唯一判据，
// 不能拿"控制面下发了多少"当结论。
func TestAccessPolicyReportsWebCoverage(t *testing.T) {
	h := newTestServer(t)
	// 一台开了七层、但**不回报** webIdleSec 的网关（旧版本形态）。
	body := map[string]any{"id": "gw-old", "proxy": webGWHost + ":18443", "spa": webGWHost + ":18201",
		"web": "0.0.0.0:18444", "webSessions": []any{}}
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), body); code != http.StatusOK {
		t.Fatal("网关注册失败")
	}
	code, out := doJSON(t, h, "GET", "/api/v1/policies/access", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读接入策略 %d", code)
	}
	web, _ := out["web"].(map[string]any)
	if web == nil {
		t.Fatal("★接入策略必须下发 B/S 覆盖面，否则页面只能凭空写一句「策略是全局的」")
	}
	if web["deviceLimitTier"] != "zero-only" {
		t.Fatalf("★「上限 N 台」在 B/S 上只兑现 0 这一档，必须如实声明，得 %v", web["deviceLimitTier"])
	}
	un, _ := web["idleUnreported"].([]any)
	if len(un) != 1 || un[0] != "gw-old" {
		t.Fatalf("★不回报阈值的网关必须被点名（它上面的浏览器接入不会被注销），得 %v", web["idleUnreported"])
	}
	// 换成会回报的新网关：它进 idleEnforcing。
	body["id"] = "gw-new"
	body["webIdleSec"] = 300
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), body); code != http.StatusOK {
		t.Fatal("网关注册失败")
	}
	_, out = doJSON(t, h, "GET", "/api/v1/policies/access", adminToken(), nil)
	web, _ = out["web"].(map[string]any)
	en, _ := web["idleEnforcing"].([]any)
	if len(en) != 1 || en[0] != "gw-new" {
		t.Fatalf("★正在执行的网关必须列得出来，得 %v", web["idleEnforcing"])
	}
}

// 控制面下发给网关的超时阈值：规则关着时必须是 0，绝不留上一次的秒数。
//
// 变异实测：把 store.WebIdleSeconds 里的 `if !p.IdleEnabled { return 0 }` 删掉 →
// 本条红（关掉规则后仍下发 300）。那个形态在现场是：管理员关掉了「接入超时注销」，
// 而网关照着上一个阈值继续把人注销掉，页面上那个开关明明是灰的。
func TestGatewayPolicyCarriesWebIdle(t *testing.T) {
	h := newTestServer(t)
	setAccessPolicy(t, h, map[string]any{
		"deviceLimitEnabled": false, "maxDevices": 3, "idleEnabled": true, "idleMinutes": 5,
	})
	code, out := doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("拉策略 %d", code)
	}
	if v, _ := out["webIdleSec"].(float64); int(v) != 300 {
		t.Fatalf("★启用后必须把阈值下发给网关（B/S 的执行方在那边），得 %v", out["webIdleSec"])
	}
	setAccessPolicy(t, h, map[string]any{
		"deviceLimitEnabled": false, "maxDevices": 3, "idleEnabled": false, "idleMinutes": 5,
	})
	_, out = doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if v, ok := out["webIdleSec"].(float64); !ok || v != 0 {
		t.Fatalf("★关掉规则必须下发 0（恒下发、不做三态：缺字段与 0 在网关侧动作相同），得 %v", out["webIdleSec"])
	}
}

// ── ② 七层会话进「在线用户」页 ──

// registerWebSessions 让一台开了七层的网关上报若干条 Web 会话（走真实注册端点）。
func registerWebSessions(t *testing.T, h http.Handler, gwID string, sessions []map[string]any) {
	t.Helper()
	body := map[string]any{"id": gwID, "proxy": webGWHost + ":18443", "spa": webGWHost + ":18201",
		"web": "0.0.0.0:18444", "webSessions": sessions, "webIdleSec": 0}
	if code, out := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), body); code != http.StatusOK {
		t.Fatalf("网关注册 %d: %v", code, out)
	}
}

// B/S 会话必须出现在「在线用户」页上，且与 C/S 分得开、可分别处置。
//
// 变异实测：把 handleOnline 里那段 gwWebSess 循环删掉 → 本条红（只剩隧道那条）。
func TestOnlineIncludesWebSessions(t *testing.T) {
	h := newTestServer(t)
	now := time.Now().Unix()
	registerWebSessions(t, h, "gw-1", []map[string]any{
		{"id": "s1", "user": "li.fang", "role": "user", "res": "oa",
			"ip": "203.0.113.9", "since": now - 600, "lastActive": now - 120, "exp": now + 600},
	})
	code, out := doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读在线会话 %d", code)
	}
	list, _ := out["sessions"].([]any)
	if len(list) != 1 {
		t.Fatalf("★浏览器接入必须出现在「在线用户」页（此前它在这一页上根本不存在），得 %d 条", len(list))
	}
	se, _ := list[0].(map[string]any)
	if se["kind"] != sessionKindWeb {
		t.Fatalf("★两种接入形态必须分得开（处置方式与判据都不同），得 %v", se["kind"])
	}
	if se["resource"] != "oa" {
		t.Fatalf("B/S 会话绑定的资源应下发，得 %v", se["resource"])
	}
	if v, ok := se["idleSec"].(float64); !ok || v < 100 {
		t.Fatalf("★空闲时长只有 L7 判得出来，必须给（隧道那侧是三态，不可判定时缺席），得 %v", se["idleSec"])
	}
	// 强制下线必须点得动：改造前这一行在页面上看得见、点下去回 404。
	kcode, kout := doJSON(t, h, "POST", "/api/v1/online/"+se["id"].(string)+"/kick", adminToken(),
		map[string]string{"reason": "测试"})
	if kcode != http.StatusOK {
		t.Fatalf("★B/S 会话必须可强制下线，得 %d %v", kcode, kout)
	}
	if kout["user"] != "li.fang" {
		t.Fatalf("处置对象应解析成会话所属账号，得 %v", kout["user"])
	}
}

// 「有网关没报七层会话」必须当面说出来——那时这一页正在漏人。
//
// ★「B/S 0 人」在两种情况下长得完全一样：确实没人用浏览器，和一台网关根本没在报。
// 少了这条披露，后者会被读成前者（一个确定结论）。
func TestOnlineReportsWebBlindGateways(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false) // 不带 webSessions 字段 = 旧网关
	_, out := doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	blind, _ := out["webBlindGateways"].([]any)
	if len(blind) != 1 || blind[0] != "gw-1" {
		t.Fatalf("★不报七层会话的在线网关必须点名，得 %v", out["webBlindGateways"])
	}
	// 报了空数组的网关是「开了七层、当前零人」——确定结论，不该进这张表。
	registerWebSessions(t, h, "gw-1", []map[string]any{})
	_, out = doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	if v, ok := out["webBlindGateways"]; ok {
		t.Fatalf("★空数组 = 确定的「零条会话」，不是不可判定，得 %v", v)
	}
}

// 「在线」的判据三页同源：B/S 接入的人在用户目录里也必须是在线。
//
// 变异实测：把 onlineAccounts 里那段 gwWebSess 循环删掉 → 本条红
// （用户目录把一个正在用浏览器访问 OA 的人画成灰点「离线」）。
func TestOnlineAccountsIncludeWebSessions(t *testing.T) {
	h := newTestServer(t)
	now := time.Now().Unix()
	registerWebSessions(t, h, "gw-1", []map[string]any{
		{"id": "s1", "user": "li.fang", "role": "user", "res": "oa",
			"ip": "203.0.113.9", "since": now - 60, "lastActive": now, "exp": now + 600},
	})
	code, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读用户目录 %d", code)
	}
	users, _ := out["users"].([]any)
	found := false
	for _, u := range users {
		m, _ := u.(map[string]any)
		if m["account"] != "li.fang" {
			continue
		}
		found = true
		if m["online"] != true {
			t.Fatalf("★经浏览器接入的人在用户目录里也必须是在线（三页同一个判据），得 %v", m["online"])
		}
		if m["ip"] != "203.0.113.9" {
			t.Fatalf("★来源 IP 同源：网关报来的对端地址不该被丢掉，得 %v", m["ip"])
		}
	}
	if !found {
		t.Fatal("用户目录里应有 li.fang")
	}
}

// 网关不再报七层会话时（关掉 -web / 降级），那批会话必须**立刻消失**。
//
// ★与 gwNAT/gwStealth 的「nil 不覆盖不清空」方向相反，因为语义不同：那两个是
// 运行态配置，这个是此刻的在线会话快照。保留旧值的话，一台刚关掉 -web 的网关
// 会让这一页永远挂着一批早就不存在的浏览器会话，点「强制下线」还会真的封禁那个账号。
func TestWebSessionsDroppedWhenGatewayStopsReporting(t *testing.T) {
	h := newTestServer(t)
	now := time.Now().Unix()
	registerWebSessions(t, h, "gw-1", []map[string]any{
		{"id": "s1", "user": "li.fang", "role": "user", "res": "oa",
			"ip": "203.0.113.9", "since": now - 60, "lastActive": now, "exp": now + 600},
	})
	registerWebGateway(t, h, "", false) // 同一台网关，这次连 web/webSessions 都不报
	_, out := doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	if list, _ := out["sessions"].([]any); len(list) != 0 {
		t.Fatalf("★网关不再报七层会话时那批会话必须消失，得 %d 条", len(list))
	}
}

// ── 纯判定：EvaluateWebAccess 的取值边界 ──
func TestEvaluateWebAccess(t *testing.T) {
	cases := []struct {
		name  string
		p     store.AccessPolicy
		allow bool
	}{
		{"规则关着", store.AccessPolicy{MaxDevices: 0}, true},
		{"上限 0 且启用", store.AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 0}, false},
		{"上限 3", store.AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 3}, true},
		// ★分平台 + PC 上限 0：浏览器没有平台判据，与 IsMobilePlatform("") 的既有
		// 约定（不可判定按 PC 计）保持同一条，故同样被挡。这条后果写在策略页上。
		{"分平台 · PC 上限 0", store.AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 0,
			SplitPlatform: true, MaxDevicesMobile: 2}, false},
		// 反过来：PC 有名额、移动端 0 时不挡浏览器（它落在 PC 桶里）。
		{"分平台 · 仅移动端 0", store.AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 3,
			SplitPlatform: true, MaxDevicesMobile: 0}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := store.EvaluateWebAccess(c.p); got.Allowed != c.allow {
				t.Fatalf("期望 allowed=%v，得 %+v", c.allow, got)
			}
		})
	}
}
