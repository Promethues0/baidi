package api

import (
	"net/http"
	"testing"
)

// 「没有网关在上报」不等于「确定没人在线」。
//
// ★缺陷原样：onlineAccounts() 只返回一张 map，"有网关在报但没报这个人"与
// "一台网关都没在报"对调用方**完全同形**，于是 enrichDirUsers / handleUserState
// 一律写 `Online = online[acc]` = false，handleOverview 那句 `if n >= 0` 的
// -1 分支又因为 store 侧 Sessions 恒 0 而等于白写。三处一起把"不可判定"
// 塌成了确定结论：用户与角色页整表灰点「离线」+ 页头「在线 0」、用户状态页绿点全灭、
// 态势总览「在线会话 0 · 当前活跃接入」，且都不带任何"数据源不可用"的提示。
//
// 而这个情形既现实又**不影响用户接入**：网关进程活着、隧道照常转发，只是它到控制面
// mTLS 口的心跳断了（网关客户端证书到期 / 控制面刚重启，内存态要等下一轮心跳重建 /
// BAIDI_MTLS_ADDR 那个独立端口挂了而管理 API 正常）。管理员正拿用户状态页判断
// "这个疑似被盗的账号要不要现在踢"，页面告诉他"已经离线了"，于是他不动手。
//
// 同一套控制台上，「在线用户」页因为有独立空态文案（"尚无网关上报在线会话"）
// 反而一直说的是实话——一个页面诚实、三个页面替一个不可知的状态下确定结论。
//
// 断言的是**字段缺席**而不是 false/0：塌回 false 时链路更长（后端如实缺席、
// 前端 `?? false` 偷偷补回），比改造前更难查，所以守在 JSON 这一层。
func TestOnlineIsAbsentWhenNoGatewayReports(t *testing.T) {
	h := newTestServer(t) // 一台网关都没注册

	// ① 用户与角色页：online 这个键**根本不该出现**。
	code, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /users http %d", code)
	}
	users, _ := out["users"].([]any)
	if len(users) == 0 {
		t.Fatal("种子用户目录不该为空")
	}
	for _, u := range users {
		m, _ := u.(map[string]any)
		if v, ok := m["online"]; ok {
			t.Fatalf("没有任何网关上报心跳时在线态不可判定，%v 却下发了 online=%v —— "+
				"把「控制面没有数据源」写成确定结论，管理员据此判断要不要踢人就会判错",
				m["account"], v)
		}
	}

	// ② 用户状态页：同一判据、同一处置——这一页是"就近处置"入口，更不能替它下结论。
	//    先造一条 posture 上报，让这个账号真的出现在受关注清单里；
	//    否则清单为空，这条断言在坏实现上照样绿。
	if code, out := doJSON(t, h, "POST", "/api/v1/posture", userToken("li.fang"), map[string]any{
		"device": "fp-online-unknown", "platform": "macOS", "os": "14.5",
		"clientVersion": "0.1.0",
		"checks": []map[string]any{
			{"key": "disk_encrypted", "ok": false, "detail": "未加密"},
		},
	}); code != http.StatusOK {
		t.Fatalf("造 posture 上报 http %d: %v", code, out)
	}
	code, out = doJSON(t, h, "GET", "/api/v1/userstate", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /userstate http %d", code)
	}
	items, _ := out["items"].([]any)
	if len(items) == 0 {
		t.Fatal("前置条件不成立：刚上报过 posture 的账号应出现在用户态势里")
	}
	for _, raw := range items {
		m, _ := raw.(map[string]any)
		if v, ok := m["online"]; ok {
			t.Fatalf("没有任何网关上报心跳时在线态不可判定，%v 却下发了 online=%v", m["account"], v)
		}
	}

	// ③ 态势总览：sessions 缺席，而不是 0——「不可判定」与「确实 0 个」
	//    在 KPI 上不能是同一个字（那一格底下还标着「当前活跃接入」）。
	code, ov := doJSON(t, h, "GET", "/api/v1/overview", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /overview http %d", code)
	}
	if v, ok := ov["sessions"]; ok {
		t.Fatalf("没有任何网关上报心跳时接入会话数不可判定，却下发了 sessions=%v", v)
	}
}

// 有网关在上报时，三处必须给出**确定结论**——不可判定不能变成一件遮羞布：
// 它只在"真的没有数据源"时成立，有网关在报却仍缺席的话，这一列就永远没用了。
func TestOnlineIsDefiniteWhenGatewayReports(t *testing.T) {
	h, _ := gwReceiptServer(t)
	// 一台在线网关，报了 li.fang 一条会话。
	body := `{"id":"gw-online-1","proxy":":18443","spa":":18201","clients":1,"tunnels":1,
	          "uptime":600,"version":"v1.2.3",
	          "sessions":[{"ip":"10.0.0.9","user":"li.fang","role":"user","since":1754800000}]}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}

	code, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /users http %d", code)
	}
	users, _ := out["users"].([]any)
	var online, offline int
	for _, u := range users {
		m, _ := u.(map[string]any)
		v, ok := m["online"]
		if !ok {
			t.Fatalf("有网关在上报时在线态是确定的，%v 却缺了 online —— "+
				"「不可判定」只在真的没有数据源时成立", m["account"])
		}
		on, _ := v.(bool)
		if str(m["account"]) == "li.fang" {
			if !on {
				t.Fatalf("网关明确报了 li.fang 的会话，这一页却说她离线")
			}
			online++
			continue
		}
		// 有网关在报、它没报这个人 → 确定离线（false，而不是缺席）。
		if on {
			t.Fatalf("%v 没有被任何网关报为会话，不该是在线", m["account"])
		}
		offline++
	}
	if online != 1 || offline == 0 {
		t.Fatalf("在线/离线口径不对：online=%d offline=%d", online, offline)
	}

	// 态势总览的会话数同源：这台网关报了 1 条。
	code, ov := doJSON(t, h, "GET", "/api/v1/overview", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /overview http %d", code)
	}
	n, ok := ov["sessions"].(float64)
	if !ok {
		t.Fatalf("有网关在上报时接入会话数是确定的，sessions 不该缺席：%v", ov["sessions"])
	}
	if int(n) != 1 {
		t.Fatalf("会话数应等于网关上报的条数 1，实得 %v", n)
	}
}

// 在线网关上报**零会话**时，答案是"确定没人连"而不是"不可判定"。
//
// ★这条钉的是 onlineAccounts 里 known 的判据必须是"心跳新鲜"而不是"报了会话"：
// 写成"有会话才算有数据源"的话，一台正常运行、此刻确实没人接入的网关会让整页
// 退化成「不可判定」——那时管理员反而看不出"现在真的没人连着"这个有用的事实，
// 而这正是空态该说的话。
func TestOnlineIsDefiniteWhenLiveGatewayReportsZeroSessions(t *testing.T) {
	h, _ := gwReceiptServer(t)
	body := `{"id":"gw-idle-1","proxy":":18443","spa":":18201","clients":0,"tunnels":0,
	          "uptime":600,"version":"v1.2.3","sessions":[]}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}

	code, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /users http %d", code)
	}
	users, _ := out["users"].([]any)
	if len(users) == 0 {
		t.Fatal("种子用户目录不该为空")
	}
	for _, u := range users {
		m, _ := u.(map[string]any)
		v, ok := m["online"]
		if !ok {
			t.Fatalf("有在线网关在上报（哪怕零会话）时在线态是确定的，%v 却缺了 online", m["account"])
		}
		if on, _ := v.(bool); on {
			t.Fatalf("网关一条会话都没报，%v 不该是在线", m["account"])
		}
	}

	code, ov := doJSON(t, h, "GET", "/api/v1/overview", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /overview http %d", code)
	}
	n, ok := ov["sessions"].(float64)
	if !ok || int(n) != 0 {
		t.Fatalf("有在线网关、零会话 → sessions 应为确定的 0，实得 %v（ok=%v）", ov["sessions"], ok)
	}
}
