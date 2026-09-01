package api

import (
	"net/http"
	"testing"
)

// 「用户与角色」页的在线态必须与「在线用户」页同源。
//
// ★缺陷原样：users.online 只在 INSERT 时写过（种子 / 外部目录建号），
// 全仓没有一处 UPDATE 它（`grep "SET online"` 零命中）。于是那一列与页头的
// 「N 在线 / M 离线」统计定格在**建号那一刻**：种子里的张伟/李芳/王强
// 从库建好起就一直显示"在线"，一次都没登录过也一样；而真正接入的人永远显示"离线"。
// 同一套控制台的侧栏角标与 /online 页读的是网关上报的真实会话——
// 两个数并排摆在控制台上，互相矛盾，且都没有任何提示。
//
// 断言两向：没有网关会话时**没有人在线**（而库里的种子值说有三个人在线），
// 且这一页与 /online 给出的账号集合一致。
func TestUsersOnlineComesFromLiveSessions(t *testing.T) {
	h := newTestServer(t)

	code, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /users http %d", code)
	}
	users, _ := out["users"].([]any)
	if len(users) == 0 {
		t.Fatal("种子用户目录不该为空")
	}

	var onlineNames []string
	for _, u := range users {
		m, _ := u.(map[string]any)
		if on, _ := m["online"].(bool); on {
			onlineNames = append(onlineNames, m["account"].(string))
		}
	}
	// 测试服务器没有任何网关注册，因此不可能有会话。
	if len(onlineNames) != 0 {
		t.Fatalf("没有任何网关上报会话时不该有人在线，却有 %v —— "+
			"这说明在线态又读回了 users.online 那一列（它只在建号时写过一次）", onlineNames)
	}

	// ★另外三列同样不能是建号那天的冻结值：接入 IP 与终端在无会话/无上报时
	//   必须降级成不可判定，风险必须是 unknown（而不是种子写下的 none/high）。
	for _, u := range users {
		m, _ := u.(map[string]any)
		acct, _ := m["account"].(string)
		if ip, _ := m["ip"].(string); ip != "—" {
			t.Fatalf("%s 当前没有活跃会话，接入 IP 不该是建号那天写下的 %q", acct, ip)
		}
		if dev, _ := m["device"].(string); dev != "—" {
			t.Fatalf("%s 从未上报过终端环境，终端列不该是 %q（那是种子值）", acct, dev)
		}
		if risk, _ := m["risk"].(string); risk != "unknown" {
			t.Fatalf("%s 从未上报过终端环境，风险应为 unknown 而不是 %q —— "+
				"把「不知道」渲染成「无风险」是替一台完全未知的机器背书", acct, risk)
		}
	}

	// 与 /online 同源：那边也必须是空的。
	code, on := doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /online http %d", code)
	}
	sess, _ := on["sessions"].([]any)
	if len(sess) != len(onlineNames) {
		t.Fatalf("两页在线口径必须一致：/users 说 %d 人在线，/online 说 %d 条会话",
			len(onlineNames), len(sess))
	}
}

// 「在线」这个词在控制台上只能有**一个**判据。
//
// ★三页曾经有两套：
//
//	· 在线用户页 / 用户与角色页 → 网关上报的真实会话（gwSess）
//	· 用户状态页 → `hasRep && now-rep.TS <= 600`（store/monitor_sqlite.go），
//	  即"这台终端十分钟内上报过环境"——那是**采集器还活着**，不是"此刻连着隧道"。
//
// 一个人后台挂着客户端按 60s 上报 posture，用户状态页给他画绿点「在线」，
// 而在线用户页里查无此人。而用户状态页的定位恰恰是"就近处置"——
// 要不要现在踢他，取决于他现在有没有连着。
func TestUserStateOnlineSharesOnePredicate(t *testing.T) {
	h := newTestServer(t)

	// ★造出**唯一能区分两套判据**的那个状态：这个人刚刚上报过 posture
	//   （store 侧因此判他"在线"），但一条网关会话都没有。
	//   不造它的话，测试服务器里既没有会话也没有上报，两套判据都算出"不在线"，
	//   这条用例就会在**坏实现上照样全绿**（实测逃逸过一次）。
	if code, out := doJSON(t, h, "POST", "/api/v1/posture", userToken("li.fang"), map[string]any{
		"device": "fp-userstate-probe", "platform": "macOS", "os": "14.5",
		"clientVersion": "0.1.0",
		"checks": []map[string]any{
			{"key": "disk_encrypted", "ok": false, "detail": "未加密"},
		},
	}); code != http.StatusOK {
		t.Fatalf("造 posture 上报 http %d: %v", code, out)
	}

	code, out := doJSON(t, h, "GET", "/api/v1/userstate", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /userstate http %d", code)
	}
	items, _ := out["items"].([]any)
	if len(items) == 0 {
		t.Fatal("前置条件不成立：刚上报过 posture 的账号应出现在用户态势里")
	}
	var onlineHere []string
	for _, raw := range items {
		m, _ := raw.(map[string]any)
		if on, _ := m["online"].(bool); on {
			onlineHere = append(onlineHere, str(m["account"]))
		}
	}
	// 测试服务器没有任何网关注册 → 不可能有会话 → 这一页也不该有人"在线"。
	if len(onlineHere) != 0 {
		t.Fatalf("没有任何网关上报会话时不该有人在线，却有 %v —— "+
			"说明这一页又用回了 posture 上报新鲜度那套判据", onlineHere)
	}

	// 与「在线用户」页同源：那边也必须是空的。
	_, on := doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	sess, _ := on["sessions"].([]any)
	if len(sess) != len(onlineHere) {
		t.Fatalf("两页在线口径必须一致：/userstate 说 %d 人在线，/online 说 %d 条会话",
			len(onlineHere), len(sess))
	}
}
