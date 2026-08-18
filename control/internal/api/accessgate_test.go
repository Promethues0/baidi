package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// newTestServerWithStore 与 newTestServer 同构，但把 store 一并交出来——
// 「网关报了活跃时刻」这一步没有对外 REST（它随 mTLS 心跳进来），用例直接落库模拟。
func newTestServerWithStore(t *testing.T) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "access.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), st
}

func nowUnix() int64 { return time.Now().Unix() }

func hasSub(s, sub string) bool { return strings.Contains(s, sub) }

// ── wave8 行动 13-①：接入策略端到端（FR-POLICY-29/30）──
//
// 被摘除的坏形态：「用户策略 · 继承编辑器」8 项落 policy_overrides.settings 后
// 全仓零消费方，保存 toast 却写着「已下发至「X」的代理网关」。
// 这两条是换上去的、**真有执行方**的规则，执行点是敲门令牌。

func setAccessPolicy(t *testing.T, h http.Handler, p map[string]any) {
	t.Helper()
	if code, out := doJSON(t, h, "PUT", "/api/v1/policies/access", adminToken(), p); code != http.StatusOK {
		t.Fatalf("保存接入策略 %d: %v", code, out)
	}
}

// knockAs 以 account/device 取一次敲门令牌，回状态码与响应。
func knockAs(t *testing.T, h http.Handler, account, device string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, h, "POST", "/api/v1/knock-token", userToken(account),
		map[string]string{"device": device})
}

// TestAccessPolicyDefaultIsInert 默认不生效——升级那一刻不能把任何人挡在门外。
func TestAccessPolicyDefaultIsInert(t *testing.T) {
	h := newTestServer(t)
	for _, dev := range []string{"d1", "d2", "d3", "d4", "d5"} {
		if code, out := knockAs(t, h, "li.fang", dev); code != http.StatusOK {
			t.Fatalf("默认配置下 %s 应放行，得到 %d: %v", dev, code, out)
		}
	}
	code, out := doJSON(t, h, "GET", "/api/v1/policies/access", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读接入策略 %d", code)
	}
	p, _ := out["policy"].(map[string]any)
	if p["deviceLimitEnabled"] != false || p["idleEnabled"] != false {
		t.Fatalf("出厂默认两条规则都必须是关的：%v", p)
	}
	// 记账仍要发生：页面上「谁在线、几台机器」是管理员定阈值的依据。
	if arr, _ := out["sessions"].([]any); len(arr) != 5 {
		t.Fatalf("规则没开也要记账（5 台），得到 %v", out["sessions"])
	}
	// 没有任何网关报过活跃时刻 → idleReady=false，页面据此提示"这条规则现在不会触发"。
	if out["idleReady"] != false {
		t.Fatalf("没有活跃回执时 idleReady 必须为 false：%v", out["idleReady"])
	}
}

// TestConcurrencyLimitEnforcedAtKnock 同时在线设备上限真的拦在敲门令牌上。
func TestConcurrencyLimitEnforcedAtKnock(t *testing.T) {
	h := newTestServer(t)
	setAccessPolicy(t, h, map[string]any{"deviceLimitEnabled": true, "maxDevices": 2})

	for _, dev := range []string{"d1", "d2"} {
		if code, _ := knockAs(t, h, "li.fang", dev); code != http.StatusOK {
			t.Fatalf("前两台应放行，%s 得到 %d", dev, code)
		}
	}
	code, out := knockAs(t, h, "li.fang", "d3")
	if code != http.StatusForbidden {
		t.Fatalf("第三台应被拒（403），得到 %d: %v", code, out)
	}
	if e := errMsg(out); e == "" {
		t.Fatalf("拒绝要给出可操作的原因：%v", out)
	}
	// ★已在名额内的两台**继续保活**必须照常放行。
	// 这一条是「先记账后判定」写反的判据：判据若是"当前表里有没有我"，
	// 这条上限对谁都不触发；若是"我在不在名额内"但漏了续期分支，
	// 用满名额后每 15s 会把自己挤下去，表现为轮流掉线。
	for i := 0; i < 3; i++ {
		for _, dev := range []string{"d1", "d2"} {
			if code, out := knockAs(t, h, "li.fang", dev); code != http.StatusOK {
				t.Fatalf("第 %d 轮保活：%s 应放行，得到 %d: %v", i, dev, code, out)
			}
		}
	}
	// ★指纹排在已在线那两台**前面**的新终端同样要被拒。
	// 这一条钉的是「新终端不许抢占已在线名额」：名额排序键是 (首次接入时间, 指纹)，
	// 而同一秒接入时指纹说了算——若新来者也走排名分支，一台叫 "a-new" 的机器
	// 会把 d1 顶掉，d1 要到下一个保活周期才发现自己被踢，且没有任何日志说得出是谁干的。
	if code, out := knockAs(t, h, "li.fang", "a-new"); code != http.StatusForbidden {
		t.Fatalf("指纹字典序靠前的新终端不该抢占已在线名额，得到 %d: %v", code, out)
	}
	// 被拒的那台不该在会话表里留下行（否则它会在排名里挤掉一台真在线的）。
	_, out = doJSON(t, h, "GET", "/api/v1/policies/access", adminToken(), nil)
	arr, _ := out["sessions"].([]any)
	for _, it := range arr {
		if fp := str(it.(map[string]any)["fingerprint"]); fp == "d3" || fp == "a-new" {
			t.Fatal("被上限拒之门外的终端不该在会话表里留行——它会在下一轮排名里挤掉一台真在线的")
		}
	}
	if len(arr) != 2 {
		t.Fatalf("应只剩两条会话，得到 %d 条", len(arr))
	}
	// 另一个账号不受影响（名额是按账号算的）。
	if code, _ := knockAs(t, h, "wang.qiang", "d9"); code != http.StatusOK {
		t.Fatalf("名额按账号算，别的账号不该被牵连，得到 %d", code)
	}
}

// TestConcurrencyZeroForbidsAccess 上限 0 = 禁止接入（PRD 原文）。
func TestConcurrencyZeroForbidsAccess(t *testing.T) {
	h := newTestServer(t)
	setAccessPolicy(t, h, map[string]any{"deviceLimitEnabled": true, "maxDevices": 0})
	code, out := knockAs(t, h, "li.fang", "d1")
	if code != http.StatusForbidden {
		t.Fatalf("上限 0 应拒，得到 %d", code)
	}
	if !hasSub(errMsg(out), "0") {
		t.Fatalf("文案要说清是被策略设成 0 了，而不是「网络问题」：%v", out)
	}
}

// TestIdleLogoutEndToEnd 接入超时注销：网关报活跃 → 超时 → 拒 → 重新登录恢复。
func TestIdleLogoutEndToEnd(t *testing.T) {
	h, st := newTestServerWithStore(t)
	setAccessPolicy(t, h, map[string]any{"idleEnabled": true, "idleMinutes": 5})

	if code, _ := knockAs(t, h, "li.fang", "d1"); code != http.StatusOK {
		t.Fatal("首次敲门应放行")
	}
	// 没有活跃回执时**不得**注销（判据缺席≠没有流量）。
	if code, out := knockAs(t, h, "li.fang", "d1"); code != http.StatusOK {
		t.Fatalf("网关没报过活跃时刻时不得注销，得到 %d: %v", code, out)
	}
	// 网关报一个 10 分钟前的活跃时刻 → 超过 5 分钟 → 下一次敲门被注销。
	sessions, _ := st.DeviceSessions(context.Background(), "li.fang")
	if len(sessions) != 1 {
		t.Fatalf("应有一条会话，得到 %d", len(sessions))
	}
	if err := st.MarkDeviceActivity(context.Background(), "li.fang", sessions[0].IP, nowUnix()-600); err != nil {
		t.Fatalf("落活跃回执: %v", err)
	}
	code, out := knockAs(t, h, "li.fang", "d1")
	if code != http.StatusForbidden {
		t.Fatalf("超过空闲时长应注销，得到 %d: %v", code, out)
	}
	if !hasSub(errMsg(out), "业务流量") {
		t.Fatalf("要说清是「无业务流量」，得到 %v", errMsg(out))
	}
	// ★注销是粘的：管理员事后关掉规则，也不该让它自己活过来。
	setAccessPolicy(t, h, map[string]any{"idleEnabled": false})
	if code, out := knockAs(t, h, "li.fang", "d1"); code != http.StatusForbidden {
		t.Fatalf("已注销的会话不该因为规则关闭就自己恢复，得到 %d: %v", code, out)
	}
	// 重新登录 → 恢复。
	portalLogin(t, h, "li.fang", "")
	if code, out := knockAs(t, h, "li.fang", "d1"); code != http.StatusOK {
		t.Fatalf("重新登录后应恢复接入，得到 %d: %v", code, out)
	}
	// ★恢复后不能立刻又被判超时（旧 first_seen / 旧 last_active 必须一起清掉，
	// 否则用户看到的是「登录成功，然后立刻又被踢」）。
	setAccessPolicy(t, h, map[string]any{"idleEnabled": true, "idleMinutes": 5})
	if code, out := knockAs(t, h, "li.fang", "d1"); code != http.StatusOK {
		t.Fatalf("恢复后重开规则不该立刻再次注销，得到 %d: %v", code, out)
	}
}

// TestAccessPolicyValidation 入口拒收越界值。
func TestAccessPolicyValidation(t *testing.T) {
	h := newTestServer(t)
	bad := []map[string]any{
		{"maxDevices": 1001},
		{"maxDevices": -1},
		{"idleEnabled": true, "idleMinutes": 4},
		{"idleEnabled": true, "idleMinutes": store.MaxIdleMinutes + 1},
	}
	for _, p := range bad {
		if code, out := doJSON(t, h, "PUT", "/api/v1/policies/access", adminToken(), p); code != http.StatusBadRequest {
			t.Errorf("越界配置应 400：%v → %d %v", p, code, out)
		}
	}
	// 普通用户不能改
	if code, _ := doJSON(t, h, "PUT", "/api/v1/policies/access", userToken("li.fang"),
		map[string]any{"deviceLimitEnabled": true, "maxDevices": 1}); code == http.StatusOK {
		t.Error("普通用户不该能改接入策略")
	}
}

// TestGwActivityReceiptIsTriState 网关活跃回执的三态：不报 / 报 0 / 报时刻。
//
// ★这条钉的是「旧网关不报 ≠ 从未活跃」。把 nil 当 0 落库的话，一台还没升级的网关
// 每 15s 就给它下面所有会话盖一个「最后活跃 = 1970 年」的戳，
// 管理员一开「接入超时注销」，全体在线用户当场被踢——而页面上那一栏看起来
// 只是「很久没有业务流量」，完全像是规则正常工作。
func TestGwActivityReceiptIsTriState(t *testing.T) {
	h, st := newTestServerWithStore(t)
	if code, _ := knockAs(t, h, "li.fang", "d1"); code != http.StatusOK {
		t.Fatal("首次敲门应放行")
	}
	rows, _ := st.DeviceSessions(context.Background(), "li.fang")
	if len(rows) != 1 {
		t.Fatalf("应有一条会话，得到 %d", len(rows))
	}
	ip := rows[0].IP
	if rows[0].ActivityKnown {
		t.Fatal("还没有任何网关上报过，活跃时刻必须是不可判定")
	}

	beat := func(sess map[string]any) {
		t.Helper()
		body := map[string]any{"id": "gw-a", "proxy": "10.0.0.1:18443", "spa": "10.0.0.1:18201",
			"sessions": []map[string]any{sess}}
		if code, out := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), body); code != http.StatusOK {
			t.Fatalf("心跳 %d: %v", code, out)
		}
	}
	// ① 旧网关：整个 lastActive 字段缺席 → 仍然不可判定。
	beat(map[string]any{"ip": ip, "user": "li.fang", "role": "user", "since": nowUnix() - 100})
	rows, _ = st.DeviceSessions(context.Background(), "li.fang")
	if rows[0].ActivityKnown {
		t.Fatal("旧网关（字段缺席）不该被当成「报告了从未活跃」——那会让超时规则把全员踢下线")
	}
	// ② 新网关明确报 0：从未有业务连接，但**这件事本身是已知的**。
	beat(map[string]any{"ip": ip, "user": "li.fang", "role": "user", "since": nowUnix() - 100, "lastActive": 0})
	rows, _ = st.DeviceSessions(context.Background(), "li.fang")
	if !rows[0].ActivityKnown || rows[0].LastActive != 0 {
		t.Fatalf("网关明确报 0 应落成「已知 · 从未活跃」，得到 known=%v last=%d",
			rows[0].ActivityKnown, rows[0].LastActive)
	}
	// ③ 报一个真实时刻。
	ts := nowUnix() - 30
	beat(map[string]any{"ip": ip, "user": "li.fang", "role": "user", "since": nowUnix() - 100, "lastActive": ts})
	rows, _ = st.DeviceSessions(context.Background(), "li.fang")
	if rows[0].LastActive != ts {
		t.Fatalf("活跃时刻应落库，期望 %d 得到 %d", ts, rows[0].LastActive)
	}
	// ④ **只往前推不倒退**：另一台网关报一个更早的时刻，不得把真实活跃时刻覆盖掉
	//    （否则"人在用、却被判超时"）。
	beat(map[string]any{"ip": ip, "user": "li.fang", "role": "user", "since": nowUnix() - 100, "lastActive": ts - 600})
	rows, _ = st.DeviceSessions(context.Background(), "li.fang")
	if rows[0].LastActive != ts {
		t.Fatalf("更早的回执不该覆盖更新的活跃时刻，得到 %d", rows[0].LastActive)
	}
}
