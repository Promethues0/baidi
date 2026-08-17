package api

import (
	"net/http"
	"strings"
	"testing"
)

// ── wave8 行动 8：C/S 隧道放行留痕 ──
//
// 被修的坏形态：审计里**只有拒绝没有放行**。`handleKnockToken` 成功路径零审计，
// 而同函数与 entryGates 里五处拒绝全部落审计；网关的「隧道路由命中」只进本机 slog，
// 网关一重启即灭失。于是「某账号何时经哪台网关访问了哪个资源」在中心侧查不到，
// 外送给 SIEM 的证据链只有半边。对照最刺眼的是——过同一道 entryGates 的 B/S 路径
// 签票时是落审计的，C/S 这条主路径反而不落。

// auditRows 拉审计并返回带全部字段的行（已有的 auditEvents 只回事件文本，
// 这里要断言 verdict / actor / src_ip 三格）。
func auditRows(t *testing.T, h http.Handler) []auditRow {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /audit = %d", code)
	}
	raw, _ := out["logs"].([]any)
	var es []auditRow
	for _, it := range raw {
		m, _ := it.(map[string]any)
		es = append(es, auditRow{
			Event:   str(m["event"]),
			Verdict: str(m["verdict"]),
			User:    str(m["user"]),
			SrcIP:   str(m["srcIp"]),
			Cat:     str(m["category"]),
		})
	}
	return es
}

type auditRow struct{ Event, Verdict, User, SrcIP, Cat string }

// findAudit 返回第一条事件文本含 sub 的审计。
func findAudit(es []auditRow, sub string) (auditRow, bool) {
	for _, e := range es {
		if strings.Contains(e.Event, sub) {
			return e, true
		}
	}
	return auditRow{}, false
}

// TestKnockTokenSuccessIsAudited 成功签发敲门令牌必须留痕（category=access，verdict=allow）。
func TestKnockTokenSuccessIsAudited(t *testing.T) {
	h := newTestServer(t)
	code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", userToken("zhang.wei"),
		map[string]string{"device": "fp-abcdef0123456789"})
	if code != http.StatusOK {
		t.Fatalf("签发失败 http %d", code)
	}
	e, ok := findAudit(auditRows(t, h), "已签发敲门令牌")
	if !ok {
		t.Fatal("成功签发零审计——审计里只有拒绝没有放行，正是被修的那个洞")
	}
	if e.Cat != "access" {
		t.Errorf("应记 category=access（这是一次访问决策），得到 %q", e.Cat)
	}
	if e.Verdict != "allow" {
		t.Errorf("应记 verdict=allow，得到 %q", e.Verdict)
	}
	if e.User != "zhang.wei" {
		t.Errorf("行为人应是账号本人，得到 %q", e.User)
	}
	if !strings.Contains(e.Event, "fp-abcdef012") {
		t.Errorf("应带上设备指纹（短形），得到 %q", e.Event)
	}
	// ★不得断言"已接入/已建立隧道"：拿到令牌只是拿到敲门的资格。
	for _, bad := range []string{"已接入", "已建立隧道"} {
		if strings.Contains(e.Event, bad) {
			t.Errorf("措辞越界（只该陈述已签发这一事实）：%q", e.Event)
		}
	}
}

// TestKnockTokenAuditThrottled 保活热路径必须节流。
//
// ★baidi-tun 每 15s 一次 reknock，不节流的话一个终端一天产出约 5700 条内容相同的
// 审计，真正的处置事件会被冲刷掉——与 auditDeviceObserved 同一条理由、同一个量级。
func TestKnockTokenAuditThrottled(t *testing.T) {
	h := newTestServer(t)
	for i := 0; i < 5; i++ {
		code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", userToken("zhang.wei"),
			map[string]string{"device": "fp-same"})
		if code != http.StatusOK {
			t.Fatalf("第 %d 次签发失败 http %d", i, code)
		}
	}
	n := 0
	for _, e := range auditRows(t, h) {
		if strings.Contains(e.Event, "已签发敲门令牌") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("5 次连续保活应只留 1 条审计（5min 节流），得到 %d 条", n)
	}
}

// TestKnockTokenAuditPerDevice 节流键含设备指纹：同账号两台设备各留一条。
// 只按账号节流的话，第二台机器的首次接入会被第一台压掉。
func TestKnockTokenAuditPerDevice(t *testing.T) {
	h := newTestServer(t)
	for _, fp := range []string{"fp-laptop", "fp-desktop"} {
		doJSON(t, h, "POST", "/api/v1/knock-token", userToken("zhang.wei"),
			map[string]string{"device": fp})
	}
	n := 0
	for _, e := range auditRows(t, h) {
		if strings.Contains(e.Event, "已签发敲门令牌") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("两台设备应各留一条，得到 %d 条", n)
	}
}

// TestDataplaneAllowEventAudited 网关上报的放行回执：verdict=allow，且**不**计攻击源。
func TestDataplaneAllowEventAudited(t *testing.T) {
	h := newTestServer(t)
	code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443",
		"events": []map[string]any{
			{"kind": "sec-allow", "cat": "tunnel-allow", "src": "192.168.9.9", "count": 1,
				"detail": "隧道放行：账号 zhang.wei 经隧道访问资源 res-git（后端 10.1.1.5:22）"},
			{"kind": "sec-deny", "cat": "proxy-unauth", "src": "203.0.113.7", "count": 3,
				"detail": "隧道代理拒绝（无 SPA 授权，直连被断）"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("register http %d", code)
	}
	es := auditRows(t, h)
	allow, ok := findAudit(es, "隧道放行")
	if !ok {
		t.Fatal("放行回执没落审计")
	}
	if allow.Verdict != "allow" {
		t.Errorf("放行应记 verdict=allow，得到 %q", allow.Verdict)
	}
	deny, ok := findAudit(es, "无 SPA 授权")
	if !ok {
		t.Fatal("拒绝回执没落审计")
	}
	if deny.Verdict != "deny" {
		t.Errorf("拒绝应记 verdict=deny，得到 %q", deny.Verdict)
	}

	// ★放行绝不能进攻击源统计：把一次正常访问数进「攻击源 TOP」，
	// 是最容易误导排障的一种错记。
	_, ov := doJSON(t, h, "GET", "/api/v1/overview", adminToken(), nil)
	if raw, _ := ov["attack"].(map[string]any); raw != nil {
		if tops, _ := raw["top"].([]any); tops != nil {
			for _, it := range tops {
				m, _ := it.(map[string]any)
				if str(m["ip"]) == "192.168.9.9" {
					t.Fatalf("放行的来源被计进攻击源 TOP 了：%v", m)
				}
			}
		}
	}
}

// TestDataplaneEventUsesReportedSrcIP 数据面事件的源 IP 记的是**网关报上来的那个**。
//
// ★此前一律记 clientIP(r) = 网关自己的地址，于是按 src_ip 检索审计永远找不到
// 攻击者/访问者，那个地址只活在事件正文的自由文本里；FR-AUDIT-05 的
// 「出向四元组检索」也就没有数据源。
func TestDataplaneEventUsesReportedSrcIP(t *testing.T) {
	h := newTestServer(t)
	doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443",
		"events": []map[string]any{
			{"kind": "sec-deny", "cat": "knock-replay", "src": "203.0.113.7", "count": 1,
				"detail": "敲门令牌重放被拒"},
			// 没有 src 的回执（策略下发这类）：来源确实就是网关自己，回落 clientIP。
			{"kind": "policy-applied", "detail": "已应用资源策略 3 条"},
		},
	})
	es := auditRows(t, h)
	e, ok := findAudit(es, "敲门令牌重放")
	if !ok {
		t.Fatal("没找到该条审计")
	}
	if e.SrcIP != "203.0.113.7" {
		t.Fatalf("源 IP 应是网关报的攻击者地址，得到 %q（记成网关自己的地址就检索不到攻击者）", e.SrcIP)
	}
	p, ok := findAudit(es, "已应用资源策略")
	if !ok {
		t.Fatal("没找到回执审计")
	}
	if p.SrcIP == "" || p.SrcIP == "203.0.113.7" {
		t.Fatalf("无来源的回执应回落到请求方地址，得到 %q", p.SrcIP)
	}
}

// ── wave8 行动 9：态势总览时间窗的接线断言 ──

// TestOverviewHonorsHoursParam ?hours= 真的传到了 store。
// ★只测 store 的话，把 handler 里那个查询参数删掉用例照样全绿。
func TestOverviewHonorsHoursParam(t *testing.T) {
	h := newTestServer(t)
	for _, c := range []struct {
		q    string
		want float64
	}{
		{"", 24},                   // 不传 = 默认 24h
		{"?hours=168", 168},        // 7 天
		{"?hours=720", 720},        // 30 天
		{"?hours=0", 24},           // 0 视为未指定
		{"?hours=999999", 24 * 90}, // 超上界钳到 90 天
	} {
		code, out := doJSON(t, h, "GET", "/api/v1/overview"+c.q, adminToken(), nil)
		if code != http.StatusOK {
			t.Fatalf("GET /overview%s = %d", c.q, code)
		}
		if got := out["windowHours"].(float64); got != c.want {
			t.Errorf("%q → windowHours=%v，期望 %v", c.q, got, c.want)
		}
		if str(out["windowNote"]) == "" {
			t.Errorf("%q 缺口径说明——页面无从标注哪些数按窗口算", c.q)
		}
	}
}

// TestOverviewDefenseScopeReachesAPI 防线口径要一路下发到 API。
func TestOverviewDefenseScopeReachesAPI(t *testing.T) {
	h := newTestServer(t)
	_, out := doJSON(t, h, "GET", "/api/v1/overview", adminToken(), nil)
	lines, _ := out["defense"].([]any)
	if len(lines) == 0 {
		t.Fatal("没有防线数据")
	}
	seen := map[string]string{}
	for _, it := range lines {
		m, _ := it.(map[string]any)
		seen[str(m["key"])] = str(m["scope"])
		if str(m["note"]) == "" {
			t.Errorf("防线 %q 缺口径说明", str(m["key"]))
		}
	}
	if seen["attack"] != "window" {
		t.Errorf("隐身防线应按窗口算，得到 %q", seen["attack"])
	}
	// ★这两条是当前状态。标成 window 的话，管理员切到「近 7 天」会以为看到的是
	// 七天内的情况，而它们压根没变——悄悄不生效的筛选比没有筛选更坏。
	for _, k := range []string{"account", "endpoint"} {
		if seen[k] != "current" {
			t.Errorf("防线 %q 是当前状态快照，应标 current，得到 %q", k, seen[k])
		}
	}
}
