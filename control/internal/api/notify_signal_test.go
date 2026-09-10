package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"baidi.dev/control/internal/notify"
	"baidi.dev/control/internal/store"
)

// ── wave11 行动 17：通知面两条 ──
//
// ① 消息通道失效此前**没有任何主动信号**：没有告警规则、没有 /diag 项，
//    只有系统页深处那一格 last_status 变红。
// ② 消息通道对「审批」这一类**零执行方**：PRD ch15.2 逐字列的三类用途
//    （认证 / 告警 / 审批）里，只有告警与两类安全事件接了线。
//
// 下面按「四种处境」逐条钉 /diag，再按三处产生点各钉一条审批通知。
//
// ★变异实测（每条修复都能被下面某条用例变红）：
//   - checkNotifyChannels 的 `live == 0` 分支判 pass  → …AllDisabledIsWarnNotPass 红；
//   - `never > 0` 分支判 pass                          → …NeverSentIsWarn 红；
//   - 摘掉 handlePortalCreateAccessRequest 里那句通知  → TestJitRequestNotifiesApprovers 红；
//   - 把 enrollReportingDevice 的 `dev.Status != trusted` 改成恒 false
//                                                      → TestDeviceApprovalNotifiesApprovers 红；
//   - 把 admitExternal 的 `if created` 改成恒 true（每次登录都发）
//                                                      → TestExtAdmissionNotifiesApproversOnceOnly 红；
//   - 摘掉 notifyApprovalPending 的「一个邮箱都没取到」那条审计
//                                                      → TestApprovalNoticeAuditsWhenNoRecipient 红；
//   - 把收件人判据从 `role.Allows(PermSecurity)` 退化成「是管理员就发」
//                                                      → TestApprovalRecipientsFollowSecurityPerm 红。

// setNotifyChannel 经真实管理端点落一条通道（不发送，故 last_* 仍为空）。
func setNotifyChannel(t *testing.T, h http.Handler, name string, enabled bool) string {
	t.Helper()
	code, out := doJSON(t, h, "POST", "/api/v1/notify/channels", adminToken(), map[string]any{
		"name": name, "kind": "webhook", "enabled": enabled,
		"config": map[string]any{"url": "http://127.0.0.1:1/hook"},
	})
	if code != http.StatusOK {
		t.Fatalf("保存通道 %d：%v", code, out)
	}
	ch, _ := out["channel"].(map[string]any)
	return str(ch["id"])
}

// TestDiagNotifyNoChannelIsSkipButSaysWhy 一条通道都没配 = 没用这个功能（skip），
// 但**后果必须写在脸上**：三条链路的通知都不会送到任何人。
func TestDiagNotifyNoChannelIsSkipButSaysWhy(t *testing.T) {
	h := newTestServer(t)
	c := diagCheck(t, getDiag(t, h), "notify")
	if c["status"] != "skip" {
		t.Fatalf("没配通道应 skip（与 checkNAT 同档，不进健康分），实得 %v", c["status"])
	}
	if sum := str(c["summary"]); !strings.Contains(sum, "不会通知到任何人") {
		t.Fatalf("skip 也要写清后果，实得 %q", sum)
	}
}

// TestDiagNotifyAllDisabledIsWarnNotPass 配了但全部停用：**不是故障**（管理员显式关的），
// 但后果与"坏了"一样，所以既不能 pass，也不能像"没配过"那样 skip 掉。
//
// ★这条与 TestDiagNotifyFailingIsFail 一起，就是「通道停用/删除与发送失败是两件事」
// 在体检面上的落点：两者的 status、summary、hint 全不同。
func TestDiagNotifyAllDisabledIsWarnNotPass(t *testing.T) {
	h := newTestServer(t)
	setNotifyChannel(t, h, "值班邮箱", false)
	c := diagCheck(t, getDiag(t, h), "notify")
	if c["status"] != "warn" {
		t.Fatalf("全部停用应 warn，实得 %v（summary=%v）", c["status"], c["summary"])
	}
	sum := str(c["summary"])
	if !strings.Contains(sum, "全部停用") || !strings.Contains(sum, "不是故障") {
		t.Fatalf("文案要把「显式停用」与「坏了」分开，实得 %q", sum)
	}
}

// TestDiagNotifyNeverSentIsWarn 启用中但从未发送过 = **没有任何证据说它能用**。
// 判 pass 就是替一条还没说过话的通道背书（照 checkAuditForward 的 never 档）。
func TestDiagNotifyNeverSentIsWarn(t *testing.T) {
	h := newTestServer(t)
	setNotifyChannel(t, h, "值班邮箱", true)
	c := diagCheck(t, getDiag(t, h), "notify")
	if c["status"] != "warn" {
		t.Fatalf("启用但从未发过应 warn（不可判定，不是正常），实得 %v（summary=%v）", c["status"], c["summary"])
	}
	if sum := str(c["summary"]); !strings.Contains(sum, "还没有证据") {
		t.Fatalf("文案要说清是「没有证据」而不是「有问题」，实得 %q", sum)
	}
}

// TestDiagNotifyFailingIsFail 真发过、且最近一次失败 → fail。
// 配置指向一个必然连不上的地址，再点一次真实的「测试」——last_* 四列只由那一次写入。
func TestDiagNotifyFailingIsFail(t *testing.T) {
	h := newTestServer(t)
	id := setNotifyChannel(t, h, "值班邮箱", true)
	code, out := doJSON(t, h, "POST", "/api/v1/notify/channels/"+id+"/test", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("测试端点 %d：%v", code, out)
	}
	if out["ok"] == true {
		t.Fatalf("用例前提不成立：127.0.0.1:1 不该连得上，实得 %v", out)
	}
	c := diagCheck(t, getDiag(t, h), "notify")
	if c["status"] != "fail" {
		t.Fatalf("最近一次发送失败应 fail，实得 %v（summary=%v）", c["status"], c["summary"])
	}
	// 明细行要带后端原话——只说"失败"会让管理员去猜是网络还是凭据。
	items, _ := c["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("应逐通道给一行明细，实得 %v", items)
	}
	it := items[0].(map[string]any)
	if it["status"] != "fail" || !strings.Contains(str(it["value"]), "失败") {
		t.Fatalf("明细行要如实标 fail 并转述原话，实得 %v", it)
	}
}

// ── ② 审批类通知 ──

// captureNotices 把派发器换成一个只记录的 sink，返回取快照的闭包。
func captureNotices(t *testing.T, s *Server) func() []notify.Message {
	t.Helper()
	var mu sync.Mutex
	var got []notify.Message
	s.notices = notify.NewDispatcher(0, func(_ context.Context, m notify.Message) {
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}, slog.Default())
	t.Cleanup(func() { s.notices.Close() })
	return func() []notify.Message {
		s.notices.Wait()
		mu.Lock()
		defer mu.Unlock()
		return append([]notify.Message(nil), got...)
	}
}

func approvalNotice(ms []notify.Message) *notify.Message {
	for i := range ms {
		if ms[i].Event == "approval-pending" {
			return &ms[i]
		}
	}
	return nil
}

// TestJitRequestNotifiesApprovers JIT 申请单产生点必须发一条待批通知。
//
// 坏形态：这张单子在被批准之前，申请人**一步也走不下去**（网关那边没有放行），
// 而管理员唯一的发现途径是自己去翻审批页——"提了申请，等了一天，没人知道"。
func TestJitRequestNotifiesApprovers(t *testing.T) {
	f := newIsoFixture(t)
	snap := captureNotices(t, f.s)

	// 造一条**受限**资源（JIT 只对设了主体限制的资源受理）+ 一个指向它的应用。
	if code, out := f.saveResource(map[string]any{
		"id": "hr", "name": "人事系统", "backend": "10.50.1.2:8080", "allowUsers": []string{"someone.else"},
	}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("建资源 %d：%v", code, out)
	}
	code, app := doJSON(t, f.h, "POST", "/api/v1/apps", adminToken(), map[string]any{
		"name": "人事系统", "addr": "10.50.1.2:8080", "mode": "web", "category": "office", "resourceId": "hr",
	})
	if code != http.StatusCreated {
		t.Fatalf("建应用 %d：%v", code, app)
	}
	code, out := doJSON(t, f.h, "POST", "/api/v1/portal/access-requests", userToken("li.fang"), map[string]any{
		"appId": str(app["id"]), "reason": "季度对账", "ttlMinutes": 60,
	})
	if code != http.StatusCreated {
		t.Fatalf("提交申请 %d：%v", code, out)
	}
	hit := approvalNotice(snap())
	if hit == nil {
		t.Fatal("JIT 申请必须发一条待批通知（改造前三处审批产生点一次都不发）")
	}
	for _, want := range []string{"li.fang", "人事系统"} {
		if !strings.Contains(hit.Subject+hit.Body, want) {
			t.Errorf("通知要点名申请人与目标资源，缺 %q：%s", want, hit.Body)
		}
	}
	if !strings.Contains(hit.Body, "在批准之前") {
		t.Error("正文要说清「不批就走不下去」——只说「有一条申请」不足以让人去处置")
	}
}

// TestDeviceApprovalNotifiesApprovers 终端绑定待批那一档另发一条**给管理员**的待办。
//
// ★与 device-first-seen 刻意分成两条：那条是给账号本人看的账号安全信号（两种绑定
// 方式下都发），这条是给持 security 权的管理员看的待办（只在审批绑定下才存在）。
// 合成一条的话，自动绑定的部署会天天收到一条不存在的"待办"。
func TestDeviceApprovalNotifiesApprovers(t *testing.T) {
	f := newIsoFixture(t)
	// 切到「审批绑定」——默认就是它，这里显式落一次，免得默认值变了用例静默失效。
	if code, out := doJSON(t, f.h, "PUT", "/api/v1/devices/settings", adminToken(), map[string]any{
		"mode": store.DeviceTrustObserve, "bindMethod": store.DeviceBindApproval, "staleDays": 30,
	}); code != http.StatusOK {
		t.Fatalf("置准入设置 %d：%v", code, out)
	}
	snap := captureNotices(t, f.s)
	code, out := doJSON(t, f.h, "POST", "/api/v1/posture", userToken("li.fang"), map[string]any{
		"device": "aa11:bb22", "platform": "macOS", "os": "macOS 15", "clientVersion": "0.1.0",
		"checks": []map[string]any{{"key": "disk_encrypted", "label": "磁盘已加密", "ok": true}},
	})
	if code != http.StatusOK {
		t.Fatalf("posture 上报 %d：%v", code, out)
	}
	ms := snap()
	hit := approvalNotice(ms)
	if hit == nil {
		t.Fatalf("终端待批必须发一条审批通知，实得事件：%v", eventsOf(ms))
	}
	if !strings.Contains(hit.Subject+hit.Body, "li.fang") {
		t.Errorf("通知要点名账号：%s", hit.Body)
	}
	// 两条通知同时存在、且是两个不同的事件键。
	var firstSeen bool
	for _, m := range ms {
		if m.Event == "device-first-seen" {
			firstSeen = true
		}
	}
	if !firstSeen {
		t.Error("「新终端首次登录」那条（给账号本人的安全信号）不该被审批通知顶掉")
	}
}

// TestExtAdmissionNotifiesApproversOnceOnly 外部身份准入待批那一处，
// **只在真的新建了一张单子那次**发。
//
// ★这条纪律与 auditAdmitDenied 的 `!v.Pending || v.NewTicket` 同源：登录可以无限重试，
// 按"每次被拒都发"的话，一个反复登录的外部账号就能把管理员的邮箱刷爆，
// 而真正的新事件（又一个人在等批准）淹在里面。
func TestExtAdmissionNotifiesApproversOnceOnly(t *testing.T) {
	s, _, _ := newFailServer(t)
	snap := captureNotices(t, s)
	rec := admitSrc(store.AdmitApproval, nil, nil)
	id := ident("wang", "wang@ex.com")

	if v := s.admitExternal(context.Background(), rec, id, false); v.Allowed || !v.NewTicket {
		t.Fatalf("首登应登记一张新待批单：%+v", v)
	}
	// 同一个人再登四次：待批单是幂等的，通知也必须是。
	for i := 0; i < 4; i++ {
		s.admitExternal(context.Background(), rec, id, false)
	}
	n := 0
	for _, m := range snap() {
		if m.Event == "approval-pending" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("5 次登录只该发 1 条审批通知（按 NewTicket 判，与审计同源），实得 %d 条", n)
	}
}

// TestApprovalNoticeAuditsWhenNoRecipient 收件人取不到时**必须留痕**。
//
// ★这是本条最要紧的断言：默认部署里 users.email 只有外部认证源带回来的账号有值，
// 本地管理员至今没有邮箱采集入口——也就是说"一个收件人都点不到"是**默认形态**。
// 静默通过的话，这个功能就是又一处"看起来接了、真出事那天一条都收不到、
// 且没有任何报错"。
func TestApprovalNoticeAuditsWhenNoRecipient(t *testing.T) {
	f := newIsoFixture(t)
	captureNotices(t, f.s)
	f.s.notifyApprovalPending(context.Background(), "JIT 访问申请", "li.fang", "主题", "正文")
	f.s.notices.Wait()

	code, out := doJSON(t, f.h, "GET", "/api/v1/audit?limit=50", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读审计 %d：%v", code, out)
	}
	found := ""
	logs, _ := out["logs"].([]any)
	for _, it := range logs {
		e := it.(map[string]any)
		if ev := str(e["event"]); strings.Contains(ev, "JIT 访问申请待批") {
			found = ev + "|" + str(e["verdict"]) + "|" + str(e["user"])
		}
	}
	if found == "" {
		t.Fatal("收件人取不到时必须落一条审计说明通知没送到任何人（照 notify 那条既有纪律）")
	}
	if !strings.Contains(found, "|fail|") {
		t.Errorf("那条审计的 verdict 应为 fail（它陈述的是一次没送达），实得 %q", found)
	}
	if !strings.Contains(found, "|system") {
		t.Errorf("行为人应是 system（异步动作记到某个管理员头上是最难自证的错记），实得 %q", found)
	}
	if !strings.Contains(found, "未登记邮箱") {
		t.Errorf("要说清是哪一种取不到（没人有权 vs 有人但没邮箱），实得 %q", found)
	}
}

// TestApprovalRecipientsFollowSecurityPerm 收件人判据 = **持 security 权限键**，
// 不是 power、也不是页面上那个中文角色名（与 requirePerm 同一条纪律）。
func TestApprovalRecipientsFollowSecurityPerm(t *testing.T) {
	f := newIsoFixture(t)
	// 造两名管理员：一名安全管理员（该收到）、一名审计管理员（不该收到），各带邮箱。
	mk := func(account, role, mail string) {
		code, out := doJSON(f.t, f.h, "POST", "/api/v1/admins", adminToken(), map[string]any{
			"name": account, "account": account, "password": "Baidi@Test#2026", "roleKey": role,
		})
		if code != http.StatusCreated && code != http.StatusOK {
			f.t.Fatalf("建管理员 %s：%d %v", account, code, out)
		}
		id := ""
		_, dir := doJSON(f.t, f.h, "GET", "/api/v1/users", adminToken(), nil)
		for _, it := range dir["users"].([]any) {
			u := it.(map[string]any)
			if str(u["account"]) == account {
				id = str(u["id"])
			}
		}
		if id == "" {
			f.t.Fatalf("目录里应能找到 %s", account)
		}
		if code, out := doJSON(f.t, f.h, "PUT", "/api/v1/users/"+id, adminToken(), map[string]any{
			"name": account, "email": mail,
		}); code != http.StatusOK {
			f.t.Fatalf("补邮箱 %d：%v", code, out)
		}
	}
	mk("sec.wang", "security", "sec@example.com")
	mk("aud.chen", "audit", "aud@example.com")

	got := f.s.securityApprovers(context.Background())
	if got.Err != nil {
		t.Fatalf("解析收件人失败：%v", got.Err)
	}
	joined := strings.Join(got.Emails, ",")
	if !strings.Contains(joined, "sec@example.com") {
		t.Fatalf("安全管理员应在收件人里（审批端点收在 PermSecurity 上），实得 %v", got.Emails)
	}
	if strings.Contains(joined, "aud@example.com") {
		t.Fatalf("审计管理员**无权**处置审批单，不该出现在收件人里，实得 %v", got.Emails)
	}
	// 超管持 `*`，Allows(security) 为真——它也该在名单里（只是种子 admin 没登记邮箱，
	// 故这里断言的是计数而不是邮箱）。
	if got.Admins < 2 {
		t.Fatalf("持 security 权的管理员应至少含超管与 sec.wang，实得 %d", got.Admins)
	}
}
