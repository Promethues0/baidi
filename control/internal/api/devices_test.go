// 授信终端主线的端到端用例（PRD ch9 FR-EP-10/12/13/14/15）。
//
// 覆盖：生命周期状态机 · 严格/观察两种准入模式下的敲门判定 · 吊销 → 会话撤销的
// 端到端链路（API → 网关策略下发）· 单账号设备上限 · trusted_devices 与
// posture_reports 的口径一致性。
package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"

	_ "modernc.org/sqlite"
)

// ── 测试助手 ──

// deviceEnv 一套可「重启」的控制面：设备吊销落库，而强制下线封禁是内存态，
// 重启后封禁消失、吊销仍在——用它把两者的生命周期差异钉住。
type deviceEnv struct {
	h    http.Handler
	path string
}

func newDeviceEnv(t *testing.T) *deviceEnv {
	t.Helper()
	e := &deviceEnv{path: filepath.Join(t.TempDir(), "devices.db")}
	e.h = openDeviceServer(t, e.path)
	return e
}

func openDeviceServer(t *testing.T, path string) http.Handler {
	t.Helper()
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes())
}

// restart 重建控制面进程态（内存里的强制下线封禁随之清空）。
func (e *deviceEnv) restart(t *testing.T) {
	t.Helper()
	e.h = openDeviceServer(t, e.path)
}

// rawDB 直连测试库（只用于构造"很久没上报"这类时间态，不走生产写路径）。
func (e *deviceEnv) rawDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+e.path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ageDevices 把某账号名下所有设备的 last_seen 推到 400 天前（造陈旧态）。
func (e *deviceEnv) ageDevices(t *testing.T, account string) {
	t.Helper()
	old := time.Now().Add(-400 * 24 * time.Hour).Unix()
	if _, err := e.rawDB(t).Exec(`UPDATE trusted_devices SET last_seen=? WHERE account=?`, old, account); err != nil {
		t.Fatalf("造陈旧态失败: %v", err)
	}
}

// countDevices 某账号名下的设备台账行数。
func countDevices(t *testing.T, h http.Handler, account string) int {
	t.Helper()
	n := 0
	for _, d := range deviceList(t, h) {
		if d["account"] == account {
			n++
		}
	}
	return n
}

// postureFingerprints 某账号名下有 posture 报告的设备指纹集合。
func postureFingerprints(t *testing.T, h http.Handler, account string) map[string]bool {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/posture", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读 posture 清单 http %d", code)
	}
	set := map[string]bool{}
	reports, _ := out["reports"].([]any)
	for _, it := range reports {
		m, ok := it.(map[string]any)
		if !ok || m["user"] != account {
			continue
		}
		set[m["device"].(string)] = true
	}
	return set
}

func countPostureDevices(t *testing.T, h http.Handler, account string) int {
	t.Helper()
	return len(postureFingerprints(t, h, account))
}

// assertTablesAligned 两表口径一致：每条 posture 报告都有设备登记；
// 每台"有判定"的设备都有报告。任一方向不成立都会产生排不掉的故障。
func assertTablesAligned(t *testing.T, h http.Handler, account string) {
	t.Helper()
	posture := postureFingerprints(t, h, account)
	devices := map[string]bool{}
	withVerdict := map[string]bool{}
	for _, d := range deviceList(t, h) {
		if d["account"] != account {
			continue
		}
		fp := d["fingerprint"].(string)
		devices[fp] = true
		if v, _ := d["verdict"].(string); v != "" {
			withVerdict[fp] = true
		}
	}
	for fp := range posture {
		if !devices[fp] {
			t.Fatalf("posture 报告 %s 没有对应的设备登记（孤儿报告：设备页看不见它，但它照样拉低跨设备最差判定）", fp)
		}
	}
	for fp := range withVerdict {
		if !posture[fp] {
			t.Fatalf("设备 %s 显示有判定却查不到 posture 报告（两表口径已分家）", fp)
		}
	}
}

// reportPosture 以某账号上报一次全合规的 posture（判定 allow），顺带完成设备登记。
func reportPosture(t *testing.T, h http.Handler, sess, device string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, h, "POST", "/api/v1/posture", sess, map[string]any{
		"platform": "macOS", "os": "macOS 15.1", "clientVersion": "0.1.0", "device": device,
		"checks": []map[string]any{
			{"key": "disk_encrypted", "label": "磁盘已加密", "ok": true, "value": "on"},
			{"key": "sys_integrity", "label": "系统完整性保护开启", "ok": true, "value": "on"},
			{"key": "firewall_on", "label": "系统防火墙启用", "ok": true, "value": "on"},
			{"key": "os_version", "label": "系统版本合规", "ok": true, "value": "15.1"},
			{"key": "edr_online", "label": "EDR 终端防护在线", "ok": true, "value": "on"},
			{"key": "client_version", "label": "客户端为最新版本", "ok": true, "value": "0.1.0"},
		}})
}

// deviceList 拉终端管理页的设备清单。
func deviceList(t *testing.T, h http.Handler) []map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/devices", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /devices http %d: %v", code, out)
	}
	arr, _ := out["devices"].([]any)
	devs := make([]map[string]any, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			devs = append(devs, m)
		}
	}
	return devs
}

// findDevice 按 (账号, 指纹) 定位设备行。
func findDevice(t *testing.T, h http.Handler, account, fingerprint string) map[string]any {
	t.Helper()
	for _, d := range deviceList(t, h) {
		if d["account"] == account && d["fingerprint"] == fingerprint {
			return d
		}
	}
	t.Fatalf("设备清单里找不到 %s / %s", account, fingerprint)
	return nil
}

func setDeviceStatus(t *testing.T, h http.Handler, account, fingerprint, status, reason string) map[string]any {
	t.Helper()
	d := findDevice(t, h, account, fingerprint)
	code, out := doJSON(t, h, "POST", "/api/v1/devices/"+d["id"].(string)+"/status", adminToken(),
		map[string]any{"status": status, "reason": reason})
	if code != http.StatusOK {
		t.Fatalf("设置设备状态 %s http %d: %v", status, code, out)
	}
	return out
}

func approveDevice(t *testing.T, h http.Handler, account, fingerprint string) {
	t.Helper()
	setDeviceStatus(t, h, account, fingerprint, store.DeviceStatusTrusted, "")
}

func revokeDevice(t *testing.T, h http.Handler, account, fingerprint, reason string) map[string]any {
	t.Helper()
	return setDeviceStatus(t, h, account, fingerprint, store.DeviceStatusRevoked, reason)
}

func saveTrustSetting(t *testing.T, h http.Handler, mode, bind string, staleDays int) {
	t.Helper()
	code, out := doJSON(t, h, "PUT", "/api/v1/devices/settings", adminToken(),
		map[string]any{"mode": mode, "bindMethod": bind, "staleDays": staleDays})
	if code != http.StatusOK {
		t.Fatalf("保存准入设置 http %d: %v", code, out)
	}
}

// knockWithDevice 带指纹申请敲门令牌。
func knockWithDevice(t *testing.T, h http.Handler, sess, device string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, h, "POST", "/api/v1/knock-token", sess, map[string]any{"device": device})
}

// auditEvents 取全部审计事件文本（新→旧）。
func auditEvents(t *testing.T, h http.Handler) []string {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读审计 http %d", code)
	}
	logs, _ := out["logs"].([]any)
	evs := make([]string, 0, len(logs))
	for _, it := range logs {
		if m, ok := it.(map[string]any); ok {
			if e, ok := m["event"].(string); ok {
				evs = append(evs, e)
			}
		}
	}
	return evs
}

func auditHasEvent(t *testing.T, h http.Handler, substr string) bool {
	t.Helper()
	for _, e := range auditEvents(t, h) {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// userSession 用真实门户登录换一个会话令牌（种子账号口令 baidi@123）。
func userSession(t *testing.T, h http.Handler, user string) string {
	t.Helper()
	out := portalLogin(t, h, user, "")
	tok, _ := out["token"].(string)
	if tok == "" {
		t.Fatalf("%s 登录未拿到令牌: %v", user, out)
	}
	return tok
}

// ── ① 生命周期状态机 ──

// 首次上报 → pending（审批绑定，默认）→ 批准 → trusted → 吊销 → revoked；
// 且 revoked 设备再次上报**不复活**（"吊销自带有效期"是必须堵死的静默失效）。
func TestDeviceLifecycleStateMachine(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")

	if code, out := reportPosture(t, h, sess, "FP-LIFE-1"); code != http.StatusOK {
		t.Fatalf("posture 上报 http %d: %v", code, out)
	}
	d := findDevice(t, h, "li.fang", "FP-LIFE-1")
	if d["status"] != store.DeviceStatusPending {
		t.Fatalf("审批绑定模式下首次上报应为 pending, got %v", d["status"])
	}
	if d["approvalId"] == "" {
		t.Fatal("审批绑定模式下应同时生成一条绑定审批单（approvalId 非空）")
	}
	// 审批队列里能看到它——复用既有 approvals 表，不另起一套。
	code, out := doJSON(t, h, "GET", "/api/v1/devices", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /devices http %d", code)
	}
	aps, _ := out["approvals"].([]any)
	if len(aps) != 1 {
		t.Fatalf("应有且只有 1 条待审批（来自本次首登记）, got %d", len(aps))
	}

	approveDevice(t, h, "li.fang", "FP-LIFE-1")
	if s := findDevice(t, h, "li.fang", "FP-LIFE-1")["status"]; s != store.DeviceStatusTrusted {
		t.Fatalf("批准后应为 trusted, got %v", s)
	}
	// 批准会把关联审批单一起收口，队列清空。
	_, out = doJSON(t, h, "GET", "/api/v1/devices", adminToken(), nil)
	if aps, _ := out["approvals"].([]any); len(aps) != 0 {
		t.Fatalf("批准后审批队列应清空, got %d", len(aps))
	}

	revokeDevice(t, h, "li.fang", "FP-LIFE-1", "设备遗失")
	after := findDevice(t, h, "li.fang", "FP-LIFE-1")
	if after["status"] != store.DeviceStatusRevoked {
		t.Fatalf("吊销后应为 revoked, got %v", after["status"])
	}
	if after["revokeReason"] != "设备遗失" {
		t.Fatalf("吊销理由应落库, got %v", after["revokeReason"])
	}

	// ★再次上报不得复活：只刷新 last_seen，状态纹丝不动。
	if code, _ := reportPosture(t, h, sess, "FP-LIFE-1"); code != http.StatusOK {
		t.Fatalf("已吊销设备仍可上报 posture（上报不是准入），http %d", code)
	}
	if s := findDevice(t, h, "li.fang", "FP-LIFE-1")["status"]; s != store.DeviceStatusRevoked {
		t.Fatalf("已吊销设备再次上报不得复活为 %v", s)
	}
}

// 自动绑定模式：首次上报即 trusted，且批准人如实记为 auto 而不是某个管理员。
func TestDeviceAutoBindEnrollsTrusted(t *testing.T) {
	h := newTestServer(t)
	saveTrustSetting(t, h, store.DeviceTrustObserve, store.DeviceBindAuto, 30)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-AUTO-1"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}
	d := findDevice(t, h, "li.fang", "FP-AUTO-1")
	if d["status"] != store.DeviceStatusTrusted {
		t.Fatalf("自动绑定应直接 trusted, got %v", d["status"])
	}
	if d["approvedBy"] != "auto" {
		t.Fatalf("自动绑定的批准人应如实记为 auto（不冒充管理员）, got %v", d["approvedBy"])
	}
	if d["approvalId"] != "" {
		t.Fatalf("自动绑定不应生成审批单, got %v", d["approvalId"])
	}
}

// 绑定审批驳回 → 设备置 revoked（审批与设备状态同事务翻转）。
func TestDeviceApprovalRejectRevokesDevice(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-AP-1"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}
	d := findDevice(t, h, "li.fang", "FP-AP-1")
	apID := d["approvalId"].(string)

	code, out := doJSON(t, h, "POST", "/api/v1/approvals/"+apID+"/decide", adminToken(),
		map[string]any{"decision": "rejected", "reason": "个人设备不予纳管"})
	if code != http.StatusOK || out["deviceLinked"] != true {
		t.Fatalf("驳回应联动设备, http %d: %v", code, out)
	}
	if s := findDevice(t, h, "li.fang", "FP-AP-1")["status"]; s != store.DeviceStatusRevoked {
		t.Fatalf("驳回后设备应为 revoked, got %v", s)
	}
	// 审计只写已发生的事实：设备被吊销 + 账号被并入封禁 + 影响面是"按账号"。
	if !auditHasEvent(t, h, "撤销通道按账号表达") {
		t.Fatal("驳回审计必须如实写明撤销按账号表达的影响面")
	}
}

// ── ② 准入闸 ──

// 严格模式：pending / 未登记 / 缺指纹一律拒发敲门令牌，且都有 deny 审计；
// 批准之后立刻放行。
func TestKnockStrictRejectsUntrustedDevice(t *testing.T) {
	h := newTestServer(t)
	saveTrustSetting(t, h, store.DeviceTrustStrict, store.DeviceBindApproval, 30)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-STRICT-1"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}

	// pending
	if code, out := knockWithDevice(t, h, sess, "FP-STRICT-1"); code != http.StatusForbidden {
		t.Fatalf("严格模式下 pending 设备应被拒, http %d: %v", code, out)
	}
	if !auditHasEvent(t, h, "终端待批准（pending）") {
		t.Fatal("严格模式拒绝必须落审计")
	}
	// 未登记的另一台设备
	if code, _ := knockWithDevice(t, h, sess, "FP-NEVER-SEEN"); code != http.StatusForbidden {
		t.Fatalf("严格模式下未登记设备应被拒, http %d", code)
	}
	// 完全不带指纹（旧客户端 / 浏览器）
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", sess, nil); code != http.StatusForbidden {
		t.Fatalf("严格模式下缺指纹应被拒, http %d", code)
	}

	approveDevice(t, h, "li.fang", "FP-STRICT-1")
	if code, out := knockWithDevice(t, h, sess, "FP-STRICT-1"); code != http.StatusOK || out["token"] == "" {
		t.Fatalf("批准后严格模式应放行, http %d: %v", code, out)
	}
}

// 观察模式（默认）：非授信设备放行，但必须留痕；不留痕的观察等于什么都没做。
func TestKnockObserveAllowsButAudits(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-OBS-1"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}
	if code, out := knockWithDevice(t, h, sess, "FP-OBS-1"); code != http.StatusOK || out["token"] == "" {
		t.Fatalf("观察模式应放行 pending 设备, http %d: %v", code, out)
	}
	if !auditHasEvent(t, h, "授信终端观察模式") {
		t.Fatal("观察模式放行必须留痕")
	}
	if auditHasEvent(t, h, "已拦截") {
		t.Fatal("观察模式没有拦截任何东西，审计措辞不得声称拦截过")
	}
}

// ★吊销的设备在**观察模式下也必须被拒**。
// 若观察模式连它都放行，「吊销」在默认配置下就是个空动作——页面变红、审计有记录、
// 设备照常接入，而且没有任何报错。这是本项目反复栽跟头的那类静默失效。
func TestKnockObserveStillRejectsRevokedDevice(t *testing.T) {
	e := newDeviceEnv(t)
	sess := userSession(t, e.h, "li.fang")
	for _, fp := range []string{"FP-REV-1", "FP-REV-2"} {
		if code, _ := reportPosture(t, e.h, sess, fp); code != http.StatusOK {
			t.Fatalf("上报 %s 应成功", fp)
		}
		approveDevice(t, e.h, "li.fang", fp)
	}
	if code, _ := knockWithDevice(t, e.h, sess, "FP-REV-1"); code != http.StatusOK {
		t.Fatal("授信设备在观察模式下应放行")
	}
	revokeDevice(t, e.h, "li.fang", "FP-REV-1", "疑似克隆")
	if code, _ := knockWithDevice(t, e.h, sess, "FP-REV-1"); code != http.StatusForbidden {
		t.Fatal("吊销后应立即拒发敲门令牌")
	}

	// ★重启控制面：强制下线封禁是内存态（重启即失），设备吊销是落库的。
	// 重启后账号封禁不再拦人，此时若设备闸自己不拦，「吊销」在默认的观察模式下
	// 就等于一个只持续 5 分钟的临时封禁，而页面上永远显示"已吊销"。
	e.restart(t)
	if revokedUsers(t, e.h)["li.fang"] {
		t.Fatal("重启后账号封禁应已消失（内存态），本用例据此隔离出设备闸自身的判定")
	}
	if code, out := knockWithDevice(t, e.h, sess, "FP-REV-1"); code != http.StatusForbidden {
		t.Fatalf("重启后被吊销的设备在观察模式下仍必须被拒, http %d: %v", code, out)
	}
	// 同一账号的另一台已授信设备应照常接入——吊销的是设备，不是账号。
	if code, out := knockWithDevice(t, e.h, sess, "FP-REV-2"); code != http.StatusOK {
		t.Fatalf("同账号的另一台授信设备应能接入, http %d: %v", code, out)
	}
}

// ── ③ 吊销 → 会话撤销（端到端：API → 网关策略下发）──
//
// ★这条链路做到的是「按**账号**撤销」，不是按设备。用例把这个事实钉住：
// 断言网关拿到的 revoked 名单里出现的是账号，同时断言 API 应答把影响面说清楚。
// 若将来有人把它改成"只标记设备不并入封禁"，这条会红——那种改法会让页面显示
// 「已吊销」而那台机器的隧道还开着。
func TestDeviceRevokeCutsSessionsViaGatewayPolicy(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-CUT-1"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}
	approveDevice(t, h, "li.fang", "FP-CUT-1")
	if revokedUsers(t, h)["li.fang"] {
		t.Fatal("吊销前不应在撤销名单里")
	}

	out := revokeDevice(t, h, "li.fang", "FP-CUT-1", "设备遗失")
	if out["banUntil"] == nil {
		t.Fatal("吊销应返回封禁截止时间")
	}
	br, _ := out["blastRadius"].(string)
	if !strings.Contains(br, "所有终端") {
		t.Fatalf("吊销应用体应把影响面（按账号撤销）如实带给控制台: %q", br)
	}
	// 网关侧：下一轮策略下发即包含该账号 → applyRevoked 撤窗 + KillUser 断隧道。
	if !revokedUsers(t, h)["li.fang"] {
		t.Fatal("吊销后账号应出现在网关撤销名单里（数据面据此撤窗断隧道）")
	}
	// 封禁期内连敲门令牌都不发（掐断 reknock 保活的令牌来源）。
	if code, _ := knockWithDevice(t, h, sess, "FP-CUT-1"); code != http.StatusForbidden {
		t.Fatal("封禁期内应拒发敲门令牌")
	}
}

// ── ④ 设备上限 ──

// 单账号 20 台上限：第 21 台被拒，且 trusted_devices 与 posture_reports 都没有多出行。
func TestDeviceCapAppliesToBothTables(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	for i := 0; i < store.MaxDevicesPerAccount; i++ {
		if code, out := reportPosture(t, h, sess, fmt.Sprintf("FP-CAP-%02d", i)); code != http.StatusOK {
			t.Fatalf("第 %d 台应成功, http %d: %v", i+1, code, out)
		}
	}
	if code, out := reportPosture(t, h, sess, "FP-CAP-OVER"); code != http.StatusForbidden {
		t.Fatalf("超上限应 403, http %d: %v", code, out)
	}
	if n := countDevices(t, h, "li.fang"); n != store.MaxDevicesPerAccount {
		t.Fatalf("设备台账应恰好 %d 行, got %d", store.MaxDevicesPerAccount, n)
	}
	if n := countPostureDevices(t, h, "li.fang"); n != store.MaxDevicesPerAccount {
		t.Fatalf("posture 报告应恰好 %d 行（超限时不得留下孤儿报告）, got %d", store.MaxDevicesPerAccount, n)
	}
	// 删掉一台就腾出名额（删设备 = 两表同删）。
	d := findDevice(t, h, "li.fang", "FP-CAP-00")
	if code, out := doJSON(t, h, "DELETE", "/api/v1/devices/"+d["id"].(string), adminToken(), nil); code != http.StatusOK {
		t.Fatalf("删除设备 http %d: %v", code, out)
	}
	if code, _ := reportPosture(t, h, sess, "FP-CAP-OVER"); code != http.StatusOK {
		t.Fatal("腾出名额后应能登记新设备")
	}
}

// ── ⑤ 口径统一 ──
//
// trusted_devices 与 posture_reports 必须一一对应，任一侧多出行都会让
// 「设备页看不到那台机器，但它照样把跨设备最差判定拉低」这种排不掉的故障出现。
func TestDeviceAndPostureTablesStayConsistent(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	for _, fp := range []string{"FP-SYNC-1", "FP-SYNC-2", "FP-SYNC-3"} {
		if code, _ := reportPosture(t, h, sess, fp); code != http.StatusOK {
			t.Fatalf("上报 %s 应成功", fp)
		}
	}
	assertTablesAligned(t, h, "li.fang")

	// 删设备 → 报告同删。
	d := findDevice(t, h, "li.fang", "FP-SYNC-2")
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/devices/"+d["id"].(string), adminToken(), nil); code != http.StatusOK {
		t.Fatal("删除设备应成功")
	}
	assertTablesAligned(t, h, "li.fang")
	if countDevices(t, h, "li.fang") != 2 {
		t.Fatal("删除后应剩 2 台")
	}

	// 删 posture 报告 → 设备登记**保留**（名额不释放），且清单上如实显示"从未上报"。
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/posture/li.fang/FP-SYNC-3", adminToken(), nil); code != http.StatusOK {
		t.Fatal("删除 posture 报告应成功")
	}
	if countDevices(t, h, "li.fang") != 2 {
		t.Fatal("删报告不应删设备登记")
	}
	if v := findDevice(t, h, "li.fang", "FP-SYNC-3")["verdict"]; v != "" {
		t.Fatalf("报告已删的设备判定应为空（从未上报），不得渲染成 allow, got %v", v)
	}
}

// ── ⑥ 陈旧清理 ──

// 陈旧清理按 staleDays 选取，**跳过 revoked**（清掉吊销记录等于给吊销配了有效期）。
func TestCleanupStaleSkipsRevoked(t *testing.T) {
	e := newDeviceEnv(t)
	sess := userSession(t, e.h, "li.fang")
	for _, fp := range []string{"FP-STALE-1", "FP-STALE-2"} {
		if code, _ := reportPosture(t, e.h, sess, fp); code != http.StatusOK {
			t.Fatalf("上报 %s 应成功", fp)
		}
	}
	revokeDevice(t, e.h, "li.fang", "FP-STALE-2", "离职回收")

	// staleDays 的最小值是 1 天，刚上报的设备一台都不该被清掉。
	saveTrustSetting(t, e.h, store.DeviceTrustObserve, store.DeviceBindApproval, 1)
	code, out := doJSON(t, e.h, "POST", "/api/v1/devices/cleanup-stale", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("清理 http %d: %v", code, out)
	}
	if n, _ := out["removed"].(float64); n != 0 {
		t.Fatalf("刚上报的设备不该被判陈旧, removed=%v", n)
	}

	// 把两台的 last_seen 推到很久以前，再清一次：只应清掉非 revoked 的那台。
	e.ageDevices(t, "li.fang")
	code, out = doJSON(t, e.h, "POST", "/api/v1/devices/cleanup-stale", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("清理 http %d: %v", code, out)
	}
	if n, _ := out["removed"].(float64); n != 1 {
		t.Fatalf("应只清掉 1 台（revoked 那台留下）, removed=%v", n)
	}
	if s := findDevice(t, e.h, "li.fang", "FP-STALE-2")["status"]; s != store.DeviceStatusRevoked {
		t.Fatalf("已吊销设备不得被陈旧清理带走, got %v", s)
	}
	// 清理也不能留下孤儿 posture 报告。
	assertTablesAligned(t, e.h, "li.fang")
}

// ── ⑦ 权限 ──

func TestDeviceEndpointsRequirePermissions(t *testing.T) {
	h := newTestServer(t)
	usr := userToken("li.fang")
	// 读：普通用户拿不到设备台账（含账号与硬件指纹）。
	if code, _ := doJSON(t, h, "GET", "/api/v1/devices", usr, nil); code != http.StatusForbidden {
		t.Fatalf("普通用户读设备台账应 403, got %d", code)
	}
	// 写：审计管理员（只读权）改不了准入设置与设备状态。
	audTok := makeAdmin(t, h, "aud.dev", "audit")
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"PUT", "/api/v1/devices/settings", map[string]any{"mode": "strict", "bindMethod": "auto", "staleDays": 30}},
		{"POST", "/api/v1/devices/dev-x/status", map[string]any{"status": "trusted"}},
		{"PUT", "/api/v1/devices/dev-x/name", map[string]any{"name": "x"}},
		{"DELETE", "/api/v1/devices/dev-x", nil},
		{"POST", "/api/v1/devices/cleanup-stale", nil},
	} {
		if code, _ := doJSON(t, h, c.method, c.path, audTok, c.body); code != http.StatusForbidden {
			t.Fatalf("审计管理员 %s %s 应 403, got %d", c.method, c.path, code)
		}
	}
}
