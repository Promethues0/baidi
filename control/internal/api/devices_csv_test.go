// 终端设备台账批量出入口的回归（wave7 行动 14）。
//
// 覆盖三类：
//
//	① 导出：CSV 公式注入中和、UTF-8 BOM、「从未上报」不被写成「合规」；
//	② 导入：字节/行数上限（超限一行都不许进）、逐行回报、指纹格式闸；
//	③ 本域特有的安全约束：导入不得复活一台已吊销的终端、不得凭空创建归属、
//	   不得预登记采集器的哨兵指纹、不得绕开单账号设备上限。
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// newCSVEnv 起一套控制面，并把本批新增的两个端点挂上。
//
// ★路由由 api.go 统一注册（本批交付里以 routes 形式报给集成方），测试自建一份等价挂载：
// 既能在主 mux 落地之前就跑通回归，也不与别的并行改动抢同一个文件。
// 其余端点（设备清单 / posture 上报 / 敲门）原样走 s.Routes()。
func newCSVEnv(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "devcsv.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/devices/export", s.handleDeviceExport)
	mux.HandleFunc("POST /api/v1/devices/import", s.handleDeviceImport)
	mux.Handle("/", s.Routes())
	return auth.Middleware(testKeys, s.IsOpen)(mux)
}

// doCSV 发一次 CSV 正文的请求，回状态码与原始响应体。
func doCSV(t *testing.T, h http.Handler, method, path, token, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "text/csv")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// importCSV 发一次导入并解出回执。
func importCSV(t *testing.T, h http.Handler, body string) (int, map[string]any) {
	t.Helper()
	code, raw := doCSV(t, h, "POST", "/api/v1/devices/import", adminToken(), body)
	out := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &out)
	return code, out
}

// exportCSV 拉一次导出，回状态码与正文（含 BOM）。
func exportCSV(t *testing.T, h http.Handler, token string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/devices/export", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// csvCells 把导出正文（去 BOM）拆成行 × 列。
func csvCells(t *testing.T, body string) [][]string {
	t.Helper()
	body = strings.TrimPrefix(body, "\ufeff")
	rows := [][]string{}
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		rows = append(rows, strings.Split(strings.TrimSuffix(line, "\r"), ","))
	}
	return rows
}

// importedLines / skipReasons 从回执里取逐行结果。
func importedLines(out map[string]any) int {
	arr, _ := out["imported"].([]any)
	return len(arr)
}

func skipReasons(out map[string]any) map[string]string {
	m := map[string]string{}
	arr, _ := out["skipped"].([]any)
	for _, it := range arr {
		row, ok := it.(map[string]any)
		if !ok {
			continue
		}
		fp, _ := row["fingerprint"].(string)
		acct, _ := row["account"].(string)
		reason, _ := row["reason"].(string)
		m[acct+"|"+fp] = reason
	}
	return m
}

// ── ① 导出 ──

// 导出的每一个单元格都必须过 csvCell：设备名是终端自报 / 管理员手输的，
// 以 = 开头的值在 Excel 里会被当公式求值（DDE 可外带数据甚至执行命令）。
// 导出件恰恰就是给人拿电子表格打开的那一份。
func TestDeviceExportNeutralizesFormulaInjection(t *testing.T) {
	h := newCSVEnv(t)
	// 名字里塞一条 DDE 公式；平台留空，走「预登记」这条真实路径进台账。
	code, out := importCSV(t, h, "账号,指纹,设备名,状态\n"+
		"zhang.wei,aabb:ccdd:eeff:0011,=cmd|' /C calc'!A0,已授信\n")
	if code != http.StatusOK || importedLines(out) != 1 {
		t.Fatalf("预登记应成功，http %d: %v", code, out)
	}

	ecode, body := exportCSV(t, h, adminToken())
	if ecode != http.StatusOK {
		t.Fatalf("导出 http %d", ecode)
	}
	if !strings.HasPrefix(body, "\ufeff") {
		t.Fatal("导出缺 UTF-8 BOM：Excel 打开中文列会乱码")
	}
	rows := csvCells(t, body)
	if len(rows) < 2 {
		t.Fatalf("导出应含表头 + 至少一行数据，实得 %d 行", len(rows))
	}
	if rows[0][0] != "账号" || rows[0][1] != "指纹" {
		t.Fatalf("表头前两列应是账号/指纹，实得 %v", rows[0][:2])
	}
	// 设备名列（第 3 列）必须被前缀单引号中和。
	name := rows[1][2]
	if !strings.HasPrefix(name, "'=") {
		t.Fatalf("设备名单元格未中和公式注入：%q（应以 '= 开头）", name)
	}
	// 从未上报的设备，「最近合规判定」必须是「从未上报」而不是「合规」。
	if !strings.Contains(body, "从未上报") {
		t.Fatalf("预登记设备的合规判定应显示「从未上报」，导出正文：%s", body)
	}
	// 授信来源要分得清「批量导入」与「某管理员逐台批准」。
	if !strings.Contains(body, "批量导入预登记") {
		t.Fatalf("导出应标明授信来源为批量导入，实得：%s", body)
	}
}

// 导出件改完能原样再导入（表头与中文状态值双向认得），且第二次全部落在
// 「已存在」跳过分支——不会把一份导出件变成一次静默的批量改写。
func TestDeviceExportRoundTripIsIdempotent(t *testing.T) {
	h := newCSVEnv(t)
	if code, out := importCSV(t, h, "账号,指纹,设备名,平台,状态\n"+
		"li.fang,1122:3344:5566:7788,李芳-MBP,macOS,已授信\n"); code != http.StatusOK || importedLines(out) != 1 {
		t.Fatalf("首次导入应成功，http %d: %v", code, out)
	}
	_, body := exportCSV(t, h, adminToken())

	code, out := importCSV(t, h, body)
	if code != http.StatusOK {
		t.Fatalf("回灌导出件 http %d: %v", code, out)
	}
	if n := importedLines(out); n != 0 {
		t.Fatalf("回灌导出件不该新增设备，实得 %d 台", n)
	}
	reasons := skipReasons(out)
	got := reasons["li.fang|1122:3344:5566:7788"]
	if !strings.Contains(got, "已登记同指纹终端") {
		t.Fatalf("回灌应逐行回报「已登记」，实得 %q", got)
	}
}

// ── ② 上限 ──

// 行数超限必须在**写任何一行之前**拒掉：先写 500 行再报错的话，
// 管理员既不知道进了多少，重试还会撞上"已存在"。
func TestDeviceImportRowLimitRejectsWholeBatch(t *testing.T) {
	h := newCSVEnv(t)
	var b strings.Builder
	b.WriteString("账号,指纹\n")
	for i := 0; i <= deviceImportMaxRows; i++ { // 501 行
		b.WriteString("zhang.wei,aabb:ccdd:" + pad4(i) + ":0011\n")
	}
	code, out := importCSV(t, h, b.String())
	if code != http.StatusBadRequest {
		t.Fatalf("超行数上限应 400，实得 %d: %v", code, out)
	}
	if n := countDevices(t, h, "zhang.wei"); n != 0 {
		t.Fatalf("超限批次一台都不该落库，实得 %d 台", n)
	}
}

// 字节上限由 http.MaxBytesReader 兜住，回 413 且明确说本批未导入。
func TestDeviceImportByteLimit(t *testing.T) {
	h := newCSVEnv(t)
	var b strings.Builder
	b.WriteString("账号,指纹,设备名\n")
	// 单行撑大到超过 512 KiB（行数只有两行，确保命中的是字节闸而不是行数闸）。
	b.WriteString("zhang.wei,aabb:ccdd:eeff:0011," + strings.Repeat("x", deviceImportMaxBytes+16) + "\n")
	code, raw := doCSV(t, h, "POST", "/api/v1/devices/import", adminToken(), b.String())
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超字节上限应 413，实得 %d: %s", code, raw)
	}
	if !strings.Contains(raw, "未导入") {
		t.Fatalf("413 文案应说明本批未导入任何设备，实得 %s", raw)
	}
	if n := countDevices(t, h, "zhang.wei"); n != 0 {
		t.Fatalf("超限批次一台都不该落库，实得 %d 台", n)
	}
}

// 表头认不出「账号/指纹」就整体拒绝——退化成按列序猜的话，
// 一份列顺序不同的表格会把设备名当指纹整批写进台账，而接口照回 200。
func TestDeviceImportRequiresHeader(t *testing.T) {
	h := newCSVEnv(t)
	code, out := importCSV(t, h, "zhang.wei,aabb:ccdd:eeff:0011\n")
	if code != http.StatusBadRequest {
		t.Fatalf("缺表头应 400，实得 %d: %v", code, out)
	}
	if n := countDevices(t, h, "zhang.wei"); n != 0 {
		t.Fatalf("表头不合法时一台都不该落库，实得 %d 台", n)
	}
}

// ── ③ 逐行回报 + 本域特有的安全约束 ──

func TestDeviceImportPerRowResults(t *testing.T) {
	h := newCSVEnv(t)
	body := strings.Join([]string{
		"账号,指纹,设备名,平台,状态",
		"zhang.wei,aabb:ccdd:eeff:0011,张伟-MBP,macOS,已授信", // ok（授信）
		"li.fang,1122:3344:5566:7788,李芳-PC,Windows,",     // ok（状态留空 → 待批准）
		"no.such.user,9988:7766:5544:3322,幽灵机,Linux,已授信", // 账号不存在
		"zhang.wei,pc,短指纹,macOS,已授信",                     // 指纹过短
		"zhang.wei,UNKNOWN-DEVICE,采集失败机,macOS,已授信",       // 哨兵指纹
		"zhang.wei,汉字指纹汉字指纹汉字,乱码机,macOS,已授信",             // 非法字符
		"zhang.wei,ccdd:eeff:0011:2233,黑名单机,macOS,已吊销",   // 导入不接受 revoked
		"zhang.wei,ddee:ff00:1122:3344,安卓机,Android,已授信",  // 平台不在枚举里
		"",
	}, "\n")
	code, out := importCSV(t, h, body)
	if code != http.StatusOK {
		t.Fatalf("部分失败不该整批失败，http %d: %v", code, out)
	}
	if n := importedLines(out); n != 2 {
		t.Fatalf("应有 2 行成功，实得 %d：%v", n, out["imported"])
	}
	reasons := skipReasons(out)
	if len(reasons) != 6 {
		t.Fatalf("应有 6 行跳过，实得 %d：%v", len(reasons), out["skipped"])
	}
	// 跳过回报必须带回原始的账号与指纹：管理员是拿这两列去文件里定位那一行的。
	want := map[string]string{
		"no.such.user|9988:7766:5544:3322": "账号不存在",
		"zhang.wei|pc":                     "指纹长度",
		"zhang.wei|UNKNOWN-DEVICE":         "哨兵值",
		"zhang.wei|汉字指纹汉字指纹汉字":             "非法字符",
		"zhang.wei|ccdd:eeff:0011:2233":    "已吊销",
		"zhang.wei|ddee:ff00:1122:3344":    "Windows|macOS|Linux",
	}
	for key, sub := range want {
		got, ok := reasons[key]
		if !ok {
			t.Fatalf("跳过清单里缺 %s：%v", key, reasons)
		}
		if !strings.Contains(got, sub) {
			t.Fatalf("%s 的跳过原因应包含 %q，实得 %q", key, sub, got)
		}
	}
	// 落库结果与回执一致：张伟 1 台（授信）、李芳 1 台（待批准）。
	if n := countDevices(t, h, "zhang.wei"); n != 1 {
		t.Fatalf("zhang.wei 应只有 1 台落库，实得 %d", n)
	}
	if d := findDevice(t, h, "li.fang", "1122:3344:5566:7788"); d["status"] != store.DeviceStatusPending {
		t.Fatalf("状态列留空必须落 pending（最保守档），实得 %v", d["status"])
	}
	if d := findDevice(t, h, "zhang.wei", "aabb:ccdd:eeff:0011"); d["status"] != store.DeviceStatusTrusted {
		t.Fatalf("「已授信」应落 trusted，实得 %v", d["status"])
	}
	// 回执必须把「预登记 ≠ 过得了合规闸」说出来，且带上当前 enforce 模式。
	if note, _ := out["note"].(string); !strings.Contains(note, "posture_reports") {
		t.Fatalf("回执缺少 posture 缺报的能力边界说明：%v", out["note"])
	}
	if out["postureEnforce"] != "observe" {
		t.Fatalf("回执应带当前 BAIDI_POSTURE_ENFORCE，实得 %v", out["postureEnforce"])
	}
}

// ★本域最要紧的一条：导入不得复活一台已吊销的终端。
//
// 允许"导入即更新"的话，一份 CSV 就能把管理员点过的吊销静默撤销，
// 而页面上只显示"导入成功 1 台"。这与 EnrollDevice「已登记状态一律不动」、
// PurgeStaleDevices「跳过 revoked」是同一条纪律：吊销不许有静默解除路径。
func TestDeviceImportCannotResurrectRevokedDevice(t *testing.T) {
	h := newCSVEnv(t)
	const fp = "beef:cafe:1234:5678"
	sess := userSession(t, h, "li.fang")
	if code, out := reportPosture(t, h, sess, fp); code != http.StatusOK {
		t.Fatalf("首次上报 http %d: %v", code, out)
	}
	revokeDevice(t, h, "li.fang", fp, "笔记本丢失")

	code, out := importCSV(t, h, "账号,指纹,状态\nli.fang,"+fp+",已授信\n")
	if code != http.StatusOK {
		t.Fatalf("导入 http %d: %v", code, out)
	}
	if n := importedLines(out); n != 0 {
		t.Fatalf("已存在的设备不该被导入改写，实得 %d 台", n)
	}
	if d := findDevice(t, h, "li.fang", fp); d["status"] != store.DeviceStatusRevoked {
		t.Fatalf("吊销状态被一次 CSV 导入改掉了：%v", d["status"])
	}
	// 准入闸的实测：吊销设备在观察模式（默认）下也必须被拒。
	saveTrustSetting(t, h, store.DeviceTrustObserve, store.DeviceBindApproval, 30)
	if code, out := knockWithDevice(t, h, sess, fp); code != http.StatusForbidden {
		t.Fatalf("被吊销终端仍应拒发敲门令牌，实得 http %d: %v", code, out)
	}
}

// 导入走的是同一个单账号上限判据（store.MaxDevicesPerAccount，全仓只有一处定义），
// 不是另开一条能绕过去的批量通道。
func TestDeviceImportRespectsPerAccountCap(t *testing.T) {
	h := newCSVEnv(t)
	var b strings.Builder
	b.WriteString("账号,指纹,状态\n")
	for i := 0; i < store.MaxDevicesPerAccount+3; i++ {
		b.WriteString("zhang.wei,aabb:ccdd:" + pad4(i) + ":0011,已授信\n")
	}
	code, out := importCSV(t, h, b.String())
	if code != http.StatusOK {
		t.Fatalf("http %d: %v", code, out)
	}
	if n := importedLines(out); n != store.MaxDevicesPerAccount {
		t.Fatalf("最多只该进 %d 台，实得 %d", store.MaxDevicesPerAccount, n)
	}
	over := 0
	for _, reason := range skipReasons(out) {
		if strings.Contains(reason, "上限") {
			over++
		}
	}
	if over != 3 {
		t.Fatalf("超出的 3 行应逐行回报超限，实得 %d：%v", over, out["skipped"])
	}
	if n := countDevices(t, h, "zhang.wei"); n != store.MaxDevicesPerAccount {
		t.Fatalf("落库台数应等于上限 %d，实得 %d", store.MaxDevicesPerAccount, n)
	}
}

// 预登记是一次准入授予，必须逐台落审计（与设备页点「批准」同等留痕），
// 汇总那条要说清 posture 的交互。
func TestDeviceImportAudits(t *testing.T) {
	h := newCSVEnv(t)
	if code, out := importCSV(t, h, "账号,指纹,设备名,状态\nzhang.wei,aabb:ccdd:eeff:0011,张伟-MBP,已授信\n"); code != http.StatusOK {
		t.Fatalf("http %d: %v", code, out)
	}
	if !auditHasEvent(t, h, "批量导入预登记终端：zhang.wei") {
		t.Fatalf("缺逐台预登记审计：%v", auditEvents(t, h))
	}
	if !auditHasEvent(t, h, "BAIDI_POSTURE_ENFORCE=observe") {
		t.Fatalf("汇总审计应记下当时的 posture 执行模式：%v", auditEvents(t, h))
	}
	if _, body := exportCSV(t, h, adminToken()); body == "" {
		t.Fatal("导出正文为空")
	}
	if !auditHasEvent(t, h, "导出终端设备台账 CSV，共 1 台") {
		t.Fatalf("导出应在流式写完后落一条如实的审计：%v", auditEvents(t, h))
	}
}

// 两个端点都归 PermSecurity（与批准/吊销同权）：审计管理员读得到设备页，
// 但拿不走整表指纹，也发不出准入授予。
func TestDeviceCSVEndpointsRequireSecurityPerm(t *testing.T) {
	h := newCSVEnv(t)
	audTok := makeAdmin(t, h, "aud.csv", "audit")
	secTok := makeAdmin(t, h, "sec.csv", "security")

	if code, _ := exportCSV(t, h, audTok); code != http.StatusForbidden {
		t.Fatalf("审计管理员导出设备台账应 403，实得 %d", code)
	}
	if code, raw := doCSV(t, h, "POST", "/api/v1/devices/import", audTok,
		"账号,指纹\nzhang.wei,aabb:ccdd:eeff:0011\n"); code != http.StatusForbidden {
		t.Fatalf("审计管理员导入应 403，实得 %d: %s", code, raw)
	}
	if code, _ := exportCSV(t, h, secTok); code != http.StatusOK {
		t.Fatalf("安全管理员导出应 200，实得 %d", code)
	}
	code, raw := doCSV(t, h, "POST", "/api/v1/devices/import", secTok,
		"账号,指纹\nzhang.wei,aabb:ccdd:eeff:0011\n")
	if code != http.StatusOK {
		t.Fatalf("安全管理员导入应 200，实得 %d: %s", code, raw)
	}
}

// pad4 造互不相同的四位指纹片段。
func pad4(i int) string {
	s := []byte("0000")
	const hex = "0123456789abcdef"
	for p := 3; p >= 0; p-- {
		s[p] = hex[i&0xf]
		i >>= 4
	}
	return string(s)
}

// 指纹格式闸的单元覆盖（导入是它唯一的调用方，但边界值在这里说得最清楚）。
func TestValidDeviceFingerprint(t *testing.T) {
	ok := []string{"aabb:ccdd:eeff:0011", "AABBCCDD", "host-01.corp_lab", strings.Repeat("a", 128)}
	for _, fp := range ok {
		if err := validDeviceFingerprint(fp); err != nil {
			t.Fatalf("%q 应通过，实得 %v", fp, err)
		}
	}
	bad := []string{"", "pc", "::::::::", "UNKNOWN-DEVICE", "unknown-device",
		"has space", "a/b/c/d/e/f", `a\b\c\d\e`, "..", strings.Repeat("a", 129)}
	for _, fp := range bad {
		if err := validDeviceFingerprint(fp); err == nil {
			t.Fatalf("%q 应被拒", fp)
		}
	}
}

// 表头/状态列的归一：中文与英文双向认得，revoked 一律不收。
func TestDeviceImportStatusNormalize(t *testing.T) {
	for _, in := range []string{"", "  ", "待批准", "pending", "PENDING"} {
		if got, ok := deviceImportStatus(in); !ok || got != store.DeviceStatusPending {
			t.Fatalf("%q 应归一为 pending，实得 %q/%v", in, got, ok)
		}
	}
	for _, in := range []string{"已授信", "trusted", "Trusted"} {
		if got, ok := deviceImportStatus(in); !ok || got != store.DeviceStatusTrusted {
			t.Fatalf("%q 应归一为 trusted，实得 %q/%v", in, got, ok)
		}
	}
	for _, in := range []string{"已吊销", "revoked", "啥也不是"} {
		if _, ok := deviceImportStatus(in); ok {
			t.Fatalf("%q 不该被接受", in)
		}
	}
}

// 导出正文里不许出现裸的 CRLF 破坏——顺带钉住列数与表头顺序（前五列要能被导入认回来）。
func TestDeviceExportHeaderMatchesImportAliases(t *testing.T) {
	h := newCSVEnv(t)
	_, body := exportCSV(t, h, adminToken())
	head := csvCells(t, body)[0]
	for i, name := range []string{"账号", "指纹", "设备名", "平台", "状态"} {
		if head[i] != name {
			t.Fatalf("表头第 %d 列应为 %s，实得 %s", i+1, name, head[i])
		}
		if _, ok := deviceImportHeader[name]; !ok {
			t.Fatalf("导出表头 %s 不在导入别名表里：导出件改完就再也导不回去了", name)
		}
	}
	if !bytes.HasPrefix([]byte(body), []byte("\xEF\xBB\xBF")) {
		t.Fatal("导出缺 UTF-8 BOM")
	}
}
