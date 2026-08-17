package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/alerting"
	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// ── wave8 行动 6：审计写入失败必须有信号 ──
//
// 被测的坏形态：`_ = s.writer.RecordAudit(...)`——写失败时管理操作照常回 200，
// 审计静默停写，链校验仍全绿（链重算的是已存在行的连续性），告警一条不响。

// failWriter 包一层 store.Writer，让 RecordAudit 按开关失败。
type failWriter struct {
	store.Writer
	fail error
	// got 记下每一条**试图**落库的审计（含失败的），供断言"内容有没有被完整交出去"。
	got []store.AuditEntry
}

func (w *failWriter) RecordAudit(ctx context.Context, e store.AuditEntry) error {
	w.got = append(w.got, e)
	if w.fail != nil {
		return w.fail
	}
	return w.Writer.RecordAudit(ctx, e)
}

// newFailServer 起一台 Server（连同它的 handler），写审计的那一路可被开关。
func newFailServer(t *testing.T) (*Server, http.Handler, *failWriter) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "audit-health.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	fw := &failWriter{Writer: st}
	s.writer = fw
	return s, auth.Middleware(testKeys, s.IsOpen)(s.Routes()), fw
}

// newPlainServer 一台不做手脚的 Server（要直接摸 *Server 的用例用）。
func newPlainServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "audit-plain.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	return s, auth.Middleware(testKeys, s.IsOpen)(s.Routes())
}

// TestAuditWriteFailureIsCounted 写失败必须被计数，且计的是"丢了几条"。
func TestAuditWriteFailureIsCounted(t *testing.T) {
	s, _, fw := newFailServer(t)
	if h0 := s.auditWrite.snapshot(); h0.Failures != 0 {
		t.Fatalf("初始应为零失败，得到 %+v", h0)
	}
	fw.fail = errors.New("database or disk is full")
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	s.auditAs(r, "admin", "admin", "改了一条策略", "ok")
	s.auditBG(context.Background(), "security", "后台动作", "fail")

	h := s.auditWrite.snapshot()
	if h.Failures != 2 {
		t.Fatalf("两次写失败应计 2，得到 %d", h.Failures)
	}
	if h.FirstAt == 0 || h.LastAt == 0 {
		t.Fatalf("首次/最近时刻都要有：%+v", h)
	}
	if !strings.Contains(h.LastErr, "disk is full") {
		t.Fatalf("错误原文要留下来（它直接决定下一步动作），得到 %q", h.LastErr)
	}
	// ★丢的是什么必须看得见："管理员改了策略"与"某账号第 6 次登录失败"取证价值天差地别。
	if !strings.Contains(h.LastEvent, "后台动作") {
		t.Fatalf("最近一条丢失的审计内容要留下来，得到 %q", h.LastEvent)
	}

	// 恢复后不再计数（计数器记的是失败，不是调用次数）。
	fw.fail = nil
	s.auditAs(r, "admin", "admin", "又一条", "ok")
	if got := s.auditWrite.snapshot().Failures; got != 2 {
		t.Fatalf("成功的写入不该计数，得到 %d", got)
	}
}

// TestAuditWriteFailureDoesNotBlockOperation 写审计失败**不影响主操作**。
// 缺的是信号不是回滚——让一条落不了的日志把管理员的正常操作也否掉，
// 换来的是可用性事故而不是安全。
func TestAuditWriteFailureDoesNotBlockOperation(t *testing.T) {
	s, h, fw := newFailServer(t)
	fw.fail = errors.New("disk I/O error")
	code, _ := doJSON(t, h, "POST", "/api/v1/objects/addr", adminToken(),
		map[string]string{"name": "审计写失败也应保存成功", "value": "10.9.9.0/24"})
	if code != http.StatusOK {
		t.Fatalf("审计写失败不该影响主操作，得到 %d", code)
	}
	if s.auditWrite.snapshot().Failures == 0 {
		t.Fatal("主操作成功了，但审计失败没被记下来——这正是被修的那个洞")
	}
}

// TestAuditEndpointExposesWriteHealth 读端点要能自曝家丑；健康时整段不下发。
//
// ★挂在**读**响应上是关键：写不进去的时候读路径通常还活着。
func TestAuditEndpointExposesWriteHealth(t *testing.T) {
	s, h, fw := newFailServer(t)
	get := func() map[string]any {
		t.Helper()
		code, out := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil)
		if code != http.StatusOK {
			t.Fatalf("GET /audit = %d", code)
		}
		return out
	}

	if _, ok := get()["writeHealth"]; ok {
		t.Fatal("零失败时不该下发 writeHealth（常态零噪声）")
	}
	fw.fail = errors.New("attempt to write a readonly database")
	s.auditBG(context.Background(), "admin", "会丢的这条", "ok")

	wh, ok := get()["writeHealth"].(map[string]any)
	if !ok {
		t.Fatal("出事后必须下发 writeHealth——否则页面上与一切正常完全同形")
	}
	if wh["failures"].(float64) != 1 {
		t.Fatalf("failures 应为 1，得到 %v", wh["failures"])
	}
	if !strings.Contains(wh["lastErr"].(string), "readonly") {
		t.Fatalf("lastErr 要如实下发，得到 %v", wh["lastErr"])
	}
}

// TestDiagAuditWriteCheck /diag 的 audit-write 项：出事即 fail，且不查库。
func TestDiagAuditWriteCheck(t *testing.T) {
	s, _, fw := newFailServer(t)
	if c := s.checkAuditWrite(); c.Status != "pass" {
		t.Fatalf("零失败应 pass，得到 %+v", c)
	}
	fw.fail = errors.New("disk full")
	s.auditBG(context.Background(), "admin", "丢了的这条", "ok")
	c := s.checkAuditWrite()
	if c.Status != "fail" {
		t.Fatalf("有丢失就该 fail，得到 %q", c.Status)
	}
	// 必须点破"链校验查不出来"——不写这句，管理员看到防篡改链全绿就会以为没事。
	if !strings.Contains(c.Summary, "防篡改链") {
		t.Fatalf("摘要要说明链校验查不出缺失，得到 %q", c.Summary)
	}
	if !strings.Contains(c.Hint, "丢了的这条") {
		t.Fatalf("提示里要带上丢失的内容，得到 %q", c.Hint)
	}
}

// TestDiagChecksHaveNoDuplicateKeys /diag 检查项不得重复。
// ★wave8 行动 4 的补丁脚本把 s.checkNAT(ctx) 插了两遍，页面上同一项画了两次，
// 而每一项自己都是对的——这种错只有整体断言看得见。
func TestDiagChecksHaveNoDuplicateKeys(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "GET", "/api/v1/diag", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /diag = %d", code)
	}
	raw, _ := out["checks"].([]any)
	if len(raw) == 0 {
		t.Fatal("一项都没有，用例失去意义")
	}
	seen := map[string]int{}
	for _, it := range raw {
		m, _ := it.(map[string]any)
		k, _ := m["key"].(string)
		seen[k]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("检查项 %q 出现 %d 次（同一项画两遍）", k, n)
		}
	}
	if _, ok := seen["audit-write"]; !ok {
		t.Error("audit-write 检查项没接进 /diag——只写实现不接线，用例照样全绿")
	}
}

// TestAlertAuditWriteFail 告警规则读的是进程内计数，并按时间窗收敛。
func TestAlertAuditWriteFail(t *testing.T) {
	spec, ok := store.AlertKindSpecOf(store.AlertKindAuditWriteFail)
	if !ok {
		t.Fatal("规则种类没登记")
	}
	rule := store.AlertRule{
		ID: "r-aw", Kind: store.AlertKindAuditWriteFail, Enabled: true,
		Threshold: map[string]float64{store.ThreshWithinMin: 60},
	}
	now := time.Now().Unix()

	// ① 零失败：不产生候选。
	if got := alerting.Evaluate([]store.AlertRule{rule}, alerting.Snapshot{Now: now}); len(got) != 0 {
		t.Fatalf("没失败过不该报，得到 %+v", got)
	}
	// ② 刚失败：报，且正文带得走排障要的四样。
	snap := alerting.Snapshot{Now: now, AuditWrite: &alerting.AuditWriteStat{
		Failures: 3, FirstAt: now - 120, LastAt: now - 10,
		LastErr: "database or disk is full", LastEvent: "admin · 张三 · 删除资源 res-1",
	}}
	got := alerting.Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 {
		t.Fatalf("应产生 1 条候选，得到 %d", len(got))
	}
	if got[0].Severity != store.AlertSevCritical || got[0].Category != spec.Category {
		t.Fatalf("严重度/类别不对：%+v", got[0])
	}
	for _, want := range []string{"3", "disk is full", "删除资源 res-1", "防篡改链"} {
		if !strings.Contains(got[0].Title+got[0].Detail, want) {
			t.Errorf("告警正文缺少 %q：%s", want, got[0].Detail)
		}
	}
	// ③ 窗口外：不再报（但计数仍在 /diag 与审计页上）。
	snap.AuditWrite.LastAt = now - 2*3600
	if got := alerting.Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("超出时间窗不该再报，得到 %+v", got)
	}
}

// TestAlertSnapshotWiresAuditWrite 取数确实接了线。
// ★只测纯函数的话，把 alertSnapshot 里那段删掉用例照样全绿（wave8 行动 2 的教训）。
func TestAlertSnapshotWiresAuditWrite(t *testing.T) {
	s, _, fw := newFailServer(t)
	if snap := s.alertSnapshot(context.Background(), false); snap.AuditWrite != nil {
		t.Fatal("零失败时不该注入")
	}
	fw.fail = errors.New("disk full")
	s.auditBG(context.Background(), "admin", "丢了的", "ok")
	snap := s.alertSnapshot(context.Background(), false)
	if snap.AuditWrite == nil || snap.AuditWrite.Failures != 1 {
		t.Fatalf("失败后必须注入进快照，得到 %+v", snap.AuditWrite)
	}
}

// TestPurgeByDiskIsAudited 按水位回收证据这件事本身必须留痕。
//
// ★「证据被轮转掉了」与「证据凭空少了一段」在库里长得一模一样，区别只在这条记录。
func TestPurgeByDiskIsAudited(t *testing.T) {
	s, _ := newPlainServer(t)
	p := &fakePurger{r: store.AuditDiskPurge{
		Enabled: true, Measurable: true, Triggered: true,
		UsedPct: 42, MaxPct: 30, Deleted: 1200, Days: 3, OldestKept: "2026-05-01 00:00:01",
	}}
	s.purgeAuditOnce(context.Background(), p, 180, 30)

	found := ""
	b, err := s.store.Audit(context.Background())
	if err != nil {
		t.Fatalf("读审计失败：%v", err)
	}
	for _, e := range b.Logs {
		if strings.Contains(e.Event, "按磁盘水位回收") {
			found = e.Event
		}
	}
	if found == "" {
		t.Fatal("按水位删了 1200 条审计，却没有任何一条记录说明这件事")
	}
	for _, want := range []string{"1200", "3 天", "42%", "30%", "不会因此变小"} {
		if !strings.Contains(found, want) {
			t.Errorf("留痕缺少 %q：%s", want, found)
		}
	}
	if !p.diskCalled || !p.daysCalled {
		t.Fatalf("按天与按水位都该跑：%+v", p)
	}
}

// TestPurgeByDiskNotTriggeredIsSilent 没触发就不该留痕（常态零噪声）。
func TestPurgeByDiskNotTriggeredIsSilent(t *testing.T) {
	s, _ := newPlainServer(t)
	p := &fakePurger{r: store.AuditDiskPurge{Enabled: true, Measurable: true, UsedPct: 5, MaxPct: 30}}
	s.purgeAuditOnce(context.Background(), p, 180, 30)
	b, _ := s.store.Audit(context.Background())
	for _, e := range b.Logs {
		if strings.Contains(e.Event, "按磁盘水位回收") {
			t.Fatalf("没触发却留了痕：%s", e.Event)
		}
	}
}

type fakePurger struct {
	r                      store.AuditDiskPurge
	err                    error
	daysCalled, diskCalled bool
}

func (p *fakePurger) PurgeExpiredAudit(context.Context, int) (int64, error) {
	p.daysCalled = true
	return 0, nil
}

func (p *fakePurger) PurgeAuditByDisk(context.Context, int) (store.AuditDiskPurge, error) {
	p.diskCalled = true
	return p.r, p.err
}
