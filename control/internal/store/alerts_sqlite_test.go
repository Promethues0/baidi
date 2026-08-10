package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openAlertStore(t *testing.T) (*SQLiteStore, context.Context) {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, context.Background()
}

func raise(t *testing.T, s *SQLiteStore, ctx context.Context, ruleID, obj string, at int64, cooldown int) bool {
	t.Helper()
	_, created, err := s.RaiseAlert(ctx, Alert{
		RuleID: ruleID, Kind: AlertKindGatewayOffline, Category: AlertCategoryDevice,
		Severity: AlertSevCritical, Title: "网关离线", Detail: "d", ObjectKey: obj, TriggeredAt: at,
	}, cooldown)
	if err != nil {
		t.Fatalf("raise: %v", err)
	}
	return created
}

// 内置规则按种类各播一条，且**只播一次**：管理员删掉之后重启不许复活。
func TestSeedAlertRulesOnceAndDeletable(t *testing.T) {
	s, ctx := openAlertStore(t)
	rules, err := s.AlertRules(ctx)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	if len(rules) != len(AlertKindSpecs()) {
		t.Fatalf("应为每个 kind 播一条规则，得到 %d 条", len(rules))
	}
	for _, r := range rules {
		if !r.Enabled || r.CooldownSec != DefaultAlertCooldownSec {
			t.Errorf("规则 %s 默认应启用且带默认冷却，得到 enabled=%v cooldown=%d", r.ID, r.Enabled, r.CooldownSec)
		}
	}
	victim := rules[0].ID
	if err := s.DeleteAlertRule(ctx, victim); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	// 再跑一次播种（等价于进程重启走 migrate）：被删的那条不该回来。
	if err := s.seedAlertRules(ctx); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	after, _ := s.AlertRules(ctx)
	for _, r := range after {
		if r.ID == victim {
			t.Fatal("被删除的内置规则在重新播种后复活了——「删了、重启就回来」是本项目踩过的坑")
		}
	}
}

// 冷却期去重：同规则同对象只留一条；冷却过后可以再报；不同对象互不影响。
func TestRaiseAlertCooldownDedup(t *testing.T) {
	s, ctx := openAlertStore(t)
	now := time.Now().Unix()

	if !raise(t, s, ctx, "r1", "gw:a", now, 600) {
		t.Fatal("首条告警应产生")
	}
	if raise(t, s, ctx, "r1", "gw:a", now+30, 600) {
		t.Fatal("冷却期内同规则同对象不应重复产生——否则网关离线会每轮刷一条，告警页当场不可用")
	}
	if !raise(t, s, ctx, "r1", "gw:b", now+30, 600) {
		t.Fatal("同规则**不同对象**应各自成条（三台网关同时离线要看得见三条）")
	}
	if !raise(t, s, ctx, "r2", "gw:a", now+30, 600) {
		t.Fatal("不同规则同对象应各自成条")
	}
	// ★冷却期过了也**不再**产生：那条 gw:a 的告警还挂在 pending。
	// 这就是留存上界的来源——条件永久成立的规则（过期 JIT 授予全系统没有回收动作）
	// 否则会按 48 行/天/对象无限增长，通知与审计跟着一起涨。
	if raise(t, s, ctx, "r1", "gw:a", now+601, 600) {
		t.Fatal("同一对象上还挂着未处置的告警时，冷却期过了也不该再产生一条")
	}
	counts, err := s.AlertCounts(ctx)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts.Pending != 3 {
		t.Fatalf("应有 3 条未处理告警（每个对象至多一条），得到 %+v", counts)
	}

	// 处置掉之后、且冷却期已过：条件仍成立就要如常再报（压制不等于永久静默）。
	list, _ := s.Alerts(ctx, AlertQuery{})
	var target string
	for _, a := range list {
		if a.RuleID == "r1" && a.ObjectKey == "gw:a" {
			target = a.ID
		}
	}
	if _, err := s.SetAlertStatus(ctx, target, AlertHandled, "admin", now+602); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !raise(t, s, ctx, "r1", "gw:a", now+1300, 600) {
		t.Fatal("处置完 + 冷却期已过，条件仍成立时必须能再报——否则问题被永久静默")
	}
}

// 已处置告警的留存轮转：超期的清掉，pending 一律留着。
//
// ★pending 不清是刻意的：按时间删掉一条待办，等于让"没人管的问题"自己消失，
// 而列表与角标会同时变干净——这正是最难发现的那种失效。pending 的行数由
// RaiseAlert 的未处置压制钳住（每对象至多一条），不需要靠留存期兜底。
func TestPurgeExpiredAlerts(t *testing.T) {
	s, ctx := openAlertStore(t)
	old := time.Now().AddDate(0, 0, -120).Unix()
	fresh := time.Now().Unix()

	raise(t, s, ctx, "r1", "gw:old-handled", old, 600)
	raise(t, s, ctx, "r1", "gw:old-pending", old, 600)
	raise(t, s, ctx, "r1", "gw:fresh-handled", fresh, 600)
	list, _ := s.Alerts(ctx, AlertQuery{})
	for _, a := range list {
		if strings.HasSuffix(a.ObjectKey, "handled") {
			if _, err := s.SetAlertStatus(ctx, a.ID, AlertHandled, "admin", a.TriggeredAt+1); err != nil {
				t.Fatalf("handle %s: %v", a.ObjectKey, err)
			}
		}
	}

	n, err := s.PurgeExpiredAlerts(ctx, 90)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Fatalf("应只清掉 1 条（超期且已处置），实得 %d", n)
	}
	left := map[string]string{}
	after, _ := s.Alerts(ctx, AlertQuery{})
	for _, a := range after {
		left[a.ObjectKey] = a.Status
	}
	if _, ok := left["gw:old-handled"]; ok {
		t.Fatal("超期的已处置告警应被清掉")
	}
	if left["gw:old-pending"] != AlertPending {
		t.Fatal("★未处置的告警不得因为超期被清掉——那是把没人管的待办悄悄删了")
	}
	if left["gw:fresh-handled"] != AlertHandled {
		t.Fatal("留存期内的已处置告警应保留")
	}
	// days<=0 = 不清理（与 PurgeExpiredAudit 同口径）。
	if n, err := s.PurgeExpiredAlerts(ctx, 0); err != nil || n != 0 {
		t.Fatalf("days<=0 应不清理，实得 %d %v", n, err)
	}
}

// 冷却只看时间不看状态：处理完之后条件仍成立，也要等冷却期过了才再报。
func TestCooldownIgnoresStatus(t *testing.T) {
	s, ctx := openAlertStore(t)
	now := time.Now().Unix()
	raise(t, s, ctx, "r1", "gw:a", now, 600)
	list, _ := s.Alerts(ctx, AlertQuery{})
	if _, err := s.SetAlertStatus(ctx, list[0].ID, AlertHandled, "admin", now+1); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if raise(t, s, ctx, "r1", "gw:a", now+2, 600) {
		t.Fatal("刚点完「已处理」就冒出同一条，是告警页最难用的形态——冷却不看状态")
	}
}

// 状态机：pending → ignored / handled；已处置的不可再处置；不存在的回 ErrAlertNotFound。
func TestAlertStatusMachine(t *testing.T) {
	s, ctx := openAlertStore(t)
	now := time.Now().Unix()
	raise(t, s, ctx, "r1", "gw:a", now, 600)
	raise(t, s, ctx, "r1", "gw:b", now, 600)
	list, _ := s.Alerts(ctx, AlertQuery{})
	a, b := list[0], list[1]

	got, err := s.SetAlertStatus(ctx, a.ID, AlertIgnored, "sec.admin", now+5)
	if err != nil {
		t.Fatalf("ignore: %v", err)
	}
	if got.Status != AlertIgnored || got.HandledBy != "sec.admin" || got.HandledAt != now+5 {
		t.Fatalf("忽略应记下处置人与时刻，得到 %+v", got)
	}
	if _, err := s.SetAlertStatus(ctx, a.ID, AlertHandled, "other", now+6); err != ErrAlertDecided {
		t.Fatalf("已处置的告警再处置应回 ErrAlertDecided，得到 %v", err)
	}
	if _, err := s.SetAlertStatus(ctx, b.ID, AlertHandled, "sec.admin", now+7); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if _, err := s.SetAlertStatus(ctx, "al-nope", AlertHandled, "sec.admin", now+8); err != ErrAlertNotFound {
		t.Fatalf("不存在的告警应回 ErrAlertNotFound，得到 %v", err)
	}
	// 非法目标状态（回退到 pending）也拒绝。
	raise(t, s, ctx, "r1", "gw:c", now, 600)
	list, _ = s.Alerts(ctx, AlertQuery{Status: AlertPending})
	if _, err := s.SetAlertStatus(ctx, list[0].ID, AlertPending, "x", now); err != ErrAlertDecided {
		t.Fatalf("不允许把告警置回 pending，得到 %v", err)
	}

	counts, _ := s.AlertCounts(ctx)
	if counts.Pending != 1 || counts.Ignored != 1 || counts.Handled != 1 {
		t.Fatalf("计数应为 1/1/1，得到 %+v", counts)
	}
}

// 过滤：状态 / 类别 / 时间窗。
func TestAlertQueryFilters(t *testing.T) {
	s, ctx := openAlertStore(t)
	now := time.Now().Unix()
	mk := func(cat string, at int64, obj string) {
		if _, _, err := s.RaiseAlert(ctx, Alert{
			RuleID: "r-" + cat, Kind: "k", Category: cat, Severity: AlertSevWarning,
			Title: "t", ObjectKey: obj, TriggeredAt: at,
		}, 60); err != nil {
			t.Fatalf("raise: %v", err)
		}
	}
	mk(AlertCategoryDevice, now-7200, "o1")
	mk(AlertCategoryAuthz, now-3600, "o2")
	mk(AlertCategorySecurity, now-60, "o3")

	if got, _ := s.Alerts(ctx, AlertQuery{Category: AlertCategoryAuthz}); len(got) != 1 || got[0].ObjectKey != "o2" {
		t.Fatalf("按类别过滤失败，得到 %+v", got)
	}
	if got, _ := s.Alerts(ctx, AlertQuery{From: now - 3700}); len(got) != 2 {
		t.Fatalf("按起始时间过滤应剩 2 条，得到 %d 条", len(got))
	}
	if got, _ := s.Alerts(ctx, AlertQuery{To: now - 3600}); len(got) != 2 {
		t.Fatalf("按结束时间过滤应剩 2 条，得到 %d 条", len(got))
	}
	// 处置一条后按状态过滤。
	all, _ := s.Alerts(ctx, AlertQuery{})
	if _, err := s.SetAlertStatus(ctx, all[0].ID, AlertHandled, "admin", now); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got, _ := s.Alerts(ctx, AlertQuery{Status: AlertPending}); len(got) != 2 {
		t.Fatalf("未处理应剩 2 条，得到 %d 条", len(got))
	}
	if got, _ := s.Alerts(ctx, AlertQuery{Status: AlertHandled}); len(got) != 1 {
		t.Fatalf("已处理应有 1 条，得到 %d 条", len(got))
	}
	// 排序：新→旧。
	if all[0].ObjectKey != "o3" {
		t.Fatalf("列表应新→旧，首条得到 %s", all[0].ObjectKey)
	}
}

// 阈值校验：未知阈值键拒绝（不静默丢弃）、缺失键补默认、未知 kind 拒绝。
func TestSaveAlertRuleValidatesThresholds(t *testing.T) {
	s, ctx := openAlertStore(t)
	if _, err := s.SaveAlertRule(ctx, AlertRule{
		ID: "x1", Kind: AlertKindGatewayOffline, Threshold: map[string]float64{"nonsense": 1},
	}); err != ErrUnknownThreshold {
		t.Fatalf("未知阈值键应拒绝，得到 %v", err)
	}
	if _, err := s.SaveAlertRule(ctx, AlertRule{ID: "x2", Kind: "made_up"}); err != ErrUnknownAlertKind {
		t.Fatalf("未知 kind 应拒绝（它背后没有任何信号），得到 %v", err)
	}
	saved, err := s.SaveAlertRule(ctx, AlertRule{ID: "x3", Kind: AlertKindGatewayLoad,
		Threshold: map[string]float64{ThreshCPUPercent: 50}})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if saved.Threshold[ThreshCPUPercent] != 50 || saved.Threshold[ThreshMemPercent] != 85 {
		t.Fatalf("缺失阈值应补默认，得到 %+v", saved.Threshold)
	}
	if saved.CooldownSec != DefaultAlertCooldownSec {
		t.Fatalf("冷却期为 0 时应取默认，得到 %d", saved.CooldownSec)
	}
}

// 已过期未回收的授予：只认库里那一份状态（active），不吃展示层的到期纠正。
func TestStaleGrants(t *testing.T) {
	s, ctx := openAlertStore(t)
	now := time.Now().Unix()
	ins := func(id string, exp int64, status string) {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO jit_grants(id,usr,resource_id,resource_name,request_id,reason,granted_by,granted_at,expires_at,status,revoked_at,revoke_reason)
VALUES(?,?,?,?,?,?,?,?,?,?,0,'')`, id, "u", "res-1", "资源", "req", "r", "admin", now-7200, exp, status); err != nil {
			t.Fatalf("insert grant: %v", err)
		}
	}
	ins("g-live", now+3600, "active")
	ins("g-rot", now-3600, "active")
	ins("g-revoked", now-3600, "revoked")

	got, err := s.StaleGrants(ctx, now)
	if err != nil {
		t.Fatalf("stale: %v", err)
	}
	if len(got) != 1 || got[0].ID != "g-rot" {
		t.Fatalf("只应报「已过期但仍标 active」的那条，得到 %+v", got)
	}
	if got[0].Status != "active" {
		t.Fatalf("状态必须是库里那一份（active），展示层纠正会把「该回收没回收」这件事抹平，得到 %s", got[0].Status)
	}
}

// 指标数据源未接入 / 表为空时，探测必须**说得出原因**，而不是静默不触发。
func TestGatewayMetricsProbeReportsReason(t *testing.T) {
	s, ctx := openAlertStore(t)
	probe, err := s.GatewayMetricsProbe(ctx)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe.Ready {
		t.Fatal("空库不应报告数据源就绪")
	}
	if probe.Reason == "" {
		t.Fatal("未就绪必须给出原因——「等待数据面上报」与「永远不触发的死规则」在页面上要能区分")
	}
	// 灌一条采样后即就绪，且 NULL 指标原样穿透（不塌缩成 0）。
	// ★IF NOT EXISTS：表由「设备状态指标上报」那条链路建立，本用例只依赖本模块读的五列。
	// 两种情况都要覆盖到——该链路已合入时用它建的表（列名对不上会当场失败，正是我们要的），
	// 未合入时本用例自建，保证探测的"就绪"分支不因为缺一张表而永远测不到。
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS gateway_metrics (
  gateway_id TEXT, ts INTEGER, cpu REAL, mem REAL, disk REAL, load REAL, rx_bps REAL, tx_bps REAL,
  PRIMARY KEY(gateway_id, ts))`); err != nil {
		t.Fatalf("ensure gateway_metrics: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO gateway_metrics(gateway_id,ts,cpu,mem,disk) VALUES('gw-1',?,91.5,NULL,20)`,
		time.Now().Unix()); err != nil {
		t.Fatalf("insert metric: %v", err)
	}
	probe, err = s.GatewayMetricsProbe(ctx)
	if err != nil {
		t.Fatalf("probe2: %v", err)
	}
	if !probe.Ready || len(probe.Samples) != 1 {
		t.Fatalf("有数据后应就绪，得到 %+v", probe)
	}
	m := probe.Samples[0]
	if m.CPU == nil || *m.CPU != 91.5 {
		t.Fatalf("CPU 应原样读出，得到 %+v", m.CPU)
	}
	if m.Mem != nil {
		t.Fatal("采不到的指标必须保持 nil——塌缩成 0 会让失明的网关看起来永远空闲")
	}
}
