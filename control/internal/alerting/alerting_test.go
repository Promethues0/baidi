package alerting

import (
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// 每类触发源两向断言：条件满足 → 出候选；条件不满足 → 不出。
// 只测"满足时会报"的话，一个恒报的实现也能全绿，而那会把告警页冲成噪声。

const now int64 = 1_700_000_000

// ruleFor 按 kind 的默认阈值造一条启用规则。
func ruleFor(t *testing.T, kind string) store.AlertRule {
	t.Helper()
	spec, ok := store.AlertKindSpecOf(kind)
	if !ok {
		t.Fatalf("未知 kind %s", kind)
	}
	return store.AlertRule{
		ID: "r-" + kind, Name: spec.Name, Kind: kind, Threshold: spec.Thresholds,
		Enabled: true, CooldownSec: store.DefaultAlertCooldownSec,
	}
}

func base() Snapshot { return Snapshot{Now: now, OfflineAfterSec: 120, MetricsFreshSec: 600} }

func f(v float64) *float64 { return &v }

func kinds(cs []Candidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Kind+"|"+c.ObjectKey)
	}
	return out
}

func TestGatewayOffline(t *testing.T) {
	rule := ruleFor(t, store.AlertKindGatewayOffline)

	snap := base()
	snap.Gateways = []GatewayStat{{ID: "gw-live", LastSeen: now - 10}, {ID: "gw-dead", LastSeen: now - 600}}
	got := Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 || got[0].ObjectKey != "gw:gw-dead" {
		t.Fatalf("只应对超时网关告警，得到 %v", kinds(got))
	}
	if got[0].Severity != store.AlertSevCritical || got[0].Category != store.AlertCategoryDevice {
		t.Errorf("类别/严重度取自 kind 元信息，得到 %s/%s", got[0].Category, got[0].Severity)
	}

	// 只有活着的网关 → 一条都不出。
	snap.Gateways = []GatewayStat{{ID: "gw-live", LastSeen: now - 10}}
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("心跳正常不应告警，得到 %v", kinds(got))
	}

	// 阈值可调：把超时放宽到 1 小时，刚才那台就不再算离线。
	relaxed := rule
	relaxed.Threshold = map[string]float64{store.ThreshOfflineSec: 3600}
	snap.Gateways = []GatewayStat{{ID: "gw-dead", LastSeen: now - 600}}
	if got := Evaluate([]store.AlertRule{relaxed}, snap); len(got) != 0 {
		t.Fatalf("阈值放宽后不应告警，得到 %v", kinds(got))
	}
}

// 规则停用 = 一条候选都不出（页面上的开关必须真的是开关）。
func TestDisabledRuleProducesNothing(t *testing.T) {
	rule := ruleFor(t, store.AlertKindGatewayOffline)
	rule.Enabled = false
	snap := base()
	snap.Gateways = []GatewayStat{{ID: "gw-dead", LastSeen: now - 600}}
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("停用规则不应产生候选，得到 %v", kinds(got))
	}
}

// 数据源未就绪时资源水位规则**一条都不出**——而不是拿零值当"一切正常"，
// 也不是对着不存在的表报错。就绪状态由 api 层如实呈现为「等待数据面上报」。
func TestGatewayLoadWaitsForDataSource(t *testing.T) {
	rule := ruleFor(t, store.AlertKindGatewayLoad)
	snap := base()
	snap.Metrics = store.MetricsProbe{Ready: false, Reason: "等待数据面上报"}
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("数据源未就绪不应产生候选，得到 %v", kinds(got))
	}
}

func TestGatewayLoadThreshold(t *testing.T) {
	rule := ruleFor(t, store.AlertKindGatewayLoad)
	snap := base()
	snap.Metrics = store.MetricsProbe{Ready: true, Samples: []store.GatewayMetricSample{
		{GatewayID: "gw-hot", CPU: f(93), Mem: f(40), Disk: f(50), TS: now - 5},
		{GatewayID: "gw-cool", CPU: f(12), Mem: f(30), Disk: f(20), TS: now - 5},
	}}
	got := Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 || got[0].ObjectKey != "gwload:gw-hot" {
		t.Fatalf("只应对超阈值网关告警，得到 %v", kinds(got))
	}
	if !strings.Contains(got[0].Detail, "CPU 93%") {
		t.Errorf("正文应给出实测值，得到 %q", got[0].Detail)
	}
}

// 采不到（nil）不是 0：一台报不出 CPU 的网关不该被当成"空闲"，也不该被当成超载。
func TestGatewayLoadUnknownMetricIsNotZero(t *testing.T) {
	rule := ruleFor(t, store.AlertKindGatewayLoad)
	snap := base()
	snap.Metrics = store.MetricsProbe{Ready: true, Samples: []store.GatewayMetricSample{
		{GatewayID: "gw-blind", CPU: nil, Mem: nil, Disk: nil, TS: now - 5},
	}}
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("采不到的指标不应产生告警，得到 %v", kinds(got))
	}
}

// 陈旧样本不参与判定：拿一小时前的读数报"现在超载"是谎报。
func TestGatewayLoadIgnoresStaleSample(t *testing.T) {
	rule := ruleFor(t, store.AlertKindGatewayLoad)
	snap := base()
	snap.Metrics = store.MetricsProbe{Ready: true, Samples: []store.GatewayMetricSample{
		{GatewayID: "gw-hot", CPU: f(99), TS: now - 3600},
	}}
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("陈旧样本不应产生告警，得到 %v", kinds(got))
	}
}

func TestGrantExpiringAndStale(t *testing.T) {
	expiring := ruleFor(t, store.AlertKindGrantExpiring)
	stale := ruleFor(t, store.AlertKindGrantStale)

	snap := base()
	snap.ActiveGrants = []store.JitGrant{
		{ID: "g-soon", User: "li.fang", ResourceName: "财务系统", ExpiresAt: now + 600},  // 10 分钟后到期
		{ID: "g-far", User: "li.fang", ResourceName: "财务系统", ExpiresAt: now + 86400}, // 一天后
	}
	snap.StaleGrants = []store.JitGrant{
		{ID: "g-rot", User: "wu.min", ResourceName: "工资单", ExpiresAt: now - 3600}, // 过期一小时
		{ID: "g-just", User: "wu.min", ResourceName: "工资单", ExpiresAt: now - 60},  // 刚过期，宽限内
	}
	got := Evaluate([]store.AlertRule{expiring, stale}, snap)
	want := []string{"grant_expiring|grant:g-soon", "grant_stale|grant:g-rot"}
	if strings.Join(kinds(got), ",") != strings.Join(want, ",") {
		t.Fatalf("候选应为 %v，得到 %v", want, kinds(got))
	}

	// 没有任何授予 → 不出候选。
	snap.ActiveGrants, snap.StaleGrants = nil, nil
	if got := Evaluate([]store.AlertRule{expiring, stale}, snap); len(got) != 0 {
		t.Fatalf("无授予不应告警，得到 %v", kinds(got))
	}
}

func TestAppUnlinked(t *testing.T) {
	rule := ruleFor(t, store.AlertKindAppUnlinked)
	snap := base()
	snap.UnlinkedApps = []AppRef{{ID: "app-1", Name: "OA 系统"}}
	got := Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 || got[0].ObjectKey != "app:app-1" {
		t.Fatalf("未关联资源的应用应告警，得到 %v", kinds(got))
	}
	snap.UnlinkedApps = nil
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("全部应用都已关联时不应告警，得到 %v", kinds(got))
	}
}

func TestAccountLockout(t *testing.T) {
	rule := ruleFor(t, store.AlertKindAccountLockout)
	snap := base()
	snap.Lockouts = []store.Lockout{
		{Kind: store.LockKindAccount, Key: "li.fang", Until: now + 300, Reason: "10 分钟内连续 5 次登录失败"},
		{Kind: store.LockKindIP, Key: "10.0.0.9", Until: now - 5, Reason: "已到期"}, // 到期的不报
	}
	got := Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 || got[0].ObjectKey != "lockout:account:li.fang" {
		t.Fatalf("只应对生效中的锁定告警，得到 %v", kinds(got))
	}
	snap.Lockouts = nil
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("无锁定不应告警，得到 %v", kinds(got))
	}
}

func TestPostureBlock(t *testing.T) {
	rule := ruleFor(t, store.AlertKindPostureBlock)
	snap := base()
	snap.PostureBlocked = []string{"ext.zhao"}
	got := Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 || got[0].ObjectKey != "posture:ext.zhao" {
		t.Fatalf("终端判 block 应告警，得到 %v", kinds(got))
	}
	snap.PostureBlocked = nil
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("无阻断账号不应告警，得到 %v", kinds(got))
	}
}

// 审计链三态：链断 → 报；自检没跑成 → 报（另一种措辞）；本轮没查（nil）→ 什么都不报。
// ★最后一条是关键：把"没查"当成"没问题"，防篡改链就退回成一句口号。
func TestAuditChainThreeStates(t *testing.T) {
	rule := ruleFor(t, store.AlertKindAuditChain)
	snap := base()

	snap.AuditChain = &ChainStatus{OK: true, Checked: 100}
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("链完好不应告警，得到 %v", kinds(got))
	}

	snap.AuditChain = &ChainStatus{OK: false, Checked: 100, BrokenAt: 42}
	got := Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "第 42 条") {
		t.Fatalf("链断裂应指出断点，得到 %v / %q", kinds(got), detailOf(got))
	}
	if got[0].Severity != store.AlertSevCritical {
		t.Errorf("链断裂应为 critical，得到 %s", got[0].Severity)
	}

	snap.AuditChain = &ChainStatus{Err: "database is locked"}
	got = Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 || !strings.Contains(got[0].Title, "未能完成") {
		t.Fatalf("自检失败应与链断裂分开措辞，得到 %v / %q", kinds(got), detailOf(got))
	}

	snap.AuditChain = nil
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("本轮未自检时不应产生任何结论，得到 %v", kinds(got))
	}
}

func detailOf(cs []Candidate) string {
	if len(cs) == 0 {
		return ""
	}
	return cs[0].Title + " / " + cs[0].Detail
}

// 空快照（什么信号都没有）必须一条候选都不出。
// ★这是「空集合语义」自查：新增规则时若把"没数据"写成了"全都异常"，
// 这条用例会立刻变红——而集成环境里那种错只表现为告警页突然爆满。
func TestEmptySnapshotProducesNothing(t *testing.T) {
	var rules []store.AlertRule
	for _, spec := range store.AlertKindSpecs() {
		rules = append(rules, ruleFor(t, spec.Kind))
	}
	if got := Evaluate(rules, base()); len(got) != 0 {
		t.Fatalf("空快照不应产生任何候选，得到 %v", kinds(got))
	}
}
