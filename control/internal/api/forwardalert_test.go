package api

import (
	"strings"
	"testing"

	"baidi.dev/control/internal/alerting"
	"baidi.dev/control/internal/store"
)

// 审计外送投递失败必须有主动信号（FR-AUDIT-14/15 + NFR-OBS-02）。
//
// ★缺陷原样：失败路径只有 `RecordAuditForwardResult` + 一行 slog.Warn，
// 13 条告警规则里没有它、/diag 里没有它、消息通道也不发。
// 合规链路因此可以**静默断掉**：审计照常落本地库、页面一切正常，
// 而 SIEM 那边从某一刻起再也没收到过东西，直到有人主动去翻系统页那一格。
func TestAuditForwardFailAlert(t *testing.T) {
	spec, ok := store.AlertKindSpecOf(store.AlertKindAuditForwardFail)
	if !ok {
		t.Fatal("规则种类应存在")
	}
	rule := store.AlertRule{
		ID: "r-af", Kind: store.AlertKindAuditForwardFail, Enabled: true,
		Threshold: spec.Thresholds, CooldownSec: 60,
	}
	const now = int64(1_700_000_000)

	// ① 没有启用中的出口 → 一条都不报（别给没用这功能的部署常年挂告警）。
	if got := alerting.Evaluate([]store.AlertRule{rule}, alerting.Snapshot{Now: now}); len(got) != 0 {
		t.Fatalf("没有出口时不该报，得到 %+v", got)
	}

	// ② 出口**停用** → 同样不报（关掉的出口本来就不该发）。
	//    ★这里必须真放一个 Enabled:false 且各项都够触发的出口进去——
	//      放 nil 的话这条断言什么都没验（实测：把判定里那道 Enabled 闸删掉，
	//      用 nil 的版本照样绿）。api 层入快照前也会滤一道，这是纵深。
	off := alerting.Snapshot{Now: now, ForwardQueueMax: 1000,
		ForwardTargets: []store.AuditForwardTarget{{
			ID: "t0", Name: "已停用出口", Enabled: false,
			LastStatus: store.AuditForwardFail, LastAt: now - 60, LastOKAt: now - 99999,
			Queued: 999, Dropped: 5,
		}}}
	if got := alerting.Evaluate([]store.AlertRule{rule}, off); len(got) != 0 {
		t.Fatalf("停用出口不该报，得到 %+v", got)
	}

	// ③ 刚配好、还没轮到投递 → 不报（LastStatus 与 LastAt 都空）。
	fresh := alerting.Snapshot{Now: now, ForwardQueueMax: 20000,
		ForwardTargets: []store.AuditForwardTarget{{ID: "t1", Name: "SIEM", Enabled: true}}}
	if got := alerting.Evaluate([]store.AlertRule{rule}, fresh); len(got) != 0 {
		t.Fatalf("刚配好还没投过不该报，得到 %+v", got)
	}

	// ④ 一次瞬时失败但刚成功过 → 不报（退避重试会自己救回来，报它只是噪声）。
	blip := alerting.Snapshot{Now: now, ForwardQueueMax: 20000,
		ForwardTargets: []store.AuditForwardTarget{{
			ID: "t1", Name: "SIEM", Enabled: true,
			LastStatus: store.AuditForwardFail, LastAt: now - 10, LastOKAt: now - 60,
		}}}
	if got := alerting.Evaluate([]store.AlertRule{rule}, blip); len(got) != 0 {
		t.Fatalf("刚成功过的瞬时失败不该报，得到 %+v", got)
	}

	// ⑤ 持续投不出去（判据是「多久没**成功**过」）→ 报，且正文要带排障要的东西。
	down := alerting.Snapshot{Now: now, ForwardQueueMax: 20000,
		ForwardTargets: []store.AuditForwardTarget{{
			ID: "t1", Name: "总部 SIEM", Enabled: true,
			LastStatus: store.AuditForwardFail, LastAt: now - 60,
			LastOKAt: now - 7200, LastDetail: "dial tcp 10.0.0.9:6514: i/o timeout", Queued: 812,
		}}}
	got := alerting.Evaluate([]store.AlertRule{rule}, down)
	if len(got) != 1 {
		t.Fatalf("持续失败应报 1 条，得到 %+v", got)
	}
	if !strings.Contains(got[0].Title, "总部 SIEM") {
		t.Fatalf("标题要点名是哪个出口，得到 %q", got[0].Title)
	}
	for _, want := range []string{"i/o timeout", "812", "本地库里一条不丢"} {
		if !strings.Contains(got[0].Detail, want) {
			t.Fatalf("正文缺 %q（排障要的），得到 %q", want, got[0].Detail)
		}
	}

	// ⑥ 队列积压逼近上界 → 单独报一条：那是**不可逆**的（到顶就开始丢新记录）。
	full := alerting.Snapshot{Now: now, ForwardQueueMax: 1000,
		ForwardTargets: []store.AuditForwardTarget{{
			ID: "t2", Name: "备用出口", Enabled: true,
			LastStatus: store.AuditForwardOK, LastAt: now - 5, LastOKAt: now - 5,
			Queued: 900, Dropped: 12,
		}}}
	got = alerting.Evaluate([]store.AlertRule{rule}, full)
	if len(got) != 1 || !strings.Contains(got[0].Title, "积压") {
		t.Fatalf("积压应单独报一条，得到 %+v", got)
	}
	if !strings.Contains(got[0].Detail, "丢弃新记录") {
		t.Fatalf("正文要说清到顶之后会丢新记录，得到 %q", got[0].Detail)
	}
}

// 新增规则种类必须能在**既有库**上补播出来。
//
// ★原来的播种靠一个全局一次性标记（alert.rules.seeded），标记一旦落下，
// 后来新增的种类就再也不会被播种：升级后那一类在告警页上根本不存在、
// 永远不会触发，而页面上看不出缺了什么——「补列迁移必须配回填」的规则表版本。
func TestNewAlertKindGetsSeededOnExistingDB(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "GET", "/api/v1/alerts/rules", adminToken(), nil)
	if code != 200 {
		t.Fatalf("GET rules http %d", code)
	}
	have := map[string]bool{}
	for _, raw := range out["rules"].([]any) {
		have[str(raw.(map[string]any)["kind"])] = true
	}
	for _, spec := range store.AlertKindSpecs() {
		if !have[spec.Kind] {
			t.Fatalf("规则种类 %q 没有被播种——它在告警页上根本不存在，也永远不会触发", spec.Kind)
		}
	}
}
