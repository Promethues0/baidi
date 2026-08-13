package alerting

import (
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

func i64(v int64) *int64 { return &v }

// 时钟偏差：超阈值才报、方向要说对、旧网关不可判定绝不告警、离线网关的陈旧读数不参与。
func TestClockSkew(t *testing.T) {
	rule := ruleFor(t, store.AlertKindClockSkew)

	snap := base()
	snap.KnockTTLSec = 90
	snap.Gateways = []GatewayStat{
		{ID: "gw-ok", LastSeen: now - 5, SkewSec: i64(3)},      // 3s：正常
		{ID: "gw-fast", LastSeen: now - 5, SkewSec: i64(45)},   // 快 45s：超默认阈值 10s
		{ID: "gw-slow", LastSeen: now - 5, SkewSec: i64(-30)},  // 慢 30s：同样超
		{ID: "gw-old", LastSeen: now - 5, SkewSec: nil},        // 旧网关：不可判定
		{ID: "gw-dead", LastSeen: now - 600, SkewSec: i64(999)}, // 离线：陈旧读数
	}
	got := Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 2 {
		t.Fatalf("应只对两台在线超阈网关告警，得到 %v", kinds(got))
	}
	byKey := map[string]Candidate{}
	for _, c := range got {
		byKey[c.ObjectKey] = c
	}
	fast, ok := byKey["gwskew:gw-fast"]
	if !ok {
		t.Fatalf("缺 gw-fast 的候选：%v", kinds(got))
	}
	if !strings.Contains(fast.Detail, "快") || !strings.Contains(fast.Detail, "45") {
		t.Errorf("快的方向与数值要说对：%s", fast.Detail)
	}
	if !strings.Contains(fast.Detail, "90") {
		t.Errorf("文案要点出敲门令牌有效期这个临界点：%s", fast.Detail)
	}
	slow, ok := byKey["gwskew:gw-slow"]
	if !ok {
		t.Fatalf("缺 gw-slow 的候选：%v", kinds(got))
	}
	if !strings.Contains(slow.Detail, "慢") {
		t.Errorf("慢的方向要说对：%s", slow.Detail)
	}
	if fast.Category != store.AlertCategoryDevice || fast.Severity != store.AlertSevWarning {
		t.Errorf("类别/严重度取自 kind 元信息：%s/%s", fast.Category, fast.Severity)
	}

	// ★不可判定绝不告警的反向钉死：只剩旧网关时一条都不出。
	// 把 nil 当 0 的实现在上面那组里恰好也对（0 不超阈值），只有这一组能揭穿
	// 「把 nil 当 999 处理」之类的错法——不可判定必须是"跳过"，不是任何数。
	snap.Gateways = []GatewayStat{{ID: "gw-old", LastSeen: now - 5, SkewSec: nil}}
	if got := Evaluate([]store.AlertRule{rule}, snap); len(got) != 0 {
		t.Fatalf("旧网关不上报时钟不得告警，得到 %v", kinds(got))
	}

	// 阈值可调：放宽到 60s 后，快 45s 的那台不再算异常。
	relaxed := rule
	relaxed.Threshold = map[string]float64{store.ThreshSkewSec: 60}
	snap.Gateways = []GatewayStat{{ID: "gw-fast", LastSeen: now - 5, SkewSec: i64(45)}}
	if got := Evaluate([]store.AlertRule{relaxed}, snap); len(got) != 0 {
		t.Fatalf("放宽阈值后不应告警，得到 %v", kinds(got))
	}

	// KnockTTLSec 未注入（=0）时文案不得编一个临界点数字。
	snap.KnockTTLSec = 0
	snap.Gateways = []GatewayStat{{ID: "gw-fast", LastSeen: now - 5, SkewSec: i64(45)}}
	got = Evaluate([]store.AlertRule{rule}, snap)
	if len(got) != 1 {
		t.Fatalf("应有一条：%v", kinds(got))
	}
	if strings.Contains(got[0].Detail, "令牌有效期") {
		t.Errorf("未注入 KnockTTLSec 时不该出现临界点句：%s", got[0].Detail)
	}
}
