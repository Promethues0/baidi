package alerting

import (
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// License 两条规则：nil 不出候选（demo/取不到）、到期窗口、失效态、席位阈值、
// 以及「-1 = 读不出」绝不当 0 判。
func TestLicenseAlerts(t *testing.T) {
	exp := ruleFor(t, store.AlertKindLicenseExpiry)
	seats := ruleFor(t, store.AlertKindLicenseSeats)

	snap := base()
	// nil：两条都不出。
	if got := Evaluate([]store.AlertRule{exp, seats}, snap); len(got) != 0 {
		t.Fatalf("License 快照缺席不该出候选，实得 %v", kinds(got))
	}

	// licensed 且剩 10 天（< 默认 15）→ expiry 出；席位 5/10=50% < 90% → seats 不出。
	snap.License = &LicenseStat{Mode: "licensed", ExpiresAt: "2026-08-23", DaysLeft: 10,
		Users: 5, MaxUsers: 10, Gateways: 1, MaxGateways: 0}
	got := Evaluate([]store.AlertRule{exp, seats}, snap)
	if len(got) != 1 || got[0].Kind != store.AlertKindLicenseExpiry {
		t.Fatalf("应只出到期提醒，实得 %v", kinds(got))
	}
	if !strings.Contains(got[0].Title, "10 天") {
		t.Errorf("标题要说剩几天：%s", got[0].Title)
	}

	// 席位 9/10=90% ≥ 90% → seats 出（用户维）；网关 0 上限不判。
	snap.License.DaysLeft = 200
	snap.License.Users = 9
	got = Evaluate([]store.AlertRule{exp, seats}, snap)
	if len(got) != 1 || got[0].Kind != store.AlertKindLicenseSeats || got[0].ObjectKey != "license-users" {
		t.Fatalf("应只出用户席位将满，实得 %v", kinds(got))
	}

	// ★读不出（-1）绝不当 0：-1/10 若被算成 0%% 不报是对的，但更险的错法是当 0 除
	// 或当满报——钉住"该维直接不判"。
	snap.License.Users = -1
	if got := Evaluate([]store.AlertRule{seats}, snap); len(got) != 0 {
		t.Fatalf("占用读不出该维不判，实得 %v", kinds(got))
	}

	// expired：expiry 出、seats 不出（已有更根本的那条）。
	snap.License = &LicenseStat{Mode: "expired", Reason: "已于 2026-08-01 到期",
		ExpiresAt: "2026-08-01", DaysLeft: -12, Users: 9, MaxUsers: 10}
	got = Evaluate([]store.AlertRule{exp, seats}, snap)
	if len(got) != 1 || got[0].Kind != store.AlertKindLicenseExpiry {
		t.Fatalf("失效态应只出 expiry 一条，实得 %v", kinds(got))
	}
	if !strings.Contains(got[0].Detail, "fail-closed") && !strings.Contains(got[0].Detail, "会被拒") {
		t.Errorf("失效告警要说清容量闸后果：%s", got[0].Detail)
	}
}
