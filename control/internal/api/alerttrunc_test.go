package api

import (
	"net/http"
	"testing"

	"baidi.dev/control/internal/store"
)

// 告警列表的截断必须可见（同 wave8 行动 17 在 /jit/grants 与 /posture 上立的那条纪律）。
//
// ★缺陷原样：列表被 store.AlertListLimit=200 硬截，前端从不发 limit/offset，
// 页脚只写「当前列表 200 条」；而页头那三个计数是**全局量**（后端注释明写"不受过滤
// 与 LIMIT 影响"）。未处理超过 200 条时，页面上并排显示着「未处理 350」和一张 200 行的表，
// 第 201 条之后的告警在管理台上根本不存在，也没有任何一句话说它被截断过。
//
// 关键断言是 **total 必须来自库里的 COUNT，而不是 len(已读)**：
// 后者恒等于上限，truncated 永远是 false，提示等于白加。
func TestAlertsReportTruncation(t *testing.T) {
	h, st := newTestServerWithStore(t)
	ctx := t.Context()

	// 造 AlertListLimit+5 条待处理告警（RaiseAlert 有 (规则,对象) 冷却，故对象键各不相同）。
	n := store.AlertListLimit + 5
	for i := 0; i < n; i++ {
		if _, _, err := st.RaiseAlert(ctx, store.Alert{
			RuleID: "ar-test", Kind: "gateway_offline", Category: "device",
			Severity: "warning", Title: "网关离线（造数）",
			ObjectKey: "gw:probe-" + itoa(i), Status: store.AlertPending,
			TriggeredAt: int64(1700000000 + i),
		}, 0); err != nil {
			t.Fatalf("造第 %d 条告警: %v", i, err)
		}
	}

	code, out := doJSON(t, h, "GET", "/api/v1/alerts", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /alerts http %d", code)
	}
	list, _ := out["alerts"].([]any)
	if len(list) != store.AlertListLimit {
		t.Fatalf("列表应被截到 %d 条，实际 %d", store.AlertListLimit, len(list))
	}
	total, _ := out["total"].(float64)
	if int(total) != n {
		t.Fatalf("total 必须是库里的行数 %d，实际 %v —— "+
			"若它等于 %d 就说明用了 len(已读)，那样 truncated 永远是 false", n, out["total"], len(list))
	}
	if trunc, _ := out["truncated"].(bool); !trunc {
		t.Fatalf("%d > %d 应报 truncated=true", n, len(list))
	}
	if lim, _ := out["limit"].(float64); int(lim) != store.AlertListLimit {
		t.Fatalf("limit 应下发 %d，实际 %v（页面要靠它说出「只显示最近 N 条」）", store.AlertListLimit, out["limit"])
	}

	// 反向：筛到一个小集合时不该报截断，且 total 要跟着筛选条件走
	// （total 若不随筛选变，页面就会在筛出 3 条时说"共 205 条"）。
	code, out = doJSON(t, h, "GET", "/api/v1/alerts?status=handled", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /alerts?status=handled http %d", code)
	}
	if total, _ := out["total"].(float64); int(total) != 0 {
		t.Fatalf("没有已处理告警时 total 应为 0，实际 %v（说明 total 没跟着筛选条件算）", out["total"])
	}
	if trunc, _ := out["truncated"].(bool); trunc {
		t.Fatal("0 条不该报截断")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
