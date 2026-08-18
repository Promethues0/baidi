package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── wave8 行动 17②：列表截断必须可见 ──
//
// 两处 `LIMIT 500` 此前不回总数、页面也不提示：第 501 条之后的行在管理台上
// **根本不存在**。判定面不受影响（告警走 ActiveGrants/StaleGrants、准入走
// PostureUsersByDisposal 的 DISTINCT），所以这是展示面问题——但一份被截断的
// **访问审查清单**或**合规清单**被当成全量，后果不轻。

// TestListsReportTotalAndTruncation 未超上限时 truncated=false 且 total 与条数一致。
func TestListsReportTotalAndTruncation(t *testing.T) {
	h := newTestServer(t)
	for _, path := range []string{"/api/v1/jit/grants", "/api/v1/posture"} {
		code, out := doJSON(t, h, "GET", path, adminToken(), nil)
		if code != http.StatusOK {
			t.Fatalf("%s http %d", path, code)
		}
		if _, ok := out["total"]; !ok {
			t.Errorf("%s 应下发库里的总行数", path)
		}
		if out["truncated"] != false {
			t.Errorf("%s 未超上限时 truncated 应为 false，实得 %v", path, out["truncated"])
		}
		if lim, _ := out["limit"].(float64); int(lim) != store.ListLimit {
			t.Errorf("%s 应下发上限值供页面写出「只显示前 N 条」，实得 %v", path, out["limit"])
		}
	}
}

// TestPostureListTruncationIsVisible 超过上限时 total 说真话、truncated=true。
//
// ★关键在 total 必须是**库里的行数**而不是 len(已读)：后者恒等于 500，
// truncated 永远算成 false，等于这道提示白加。
func TestPostureListTruncationIsVisible(t *testing.T) {
	h, st := newTestServerWithStore(t)
	ctx := context.Background()
	// 直接落库造 ListLimit+7 条（走 API 会被「每账号 ≤20 台」钳住）。
	for i := 0; i < store.ListLimit+7; i++ {
		if err := st.SavePostureReport(ctx, store.PostureReport{
			User: fmt.Sprintf("u%04d", i), Device: fmt.Sprintf("d%04d", i),
			Platform: "macOS", OS: "macOS 14", ClientVersion: "0.9.0",
			Verdict: "allow", Level: "low", TS: int64(1_700_000_000 + i),
		}); err != nil {
			t.Fatalf("落 posture 第 %d 条: %v", i, err)
		}
	}
	code, out := doJSON(t, h, "GET", "/api/v1/posture", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("http %d", code)
	}
	rows, _ := out["reports"].([]any)
	total, _ := out["total"].(float64)
	if len(rows) != store.ListLimit {
		t.Fatalf("应只读前 %d 条，实得 %d", store.ListLimit, len(rows))
	}
	if int(total) != store.ListLimit+7 {
		t.Fatalf("total 必须是**库里的行数**（否则它恒等于已读条数，truncated 永远算成 false，"+
			"这道提示等于白加），期望 %d 实得 %v", store.ListLimit+7, out["total"])
	}
	if out["truncated"] != true {
		t.Fatalf("超过上限必须标 truncated，实得 %v", out["truncated"])
	}
}
