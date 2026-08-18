package api

import (
	"context"
	"net/http"
	"testing"
)

// ── wave8 行动 15：灰度链收尾（FR-UPG-19 AC-12）──
//
// 被修的三处：①控制台保存灰度计划时请求体里写死 `groups: []`，而 SaveGrayPlan 是
// **整条覆盖式保存**——管理员只把比例从 10% 调到 20%，经 API 配好的用户组定向
// 当场被清空，接口回 200、页面看不出差别，灰度对象从「测试组」变成「全体 20% 随机分桶」；
// ②`upgrade.Coverage` 全仓只有单测在调，而它的注释写着「供控制台显示『预计影响 N 人』」；
// ③移动端从没调过 `GET /client/update`（后端按 platform 分桶早就支持 android/ios/harmony）。

// TestUpgradeBundleCarriesCoverage /upgrade 下发精确覆盖数、总数、用户组候选与版本分布。
func TestUpgradeBundleCarriesCoverage(t *testing.T) {
	h := newTestServer(t)
	if code, out := doJSON(t, h, "PUT", "/api/v1/upgrade/gray", adminToken(), map[string]any{
		"platform": "macos", "stable": "0.4.0", "version": "0.5.0", "percent": 100,
		"accounts": []string{}, "groups": []string{},
	}); code != http.StatusOK {
		t.Fatalf("保存灰度 %d: %v", code, out)
	}
	code, out := doJSON(t, h, "GET", "/api/v1/upgrade", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读升级页 %d", code)
	}
	total, _ := out["total"].(float64)
	if total <= 0 {
		t.Fatalf("应下发参与分桶的账号总数，实得 %v", out["total"])
	}
	cov, _ := out["coverage"].(map[string]any)
	if cov == nil {
		t.Fatal("应下发每条灰度计划的精确覆盖数（upgrade.Coverage 改造前零调用方）")
	}
	// percent=100 → 全员命中，覆盖数必须等于总数。
	if got, _ := cov["macos"].(float64); got != total {
		t.Fatalf("percent=100 时覆盖数应等于总数（%v），实得 %v", total, got)
	}
	if _, ok := out["groups"].([]any); !ok {
		t.Error("应下发用户组候选（灰度定向的数据源，与资源授权/认证策略同一处展开）")
	}
	if _, ok := out["versions"].([]any); !ok {
		t.Error("应下发现场终端的实际版本分布")
	}
}

// TestGrayCoverageCountsDirectedGroups 用户组定向必须真的进覆盖数。
//
// ★这条同时钉住两件事：groups 能存能读（不被整条覆盖式保存清空），
// 且 Coverage 的 groupsOf 真的接了 SubjectIndex——没接的话，
// 「按用户组定向」在页面上永远显示 0 人命中。
func TestGrayCoverageCountsDirectedGroups(t *testing.T) {
	h := newTestServer(t)
	putVendorGroup(t, h) // g-test-vendor = { li.fang }
	// percent=0：只有定向才可能命中，覆盖数直接反映定向是否生效。
	if code, out := doJSON(t, h, "PUT", "/api/v1/upgrade/gray", adminToken(), map[string]any{
		"platform": "macos", "stable": "0.4.0", "version": "0.5.0", "percent": 0,
		"accounts": []string{}, "groups": []string{"g-test-vendor"},
	}); code != http.StatusOK {
		t.Fatalf("保存灰度 %d: %v", code, out)
	}
	code, out := doJSON(t, h, "GET", "/api/v1/upgrade", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读升级页 %d", code)
	}
	cov, _ := out["coverage"].(map[string]any)
	if got, _ := cov["macos"].(float64); got != 1 {
		t.Fatalf("percent=0 + 定向一个 1 人的用户组 → 覆盖数应是 1，实得 %v"+
			"（0 说明 Coverage 的 groupsOf 没接 SubjectIndex，"+
			"「按用户组定向」在页面上永远显示 0 人命中）", got)
	}
	// 计划本身要能回读出 groups——回读不出来，控制台编辑一次就会把它清空。
	plans, _ := out["gray"].([]any)
	found := false
	for _, raw := range plans {
		p := raw.(map[string]any)
		if str(p["platform"]) != "macos" {
			continue
		}
		gs, _ := p["groups"].([]any)
		if len(gs) != 1 || str(gs[0]) != "g-test-vendor" {
			t.Fatalf("用户组定向应能回读，实得 %v", p["groups"])
		}
		found = true
	}
	if !found {
		t.Fatal("找不到 macos 的灰度计划")
	}
}

// TestClientVersionStatsIsTriState 版本分布：未上报单列一桶，绝不并进具体版本。
func TestClientVersionStatsIsTriState(t *testing.T) {
	h, st := newTestServerWithStore(t)
	post := func(user, dev, plat, ver string) {
		t.Helper()
		if code, out := doJSON(t, h, "POST", "/api/v1/posture", userToken(user), map[string]any{
			"device": dev, "platform": plat, "os": plat + " 14", "clientVersion": ver,
			"checks": []map[string]any{{"key": "disk_encrypted", "label": "磁盘已加密", "ok": true, "value": "On"}},
		}); code != http.StatusOK {
			t.Fatalf("上报 %d: %v", code, out)
		}
	}
	post("li.fang", "d1", "macOS", "0.4.0")
	post("li.fang", "d2", "macOS", "0.5.0")
	post("wang.qiang", "d3", "macOS", "") // 没报版本
	rows, err := st.ClientVersionStats(context.Background())
	if err != nil {
		t.Fatalf("读版本分布: %v", err)
	}
	byVer := map[string]int{}
	for _, r := range rows {
		byVer[r.Version] += r.Count
	}
	if byVer["0.4.0"] != 1 || byVer["0.5.0"] != 1 {
		t.Fatalf("两个具体版本各 1 台，实得 %v", byVer)
	}
	if byVer[""] != 1 {
		t.Fatalf("「未上报版本」必须单列一桶（并进任何具体版本都会让「有一批机器没报过版本」"+
			"这件事消失，而那批机器恰恰是升级里最需要盯的），实得 %v", byVer)
	}
}
