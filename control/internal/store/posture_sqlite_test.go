package store

import (
	"context"
	"testing"
)

func rep(user, device, verdict string, score int, ts int64) PostureReport {
	level := "low"
	if verdict == "block" {
		level = "high"
	}
	return PostureReport{User: user, Device: device, Platform: "macOS", OS: "macOS 14.4", ClientVersion: "0.1.0",
		Checks:  []PostureCheckResult{{Key: "disk_encrypted", Label: "磁盘已加密", OK: verdict != "block", Value: "x"}},
		Verdict: verdict, Score: score, Level: level, Reasons: []string{}, TS: ts}
}

// upsert 语义：同 (user,device) 覆盖；不同设备并存。
func TestSavePostureReportUpsert(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.SavePostureReport(ctx, rep("li.fang", "DEV-A", "allow", 0, 100)); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePostureReport(ctx, rep("li.fang", "DEV-A", "block", 25, 200)); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePostureReport(ctx, rep("li.fang", "DEV-B", "allow", 0, 150)); err != nil {
		t.Fatal(err)
	}
	all, err := s.PostureReports(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("应 2 行（A 覆盖 + B）: %d %v", len(all), err)
	}
	if all[0].TS != 200 { // ts DESC
		t.Fatalf("排序应 ts DESC: %+v", all[0])
	}
	if all[0].Checks[0].Key != "disk_encrypted" {
		t.Fatalf("checks JSON 往返丢失: %+v", all[0].Checks)
	}
}

// 跨设备取最差：任一设备 block 则用户判定 block；账号规范化匹配。
func TestPostureVerdictWorstAcrossDevices(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_ = s.SavePostureReport(ctx, rep("li.fang", "DEV-A", "allow", 0, 300))
	_ = s.SavePostureReport(ctx, rep("li.fang", "DEV-B", "block", 25, 100))
	v, found, err := s.PostureVerdict(ctx, "  Li.Fang ") // 规范化匹配
	if err != nil || !found || v.Verdict != "block" || v.Device != "DEV-B" {
		t.Fatalf("最差应为 DEV-B block: %+v %v %v", v, found, err)
	}
	if _, found, _ := s.PostureVerdict(ctx, "ghost"); found {
		t.Fatal("无报告账号应 found=false")
	}
	pd, found, _ := s.PostureReportFor(ctx, "li.fang", "DEV-A")
	if !found || pd.Verdict != "allow" {
		t.Fatalf("单设备读取: %+v", pd)
	}
	blocked, _ := s.PostureBlockedUsers(ctx)
	if len(blocked) != 1 || blocked[0] != "li.fang" {
		t.Fatalf("blocked 名单: %v", blocked)
	}
}
