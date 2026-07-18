package store

import (
	"context"
	"testing"
	"time"
)

// userstate 覆盖：真实 users × posture 判定；种子目录含 zhao.min(locked)/ext.zhou(disabled)。
func TestUserStatesReal(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	// li.fang 一台设备 block（高风险）；目录外账号的报告忽略不进清单
	_ = s.SavePostureReport(ctx, PostureReport{User: "li.fang", Device: "DEV-A", Platform: "macOS",
		Verdict: "block", Score: 25, Level: "high", Reasons: []string{"磁盘已加密"}, TS: now})

	b, err := s.UserStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byAcc := map[string]UserStateItem{}
	for _, it := range b.Items {
		byAcc[it.Account] = it
	}
	if it := byAcc["li.fang"]; it.State != "risk-high" || it.Risk != "high" || len(it.Reasons) == 0 {
		t.Fatalf("li.fang 应 risk-high: %+v", it)
	}
	if it := byAcc["zhao.min"]; it.State != "locked" {
		t.Fatalf("zhao.min 应 locked: %+v", it)
	}
	if it := byAcc["ext.zhou"]; it.State != "disabled" {
		t.Fatalf("ext.zhou 应 disabled: %+v", it)
	}
	if _, ok := byAcc["admin"]; ok {
		t.Fatal("正常无报告用户不应进清单")
	}
	byKey := map[string]int{}
	for _, bk := range b.Buckets {
		byKey[bk.Key] = bk.Count
	}
	if byKey["risk-high"] != 1 || byKey["locked"] != 1 || byKey["disabled"] != 1 || byKey["idle"] != 0 {
		t.Fatalf("分桶: %v", byKey)
	}
}

// overview：posture 高危并入账号防线 TOP；终端防线用最差报告真实化。
func TestOverviewWithPosture(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_ = s.SavePostureReport(ctx, PostureReport{User: "li.fang", Device: "DEV-A", Platform: "macOS",
		Verdict: "block", Score: 25, Level: "high", Reasons: []string{"磁盘已加密"}, TS: time.Now().Unix()})
	ov, err := s.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var accTop, epTop []string
	var epRisk int
	for _, d := range ov.Defense {
		if d.Key == "account" {
			accTop = d.Top
		}
		if d.Key == "endpoint" {
			epTop, epRisk = d.Top, d.Risk
		}
	}
	if !containsStr(accTop, "li.fang") {
		t.Fatalf("账号防线 TOP 应含 posture 高危 li.fang: %v", accTop)
	}
	if len(epTop) == 0 || epRisk != 25 {
		t.Fatalf("终端防线应由最差报告真实化: top=%v risk=%d", epTop, epRisk)
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
