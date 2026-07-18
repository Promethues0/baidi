package store

import (
	"context"
	"testing"
)

// openTestStore 复用 credential_test.go 的 helper。

// 首启种子灌库；Security() 的 baselines 走库、Spa 走种子。
func TestBaselinesSeededAndSecurityOverride(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	bls, err := s.Baselines(ctx)
	if err != nil || len(bls) != 2 {
		t.Fatalf("种子基线应有 2 条: %v %v", len(bls), err)
	}
	sec, err := s.Security(ctx)
	if err != nil || len(sec.Baselines) != 2 || sec.Spa.Generation == "" {
		t.Fatalf("Security 应库读 baselines + 种子 Spa: %+v %v", sec, err)
	}
}

// Save upsert（新建生成 id / 修改覆盖）+ Delete；改动后 Baselines 反映库态而非种子。
func TestSaveDeleteBaseline(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	nb, err := s.SaveBaseline(ctx, BaselinePolicy{Name: "外包收紧基线", Type: "onboarding", Disposal: "block", Status: "enabled",
		Platforms: []string{"macOS"}, Checks: []BaselineCheck{{Key: "disk_encrypted", Label: "磁盘已加密", Platform: "All", Severity: "high"}}})
	if err != nil || nb.ID == "" {
		t.Fatalf("save new: %+v %v", nb, err)
	}
	nb.Disposal = "gray"
	if _, err := s.SaveBaseline(ctx, nb); err != nil {
		t.Fatalf("update: %v", err)
	}
	bls, _ := s.Baselines(ctx)
	if len(bls) != 3 {
		t.Fatalf("应 3 条, got %d", len(bls))
	}
	var found bool
	for _, b := range bls {
		if b.ID == nb.ID && b.Disposal == "gray" {
			found = true
		}
	}
	if !found {
		t.Fatal("update 未生效")
	}
	if err := s.DeleteBaseline(ctx, nb.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if bls, _ = s.Baselines(ctx); len(bls) != 2 {
		t.Fatalf("删后应 2 条, got %d", len(bls))
	}
}
