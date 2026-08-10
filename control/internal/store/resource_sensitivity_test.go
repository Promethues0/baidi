package store

import (
	"context"
	"testing"
)

// 种子资源自带敏感度：财务核算系统 high，其余 normal。
// 全新库不经回填路径（seed 直接写值），故单独钉一次——种子写错的话，
// 降权在演示环境里对财务系统完全不生效，而页面上一切正常。
func TestSeedResourceSensitivity(t *testing.T) {
	s := openTestStore(t)
	rs, err := s.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rs {
		got[r.ID] = r.Sensitivity
	}
	if got["finance"] != SensitivityHigh {
		t.Fatalf("finance 应为 high，got %q", got["finance"])
	}
	if got["oa"] != SensitivityNormal || got["git"] != SensitivityNormal {
		t.Fatalf("oa/git 应为 normal：%v", got)
	}
}

// 补列迁移的回填：模拟"该列刚补上、既有行全为 NULL"的旧库。
//
// ★这正是 apps.resource_id 踩过的坑（只加列不填值）。这里额外要验的是第二步语义迁移：
// 改造前"高敏"的唯一来源是 apps.category='finance'，不迁的话升级后财务系统从高敏
// 变成普通资源——降权与门户审批双双对它失效，且没有任何报错。
func TestBackfillResourceSensitivity(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	// 退回旧库形态：清空该列 + 清掉一次性标记
	if _, err := s.db.Exec(`UPDATE resources SET sensitivity=NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM settings WHERE k=?`, sensBackfillMarker); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillResourceSensitivity(); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	rs, err := s.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		want := SensitivityNormal
		if r.ID == "finance" { // a2 财务核算系统 category=finance → resource_id=finance
			want = SensitivityHigh
		}
		if r.Sensitivity != want {
			t.Fatalf("资源 %s 回填应为 %s，got %q", r.ID, want, r.Sensitivity)
		}
	}
}

// 管理员重新评估过的值不能被下次启动的迁移拽回去。
// 没有这道一次性闸的话，症状是"改了敏感度、重启就变回 high"——
// 管理员看到的是自己的保存没生效，而保存接口明明返回了成功。
func TestBackfillResourceSensitivityRunsOnce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	fin, err := s.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range fin {
		if r.ID != "finance" {
			continue
		}
		r.Sensitivity = SensitivityNormal // 管理员重新评估：不再算高敏
		if err := s.SaveResource(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// 再跑一次迁移（等价于进程重启）
	if err := s.backfillResourceSensitivity(); err != nil {
		t.Fatal(err)
	}
	rs, _ := s.Resources(ctx)
	for _, r := range rs {
		if r.ID == "finance" && r.Sensitivity != SensitivityNormal {
			t.Fatalf("管理员的评估结论被迁移覆盖了：got %q", r.Sensitivity)
		}
	}
}

// 未知/空取值一律收敛到 normal，绝不收敛到 high。
// 收敛到 high 的话，一个拼写错误就能把整批资源对降级用户关掉，而页面上显示"已配置"。
func TestNormalizeSensitivity(t *testing.T) {
	for _, in := range []string{"", "High", "敏感", "unknown"} {
		if got := NormalizeSensitivity(in); got != SensitivityNormal {
			t.Fatalf("NormalizeSensitivity(%q) = %q，应为 normal", in, got)
		}
	}
	for _, in := range []string{SensitivityLow, SensitivityNormal, SensitivityHigh} {
		if got := NormalizeSensitivity(in); got != in {
			t.Fatalf("NormalizeSensitivity(%q) = %q", in, got)
		}
	}
	if !(Resource{Sensitivity: SensitivityHigh}).HighSensitivity() {
		t.Fatal("high 资源应判高敏")
	}
	for _, in := range []string{"", SensitivityLow, SensitivityNormal} {
		if (Resource{Sensitivity: in}).HighSensitivity() {
			t.Fatalf("%q 不应判高敏", in)
		}
	}
}

// 按处置档取名单：任一设备命中即计入，且与"跨设备取最差"口径一致。
func TestPostureUsersByDisposal(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.SavePostureReport(ctx, PostureReport{User: "li.fang", Device: "A", Platform: "macOS", Verdict: DisposalDegrade, TS: 100}))
	must(s.SavePostureReport(ctx, PostureReport{User: "li.fang", Device: "B", Platform: "macOS", Verdict: DisposalAllow, TS: 200}))
	must(s.SavePostureReport(ctx, PostureReport{User: "wang.qiang", Device: "C", Platform: "macOS", Verdict: DisposalGray, TS: 100}))

	deg, err := s.PostureUsersByDisposal(ctx, DisposalDegrade)
	if err != nil || len(deg) != 1 || deg[0] != "li.fang" {
		t.Fatalf("degrade 名单应只有 li.fang（一台干净机器洗不掉判定）：%v %v", deg, err)
	}
	gray, _ := s.PostureUsersByDisposal(ctx, DisposalGray)
	if len(gray) != 1 || gray[0] != "wang.qiang" {
		t.Fatalf("gray 名单: %v", gray)
	}
	// 跨设备取最差与名单同口径：li.fang 仍是 degrade
	worst, ok, _ := s.PostureVerdict(ctx, "li.fang")
	if !ok || worst.Verdict != DisposalDegrade {
		t.Fatalf("跨设备最差应为 degrade：%+v", worst)
	}
}
