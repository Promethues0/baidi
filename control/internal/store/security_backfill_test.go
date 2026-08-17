package store

import (
	"context"
	"testing"
)

// ── client_version 检测项文案的一次性回填（wave8 行动 2）──
//
// ★这是「改种子只影响全新库」这条坑的又一次实例。行为改成了「控制面按灰度稳定版判」，
// 而既有部署（含在线演示站）里那一行是首启时落库的，此后没有任何 UPDATE——
// 页面上仍写着「客户端为最新版本 / ≥ v0.1.0」，两句话现在都是假的：
// 判据既不是「最新」，也不是 v0.1.0。
//
// 与 CLAUDE.md 记的「补列迁移必须配回填」是同一条纪律，只是这次踩在种子行的
// **语义**上而不是新列上——而这一种更隐蔽：列是有的、值也不是 NULL，只是含义变了。

// TestSeedClientVersionCheckLabel 全新库不经回填路径（seed 直接写值），单独钉一次。
func TestSeedClientVersionCheckLabel(t *testing.T) {
	s := openTestStore(t)
	spec, ok := CheckSpecOf(CheckKeyClientVersion)
	if !ok {
		t.Fatal("采集目录里没有 client_version")
	}
	n := 0
	for _, b := range must(s.Baselines(context.Background()))(t) {
		for _, c := range b.Checks {
			if c.Key != CheckKeyClientVersion {
				continue
			}
			n++
			if c.Label != spec.Label || c.Expect != spec.Expect {
				t.Fatalf("种子里的 client_version 文案与采集目录不一致：label=%q expect=%q（目录 %q / %q）",
					c.Label, c.Expect, spec.Label, spec.Expect)
			}
		}
	}
	if n == 0 {
		t.Fatal("种子基线里没有 client_version 检测项，本用例的前提不成立")
	}
}

// TestBackfillClientVersionCheckLabel 模拟既有部署：那一行还是旧文案、标记也还没写。
func TestBackfillClientVersionCheckLabel(t *testing.T) {
	s := openTestStore(t)
	// 退回旧库形态：把文案改回旧种子的字面值 + 清掉一次性标记
	setClientVersionText(t, s, "客户端为最新版本", "≥ v0.1.0")
	if _, err := s.db.Exec(`DELETE FROM settings WHERE k=?`, clientVersionLabelMarker); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillClientVersionCheckLabel(); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	spec, _ := CheckSpecOf(CheckKeyClientVersion)
	gotLabel, gotExpect := readClientVersionText(t, s)
	if gotLabel != spec.Label {
		t.Fatalf("label 没被回填：%q（应为 %q）——既有部署会一直显示「客户端为最新版本」，而判据根本不是「最新」",
			gotLabel, spec.Label)
	}
	if gotExpect != spec.Expect {
		t.Fatalf("expect 没被回填：%q（应为 %q）——v0.1.0 不是真实判据", gotExpect, spec.Expect)
	}
	// 一次性：标记写上后不再跑。管理员之后自己改的文案不该被下次启动覆盖回去。
	setClientVersionText(t, s, "运维自定义文案", "自定义期望")
	if err := s.backfillClientVersionCheckLabel(); err != nil {
		t.Fatalf("二次 backfill: %v", err)
	}
	if l, _ := readClientVersionText(t, s); l != "运维自定义文案" {
		t.Fatalf("回填不是一次性的：第二次跑又把文案改了（%q）", l)
	}
}

// TestBackfillClientVersionKeepsAdminEdits 回填修的是历史遗留，不是把配置拉回出厂设置。
func TestBackfillClientVersionKeepsAdminEdits(t *testing.T) {
	s := openTestStore(t)
	const custom = "客户端版本（我们自己的说法）"
	setClientVersionText(t, s, custom, "由运维统一约定")
	if _, err := s.db.Exec(`DELETE FROM settings WHERE k=?`, clientVersionLabelMarker); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillClientVersionCheckLabel(); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if l, e := readClientVersionText(t, s); l != custom || e != "由运维统一约定" {
		t.Fatalf("管理员改过的文案被回填覆盖了：label=%q expect=%q", l, e)
	}
}

func setClientVersionText(t *testing.T, s *SQLiteStore, label, expect string) {
	t.Helper()
	ctx := context.Background()
	for _, b := range must(s.Baselines(ctx))(t) {
		hit := false
		for i := range b.Checks {
			if b.Checks[i].Key == CheckKeyClientVersion {
				b.Checks[i].Label, b.Checks[i].Expect, hit = label, expect, true
			}
		}
		if hit {
			if _, err := s.SaveBaseline(ctx, b); err != nil {
				t.Fatalf("SaveBaseline: %v", err)
			}
			return
		}
	}
	t.Fatal("找不到含 client_version 的基线")
}

func readClientVersionText(t *testing.T, s *SQLiteStore) (label, expect string) {
	t.Helper()
	for _, b := range must(s.Baselines(context.Background()))(t) {
		for _, c := range b.Checks {
			if c.Key == CheckKeyClientVersion {
				return c.Label, c.Expect
			}
		}
	}
	t.Fatal("回填后 client_version 检测项不见了")
	return "", ""
}

// must 把 (值, error) 收成一个取值函数，省掉每次三行的错误处理。
func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}
