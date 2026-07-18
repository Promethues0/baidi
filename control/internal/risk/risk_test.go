package risk

import (
	"reflect"
	"testing"

	"baidi.dev/control/internal/store"
)

func bl(id, disposal, status string, platforms []string, checks ...store.BaselineCheck) store.BaselinePolicy {
	return store.BaselinePolicy{ID: id, Name: id, Type: "onboarding", Disposal: disposal, Status: status, Platforms: platforms, Checks: checks}
}
func chk(key, platform, severity string) store.BaselineCheck {
	return store.BaselineCheck{Key: key, Label: "检查-" + key, Platform: platform, Severity: severity}
}
func ok(key string) store.PostureCheckResult {
	return store.PostureCheckResult{Key: key, Label: "检查-" + key, OK: true}
}
func bad(key string) store.PostureCheckResult {
	return store.PostureCheckResult{Key: key, Label: "检查-" + key, OK: false}
}

func TestEvaluate(t *testing.T) {
	admission := bl("b-adm", "block", "enabled", []string{"macOS", "Windows"},
		chk("disk", "All", "high"), chk("sip", "macOS", "high"))
	health := bl("b-health", "degrade", "enabled", []string{"macOS"},
		chk("fw", "All", "medium"), chk("edr", "All", "low"))

	cases := []struct {
		name     string
		platform string
		checks   []store.PostureCheckResult
		bls      []store.BaselinePolicy
		want     Verdict
	}{
		{"全部通过", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health},
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}}},
		{"高危失败触发 block 且 level 强制 high", "macOS", []store.PostureCheckResult{bad("disk"), ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health},
			Verdict{Score: 25, Level: "high", Disposal: "block", Reasons: []string{"检查-disk 未通过"}}},
		{"降权基线失败只 degrade", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), bad("fw"), bad("edr")},
			[]store.BaselinePolicy{admission, health},
			Verdict{Score: 15, Level: "low", Disposal: "degrade", Reasons: []string{"检查-fw 未通过", "检查-edr 未通过"}}},
		{"缺失 key 视为失败", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), ok("edr")},
			[]store.BaselinePolicy{admission, health},
			Verdict{Score: 10, Level: "low", Disposal: "degrade", Reasons: []string{"检查-fw（未上报）"}}},
		{"平台不匹配的基线/检查跳过", "Windows", []store.PostureCheckResult{ok("disk")},
			[]store.BaselinePolicy{admission, health}, // health 只适用 macOS；sip 只适用 macOS
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}}},
		{"停用基线跳过", "macOS", []store.PostureCheckResult{bad("disk")},
			[]store.BaselinePolicy{bl("b-off", "block", "disabled", nil, chk("disk", "All", "high"))},
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}}},
		{"空 Platforms 视为全平台适用", "Linux", []store.PostureCheckResult{bad("disk")},
			[]store.BaselinePolicy{bl("b-any", "gray", "enabled", nil, chk("disk", "All", "medium"))},
			Verdict{Score: 10, Level: "low", Disposal: "gray", Reasons: []string{"检查-disk 未通过"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(c.platform, c.checks, c.bls)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Evaluate() = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestScoreCapAndLevels(t *testing.T) {
	var checks []store.BaselineCheck
	var reported []store.PostureCheckResult
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		checks = append(checks, chk(k, "All", "high"))
		reported = append(reported, bad(k))
	}
	v := Evaluate("macOS", reported, []store.BaselinePolicy{bl("b", "degrade", "enabled", nil, checks...)})
	if v.Score != 100 { // 5×25 = 125 → cap 100
		t.Fatalf("score cap: got %d", v.Score)
	}
	if v.Level != "high" { // ≥60
		t.Fatalf("level: got %s", v.Level)
	}
	if v.Disposal != "degrade" {
		t.Fatalf("disposal: got %s", v.Disposal)
	}
}

func TestDisposalRank(t *testing.T) {
	if !(DisposalRank("block") > DisposalRank("gray") && DisposalRank("gray") > DisposalRank("degrade") && DisposalRank("degrade") > DisposalRank("allow")) {
		t.Fatal("disposal 排序应为 block > gray > degrade > allow")
	}
}
