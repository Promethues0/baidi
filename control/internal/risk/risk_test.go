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

// unk 探不到（命令缺失/权限不足）：客户端把 OK 置 false 但打上 Unknown。
func unk(key string) store.PostureCheckResult {
	return store.PostureCheckResult{Key: key, Label: "检查-" + key, OK: false, Unknown: true}
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
		opts     Options
		want     Verdict
	}{
		{"全部通过", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health}, Options{},
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}, Unknowns: []string{}}},
		{"高危失败触发 block 且 level 强制 high", "macOS", []store.PostureCheckResult{bad("disk"), ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health}, Options{},
			Verdict{Score: 25, Level: "high", Disposal: "block", Reasons: []string{"检查-disk 未通过"}, Unknowns: []string{}}},
		{"降权基线失败只 degrade", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), bad("fw"), bad("edr")},
			[]store.BaselinePolicy{admission, health}, Options{},
			Verdict{Score: 15, Level: "low", Disposal: "degrade", Reasons: []string{"检查-fw 未通过", "检查-edr 未通过"}, Unknowns: []string{}}},
		{"缺失 key 视为失败", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), ok("edr")},
			[]store.BaselinePolicy{admission, health}, Options{},
			Verdict{Score: 10, Level: "low", Disposal: "degrade", Reasons: []string{"检查-fw（未上报）"}, Unknowns: []string{}}},
		{"平台不匹配的基线/检查跳过", "Windows", []store.PostureCheckResult{ok("disk")},
			[]store.BaselinePolicy{admission, health}, Options{}, // health 只适用 macOS；sip 只适用 macOS
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}, Unknowns: []string{}}},
		{"停用基线跳过", "macOS", []store.PostureCheckResult{bad("disk")},
			[]store.BaselinePolicy{bl("b-off", "block", "disabled", nil, chk("disk", "All", "high"))}, Options{},
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}, Unknowns: []string{}}},
		{"空 Platforms 视为全平台适用", "Linux", []store.PostureCheckResult{bad("disk")},
			[]store.BaselinePolicy{bl("b-any", "gray", "enabled", nil, chk("disk", "All", "medium"))}, Options{},
			Verdict{Score: 10, Level: "low", Disposal: "gray", Reasons: []string{"检查-disk 未通过"}, Unknowns: []string{}}},

		// ── 不可判定（Unknown）──
		// observe：探不到 ≠ 不合规。若塌缩成 false，一台 Linux 非 root 终端（读不到防火墙状态）
		// 会被 block 基线永久拒之门外，而管理台上看不出任何异常。
		{"observe：不可判定不抬处置、不计分，只单列", "macOS",
			[]store.PostureCheckResult{unk("disk"), ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health}, Options{},
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}, Unknowns: []string{"检查-disk（无法判定）"}}},
		// strict：说不清楚就不放行，与「缺报即拒」同口径。
		{"strict：不可判定视为不合规", "macOS",
			[]store.PostureCheckResult{unk("disk"), ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health}, Options{StrictUnknown: true},
			Verdict{Score: 25, Level: "high", Disposal: "block",
				Reasons: []string{"检查-disk（无法判定，strict 视为不合规）"}, Unknowns: []string{}}},
		// Unknown 优先于 OK：客户端探不到时 OK 恒 false，先看 OK 就会退化回"不可判定=不合规"。
		{"Unknown 与 OK=true 并存时按不可判定处理", "macOS",
			[]store.PostureCheckResult{{Key: "disk", Label: "检查-disk", OK: true, Unknown: true}, ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health}, Options{},
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}, Unknowns: []string{"检查-disk（无法判定）"}}},
		// 缺报（key 根本没出现）仍是失败，不因引入 Unknown 而放松——否则选择性上报即可逃逸。
		{"缺报仍视为失败（区别于不可判定）", "macOS",
			[]store.PostureCheckResult{ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health}, Options{},
			Verdict{Score: 25, Level: "high", Disposal: "block", Reasons: []string{"检查-disk（未上报）"}, Unknowns: []string{}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(c.platform, c.checks, c.bls, c.opts)
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
	v := Evaluate("macOS", reported, []store.BaselinePolicy{bl("b", "degrade", "enabled", nil, checks...)}, Options{})
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

// 处置严厉度排序：block > degrade > gray > allow。
//
// ★gray 排在 degrade **之下**（此前是反的）。四档都有执行方之后这个顺序有了实际后果：
// 一台同时命中「gray 基线」与「degrade 基线」的终端，若 gray 更严就会被判成 gray，
// 高敏资源的收缩于是静默失效——而 gray 的语义恰恰是"什么都不改，只观察"。
func TestDisposalRank(t *testing.T) {
	if !(DisposalRank("block") > DisposalRank("degrade") &&
		DisposalRank("degrade") > DisposalRank("gray") &&
		DisposalRank("gray") > DisposalRank("allow")) {
		t.Fatal("disposal 排序应为 block > degrade > gray > allow")
	}
}

// 同一终端命中两条基线（gray + degrade）时必须取 degrade：
// 取 gray 就等于"命中了降权基线却什么都没降"，且页面上完全看不出来。
func TestEvaluate_DegradeWinsOverGray(t *testing.T) {
	grayCheck := store.BaselineCheck{Key: "firewall_on", Label: "防火墙已开启", Platform: "All", Severity: "low"}
	degCheck := store.BaselineCheck{Key: "sys_integrity", Label: "系统完整性保护", Platform: "All", Severity: "medium"}
	v := Evaluate("macOS", nil, []store.BaselinePolicy{
		bl("gray-bl", "gray", "enabled", nil, grayCheck),
		bl("deg-bl", "degrade", "enabled", nil, degCheck),
	}, Options{})
	if v.Disposal != store.DisposalDegrade {
		t.Fatalf("gray + degrade 同时命中应取 degrade，got %s", v.Disposal)
	}
}
