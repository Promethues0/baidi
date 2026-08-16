package risk

import (
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── client_version：把「假绿」钉死 ──
//
// 采集器此前对这一项写死 Pass，于是终端合规页对跑三个版本以前客户端的机器也亮绿。
// 这一族用例守两件事：①判据真的在控制面（低于稳定版 = 不合规）；
// ②判不了的时候一律「无法判定」，**绝不回落成合规**——那正是要消灭的形态。

func checksWith(v store.PostureCheckResult) []store.PostureCheckResult {
	return []store.PostureCheckResult{
		{Key: "disk_encrypted", Label: "磁盘已加密", OK: true, Value: "on"},
		v,
	}
}

func findCheck(cs []store.PostureCheckResult, key string) (store.PostureCheckResult, bool) {
	for _, c := range cs {
		if c.Key == key {
			return c, true
		}
	}
	return store.PostureCheckResult{}, false
}

func TestResolveClientVersion(t *testing.T) {
	// 采集器现在报的形态：unknown + 原始版本号（本地判不了目标版本）。
	reportedByClient := store.PostureCheckResult{
		Key: store.CheckKeyClientVersion, Label: "客户端版本合规", OK: false, Unknown: true, Value: "0.1.0"}

	cases := []struct {
		name        string
		reported    string
		minVersion  string
		wantOK      bool
		wantUnknown bool
		wantInValue string
	}{
		{"低于稳定版即不合规", "0.1.0", "0.3.0", false, false, "低于要求的"},
		{"等于稳定版即合规", "0.3.0", "0.3.0", true, false, "≥"},
		{"高于稳定版（灰度批次）也合规", "0.4.0", "0.3.0", true, false, "≥"},
		{"带 v 前缀照样能比", "v0.4.0", "0.3.0", true, false, "≥"},
		{"预发布版低于同号正式版", "0.3.0-rc1", "0.3.0", false, false, "低于要求的"},
		// ★以下三条是本用例族的重点：判不了就必须是「无法判定」。
		// 任何一条回落成 OK=true，终端合规页就又开始替坏链路背书了。
		{"该平台没配稳定版 → 无法判定", "0.1.0", "", false, true, "无法判定"},
		{"终端没报版本 → 无法判定", "", "0.3.0", false, true, "无法判定"},
		{"版本号形态不合法 → 无法判定", "不是版本号", "0.3.0", false, true, "无法判定"},
		{"稳定版配错形态 → 无法判定", "0.1.0", "最新", false, true, "无法判定"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveClientVersion(checksWith(reportedByClient), tc.reported, tc.minVersion)
			c, ok := findCheck(got, store.CheckKeyClientVersion)
			if !ok {
				t.Fatal("重算后 client_version 这一项不见了")
			}
			if c.OK != tc.wantOK || c.Unknown != tc.wantUnknown {
				t.Fatalf("OK=%v Unknown=%v，期望 OK=%v Unknown=%v（值 %q）",
					c.OK, c.Unknown, tc.wantOK, tc.wantUnknown, c.Value)
			}
			if !strings.Contains(c.Value, tc.wantInValue) {
				t.Fatalf("展示值 %q 里应含 %q——用户与管理员要靠这句话知道为什么", c.Value, tc.wantInValue)
			}
			// 其余检查项一字不动：这个函数只该碰 client_version 这一格。
			if d, _ := findCheck(got, "disk_encrypted"); !d.OK || d.Unknown {
				t.Fatalf("其他检查项被改动了：%+v", d)
			}
		})
	}
}

// 客户端谎称自己合规（OK=true）时，控制面的重算必须**压过**它。
// 这条是整个改造的要害：判据在控制面，就不能让终端自报的那一格漏出来。
func TestResolveClientVersion_客户端自称合规也压不过控制面判定(t *testing.T) {
	lying := store.PostureCheckResult{
		Key: store.CheckKeyClientVersion, Label: "客户端为最新版本", OK: true, Value: "0.1.0"}
	got := ResolveClientVersion(checksWith(lying), "0.1.0", "0.3.0")
	c, _ := findCheck(got, store.CheckKeyClientVersion)
	if c.OK {
		t.Fatal("终端报 OK=true 就被采信 = 判据又回到了客户端手里，正是本次要消灭的形态")
	}
	if !strings.Contains(c.Value, "0.3.0") {
		t.Fatalf("展示值应点名要求的版本，实得 %q", c.Value)
	}
}

// 终端根本没报这一项时不要凭空造一格：那会把「客户端没报」洗成「控制面判过了」，
// 而 Evaluate 的「缺失即不合规」是防选择性上报的既有设计，不该被绕过去。
func TestResolveClientVersion_未上报该项则不补(t *testing.T) {
	only := []store.PostureCheckResult{{Key: "disk_encrypted", OK: true}}
	got := ResolveClientVersion(only, "0.1.0", "0.3.0")
	if _, ok := findCheck(got, store.CheckKeyClientVersion); ok {
		t.Fatal("终端没上报 client_version，不该由控制面补一格出来")
	}
	if len(got) != 1 {
		t.Fatalf("不该改变检查项数量，实得 %d 条", len(got))
	}
}

// 不改调用方持有的那份切片（handler 会把原始上报与重算结果分别用于不同用途）。
func TestResolveClientVersion_不原地改调用方切片(t *testing.T) {
	src := checksWith(store.PostureCheckResult{
		Key: store.CheckKeyClientVersion, OK: false, Unknown: true, Value: "0.1.0"})
	_ = ResolveClientVersion(src, "0.1.0", "0.3.0")
	c, _ := findCheck(src, store.CheckKeyClientVersion)
	if !c.Unknown || c.Value != "0.1.0" {
		t.Fatalf("原切片被改动了：%+v", c)
	}
}

// 端到端：重算结果真的进了 Evaluate 的判定，而不是只改了展示。
// 低于稳定版 → 该基线判违规 → 处置抬到基线声明的那一档。
func TestResolveClientVersion_进得了判定(t *testing.T) {
	bl := []store.BaselinePolicy{{
		ID: "bl", Name: "终端健康", Status: "enabled", Disposal: store.DisposalDegrade,
		Platforms: []string{"macOS"},
		Checks: []store.BaselineCheck{
			{Key: store.CheckKeyClientVersion, Label: "客户端版本合规", Platform: "All", Severity: "low"},
		},
	}}
	client := checksWith(store.PostureCheckResult{
		Key: store.CheckKeyClientVersion, OK: false, Unknown: true, Value: "0.1.0"})

	// 旧客户端 + 已配稳定版 → 不合规，处置抬到 degrade
	old := ResolveClientVersion(client, "0.1.0", "0.3.0")
	if v := Evaluate("macOS", old, bl, Options{}); v.Disposal != store.DisposalDegrade {
		t.Fatalf("低于稳定版应判违规并抬到 degrade，实得 %q（reasons=%v）", v.Disposal, v.Reasons)
	}
	// 新客户端 → 合规，不抬处置
	cur := ResolveClientVersion(client, "0.3.0", "0.3.0")
	if v := Evaluate("macOS", cur, bl, Options{}); v.Disposal != store.DisposalAllow {
		t.Fatalf("已达稳定版不该抬处置，实得 %q（reasons=%v）", v.Disposal, v.Reasons)
	}
	// 没配稳定版 → 无法判定：observe 下不计分不抬处置，但必须单列出来让人看见
	none := ResolveClientVersion(client, "0.1.0", "")
	v := Evaluate("macOS", none, bl, Options{})
	if v.Disposal != store.DisposalAllow || v.Score != 0 {
		t.Fatalf("observe 下「无法判定」不该计分/抬处置，实得 disposal=%q score=%d", v.Disposal, v.Score)
	}
	if len(v.Unknowns) == 0 {
		t.Fatal("「无法判定」必须进 Unknowns——不计分不等于可以不说")
	}
	// strict 下「说不清楚就不放行」：同一份输入要翻成违规
	if v := Evaluate("macOS", none, bl, Options{StrictUnknown: true}); v.Disposal != store.DisposalDegrade {
		t.Fatalf("strict 下无法判定应视为不合规，实得 %q", v.Disposal)
	}
}
