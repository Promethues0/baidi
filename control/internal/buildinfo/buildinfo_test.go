package buildinfo

import "testing"

// TestNotInjectedIsEmptyNotAGuess 未注入必须是**空串**，不是任何猜出来的值。
//
// 这条看起来像在测常量，但它守的是本次改造的全部意义：改造前控制面版本是
// `const Version = "0.3.0"`，而 `-ldflags -X` 对常量静默无效——于是任何一个
// go run 起来的进程都自称 0.3.0，升级判定拿着它一本正经地比大小。
// 哪天有人"顺手给个默认值"（"dev" / "0.0.0" / "unknown"），这条会红。
func TestNotInjectedIsEmptyNotAGuess(t *testing.T) {
	// 单测二进制不带 -ldflags，所以此刻三个值就是源码缺省。
	i := Current()
	if i.Semantic != "" || i.Commit != "" || i.BuiltAt != "" {
		t.Fatalf("未注入时三项都必须是空串（不可判定），得到 %+v", i)
	}
	if i.Injected() {
		t.Error("空语义版本不能算「已注入」")
	}
	if i.BuildID() != "" {
		t.Errorf("BuildID 是机读形式，什么都不知道时必须回空串，得到 %q", i.BuildID())
	}
}

// TestBuildIDVsBuildText 机读与展示两种形式的**区别**就是这条纪律本身。
//
// BuildText 在两半都缺时吐「未注入」三个字，那是给人看的；
// 一旦它被误用在上报/落库路径上，下游就再也分不出「对面说它不知道」与
// 「对面报了一个叫『未注入』的构建号」——后者会被当成一个真实的构建标识存起来。
func TestBuildIDVsBuildText(t *testing.T) {
	empty := Info{}
	if empty.BuildText() != NotInjected {
		t.Errorf("展示形式在两半都缺时应说「%s」，得到 %q", NotInjected, empty.BuildText())
	}
	if empty.BuildID() != "" {
		t.Errorf("机读形式必须回空串，得到 %q", empty.BuildID())
	}

	// 半缺席：如实只显示已知的那半，不整体折成"未注入"——
	// 折掉的话，一个只注了 commit 的二进制在页面上会显示成完全不可判定。
	onlyCommit := Info{Commit: "a9ae190"}
	if got := onlyCommit.BuildText(); got != "a9ae190" {
		t.Errorf("只有 commit 时应只显示它，得到 %q", got)
	}
	if got := onlyCommit.BuildID(); got != "a9ae190" {
		t.Errorf("只有 commit 时机读形式也该有值，得到 %q", got)
	}
	onlyTime := Info{BuiltAt: "2026-09-10T00:00:00Z"}
	if got := onlyTime.BuildText(); got != "2026-09-10T00:00:00Z" {
		t.Errorf("只有构建时间时应只显示它，得到 %q", got)
	}

	full := Info{Commit: "a9ae190", BuiltAt: "2026-09-10T00:00:00Z"}
	if got := full.BuildID(); got != "a9ae190 · 2026-09-10T00:00:00Z" {
		t.Errorf("两半齐全时应拼在一起，得到 %q", got)
	}
}

// TestSemanticTextOnlyForDisplay 语义版本的展示兜底同理：机读字段读 Semantic，
// 「未注入」三个字只出现在 SemanticText。
func TestSemanticTextOnlyForDisplay(t *testing.T) {
	if got := (Info{}).SemanticText(); got != NotInjected {
		t.Errorf("未注入时展示文案应是「%s」，得到 %q", NotInjected, got)
	}
	if got := (Info{Semantic: "0.4.0"}).SemanticText(); got != "0.4.0" {
		t.Errorf("已注入时应原样显示，得到 %q", got)
	}
}

// TestNoteTellsHowToFix 「未注入」这句话必须能指导下一步动作。
// 只说"未注入"而不说怎么才能有，管理员唯一的选择是绕过这道校验。
func TestNoteTellsHowToFix(t *testing.T) {
	for _, want := range []string{"build.sh", "VERSION"} {
		if !contains(Note, want) {
			t.Errorf("处置说明里应提到 %q：%s", want, Note)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
