package kernelfwd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestParseFlagIsTriState 钉住本包唯一的判据：**只有 "0" 和 "1" 是结论**。
//
// ★这条用例值钱的地方是那批"看起来像 0"的输入。写成 `strings.TrimSpace(s) == "1"`
// 的实现会把空串、"true"、"disabled" 全部判成 false，也就是斩钉截铁地宣称
// 「这台机器的转发关着」——而真实情况是我们**根本没读到值**（procfs 被容器屏蔽、
// 挂了个空文件、sysctl 换了输出格式）。虚警的代价很具体：运维会去开一个
// 本来就开着的开关，然后回来说"这功能在骗人"。
func TestParseFlagIsTriState(t *testing.T) {
	for _, c := range []struct {
		in       string
		wantVal  bool
		wantKnow bool
	}{
		{"1", true, true},
		{"1\n", true, true},
		{" 1 \n", true, true},
		{"0", false, true},
		{"0\n", false, true},
		// 以下每一条都必须是「不可判定」，不是 false。
		{"", false, false},
		{"\n", false, false},
		{"true", false, false},
		{"net.inet.ip.forwarding: 1", false, false}, // sysctl 换成带名字的格式
		{"2", false, false},
		{"01", false, false},
	} {
		got, known := parseFlag(c.in)
		if got != c.wantVal || known != c.wantKnow {
			t.Fatalf("parseFlag(%q) = (%v,%v)，期望 (%v,%v)", c.in, got, known, c.wantVal, c.wantKnow)
		}
	}
}

// TestProbeProcTriState 用真实文件跑一遍 IO 那一层。
func TestProbeProcTriState(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	on, detail := probeProc(write("on", "1\n"))
	if on == nil || !*on || detail != "" {
		t.Fatalf("读到 1 应判为开启且无异常说明，得到 %v / %q", on, detail)
	}
	off, detail := probeProc(write("off", "0\n"))
	if off == nil || *off || detail != "" {
		t.Fatalf("读到 0 应判为关闭，得到 %v / %q", off, detail)
	}

	// 文件不存在：必须是 nil + 说得出原因。
	// ★「不可判定不带原因等于没说」——回执要指导下一步动作，光说"不知道"没用。
	missing, detail := probeProc(filepath.Join(dir, "nope"))
	if missing != nil {
		t.Fatalf("读不到文件时必须回 nil（不可判定），得到 %v", *missing)
	}
	if detail == "" {
		t.Fatal("读不到时必须给出原因，否则控制台上只会显示一句无从下手的「不可判定」")
	}

	// 内容认不出来：同样是 nil，且原因里要带上实际内容（否则没人知道该去看什么）。
	bad, detail := probeProc(write("bad", "yes"))
	if bad != nil {
		t.Fatalf("内容认不出来时必须回 nil，得到 %v", *bad)
	}
	if detail == "" {
		t.Fatal("内容认不出来时必须给出原因")
	}
}

// TestProbeNeverPanicsAndReportsPlatform 在**本机**真跑一次。
//
// 不断言 v4/v6 的具体值（开发机与 CI 上都可能是任意值），只断言两件事：
// 不炸，且平台名对得上。真跑的价值是覆盖 darwin 的 exec 分支——
// 那一支只活在 runtime.GOOS 判断里，不真跑就永远没被执行过。
func TestProbeNeverPanicsAndReportsPlatform(t *testing.T) {
	st := Probe()
	if st.Platform != runtime.GOOS {
		t.Fatalf("Platform=%q，期望 %q", st.Platform, runtime.GOOS)
	}
	switch runtime.GOOS {
	case "linux", "darwin":
		// 探不到时必须有 Detail；探到了 Detail 可以为空。
		if (st.V4 == nil || st.V6 == nil) && st.Detail == "" {
			t.Fatalf("有一格探不到（v4=%v v6=%v）却没有任何说明", st.V4, st.V6)
		}
	default:
		if st.V4 != nil || st.V6 != nil {
			t.Fatal("不支持的平台上不该凭空给出结论")
		}
		if st.Detail == "" {
			t.Fatal("不支持的平台必须说明「本平台读不到」")
		}
	}
}

// TestShortenBoundsErrorText 异常内容进错误文案前必须截短。
// 不截的话，一个被挂成大文件的 /proc 路径会把整段内容拼进日志与状态回报里。
func TestShortenBoundsErrorText(t *testing.T) {
	long := make([]byte, 4096)
	for i := range long {
		long[i] = 'x'
	}
	if got := shorten(string(long)); len(got) > 40 {
		t.Fatalf("shorten 未截断：长度 %d", len(got))
	}
	if shorten("   ") != "空" {
		t.Fatal("全空白应说成「空」，拼一段空串进文案等于没说")
	}
}
