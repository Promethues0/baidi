package darkfw

import (
	"os"
	"testing"
)

func osGeteuid() int { return os.Geteuid() }

// ── wave8 行动 7：规则集探测的解析 ──
//
// 这两个解析器是「规则集保护的是不是本网关那个端口」这道判定的全部依据。
// setup 脚本的 PROXY_PORT 默认 18443，而网关可以 -proxy 换端口——规则集装得
// 好好的、保护的却是另一个端口，隧道口照样全世界可见，两侧都不报错。

// TestParseNftDropPort 从 `nft list table inet baidi` 的真实输出里取默认 DROP 端口。
func TestParseNftDropPort(t *testing.T) {
	// baidi-nft.sh setup 之后 nft 的实际输出形状。
	const out = `table inet baidi {
	set baidi_allowed {
		type ipv4_addr
		flags interval
	}

	chain input {
		type filter hook input priority -10; policy accept;
		udp dport 18201 accept
		tcp dport 18443 ip saddr @baidi_allowed accept
		tcp dport 18443 drop
	}
}`
	got := parseNftDropPort(out)
	if got == nil {
		t.Fatal("应解析出被保护的端口")
	}
	if *got != 18443 {
		t.Fatalf("应为 18443，得到 %d", *got)
	}
}

// TestParseNftDropPortNonDefault 换过端口的规则集同样解析得出——
// 这条正是端口错配那道判定要能工作的前提。
func TestParseNftDropPortNonDefault(t *testing.T) {
	const out = `table inet baidi {
	chain input {
		tcp dport 19443 ip saddr @baidi_allowed accept
		tcp dport 19443 drop
	}
}`
	got := parseNftDropPort(out)
	if got == nil || *got != 19443 {
		t.Fatalf("应为 19443，得到 %v", got)
	}
}

// TestParseNftDropPortAbsent 只有 accept 没有 drop（规则集被改残了）→ **回 nil**。
//
// ★绝不猜一个默认值：猜 18443 恰好会在「脚本用默认端口、网关换了端口」这个
// 最需要报警的组合上给出"一切正常"。
func TestParseNftDropPortAbsent(t *testing.T) {
	for _, out := range []string{
		"table inet baidi {\n\tchain input {\n\t\ttcp dport 18443 ip saddr @baidi_allowed accept\n\t}\n}",
		"", "table inet baidi { }",
	} {
		if got := parseNftDropPort(out); got != nil {
			t.Errorf("没有 drop 规则时应回 nil（不可判定），得到 %d；输入 %q", *got, out)
		}
	}
}

// TestParsePfDropPort pf 的 `pfctl -a baidi-gw -sr` 输出。
func TestParsePfDropPort(t *testing.T) {
	const out = `block drop in quick proto tcp from any to any port = 18443
pass in quick proto tcp from <baidi_allowed> to any port = 18443 flags S/SA keep state
pass in quick proto udp from any to any port = 18201 keep state`
	got := parsePfDropPort(out)
	if got == nil || *got != 18443 {
		t.Fatalf("应为 18443，得到 %v", got)
	}
}

// TestParsePfDropPortIgnoresPassRules 只认 block drop 那条：
// pass 规则的端口相同是巧合，不能拿它当"被保护"的证据。
func TestParsePfDropPortIgnoresPassRules(t *testing.T) {
	const out = `pass in quick proto tcp from <baidi_allowed> to any port = 18443 keep state
pass in quick proto udp from any to any port = 18201 keep state`
	if got := parsePfDropPort(out); got != nil {
		t.Fatalf("没有 block drop 规则时应回 nil，得到 %d", *got)
	}
}

// TestProbeReportsBackendAndRoot 后端与 root 态必须如实上报——
// 控制面靠这两格区分「没开」「探不到」「真生效」。
//
// ★这里刻意**不断言 Ruleset**：它取决于跑测试这台机器上有没有装规则集、
// 是不是 root。断言它等于在断言运行环境，而不是在断言代码
// （本机非 root 时它恒为 nil，测试会因为"碰巧"而绿——CI 上以 root 跑就红了）。
// 规则集判定的真正覆盖在上面四条解析用例与控制面侧的 stealth_test.go。
func TestProbeReportsBackendAndRoot(t *testing.T) {
	for _, wanted := range []bool{true, false} {
		st := Probe(wanted)
		if st.Wanted != wanted {
			t.Fatalf("Wanted 应如实反映入参 %v", wanted)
		}
		if st.Backend != Backend() {
			t.Fatalf("Backend 应与 darkfw.Backend() 一致，得到 %q", st.Backend)
		}
		if st.Root != (osGeteuid() == 0) {
			t.Fatalf("Root 应如实反映当前进程，得到 %v", st.Root)
		}
		// 非 root 时必须说明为什么探不到，而不是默默留空。
		if !st.Root && Available() && st.Detail == "" {
			t.Fatal("非 root 探不到时要给出原因，否则控制面只能显示一个空白的「不可判定」")
		}
	}
}
