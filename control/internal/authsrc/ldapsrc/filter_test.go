package ldapsrc

import "testing"

func TestEscapeFilterValue(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"普通字符原样保留", "alice", "alice"},
		{"反斜杠", `a\b`, `a\5cb`},
		{"左括号", "a(b", `a\28b`},
		{"右括号", "a)b", `a\29b`},
		{"星号", "a*b", `a\2ab`},
		{"NUL", "a\x00b", `a\00b`},
		{"经典注入载荷", "*)(uid=*", `\2a\29\28uid=\2a`},
		{"全通配", "*", `\2a`},
		{"反斜杠必须先于其它字符被处理，不能出现二次转义", `\2a`, `\5c2a`},
		{"UTF-8 中文按字节遍历也不会被切坏", "张三", "张三"},
		{"UTF-8 与特殊字符混排", "张*三", `张\2a三`},
		{"空串", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := escapeFilterValue(c.in); got != c.want {
				t.Fatalf("escapeFilterValue(%q) = %q，期望 %q", c.in, got, c.want)
			}
		})
	}
}

// TestEscapeFilterValue_反斜杠不会被二次转义 单独拎出来说明理由：
// 若实现里先把 ( 换成 \28、再统一把 \ 换成 \5c，`(` 就会变成 `\5c28`——
// 那是字面量 "\28" 三个字符，语义已经错了。逐字节 switch 天然不会有这个问题，
// 但这个用例守着"以后谁都别改成两轮 ReplaceAll"。
func TestEscapeFilterValue_反斜杠不会被二次转义(t *testing.T) {
	if got := escapeFilterValue("("); got != `\28` {
		t.Fatalf("escapeFilterValue(\"(\") = %q，期望 %q", got, `\28`)
	}
}

func TestRenderUserFilter(t *testing.T) {
	tmpl := "(&(objectClass=person)(uid=" + usernamePlaceholder + "))"
	got := renderUserFilter(tmpl, "*)(uid=*")
	want := `(&(objectClass=person)(uid=\2a\29\28uid=\2a))`
	if got != want {
		t.Fatalf("renderUserFilter = %q，期望 %q", got, want)
	}
}

// TestRenderUserFilter_不会二次展开占位符：用户名里写着字面量 {{username}} 时，
// 不能被再替换一轮（否则就是模板注入）。
func TestRenderUserFilter_不会二次展开占位符(t *testing.T) {
	tmpl := "(uid=" + usernamePlaceholder + ")"
	got := renderUserFilter(tmpl, usernamePlaceholder)
	want := "(uid=" + usernamePlaceholder + ")"
	if got != want {
		t.Fatalf("renderUserFilter = %q，期望 %q（占位符只应展开一轮）", got, want)
	}
}

// TestFilter注入_不转义会改写语义_转义后不会 是本包最重要的一个用例。
//
// 它同时证明两件事：
//
//	① 求值器**确实**会被未转义的载荷骗到（否则"转义后不匹配"什么也证明不了，
//	   因为可能只是求值器太弱、对什么都不匹配）；
//	② 经 renderUserFilter 转义之后，同一个载荷退化成一个普通的字面值，匹配不到任何人。
func TestFilter注入_不转义会改写语义_转义后不会(t *testing.T) {
	tmpl := "(&(objectClass=person)(uid=" + usernamePlaceholder + "))"
	alice := map[string][]string{
		"objectClass": {"person"},
		"uid":         {"alice"},
	}

	for _, payload := range []string{"*", "*)(uid=*", "*)(|(uid=*"} {
		t.Run(payload, func(t *testing.T) {
			// ① 故意用"未转义拼接"这种写法复现漏洞形态。
			vulnerable := naiveRender(tmpl, payload)
			vf, err := parseTestFilter(vulnerable)
			if err != nil {
				// 有些载荷拼出来括号不配对，解析不了——那也是一种"没被利用成功"，
				// 但至少要有一个载荷能真的骗过求值器，见循环末尾的整体断言。
				t.Logf("未转义过滤器 %q 解析失败（该载荷未构成可利用形态）: %v", vulnerable, err)
			} else if !vf.eval(alice) {
				t.Logf("未转义过滤器 %q 未命中 alice（该载荷未构成可利用形态）", vulnerable)
			} else {
				t.Logf("已复现：未转义过滤器 %q 命中了 alice", vulnerable)
			}

			// ② 转义之后必须匹配不到任何人。
			safe := renderUserFilter(tmpl, payload)
			sf, err := parseTestFilter(safe)
			if err != nil {
				t.Fatalf("转义后的过滤器 %q 应当仍是合法过滤器: %v", safe, err)
			}
			if sf.eval(alice) {
				t.Fatalf("★LDAP 注入未被挡住：转义后的过滤器 %q 仍然命中了 alice", safe)
			}
		})
	}

	// 至少要有一个载荷在"不转义"的情况下真的能命中，否则本用例的对照组是无效的。
	hit := false
	for _, payload := range []string{"*", "*)(uid=*"} {
		if f, err := parseTestFilter(naiveRender(tmpl, payload)); err == nil && f.eval(alice) {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatal("对照组失效：没有任何未转义载荷命中 alice，说明求值器过弱，本用例证明不了转义有效")
	}
}

// naiveRender 是**故意写错**的实现，只在测试里存在，用作漏洞对照组。
func naiveRender(tmpl, username string) string {
	out := ""
	for i := 0; i < len(tmpl); {
		if len(tmpl)-i >= len(usernamePlaceholder) && tmpl[i:i+len(usernamePlaceholder)] == usernamePlaceholder {
			out += username
			i += len(usernamePlaceholder)
			continue
		}
		out += string(tmpl[i])
		i++
	}
	return out
}

// TestMatchAssertion_转义星号不是通配符 守着求值器自身的正确性：
// `\2a` 必须被当成字面 '*'，而不是通配。这个搞错了，注入用例就会因为
// 完全错误的理由通过（见 matchAssertion 的注释）。
func TestMatchAssertion_转义星号不是通配符(t *testing.T) {
	if matchAssertion(`\2a`, "alice") {
		t.Fatal("★求值器把转义的 \\2a 当成了通配符，注入用例将失去意义")
	}
	if !matchAssertion(`\2a`, "*") {
		t.Fatal("求值器应当把 \\2a 匹配到字面量 *")
	}
	if !matchAssertion("*", "alice") {
		t.Fatal("求值器应当把未转义的 * 当成通配符")
	}
	if !matchAssertion("al*e", "alice") {
		t.Fatal("求值器应当支持前后缀通配")
	}
	if matchAssertion("al*e", "bob") {
		t.Fatal("求值器不应把 al*e 匹配到 bob")
	}
}
