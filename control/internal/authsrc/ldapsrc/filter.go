package ldapsrc

import "strings"

// usernamePlaceholder 用户过滤器模板里的占位符。刻意用 {{...}} 而不是 %s：
// %s 会诱使人用 fmt.Sprintf 直接拼，而 fmt.Sprintf 不做任何转义——
// 换个显眼的记号，是为了让"拼过滤器"这件事必须经过 renderUserFilter 这一个入口。
const usernamePlaceholder = "{{username}}"

// escapeFilterValue 按 RFC 4515 §3 转义 LDAP 搜索过滤器里的**断言值**。
//
// ★不转义就是经典的 LDAP 注入漏洞，症状极其隐蔽：
// 模板 `(&(objectClass=person)(uid={{username}}))` 里塞进用户名 `*)(uid=*`，
// 拼出来是 `(&(objectClass=person)(uid=*)(uid=*))`——语义已经被改写成"任意 uid"，
// 于是**任何用户名都能匹配到目录里某个存在的条目**。后续流程会拿这个条目的 DN 去 bind，
// 攻击者只要知道任意一个真实账号的口令，就能借别人的用户名走完整条登录链路；
// 更糟的是配合"命中多条时挑第一个"的实现，登录审计里记下的是攻击者输入的名字，
// 而实际认证过的是另一个人。日志、告警、行为基线全部对不上号。
//
// 五个必须转义的字符（RFC 4515 §3 的 ESC / LPAREN / RPAREN / ASTERISK / NUL）：
//
//	\  →  \5c      (  →  \28      )  →  \29      *  →  \2a      NUL  →  \00
//
// ★按**字节**遍历而不是按 rune：UTF-8 的多字节序列里，后续字节恒 ≥ 0x80，
// 不可能等于上面这五个 ASCII 码点，所以逐字节扫描既安全又不会把中文名字切坏。
// 反过来，若按 rune 遍历再 string(r) 拼回去，遇到非法 UTF-8 会被替换成 U+FFFD，
// 把"用户名里有个坏字节"悄悄变成"用户名不一样了"。
//
// ★这里刻意**自己实现**而不是直接用 go-ldap 的 ldap.EscapeFilter：
// 转义是这条链路上唯一挡住注入的东西，它必须由本仓库的测试直接覆盖、
// 且不随第三方库升级而改变语义。库里那个实现同样正确，但"正确"要由我们的用例说了算。
func escapeFilterValue(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b.WriteString(`\5c`)
		case '(':
			b.WriteString(`\28`)
		case ')':
			b.WriteString(`\29`)
		case '*':
			b.WriteString(`\2a`)
		case 0x00:
			b.WriteString(`\00`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// renderUserFilter 把用户名填进过滤器模板。**先转义、再替换**，顺序不能反。
//
// strings.ReplaceAll 只扫描原模板、不会回头重扫替换进去的内容，所以即便用户名里
// 恰好写着字面量 `{{username}}` 也不会发生二次展开（否则就是另一种模板注入）。
func renderUserFilter(tmpl, username string) string {
	return strings.ReplaceAll(tmpl, usernamePlaceholder, escapeFilterValue(username))
}
