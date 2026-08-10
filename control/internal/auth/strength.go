package auth

import (
	"strings"
	"unicode"
)

// ── 口令强度判定（认证策略「弱密码」增强规则的唯一判据来源）──
//
// ★为什么必须在「设置口令的那一刻」判、而不是登录时判：
// 库里存的是 bcrypt 哈希，登录时服务端手上只有哈希与一次比对结果，**没有任何办法**
// 从哈希反推强度。登录链路想消费「弱密码」这个条件，就只能消费一个在改密/建号时
// 落下来的标记。这也是为什么会有 users.pw_strength 这一列。
//
// ★三态而非两态：既有库里的行是在这套判定存在之前写进去的，明文早已不可得，
// 只能是 PwUnknown（未知），不能回填成 PwStrong——那等于凭空宣称"这些口令是强的"，
// 「弱密码」规则会对全部存量账号静默失效且没人看得出来。未知既不命中弱密码规则，
// 也会在管理台如实显示成"未知"，改一次口令即自动补齐。
const (
	// PwWeak 判定为弱口令（命中下方任一条判据）。
	PwWeak = "weak"
	// PwStrong 判定为强口令（未命中任何弱判据）。
	PwStrong = "strong"
	// PwUnknown 无法判定：口令是在本判定存在之前设置的，明文不可得。
	PwUnknown = "unknown"
)

// minStrongLen 低于该长度一律判弱（无论字符多复杂，8 位以内穷举成本已不足以依赖）。
const minStrongLen = 10

// longPassphraseLen 达到该长度且不在弱口令表内即判强，不再要求字符类别——
// 长口令句（passphrase）本就以长度换复杂度，硬要求符号只会把人逼回 "Passw0rd!"。
const longPassphraseLen = 16

// commonWeak 常见弱口令表（含本项目自己的演示口令）。
// 只收最典型的几十条：这一层是"显而易见的弱"，不是完整字典攻击模拟。
var commonWeak = map[string]bool{
	"password": true, "passw0rd": true, "password1": true, "password123": true,
	"123456": true, "1234567": true, "12345678": true, "123456789": true, "1234567890": true,
	"qwerty": true, "qwerty123": true, "abc123": true, "111111": true, "000000": true,
	"iloveyou": true, "admin": true, "admin123": true, "root": true, "root123": true,
	"letmein": true, "welcome": true, "monkey": true, "dragon": true, "sunshine": true,
	"baidi": true, "baidi@123": true, "baidi123": true, "zhulong": true,
	"1qaz2wsx": true, "zxcvbnm": true, "asdfgh": true, "p@ssw0rd": true,
	"woaini1314": true, "5201314": true, "wang123": true, "test123": true,
}

// PasswordWeakness 判定口令是否为弱口令，并给出可展示的中文原因。
// account 参与判定：口令里含账号名（如 zhang.wei / Zhangwei2024）是最常见的可猜口令形态。
func PasswordWeakness(account, pw string) (bool, string) {
	if pw == "" {
		return true, "口令为空"
	}
	low := strings.ToLower(pw)
	if commonWeak[low] {
		return true, "命中常见弱口令表"
	}
	if a := accountCore(account); a != "" && strings.Contains(low, a) {
		return true, "口令中包含账号名"
	}
	if len([]rune(pw)) < minStrongLen {
		return true, "长度不足 10 位"
	}
	if len([]rune(pw)) >= longPassphraseLen {
		return false, ""
	}
	if classes(pw) < 3 {
		return true, "字符种类不足（大写/小写/数字/符号 至少三类）"
	}
	if singleRun(low) {
		return true, "全为连续或重复字符"
	}
	return false, ""
}

// PasswordStrength 返回落库用的强度标记（PwWeak | PwStrong）。
// 注意它**不会**返回 PwUnknown：未知只属于"这套判定还不存在时写下的行"。
func PasswordStrength(account, pw string) string {
	if weak, _ := PasswordWeakness(account, pw); weak {
		return PwWeak
	}
	return PwStrong
}

// accountCore 取账号里可比对的主体部分：小写、去掉分隔符与常见前缀域。
// 长度 <3 的返回空——两三个字母的子串会把无关口令误判成"含账号名"。
func accountCore(account string) string {
	a := strings.ToLower(strings.TrimSpace(account))
	if i := strings.IndexAny(a, "@\\/"); i > 0 {
		a = a[:i]
	}
	a = strings.NewReplacer(".", "", "-", "", "_", "").Replace(a)
	if len(a) < 3 {
		return ""
	}
	return a
}

func classes(pw string) int {
	var upper, lower, digit, sym bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			sym = true
		}
	}
	n := 0
	for _, b := range []bool{upper, lower, digit, sym} {
		if b {
			n++
		}
	}
	return n
}

// singleRun 报告整串是否为单调递增/递减或全同字符（abcdefghij / 1111111111）。
func singleRun(low string) bool {
	rs := []rune(low)
	if len(rs) < 2 {
		return true
	}
	same, inc, dec := true, true, true
	for i := 1; i < len(rs); i++ {
		d := rs[i] - rs[i-1]
		if d != 0 {
			same = false
		}
		if d != 1 {
			inc = false
		}
		if d != -1 {
			dec = false
		}
	}
	return same || inc || dec
}
