package ldapsrc

import (
	"regexp"
	"strings"
)

// ── Active Directory 的 49 号结果码子状态 ────────────────────────────────────
//
// ★这是 AD 与通用 LDAP 最容易坑人的方言差异。AD 在 bind 失败时**一律**回
// LDAPResult 49（invalidCredentials），真正的原因藏在诊断串里的十六进制 data 码：
//
//	80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 533, v2580
//
// 若把 49 一律当"密码错误"回给用户，症状是：账号被锁定/口令过期/账号禁用的人
// 反复被告知"密码错误"，他自己一遍遍重试（把锁定时间续上），运维顺着"用户忘了密码"
// 这条线查，谁都不会想到去看 AD 的账号状态——一次这样的误导能烧掉半天。
//
// 对**用户**仍然只回统一的"用户名或密码错误"（不区分才不构成账号枚举接口，
// 见 authsrc.ErrInvalidCredentials 的说明），但**服务端日志里必须把码解出来**：
// 归因信息要留在只有运维看得到的那一侧。

// adSubStatus 常见 data 码 → 人话。刻意只收录会影响运维判断的那些，
// 不追求穷举 AD 的全部子状态（穷举清单会腐坏，而未知码我们照样原样打印）。
var adSubStatus = map[string]string{
	"525": "目录中不存在该用户",
	"52e": "口令错误",
	"52f": "账号受限（如口令不符合策略要求）",
	"530": "不在允许的登录时间段内",
	"531": "不允许从该工作站登录",
	"532": "口令已过期",
	"533": "账号已被禁用",
	"568": "登录令牌过大（用户所属组过多）",
	"701": "账号已过期",
	"773": "用户必须先修改口令后才能登录",
	"775": "账号已被锁定",
}

// adDataRe 从诊断串里抠出 data 码。
//
// 只认十六进制且限长 1~4 位：诊断串里还有 `DSID-0C0903A9`、`v2580` 这类噪声，
// 放宽了会抓错东西，把"账号禁用"错解成别的状态比不解释更坏。
var adDataRe = regexp.MustCompile(`(?i)\bdata\s+([0-9a-f]{1,4})\b`)

// decodeADBindFailure 解析 AD bind 失败的诊断串，返回 (data 码, 中文解释)。
//
// 不是 AD（或诊断串里没有 data 码）时返回两个空串，调用方据此退回通用文案。
// 解出了码但不认识时返回 (码, "")，调用方仍应把码原样打进日志——
// 一个能 Google 到的十六进制码，价值远大于一句"未知错误"。
func decodeADBindFailure(diag string) (code, reason string) {
	m := adDataRe.FindStringSubmatch(diag)
	if m == nil {
		return "", ""
	}
	code = strings.ToLower(m[1])
	return code, adSubStatus[code]
}
