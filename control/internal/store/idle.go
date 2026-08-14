package store

import "time"

// ── 闲置账号治理（wave7 行动 8②：FR-MON-19/20）──
//
// 判据是 users.last_login（8① 起由登录成功路径真实写入）。僵尸账号是最便宜的
// 攻击面；license 席位提示一直在说「删除闲置账号释放席位」，系统此前却给不出
// 哪些账号闲置——自相矛盾在这里解决。
//
// ★三态纪律（与 posture 的 unknown 同款）：last_login 解析不出（建号占位 "—"、
// 或 8① 上线前的历史行）不等于「从未用过」——按 created_at 兜底估算并标
// NeverRecorded=true 单列展示；连 created_at 都解析不出的行**不列入**闲置清单
// （不可判定 ≠ 闲置，把判不了的账号批量锁掉是拿误伤换整洁）。

// IdleAccount 一个疑似闲置的账号（只含 status=active 的行：其余状态已被处置过）。
type IdleAccount struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Account string `json:"account"`
	// LastLogin 原始展示值（可能是 "—"）。
	LastLogin string `json:"lastLogin"`
	// IdleDays 距最后登录（或 NeverRecorded 时距建号）的天数。
	IdleDays int `json:"idleDays"`
	// NeverRecorded 没有可解析的登录记录，闲置天数按建号时间估算。
	// ★不等于「从未登录」：8① 之前的登录不落 last_login，如实说"无记录"。
	NeverRecorded bool `json:"neverRecorded"`
	// IsAdmin 管理员账号：批量锁定时目标是管理员须 PermAdmins（guardAdminTarget 同款），
	// 且最后一名超管由 store 防自锁拦截。前端据此单独标记。
	IsAdmin bool `json:"isAdmin"`
}

// idleTimeLayouts last_login/created_at 的历史形态（种子行有不带秒的）。
var idleTimeLayouts = []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"}

func parseIdleTime(s string) (time.Time, bool) {
	for _, layout := range idleTimeLayouts {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ClassifyIdle 判定一行是否闲置（纯函数，好测）。
// 返回 (闲置天数, 是否按建号时间估算, 是否命中阈值)。两个时间都解析不出 → hit=false。
func ClassifyIdle(lastLogin, createdAt string, now time.Time, thresholdDays int) (idleDays int, never, hit bool) {
	if t, ok := parseIdleTime(lastLogin); ok {
		d := int(now.Sub(t).Hours() / 24)
		return d, false, d >= thresholdDays
	}
	if t, ok := parseIdleTime(createdAt); ok {
		d := int(now.Sub(t).Hours() / 24)
		return d, true, d >= thresholdDays
	}
	return -1, true, false
}
