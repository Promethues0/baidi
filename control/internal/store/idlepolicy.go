package store

// 闲置账号治理策略（PRD 第 5 章 FR-MON-19，数据模型见 PRD「IdleAccountPolicy」）。
//
// ★这一条此前只做了一半，而**缺的正是"策略"那一半**：
//
//   PRD FR-MON-19 原文是「闲置账号阈值配置：可定义"用户多久未登录即判定为闲置"，
//   并设置**是否对闲置账号自动锁定**」，验收标准（PRD 905 行）写着
//   「若开启自动锁定，Then 该账号被自动锁定」。
//
//   实现里：阈值只从 URL 参数 `?days=` 取（`api.idleDaysParam`），管理员在页面上
//   调过的值**不落库**——换台机器、换个浏览器、或者仅仅是刷新之后回到默认 90 天；
//   `autoLockEnabled` 整项不存在，于是「自动锁定」这件事没有任何执行方，
//   闲置治理必须有人手工点进那一页、手工选中、手工点批量锁定。
//   一个要靠人记得去点的"自动治理"等于没有治理，而页面上看不出这个区别。
//
// 落 settings 表（键 IdlePolicySettingKey），与接入策略 policy.access.v1 同一套做法。

import (
	"encoding/json"
	"fmt"
)

// IdlePolicySettingKey 落 settings 表的键。
const IdlePolicySettingKey = "policy.idle.v1"

// 闲置阈值的取值边界。
const (
	// MinIdleDays 下限 7 天。★低于 7 天的"闲置"会把请了个年假的人扫进来，
	// 那不是治理是误伤——而处置是锁账号 + 数据面撤窗断隧道，代价不对称。
	MinIdleDays = 7
	// MaxIdleDays 上限 10 年（超过这个数就不是"闲置判定"了）。
	MaxIdleDays = 3650
	// DefaultIdleDays 出厂阈值（与改造前 idleDaysParam 的默认值一致，行为不变）。
	DefaultIdleDays = 90
)

// IdlePolicy 闲置账号治理策略。
type IdlePolicy struct {
	// ThresholdDays 多久未登录判定为闲置（7 ~ 3650 天）。
	ThresholdDays int `json:"thresholdDays"`
	// AutoLock 是否对识别出的闲置账号**自动锁定**。
	//
	// ★默认必须是 false。判据与 CLAUDE.md 那条「默认值就是绝大多数部署的真实姿态」
	// 一致，而这一项的失败方向格外重：开着它升级一次，后台任务会在管理员还没看过
	// 这一页时按一份他没同意过的阈值批量锁人，并同步撤窗断隧道。
	AutoLock bool `json:"autoLock"`
}

// DefaultIdlePolicy 出厂值：阈值 90 天、**不自动锁定**。
func DefaultIdlePolicy() IdlePolicy {
	return IdlePolicy{ThresholdDays: DefaultIdleDays}
}

// Validate 入口校验（保存接口与读取回落共用）。
func (p IdlePolicy) Validate() error {
	if p.ThresholdDays < MinIdleDays || p.ThresholdDays > MaxIdleDays {
		return fmt.Errorf("闲置判定时长须在 %d ~ %d 天之间（低于 %d 天会把休假的人判成闲置）",
			MinIdleDays, MaxIdleDays, MinIdleDays)
	}
	return nil
}

// ParseIdlePolicy 从 settings 里那串 JSON 解出策略；解不出一律回默认值。
//
// ★回落方向恒定为「不自动锁定」：一条解析失败若回落成 AutoLock=true，
// 就是后台任务按一份没人配过的阈值开始锁人——与 ParseAccessPolicy 同一条纪律
// （坏数据绝不能变成更严的策略）。
func ParseIdlePolicy(raw string, ok bool) IdlePolicy {
	if !ok || raw == "" {
		return DefaultIdlePolicy()
	}
	var p IdlePolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return DefaultIdlePolicy()
	}
	if err := p.Validate(); err != nil {
		return DefaultIdlePolicy()
	}
	return p
}

// ClampIdleDays 把一个天数夹进合法区间。
//
// ★阈值的夹取只有这一处实现：识别清单（GET）与自动锁定（后台任务）**必须用同一个值**，
// 各夹各的话，页面上列出 N 个闲置账号、后台任务锁的却是另一批，
// 而两边都不会报错——管理员只会觉得"这个功能时灵时不灵"。
func ClampIdleDays(d int) int {
	if d < MinIdleDays {
		return MinIdleDays
	}
	if d > MaxIdleDays {
		return MaxIdleDays
	}
	return d
}
