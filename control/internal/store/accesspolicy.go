package store

import (
	"encoding/json"
	"fmt"
)

// ── 接入策略（PRD FR-POLICY-29 同时在线设备上限 / FR-POLICY-30 接入超时注销）──
//
// 这两条是「策略管理 → 用户策略」页上**仅有的两条真能生效**的规则。同页此前那八项
// （设备并发数 / 会话空闲超时 / 专用 DNS / 虚拟专线隔离 / 登录时段 / 二次认证豁免期 /
// 卸载防护 / 进程防护）落进 `policy_overrides.settings` 之后**全仓零消费方**，
// 而保存成功的提示还写着「已下发至「X」的代理网关」。整批已摘除，改为如实声明。
//
// 执行点唯一：`api.accessSessionGate` → `handleKnockToken`。与设备准入闸同一处收口，
// 因为敲门令牌是「这台终端此刻能不能接入」的唯一命门（网关 strict 模式只认它，
// 30s 过期，客户端必须每 15s 回来续）。**刻意不接账号级的强制下线通道**：
// 那条通道没有设备维度，一台机器超时会把这个人所有机器一起断掉。

// AccessPolicySettingKey 落 settings 表的键。
const AccessPolicySettingKey = "policy.access.v1"

// 接入策略的取值边界（PRD 原文）。
const (
	MaxDeviceLimit     = 1000   // FR-POLICY-29：0~1000
	MinIdleMinutes     = 5      // FR-POLICY-30：5 分钟
	MaxIdleMinutes     = 525600 // FR-POLICY-30：365 天
	DefaultIdleMinutes = 480    // 8 小时（与会话令牌寿命同量级；仅在管理员开启该规则后才用得到）
)

// AccessPolicy 接入策略。
type AccessPolicy struct {
	// DeviceLimitEnabled 是否启用「同时在线设备上限」。
	//
	// ★为什么要有这个开关，而不是用 MaxDevices==0 表示不限：PRD 明写 **0 = 禁止登录**。
	// 若不另设开关，存量库里那一列的零值就等于「所有人禁止登录」——升级重启那一刻
	// 全员被挡在门外，而配置页看起来一切正常（0 是它的默认显示值）。
	// 这是「补列迁移必须配回填」的同一类坑，只是这次坑在**枚举的语义**上。
	DeviceLimitEnabled bool `json:"deviceLimitEnabled"`
	// MaxDevices 同时在线设备上限（0~1000；**0 = 禁止登录**，PRD 原文）。
	MaxDevices int `json:"maxDevices"`
	// SplitPlatform 是否区分 PC 与移动端分别计数（PRD：可区分/不区分）。
	SplitPlatform bool `json:"splitPlatform"`
	// MaxDevicesMobile 移动端上限，仅 SplitPlatform 时有意义。
	MaxDevicesMobile int `json:"maxDevicesMobile"`

	// IdleEnabled 是否启用「接入超时注销」。
	IdleEnabled bool `json:"idleEnabled"`
	// IdleMinutes 无业务流量多久后注销（5 分钟 ~ 365 天）。
	IdleMinutes int `json:"idleMinutes"`
}

// DefaultAccessPolicy 出厂值：两条规则都**关闭**。
//
// ★默认必须是关的。这两条规则的失败方向都是「把合法用户挡在门外」，
// 而它们依赖的判据（设备指纹、业务活跃时刻）都要终端与网关配合上报——
// 默认开启就等于在管理员还没看过这一页时，先按一份他没同意过的配置拒人。
func DefaultAccessPolicy() AccessPolicy {
	return AccessPolicy{MaxDevices: 3, MaxDevicesMobile: 2, IdleMinutes: DefaultIdleMinutes}
}

// Validate 入口校验（保存接口与读取回落共用）。
func (p AccessPolicy) Validate() error {
	if p.MaxDevices < 0 || p.MaxDevices > MaxDeviceLimit {
		return fmt.Errorf("同时在线设备上限须在 0~%d 之间（0 = 禁止登录）", MaxDeviceLimit)
	}
	if p.MaxDevicesMobile < 0 || p.MaxDevicesMobile > MaxDeviceLimit {
		return fmt.Errorf("移动端设备上限须在 0~%d 之间", MaxDeviceLimit)
	}
	if p.IdleEnabled && (p.IdleMinutes < MinIdleMinutes || p.IdleMinutes > MaxIdleMinutes) {
		return fmt.Errorf("接入超时注销时长须在 %d 分钟 ~ %d 分钟（365 天）之间",
			MinIdleMinutes, MaxIdleMinutes)
	}
	return nil
}

// ParseAccessPolicy 从 settings 里那串 JSON 解出策略；解不出一律回默认值（两条规则都关）。
//
// ★坏数据不能变成"更严的策略"：一条解析失败若回落成 MaxDevices=0 + 启用，
// 就是全员禁止登录。回落方向恒定为「不生效」。
func ParseAccessPolicy(raw string, ok bool) AccessPolicy {
	if !ok || raw == "" {
		return DefaultAccessPolicy()
	}
	var p AccessPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return DefaultAccessPolicy()
	}
	if err := p.Validate(); err != nil {
		return DefaultAccessPolicy()
	}
	return p
}
