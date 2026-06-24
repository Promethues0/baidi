package store

import "context"

// ── 认证策略（PRD 第 7 章 FR-AUTH-12，P0）──
// 认证策略按用户目录分组，可分别为 PC/WEB 端与移动端 APP 配置主认证 / 二次认证方式，
// 并叠加自适应认证（免二次认证豁免、一键上线、增强认证条件）与默认授权应用。

// AuthMethodSet 一个接入端（PC/WEB 或 移动端）的认证方式组合。
type AuthMethodSet struct {
	Primary   string   `json:"primary"`   // 主认证：local | ad | ldap | radius | oauth | sms | cert
	Secondary []string `json:"secondary"` // 二次认证（可多选 / 可空）：sms | totp | radius | cert | http
}

// ExemptRule 自适应 · 免二次认证 / 一键上线 的豁免触发条件。
type ExemptRule struct {
	TrustedDevice  bool `json:"trustedDevice"`  // 使用授信终端时
	TrustedNetwork bool `json:"trustedNetwork"` // 满足可信网络环境时
	WinDomain      bool `json:"winDomain"`      // Windows 域环境时
}

// EnhanceRule 自适应 · 增强认证的强制触发条件（命中则强制追加增强认证）。
type EnhanceRule struct {
	WeakPwd    bool `json:"weakPwd"`    // 弱密码
	OffHours   bool `json:"offHours"`   // 异常时间段
	GeoAnomaly bool `json:"geoAnomaly"` // 异地登录
}

// AuthPolicy 一条认证策略。
type AuthPolicy struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Directory string        `json:"directory"` // 所属用户目录（认证源 key：local | ad | ...）
	IsDefault bool          `json:"isDefault"` // 是否该目录的默认策略（自动生成，不可删除）
	Scope     string        `json:"scope"`     // 适用范围（用户 / 组织 / 安全组的描述）
	Priority  int           `json:"priority"`  // 优先级，数字小者先匹配；冲突以最新（最小）为准
	Enabled   bool          `json:"enabled"`
	PC        AuthMethodSet `json:"pc"`        // PC/WEB 端认证
	Mobile    AuthMethodSet `json:"mobile"`    // 移动端 APP 认证
	Exempt    ExemptRule    `json:"exempt"`    // 免二次认证豁免条件
	OneClick  bool          `json:"oneClick"`  // 一键上线（保存认证票据，下次免认证；仅客户端生效）
	Enhance   EnhanceRule   `json:"enhance"`   // 增强认证触发条件
	AuthzApps string        `json:"authzApps"` // 默认授权应用（描述：全部应用 / 指定应用 / 不授权）
}

// AuthPolicies 返回演示用的认证策略（内存种子；SQLiteStore 覆盖为落库版）。
// 按用户目录铺：每个目录一条默认策略 + 若干精细化策略，覆盖「PC 严 / 移动端便捷」「外部强制增强」等典型编排。
func (m *Memory) AuthPolicies(_ context.Context) ([]AuthPolicy, error) {
	return []AuthPolicy{
		// 总部 AD 域
		{
			ID: "ap-ad-default", Name: "AD 域 · 默认策略", Directory: "ad", IsDefault: true,
			Scope: "总部 AD 域 · 全体用户", Priority: 100, Enabled: true,
			PC:     AuthMethodSet{Primary: "ad", Secondary: []string{"totp"}},
			Mobile: AuthMethodSet{Primary: "ad", Secondary: []string{"sms"}},
			Exempt: ExemptRule{TrustedDevice: true, WinDomain: true}, OneClick: true,
			Enhance: EnhanceRule{WeakPwd: true, GeoAnomaly: true}, AuthzApps: "默认授权全部应用",
		},
		{
			ID: "ap-ad-rd", Name: "研发中心 · 授信终端免二次", Directory: "ad", IsDefault: false,
			Scope: "研发中心 / 架构组、平台组", Priority: 20, Enabled: true,
			PC:     AuthMethodSet{Primary: "ad", Secondary: []string{}},
			Mobile: AuthMethodSet{Primary: "ad", Secondary: []string{}},
			Exempt: ExemptRule{TrustedDevice: true, TrustedNetwork: true}, OneClick: true,
			Enhance: EnhanceRule{GeoAnomaly: true}, AuthzApps: "默认授权：研发 Git、CI/CD",
		},
		// 本地用户目录
		{
			ID: "ap-local-default", Name: "本地目录 · 默认策略", Directory: "local", IsDefault: true,
			Scope: "本地用户目录 · 全体用户", Priority: 100, Enabled: true,
			PC:     AuthMethodSet{Primary: "local", Secondary: []string{"sms"}},
			Mobile: AuthMethodSet{Primary: "local", Secondary: []string{"sms"}},
			Exempt: ExemptRule{}, OneClick: false,
			Enhance: EnhanceRule{WeakPwd: true}, AuthzApps: "默认授权：OA 协同办公",
		},
		// 外部协作 / 外包（走本地账密 + 扫码，强制增强）
		{
			ID: "ap-ext-strict", Name: "外包人员 · 强制增强认证", Directory: "local", IsDefault: false,
			Scope: "外部协作安全组", Priority: 10, Enabled: true,
			PC:     AuthMethodSet{Primary: "local", Secondary: []string{"totp", "sms"}},
			Mobile: AuthMethodSet{Primary: "oauth", Secondary: []string{"totp"}},
			Exempt: ExemptRule{}, OneClick: false,
			Enhance: EnhanceRule{WeakPwd: true, OffHours: true, GeoAnomaly: true}, AuthzApps: "不授权（按需单独授权）",
		},
	}, nil
}
