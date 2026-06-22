package store

import "context"

// AuthSrcBundle 认证源接入页：身份/认证源 + 自适应认证规则。
type AuthSrcBundle struct {
	Sources []AuthSource   `json:"sources"`
	Rules   []AdaptiveRule `json:"rules"`
}

type AuthSource struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Type    string `json:"type"` // local | ad | ldap | radius | oauth | sms | cert
	Status  string `json:"status"`
	Users   int    `json:"users"`
	Primary bool   `json:"primary"`
}

// AdaptiveRule 自适应认证规则（IF 条件组合 THEN 动作）。
type AdaptiveRule struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Enabled    bool       `json:"enabled"`
	Logic      string     `json:"logic"` // AND | OR
	Conditions []RuleCond `json:"conditions"`
	Action     string     `json:"action"` // allow | mfa | stepup | block
	Priority   int        `json:"priority"`
}

type RuleCond struct {
	Field string `json:"field"` // weakPwd | geoAnomaly | offHours | riskScore | untrustedDevice | newDevice
	Op    string `json:"op"`    // is | gt | in
	Value string `json:"value"`
}

func (m *Memory) AuthSrc(_ context.Context) (AuthSrcBundle, error) {
	return AuthSrcBundle{
		Sources: []AuthSource{
			{Key: "local", Name: "本地用户目录", Type: "local", Status: "online", Users: 124, Primary: false},
			{Key: "ad", Name: "总部 AD 域", Type: "ad", Status: "online", Users: 1160, Primary: true},
			{Key: "radius", Name: "RADIUS 双因子", Type: "radius", Status: "online", Users: 0, Primary: false},
			{Key: "oauth", Name: "企业微信 OAuth", Type: "oauth", Status: "online", Users: 0, Primary: false},
			{Key: "sms", Name: "阿里云短信网关", Type: "sms", Status: "online", Users: 0, Primary: false},
			{Key: "cert", Name: "商密证书 (SM2)", Type: "cert", Status: "warning", Users: 0, Primary: false},
		},
		Rules: []AdaptiveRule{
			{ID: "r1", Name: "弱口令强制 MFA", Enabled: true, Logic: "OR", Priority: 1, Action: "mfa", Conditions: []RuleCond{{Field: "weakPwd", Op: "is", Value: "true"}}},
			{ID: "r2", Name: "异地登录强制增强认证", Enabled: true, Logic: "AND", Priority: 2, Action: "stepup", Conditions: []RuleCond{{Field: "geoAnomaly", Op: "is", Value: "true"}, {Field: "untrustedDevice", Op: "is", Value: "true"}}},
			{ID: "r3", Name: "高风险分直接阻断", Enabled: true, Logic: "AND", Priority: 3, Action: "block", Conditions: []RuleCond{{Field: "riskScore", Op: "gt", Value: "70"}}},
			{ID: "r4", Name: "异常时段二次认证", Enabled: false, Logic: "AND", Priority: 4, Action: "mfa", Conditions: []RuleCond{{Field: "offHours", Op: "in", Value: "22:00-06:00"}}},
		},
	}, nil
}
