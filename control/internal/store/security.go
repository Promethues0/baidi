package store

import "context"

// SecurityBundle 安全中心页：安全基线策略 + SPA 服务隐身概览（白帝仅承载基线 + SPA 内建）。
type SecurityBundle struct {
	Baselines []BaselinePolicy `json:"baselines"`
	Spa       SpaStatus        `json:"spa"`
}

// BaselinePolicy 安全基线策略（应用防护 / 上线准入），含分平台条件与处置。
type BaselinePolicy struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`     // app-protect | onboarding
	Scope     string          `json:"scope"`    // 适用范围
	Disposal  string          `json:"disposal"` // allow | degrade | block | gray
	Status    string          `json:"status"`   // enabled | disabled
	Platforms []string        `json:"platforms"`
	Checks    []BaselineCheck `json:"checks"`
}

type BaselineCheck struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Platform string `json:"platform"` // Windows | macOS | Linux | All
	Expect   string `json:"expect"`
	Severity string `json:"severity"` // high | medium | low
}

func (m *Memory) Security(_ context.Context) (SecurityBundle, error) {
	return SecurityBundle{
		Baselines: []BaselinePolicy{
			{ID: "b1", Name: "终端上线准入基线", Type: "onboarding", Scope: "全体员工", Disposal: "block", Status: "enabled",
				Platforms: []string{"Windows", "macOS", "Linux"},
				Checks: []BaselineCheck{
					{Key: "disk-enc", Label: "磁盘已加密", Platform: "All", Expect: "true", Severity: "high"},
					{Key: "jailbreak", Label: "未越狱 / 未 root", Platform: "All", Expect: "true", Severity: "high"},
					{Key: "os-ver", Label: "系统版本合规", Platform: "All", Expect: ">=合规基线", Severity: "medium"},
					{Key: "av", Label: "杀毒软件运行中", Platform: "Windows", Expect: "running", Severity: "medium"},
				}},
			{ID: "b2", Name: "高敏应用防护基线", Type: "app-protect", Scope: "财务核算系统 / OA", Disposal: "degrade", Status: "enabled",
				Platforms: []string{"Windows", "macOS"},
				Checks: []BaselineCheck{
					{Key: "edr", Label: "EDR 在线且无高危告警", Platform: "All", Expect: "online", Severity: "high"},
					{Key: "screen-lock", Label: "屏保锁定 ≤ 5 分钟", Platform: "All", Expect: "<=300s", Severity: "low"},
					{Key: "proc", Label: "无远控 / 录屏进程", Platform: "All", Expect: "none", Severity: "high"},
				}},
		},
		Spa: SpaStatus{
			Generation:     "G3",
			AuthMode:       "先认证后连接（SPA 敲门 + 双向证书）",
			ProtectedPorts: []string{"443 用户接入", "112 设备通信", "4434 控制信道"},
			Hidden:         true,
			KnockOK:        true,
		},
	}, nil
}
