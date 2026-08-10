package store

import "context"

// SecurityBundle 安全中心页：安全基线策略 + SPA 服务隐身概览（白帝仅承载基线 + SPA 内建）。
type SecurityBundle struct {
	Baselines []BaselinePolicy `json:"baselines"`
	Spa       SpaStatus        `json:"spa"`
}

// SpaStatus SPA 服务隐身概览。
//
// ★类型原本住在 store/gateway.go 里，那个文件连同它的「华东/华南出口」种子拓扑
// 已整体删除（网关与隐身页改由 api 层按 mTLS 注册心跳的真实网关构建，见
// api/gatewaypage.go）。这里只剩安全中心页在用，且这一份**仍是种子**：
// generation/hidden/knockOk 三项在控制面没有真实来源（控制面不从外部实测端口
// 可见性），下一波脱壳时应按同样口径处理。
type SpaStatus struct {
	Generation     string   `json:"generation"` // G2 | G3 | G4
	AuthMode       string   `json:"authMode"`
	ProtectedPorts []string `json:"protectedPorts"`
	Hidden         bool     `json:"hidden"`
	KnockOK        bool     `json:"knockOk"`
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
		// 种子基线：check key 与桌面客户端采集键一致（disk_encrypted/sys_integrity/firewall_on/os_version/edr_online/client_version）。
		// 接入准入=block（典型开发 Mac 默认通过：FileVault+SIP），终端健康=degrade（常见部分失败→风险抬升可见）。
		Baselines: []BaselinePolicy{
			{ID: "bl-admission", Name: "接入准入基线", Type: "onboarding", Scope: "全体访问者 / 数据面接入", Disposal: "block", Status: "enabled",
				Platforms: []string{"Windows", "macOS", "Linux"},
				Checks: []BaselineCheck{
					{Key: "disk_encrypted", Label: "磁盘已加密", Platform: "All", Expect: "FileVault / BitLocker = On", Severity: "high"},
					{Key: "sys_integrity", Label: "系统完整性保护开启", Platform: "macOS", Expect: "SIP = enabled", Severity: "high"},
				}},
			{ID: "bl-health", Name: "终端健康基线", Type: "app-protect", Scope: "全体访问者 / 持续验证", Disposal: "degrade", Status: "enabled",
				Platforms: []string{"Windows", "macOS", "Linux"},
				Checks: []BaselineCheck{
					{Key: "firewall_on", Label: "系统防火墙启用", Platform: "All", Expect: "firewall = enabled", Severity: "medium"},
					{Key: "os_version", Label: "系统版本合规", Platform: "All", Expect: "macOS ≥ 13 / Win ≥ 10", Severity: "medium"},
					{Key: "edr_online", Label: "EDR 终端防护在线", Platform: "All", Expect: "EDR 进程存活", Severity: "low"},
					{Key: "client_version", Label: "客户端为最新版本", Platform: "All", Expect: "≥ v0.1.0", Severity: "low"},
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

// Baselines 返回安全基线清单（Memory：种子；SQLiteStore 覆盖为库读）。
func (m *Memory) Baselines(ctx context.Context) ([]BaselinePolicy, error) {
	b, err := m.Security(ctx)
	if err != nil {
		return nil, err
	}
	return b.Baselines, nil
}
