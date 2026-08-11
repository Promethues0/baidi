package store

import "context"

// SecurityBundle 安全中心页：安全基线策略（可编辑、被风险引擎消费的那一份）。
//
// ★原来还有一个 Spa SpaStatus 字段，已整体删除，连同它在安全中心页的那张卡片。
// 它是「方法实现了、字段仍来自种子」的第二例：SQLiteStore.Security 以
// s.Memory.Security(ctx) 打底、只把 Baselines 换成库里的真实行，Spa 那一段
// （generation=G3 / 已隐身 / 敲门正常 / 三个被保护端口）原样继承种子——
// 控制面**没有任何**判定这三件事的能力：它不从外部实测端口可见性，也不代
// 数据面宣布敲门是否正常。而"已隐身 · 绿点"恰恰是最不该由一份常量来打包票的读数。
//
// 这块内容真实存在的出处是「网关与隐身」页（api/gatewaypage.go）：那里的敲门口 /
// 隧道口 / 在线判据全部来自网关 mTLS 注册心跳，没上报就如实缺席。同一件事只留
// 一个出口，删掉的这份不是"少了个视图"，而是少了一份与真实来源打架的假读数。
type SecurityBundle struct {
	Baselines []BaselinePolicy `json:"baselines"`
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
