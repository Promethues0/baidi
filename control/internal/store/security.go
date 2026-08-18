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

// BaselinePolicy 安全基线策略，含适用范围、分平台条件与处置。
type BaselinePolicy struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// ★这里曾经有 Type（app-protect | onboarding）与自由文本 Scope（"全体访问者 / 持续验证"）。
	//
	// Type 已摘除（wave8 行动 13-④）：risk.Evaluate 一眼都不看它，而页面按策略属性
	// 渲染成蓝标签——一条标着「应用防护」的基线若 disposal=block，实际行为是
	// **拒发敲门令牌 + 撤窗断隧道**，也就是上线准入，标签与行为方向相反。
	// 处置的真相只有一个字段：Disposal。
	//
	// Scope 改成了结构化的 ScopeOrgs/ScopeGroups 并**真的接进判定**（见下）。
	// 自由文本写什么都不影响任何人，而它长得像个筛选条件。
	Disposal string `json:"disposal"` // allow | degrade | block | gray
	// ScopeOrgs / ScopeGroups 适用范围（组织含子树 / 用户组）。
	//
	// **两者都空 = 对全体生效**（与认证策略同口径，也是改造前自由文本时代的实际行为，
	// 所以存量基线回填成空数组即行为不变）。展开只有一处实现：store.SubjectIndex，
	// 与资源授权、认证策略共用——各写一份的话，同一个「这个人算不算在范围内」
	// 会在三个页面上给出不同答案。
	//
	// ★过滤在**调用方**（api.handlePostureReport）做，不在 risk.Evaluate 里：
	// Evaluate 是纯函数、不碰 IO，把取数塞进去就再也测不动了。
	ScopeOrgs   []string        `json:"scopeOrgs"`
	ScopeGroups []string        `json:"scopeGroups"`
	Status      string          `json:"status"` // enabled | disabled
	Platforms   []string        `json:"platforms"`
	Checks      []BaselineCheck `json:"checks"`
}

type BaselineCheck struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Platform string `json:"platform"` // Windows | macOS | Linux | All
	Expect   string `json:"expect"`
	Severity string `json:"severity"` // high | medium | low
}

// CheckSpec 采集器**真的会上报**的一个检查项。
//
// 这是安全基线检测项 key 的**唯一合法取值来源**，也是「采集器报什么」与
// 「基线要求什么」之间那份契约的唯一书面形式。
type CheckSpec struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Expect string `json:"expect"` // 默认期望值描述（页面展示，可由管理员改）
	// Platform 该项能在哪些平台上被采到。当前六项三平台都采，故恒为 All——
	// 真出现平台专属项时，入口校验要连这一维一起校（Windows 独有的项配在 macOS 上
	// 会让那条基线对 Mac 永远判违规，与 key 拼错是同一种坑）。
	Platform string `json:"platform"`
	Note     string `json:"note,omitempty"`
}

// collectableChecks 桌面采集器（clients/desktop/src-tauri/src/posture.rs）实际上报的六项。
//
// ★这份清单必须与采集器逐字对齐。基线里配一个采集器**从不上报**的 key，
// risk.Evaluate 会按「缺失即不合规」判该项失败（防选择性上报的正确设计），
// 于是那条基线对**该平台全体终端**永远违规——而接入准入基线的默认处置是 block，
// 等于一键给所有人拒发敲门令牌 + 撤窗断隧道，保存那一刻零报错零提示。
// 入口拒绝（api.handleSaveBaseline）+ 页面下拉（Security.vue）两道，都读这一份。
var collectableChecks = []CheckSpec{
	{Key: "disk_encrypted", Label: "磁盘已加密", Expect: "FileVault / BitLocker = On", Platform: "All",
		Note: "macOS 读 fdesetup、Windows 读 BitLocker、Linux 看有无 LUKS 块设备"},
	{Key: "sys_integrity", Label: "系统完整性保护开启", Expect: "SIP / Secure Boot = enabled", Platform: "All",
		Note: "macOS 读 csrutil、Windows 读 Secure Boot、Linux 看 lockdown/SELinux"},
	{Key: "firewall_on", Label: "系统防火墙启用", Expect: "firewall = enabled", Platform: "All",
		Note: "Linux 非 root、Windows 非管理员时探不到，会如实报「无法判定」而不是不合规"},
	{Key: "os_version", Label: "系统版本合规", Expect: "macOS ≥ 13 / Win ≥ 10", Platform: "All"},
	{Key: "edr_online", Label: "EDR 终端防护在线", Expect: "EDR 进程存活", Platform: "All",
		Note: "枚举不到进程时报「无法判定」"},
	{Key: "client_version", Label: "客户端版本合规", Expect: "≥ 灰度发布里配置的稳定版", Platform: "All",
		Note: "★判据在控制面：按「升级 → 灰度发布」里该平台的稳定版比对上报版本。" +
			"该平台没有发布计划、或终端没报版本时一律「无法判定」，不会假绿"},
}

// CollectableChecks 采集器可上报的检查项目录（副本，调用方改不动内部状态）。
func CollectableChecks() []CheckSpec {
	return append([]CheckSpec(nil), collectableChecks...)
}

// CheckSpecOf 按 key 取采集项定义。
func CheckSpecOf(key string) (CheckSpec, bool) {
	for _, c := range collectableChecks {
		if c.Key == key {
			return c, true
		}
	}
	return CheckSpec{}, false
}

// CollectableCheckKeys 全部合法 key（拼错误时原样报给管理员，让他知道能填什么）。
func CollectableCheckKeys() []string {
	out := make([]string, 0, len(collectableChecks))
	for _, c := range collectableChecks {
		out = append(out, c.Key)
	}
	return out
}

// CheckKeyClientVersion 客户端版本项的 key。判据在控制面（见 risk.ResolveClientVersion），
// 与其余五项「客户端采集 + 机械布尔化」不同，单独取个常量免得三处各写一遍字面量。
const CheckKeyClientVersion = "client_version"

func (m *Memory) Security(_ context.Context) (SecurityBundle, error) {
	return SecurityBundle{
		// 种子基线：check key 与桌面客户端采集键一致（disk_encrypted/sys_integrity/firewall_on/os_version/edr_online/client_version）。
		// 接入准入=block（典型开发 Mac 默认通过：FileVault+SIP），终端健康=degrade（常见部分失败→风险抬升可见）。
		Baselines: []BaselinePolicy{
			{ID: "bl-admission", Name: "接入准入基线", Disposal: "block", Status: "enabled",
				Platforms: []string{"Windows", "macOS", "Linux"},
				Checks: []BaselineCheck{
					{Key: "disk_encrypted", Label: "磁盘已加密", Platform: "All", Expect: "FileVault / BitLocker = On", Severity: "high"},
					{Key: "sys_integrity", Label: "系统完整性保护开启", Platform: "macOS", Expect: "SIP = enabled", Severity: "high"},
				}},
			{ID: "bl-health", Name: "终端健康基线", Disposal: "degrade", Status: "enabled",
				Platforms: []string{"Windows", "macOS", "Linux"},
				Checks: []BaselineCheck{
					{Key: "firewall_on", Label: "系统防火墙启用", Platform: "All", Expect: "firewall = enabled", Severity: "medium"},
					{Key: "os_version", Label: "系统版本合规", Platform: "All", Expect: "macOS ≥ 13 / Win ≥ 10", Severity: "medium"},
					{Key: "edr_online", Label: "EDR 终端防护在线", Platform: "All", Expect: "EDR 进程存活", Severity: "low"},
					// ★label/expect 与实现对齐：判据是控制面按「升级 → 灰度发布」里该平台的
					// 稳定版比对（risk.ResolveClientVersion），不是终端自称「我是最新版」。
					// 没配稳定版时这一项是「无法判定」，observe 下不计分——如实，不假绿。
					{Key: "client_version", Label: "客户端版本合规", Platform: "All", Expect: "≥ 灰度发布里配置的稳定版", Severity: "low"},
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
