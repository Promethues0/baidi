package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// ── 授信终端（trusted_devices，PRD ch9 FR-EP-10/12/13/14/15）──
//
// 此前白帝有「硬件指纹」这个词，却没有设备这个**实体**：指纹只在 posture 上报里出现、
// 在页面上被展示，从来不是任何准入判据。终端管理页整页是内存种子（MOCK_/Memory.Devices），
// 点「绑定」弹一个 toast，审批队列里的申请与任何真实设备都对不上。
//
// 现在设备是一等实体，有状态机、有准入执行方：
//
//	pending  首次上报（审批绑定模式下）。**不是授信**——严格模式下敲不开门。
//	trusted  管理员批准，或自动绑定模式下首次上报即授信。
//	revoked  管理员吊销 / 绑定申请被驳回。**两种准入模式下都拒**（见下）。
//
// 执行方是 api.handleKnockToken 的设备闸：敲门令牌是终端进入数据面的唯一入口，
// 拒发即从密码学上敲不开门（网关只认 control 签发的 use=knock 令牌）。
//
// ★为什么 revoked 在观察模式下也拒：observe 放宽的是「这台设备我还不认识」
// （pending / 从未登记），那是纳管进度问题；revoked 是管理员**显式**说过"这台不许进"。
// 若观察模式连它也放行，「吊销」在默认配置下就是个空动作——管理员点完按钮、页面
// 变红、设备照常接入，且没有任何报错。这正是本项目反复栽跟头的那类静默失效。
const (
	DeviceStatusPending = "pending"
	DeviceStatusTrusted = "trusted"
	DeviceStatusRevoked = "revoked"
)

// DeviceStatusValid 报告状态是否为合法枚举（写入口校验，杜绝拼错的状态永远匹配不上判据）。
func DeviceStatusValid(s string) bool {
	return s == DeviceStatusPending || s == DeviceStatusTrusted || s == DeviceStatusRevoked
}

// 准入模式：敲门令牌签发时对「非授信设备」的处置。
//
// 默认 observe，与终端 posture 的 observe 默认一致——上线一个会把全体终端挡在门外的
// 默认值，只会让人把整个功能关掉。strict 是运维在设备纳管完成后主动切换的。
const (
	DeviceTrustObserve = "observe" // 放行 + 记审计（节流），不拦
	DeviceTrustStrict  = "strict"  // 非 trusted 一律拒发敲门令牌（含缺指纹）
)

// 绑定方式：首次上报时新设备的初始状态。
const (
	DeviceBindAuto     = "auto"     // 首次上报即 trusted（省事，但等于放弃人工核验）
	DeviceBindApproval = "approval" // 首次上报入 pending 并生成一条绑定审批（复用既有审批流）
)

// ── 资产分类（wave7 行动 15，PRD ch9 FR-EP-06~09）──
//
// 分类回答的是「这台机器是谁的」，与 status（这台机器批没批过）正交：
//
//	enterprise  企业资产。公司配发、完全纳管。**这是回填值与默认值**——
//	            分类是本次新增的维度，既有设备此前都是按企业资产在用的，
//	            回填成别的值会在升级那一刻改变既有主体的实际接入权。
//	personal    个人资产（BYOD）。员工自带、未纳管。**唯一受个人资产准入策略约束的一档**。
//	managed     企业纳管个人。员工自带但已装管控/已备案——语义就是"个人设备但已纳管"，
//	            因此**按企业资产处理**（见 IsPersonalAsset）。
//
// ★分类是**管理员标注**的，白帝不自动识别设备归属：没有 MDM、没有资产系统对接，
// 硬件指纹只能说明"是同一台机器"，说明不了"这台机器是谁买的"。标错就是标错，
// 与资源敏感度（resources.sensitivity）同一条纪律。
const (
	AssetClassEnterprise = "enterprise"
	AssetClassPersonal   = "personal"
	AssetClassManaged    = "managed"
)

// AssetClassValid 报告分类是否为合法枚举（写入口校验：拼错的值会永远匹配不上判据，
// 表现为「明明标成个人资产、deny 策略却不生效」这种零报错的静默失效）。
func AssetClassValid(s string) bool {
	return s == AssetClassEnterprise || s == AssetClassPersonal || s == AssetClassManaged
}

// NormalizeAssetClass 把空值/脏值收敛到 enterprise。
//
// ★兜底方向必须是 enterprise 而不是 personal：这一列读出脏值时若按个人资产处理，
// 在 personalPolicy=deny 下会把一台企业机整台挡在门外，而管理员在页面上看到的
// 仍然是「企业资产」。与 DeviceTrustSetting.Normalize 的兜底方向同一条理由——
// 收缩动作宁可短暂不生效，也不能因为一个脏值把人锁在门外；真正的 fail-closed
// 底线由 status（pending/revoked）与 posture block 承担。
//
// 它同时是**旧库补列尚未回填**时的读侧兜底（asset_class 为 NULL → enterprise，
// 与回填值逐字节一致）。但这不能替代回填：回填才让 SQL 侧的按分类查询/统计成立。
func NormalizeAssetClass(s string) string {
	if AssetClassValid(s) {
		return s
	}
	return AssetClassEnterprise
}

// IsPersonalAsset 报告该分类是否受「个人资产准入策略」约束。
//
// ★只有 personal 受约束。managed（企业纳管个人）按企业资产处理——它的语义就是
// "个人设备但已纳管"，纳管完成之后仍按 BYOD 收紧的话，管理员就没有任何办法
// 让一台已纳管的自带设备正常接入，「纳管」这个动作也就没有了结果。
func IsPersonalAsset(class string) bool {
	return NormalizeAssetClass(class) == AssetClassPersonal
}

// AssetClassZh 分类的中文名。**唯一定义在这里**：审计文案、CSV 导出、控制台
// 三处都取它，免得同一个枚举在三个地方长出三种说法（导出件与页面对不上时，
// 拿导出件做资产盘点的人无从发现自己看的是另一套口径）。
func AssetClassZh(class string) string {
	switch NormalizeAssetClass(class) {
	case AssetClassPersonal:
		return "个人资产"
	case AssetClassManaged:
		return "企业纳管个人"
	}
	return "企业资产"
}

// ── 个人资产准入策略（资产分类的唯一执行方）──
//
// 它是 DeviceTrustSetting 里独立于 Mode 的一档，消费方只有 api.deviceAdmissionGate：
//
//	inherit  个人资产与企业资产一视同仁，走全局 Mode。**默认值，行为与本功能上线前完全一致**。
//	strict   个人资产恒按 strict 判（即使全局 Mode=observe）：未显式批准为 trusted 就拒发敲门令牌。
//	deny     个人资产一律拒（即使已批准为 trusted）。
//
// ★为什么执行方落在准入闸而不是并入风险降权（disposal=degrade）：
// degrade 是**账号维度**的（store.PostureUsersByDisposal 出账号名单 → 网关 DenyUsers），
// 而资产分类是**设备维度**的。一个人同时有企业机与个人机时，按账号并入 degrade
// 会把他用**企业机**访问高敏资源的权限也一起摘掉——误伤，且用户完全无从理解
// （他那台公司发的电脑昨天还好好的）。准入闸天然就是 (账号,指纹) 粒度，
// 判定落在这里才能只影响那一台。用例 TestPersonalDenyDoesNotAffectEnterpriseDevice 钉住。
const (
	PersonalPolicyInherit = "inherit"
	PersonalPolicyStrict  = "strict"
	PersonalPolicyDeny    = "deny"
)

// PersonalPolicyValid 报告个人资产策略是否为合法枚举。
func PersonalPolicyValid(s string) bool {
	return s == PersonalPolicyInherit || s == PersonalPolicyStrict || s == PersonalPolicyDeny
}

// PersonalPolicyZh 个人资产策略的中文名（审计与控制台同源）。
func PersonalPolicyZh(p string) string {
	switch p {
	case PersonalPolicyStrict:
		return "个人资产按严格准入判定（未批准即拒）"
	case PersonalPolicyDeny:
		return "个人资产一律拒绝接入（含已批准）"
	}
	return "跟随全局准入模式（与企业资产一视同仁）"
}

// ── 资产标签（纯管理属性，**没有执行方**）──
//
// ★标签不参与任何判定：不影响准入、不影响授权、不影响风险评分。它的用途只有
// 台账筛选、导出与资产盘点。这一点必须在 UI 上写明——本项目的纪律是
// 「界面上任何一个勾都必须真能生效」，反过来说，不生效的东西要标明它只是标签，
// 否则管理员会以为给一台机器打上「禁止外网」就真的限制了什么。
//
// 要让某个维度真能控制访问，得给它做一个执行点（像 asset_class 那样落在准入闸上），
// 而不是让它长在一个自由文本字段里。
const (
	// DeviceTagMaxCount 单台设备的标签数上界。标签会随 GET /api/v1/devices 全量下发
	// （那个端点刻意不分页），不设上界等于给台账响应体开一个由管理员自己撑爆的口子。
	DeviceTagMaxCount = 12
	// DeviceTagMaxRunes 单个标签的长度上界（字符）。与 DeviceNameMaxRunes 同一条理由。
	DeviceTagMaxRunes = 24
)

// NormalizeDeviceTags 归一标签集合：去首尾空白 → 丢空串 → 去重（**保序**）→ 逐个截长 →
// 截到 DeviceTagMaxCount。恒返回非 nil 切片（JSON 里是 [] 而不是 null——前端少一处判空）。
//
// 去重按截断**之后**的值比较：两个只在第 25 个字符起才不同的标签，截完就是同一个，
// 留两份只会让筛选器里出现两个看起来一模一样的选项。
func NormalizeDeviceTags(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if r := []rune(t); len(r) > DeviceTagMaxRunes {
			t = string(r[:DeviceTagMaxRunes])
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= DeviceTagMaxCount {
			break
		}
	}
	return out
}

// EmptyDeviceTagsJSON 空标签集合的落库形态（回填值）。
const EmptyDeviceTagsJSON = "[]"

// ParseDeviceTags 把库里的 JSON 文本解回切片。坏值/空值一律回空集合而不是报错：
// 标签没有执行方，一条坏 JSON 不该让设备台账整页读不出来，更不该让敲门链路上的
// DeviceByFingerprint 失败（那一步失败在 strict 下是 fail-closed 拒绝接入）。
func ParseDeviceTags(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	var tags []string
	if json.Unmarshal([]byte(raw), &tags) != nil {
		return []string{}
	}
	return NormalizeDeviceTags(tags)
}

// MarshalDeviceTags 归一后序列化，供落库。
func MarshalDeviceTags(tags []string) string {
	b, err := json.Marshal(NormalizeDeviceTags(tags))
	if err != nil {
		return EmptyDeviceTagsJSON
	}
	return string(b)
}

// MaxDevicesPerAccount 单账号最多留存的终端设备数。
//
// ★这是 trusted_devices 与 posture_reports **共用**的一份上限（两表按 (账号,指纹)
// 一一对应：设备登记走 EnrollDevice、报告落库走 SavePostureReport，删除两侧同删）。
// 此前只有 posture_reports 那边算，设备表一旦独立计数就会出现「设备页显示 20 台、
// 还能再报第 21 台」这种两处不打架不行、打架了又没人看得出来的分歧。
const MaxDevicesPerAccount = 20

// ErrDeviceCap 新设备登记超出单账号上限。判定与写入在同一条 SQL 里原子完成
// （见 SQLiteStore.EnrollDevice），而非 handler 层 check-then-act。
var ErrDeviceCap = errors.New("单账号终端设备数超限")

// ErrDeviceNotFound 设备 id 不存在。
var ErrDeviceNotFound = errors.New("设备不存在")

// ErrApprovalNotFound 审批单 id 不存在。
//
// ★必须与「审批单存在但没有关联设备」区分开：后者是正常路径（auto 绑定 / 迁移遗留），
// 前者是调用方给了一个不存在的 id。混成同一个"静默成功"的话，
// DecideApproval("ap-不存在") 会回 200 并落一条「设备绑定审批 xxx：通过」的审计——
// 审计里出现了一件没发生过的事。
var ErrApprovalNotFound = errors.New("审批单不存在")

// ErrApprovalDecided 审批单已处置（非 pending），不接受重复处置。
//
// ★这道闸挡的是**重放**：closeApprovalTx 对已处置的单子静默返回，而 DecideApproval
// 后半段照常按 approval_id 改设备状态，于是一张已驳回的单子再"通过"一次，
// 就能把 revoked 的设备悄悄改回 trusted，而审批行与时间线仍停在「驳回」——
// 「这台终端当初怎么了」的唯一依据与设备的实际授信状态永久矛盾。
var ErrApprovalDecided = errors.New("审批单已处置，不能重复处置")

// DeviceNameMaxRunes 设备名长度上界（字符）。
//
// ★同一列的写入口径只能有一份：RenameDevice（管理员改名）与 EnrollDevice
// （拿 posture 上报的 os 字段当默认名）都写 trusted_devices.name。此前只有前者限长，
// 于是任何 role=user 的账号上报一次 32 KB 的 os，就能在设备台账、安全审计与
// GET /api/v1/devices（刻意不加 LIMIT）里各塞进一份 32 KB 文本，每账号可重复 20 次。
const DeviceNameMaxRunes = 64

// ClampDeviceName 把设备名截到 DeviceNameMaxRunes（按字符，不切半个汉字）。
// 用于**机器生成**的名字（posture 的 os 字段）：那条路径上没人能改错误提示，
// 截断比拒绝整条上报更合适（拒绝会让终端从此报不上环境，反而丢掉合规判据）。
func ClampDeviceName(s string) string {
	r := []rune(s)
	if len(r) <= DeviceNameMaxRunes {
		return s
	}
	return string(r[:DeviceNameMaxRunes])
}

// DeviceBundle 终端管理页：准入设置 + 设备清单 + 绑定审批队列。
type DeviceBundle struct {
	Settings  DeviceTrustSetting `json:"settings"`
	Devices   []Device           `json:"devices"`
	Approvals []TrustApproval    `json:"approvals"`
}

// DeviceTrustSetting 授信终端的准入与纳管设置（落 settings 表，键 deviceTrustSettingKey）。
type DeviceTrustSetting struct {
	// Mode 准入模式：observe | strict。消费方 api.deviceAdmissionGate（敲门令牌签发）。
	Mode string `json:"mode"`
	// PersonalPolicy 个人资产（asset_class=personal）的准入策略：inherit | strict | deny。
	// 消费方同为 api.deviceAdmissionGate；managed 按企业资产处理，不受它约束。
	// 默认 inherit = 与本功能上线前完全一致的行为。
	PersonalPolicy string `json:"personalPolicy"`
	// BindMethod 绑定方式：auto | approval。消费方 SQLiteStore.EnrollDevice（首次上报的初始状态）。
	BindMethod string `json:"bindMethod"`
	// StaleDays 多少天没上报 posture 即标记陈旧。消费方：Devices() 的 Stale 派生 +
	// PurgeStaleDevices（批量清理的选取条件）。0/负数按 DefaultStaleDays 处理。
	StaleDays int `json:"staleDays"`
	// PerUserQuota 单账号设备上限。**只读**（恒为 MaxDevicesPerAccount）：
	// 上限判定写死在 EnrollDevice / SavePostureReport 的原子 SQL 里，做成可配就要把它
	// 读进两条热路径的 SQL 参数。做不出真实消费方的开关一律不给可编辑入口——
	// 前端按这个值置灰并注明「内置上限」，而不是留一个改了不生效的输入框。
	PerUserQuota int `json:"perUserQuota"`
}

// DefaultStaleDays 陈旧判定的默认天数（未配置时用它）。
const DefaultStaleDays = 30

// DefaultDeviceTrustSetting 未落库时的默认设置。
func DefaultDeviceTrustSetting() DeviceTrustSetting {
	return DeviceTrustSetting{
		Mode: DeviceTrustObserve, BindMethod: DeviceBindApproval,
		StaleDays: DefaultStaleDays, PerUserQuota: MaxDevicesPerAccount,
		PersonalPolicy: PersonalPolicyInherit,
	}
}

// Normalize 把非法/缺省字段收敛到安全默认值（读出与写入都过一遍，避免脏值让判据失效）。
//
// ★Mode 的兜底方向是 observe 而不是 strict：这一项读出脏值时把全体终端挡在门外，
// 与「终端合规 observe 默认」的取舍一致——收缩动作宁可短暂不生效，也不能因为一个
// 拼错的枚举值把所有人锁在门外。真正的 fail-closed 底线由账号状态/posture block 承担。
func (s DeviceTrustSetting) Normalize() DeviceTrustSetting {
	if s.Mode != DeviceTrustStrict {
		s.Mode = DeviceTrustObserve
	}
	if s.BindMethod != DeviceBindAuto {
		s.BindMethod = DeviceBindApproval
	}
	if s.StaleDays <= 0 {
		s.StaleDays = DefaultStaleDays
	}
	if s.StaleDays > 3650 {
		s.StaleDays = 3650
	}
	// ★个人资产策略的兜底方向同样是"最宽的那一档"（inherit）：脏值不该把一批
	// 自带设备静默挡在门外。它与 Mode 的兜底方向一致，理由见该处说明。
	// 存量库里这个键根本不存在（本功能之前落的 JSON 没有这一项），读出来是空串 →
	// inherit，恰好就是"行为不变"这个正确语义，故这一项**不需要单独的回填**。
	if !PersonalPolicyValid(s.PersonalPolicy) {
		s.PersonalPolicy = PersonalPolicyInherit
	}
	s.PerUserQuota = MaxDevicesPerAccount // 只读：永远回内置上限，不接受前端回传值
	return s
}

// Device 一台已登记终端（trusted_devices 的一行 + 读时派生的 posture 现况）。
type Device struct {
	ID          string `json:"id"`
	Account     string `json:"account"`     // 规范化账号（与令牌主体、posture_reports.user 同键）
	Fingerprint string `json:"fingerprint"` // 设备指纹（= posture_reports.device）
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	Status      string `json:"status"` // pending | trusted | revoked
	FirstSeen   int64  `json:"firstSeen"`
	LastSeen    int64  `json:"lastSeen"` // 最近一次 posture 上报时间（陈旧判定的唯一依据）
	// ApprovedBy 批准人账号。迁移回填的存量设备是 DeviceApproverBackfill，
	// 前端据此显示「升级前既有设备」而不是把它冒充成某个管理员的批准动作。
	ApprovedBy   string `json:"approvedBy"`
	ApprovedAt   int64  `json:"approvedAt"`
	ApprovalID   string `json:"approvalId"`   // 关联的绑定审批单 id（approval 绑定模式下非空）
	RevokeReason string `json:"revokeReason"` // 吊销/驳回理由（UI 展示 + 审计取同一份文本）

	// AssetClass 资产分类：enterprise | personal | managed。**是准入判据**——
	// personal 受 DeviceTrustSetting.PersonalPolicy 约束（api.deviceAdmissionGate）。
	AssetClass string `json:"assetClass"`
	// Tags 自由标签。**纯管理属性，没有任何执行方**：不参与准入、授权、风险评分。
	// 只用于台账筛选、导出与资产盘点，UI 上必须照实说明（见 NormalizeDeviceTags 顶部）。
	Tags []string `json:"tags"`

	// ── 以下为读时派生，不落库 ──
	Stale         bool   `json:"stale"`         // LastSeen 早于 now-StaleDays
	OS            string `json:"os"`            // 取自最近一条 posture 报告
	ClientVersion string `json:"clientVersion"` // 同上
	Verdict       string `json:"verdict"`       // 最近 posture 判定；"" = 从未上报成功
	Level         string `json:"level"`
	PostureTS     int64  `json:"postureTs"`
}

// DeviceApproverBackfill 迁移回填给存量设备打的批准人标记（见 backfillTrustedDevices）。
const DeviceApproverBackfill = "(迁移回填)"

// TrustApproval 设备信任绑定申请（含生命周期时间线）。
//
// ★不另起一套审批流：设备生命周期复用这张既有的 approvals 表，
// trusted_devices.approval_id 是两者之间的唯一桥接。DecideApproval 一次事务同时
// 改审批单与设备状态——分成两步的话，「审批通过了但设备还是 pending」会是
// 一个无报错、只在用户连不上时才被发现的状态。
type TrustApproval struct {
	ID          string          `json:"id"`
	User        string          `json:"user"`
	Device      string          `json:"device"`
	Fingerprint string          `json:"fingerprint"`
	SubmittedAt string          `json:"submittedAt"`
	Reason      string          `json:"reason"`
	Status      string          `json:"status"` // pending | approved | rejected
	Timeline    []ApprovalEvent `json:"timeline"`
}

type ApprovalEvent struct {
	Time   string `json:"time"`
	Kind   string `json:"kind"` // submit | login | review | notify | risk
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// Memory 无设备种子。
//
// ★这里刻意不给演示设备（与 alerts 同一条纪律，也是本轮从种子改成真实现的原因）：
// 编造的「已授信终端」清单会让人以为设备纳管正在运行，而"哪些终端被允许接入"
// 是安全声明，不是装饰性数据。控制台在后端不可达时显示"未连"，不降级演示。
func (m *Memory) Devices(_ context.Context) (DeviceBundle, error) {
	return DeviceBundle{
		Settings:  DefaultDeviceTrustSetting(),
		Devices:   []Device{},
		Approvals: []TrustApproval{},
	}, nil
}

// DeviceByFingerprint Memory 无设备（敲门设备闸在无 SQLite 时恒判"未登记"）。
func (m *Memory) DeviceByFingerprint(_ context.Context, _, _ string) (Device, bool, error) {
	return Device{}, false, nil
}

// DeviceTrustSetting Memory 恒回默认（observe + 审批绑定）。
func (m *Memory) DeviceTrustSetting(_ context.Context) (DeviceTrustSetting, error) {
	return DefaultDeviceTrustSetting(), nil
}
