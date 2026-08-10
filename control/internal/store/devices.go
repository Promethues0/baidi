package store

import (
	"context"
	"errors"
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
