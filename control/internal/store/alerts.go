package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// ── 业务告警实体与规则（PRD ch5 FR-MON-21~25）──
//
// 与 audit_log 的分工必须说清楚，否则这一层就是重复造轮子：
// audit_log 是**流水**（谁在什么时候做了什么，只追加、不可处置、按时间读）；
// alerts 是**实体**（一条待办：有类别、有严重度、有 pending/ignored/handled 状态机、
// 有 triggered_at 与 handled_by）。「谁值班时把这条异常处理掉了」这件事，流水表达不了。
//
// ★本文件里的每一个 AlertKind 都必须对应一份**真实存在的信号**。
// 规则是「读某份真实数据 + 判个阈值」，不是「先建个开关，将来接」——
// 为不存在的信号建规则，等于造一条永远不触发的死规则，而页面上它看起来是开着的。
// 各 kind 的信号出处逐条写在 alertKindSpecs 里，评估实现在 internal/alerting。

// 告警类别（PRD 要求的两大类 + 安全事件类）。
const (
	// AlertCategoryDevice 设备异常：网关心跳超时离线、网关资源水位超阈值。
	AlertCategoryDevice = "device"
	// AlertCategoryAuthz 授权信息：JIT 授予即将到期 / 已过期未回收、应用未关联受控资源。
	AlertCategoryAuthz = "authz"
	// AlertCategorySecurity 安全事件：账号爆破锁定、终端 posture 判 block、审计链校验失败。
	AlertCategorySecurity = "security"
)

// AlertCategoryZh 类别中文名（审计文案与前端标签共用一份，免得两处叫法不一致）。
var AlertCategoryZh = map[string]string{
	AlertCategoryDevice:   "设备异常",
	AlertCategoryAuthz:    "授权信息",
	AlertCategorySecurity: "安全事件",
}

// ValidAlertCategory 报告类别是否合法。
func ValidAlertCategory(c string) bool { _, ok := AlertCategoryZh[c]; return ok }

// 告警状态机：pending（未处理）→ ignored（已忽略）| handled（已处理）。
// 只能从 pending 迁出，见 SetAlertStatus。
const (
	AlertPending = "pending"
	AlertIgnored = "ignored"
	AlertHandled = "handled"
)

// AlertStatusZh 状态中文名。
var AlertStatusZh = map[string]string{
	AlertPending: "未处理", AlertIgnored: "已忽略", AlertHandled: "已处理",
}

// ValidAlertStatus 报告状态是否合法。
func ValidAlertStatus(s string) bool { _, ok := AlertStatusZh[s]; return ok }

// 严重度。info < warning < critical，仅用于排序与着色，不参与任何判定。
const (
	AlertSevInfo     = "info"
	AlertSevWarning  = "warning"
	AlertSevCritical = "critical"
)

// 规则种类。每一项都在 alertKindSpecs 里登记它读的是哪份真实信号。
const (
	// AlertKindGatewayOffline 网关心跳超时离线（判据与 api.gatewayOnlineWindow 同源）。
	AlertKindGatewayOffline = "gateway_offline"
	// AlertKindGatewayLoad 网关 CPU/内存/磁盘超阈值。信号来自 gateway_metrics 表——
	// 该表由数据面资源指标上报（另一项任务）建立，**尚未落地**：探测不到表或表里没有
	// 数据时，规则如实报「等待数据面上报」而不是装作在监控（见 GatewayMetricsProbe）。
	AlertKindGatewayLoad = "gateway_load"
	// AlertKindGrantExpiring JIT 授予即将到期（提前量可配）。
	AlertKindGrantExpiring = "grant_expiring"
	// AlertKindGrantStale JIT 授予已过期但行仍是 active（惰性回收没被触发，授权清单上是失真的）。
	AlertKindGrantStale = "grant_stale"
	// AlertKindAppUnlinked 应用未关联受控资源（apps.resource_id 为空）。
	// ★方向是「应用→资源」而不是「资源→应用」：断的是这一头才有真实后果——
	// JIT 解析不出资源、客户端剖面排不出路由，两处都无报错（剖面 warnings 已有同一条信号）。
	AlertKindAppUnlinked = "app_unlinked"
	// AlertKindAccountLockout 账号/源 IP 因连续登录失败被锁定（登录防爆破 Guard 的生效锁定）。
	AlertKindAccountLockout = "account_lockout"
	// AlertKindPostureBlock 终端合规判定 block（该账号已被拒发敲门令牌 + 撤窗断隧道）。
	AlertKindPostureBlock = "posture_block"
	// AlertKindClockSkew 网关时钟偏差超阈值。信号来自注册心跳里网关自报的本机时钟
	// 与控制面收包时刻的差。★它守的是敲门链路的一个隐性前提：敲门令牌是控制面按
	// 自己的钟签的（knockTTL），验它的却是网关的钟——两侧漂过有效期，合法客户端的
	// 每次敲门都以"过期"被拒，SPA 又是单包无回应的，客户端连错误都看不到。
	// 旧网关不上报时钟：该网关不参与判定（不可判定 ≠ 偏差 0）。
	AlertKindClockSkew = "clock_skew"
	// AlertKindLicenseExpiry License 将到期/已过期/无效。信号 = settings 里的 license blob
	// 经 license.Evaluate 现算的状态（与 GET /api/v1/license、容量闸同一份判定）。
	// ★license 的容量闸是 fail-closed 的（过期即拒建号拒签网关证书）——无预警等于
	// 定时故障，这条把「会突然咬人」补成「先叫后咬」。demo 模式不产生候选。
	AlertKindLicenseExpiry = "license_expiry"
	// AlertKindLicenseSeats License 席位将满（用户/网关任一维占用率超阈值）。
	AlertKindLicenseSeats = "license_seats"
	// AlertKindAuditWriteFail 控制面**自己**没能把审计写进库。
	// ★信号是 api 层的进程内计数（每次 RecordAudit 返回错误 +1），不是查库得来的——
	// 恰恰因为库可能正是坏掉的那一环。这也是本组唯一一条看控制面自身存储的规则：
	// 此前 11 条规则里，gateway_load 看的是**数据面**的盘，没有一条看控制面。
	//
	// ★这条规则有一段自己够不着的盲区，必须写下来：整盘写满时 RaiseAlert 同样落不了库，
	// 告警产生不出来。它覆盖的是可恢复的那半（写锁争用、单表权限、瞬时 I/O 错误）。
	// 不可恢复的那半由 slog.Error 与 /diag 的 audit-write 兜底（都不依赖写库）。
	AlertKindAuditWriteFail = "audit_write_fail"
	// AlertKindAuditChain 审计防篡改链周期性自检失败。
	// ★这条是本组里最该存在的一条：防篡改链没人定期查就等于没有——
	// 篡改发生到被发现之间的窗口，取决于有没有人手动点那个「校验」按钮。
	AlertKindAuditChain = "audit_chain"
	// AlertKindAuditForwardFail 审计外送出口持续投递失败 / 队列积压。
	//
	// ★这条此前不存在，而外送失败的信号面**只有两处**：进程日志一行 slog.Warn，
	// 与系统页里那一格 lastStatus。没有告警、没有 /diag 项、消息通道也不发。
	// 后果是合规链路**静默断掉**：审计照常落本地库、页面一切正常，
	// 而 SIEM 那边从某一刻起再也没收到过东西，直到有人主动去翻那一格才发现。
	// 队列本身是可靠的（成功才出队、失败退避重试），但它有上界——
	// 积压到顶就开始丢新的，那时才发现已经晚了。
	AlertKindAuditForwardFail = "audit_forward_fail"
)

// 冷却期边界（秒）。默认 30 分钟。
//
// ★冷却不是"少发点通知"的体面话，而是可用性前提：网关离线这类条件会持续成立，
// 评估循环每分钟跑一次的话，一小时就是 60 条同样的告警，告警页当场不可用、
// 真正的新告警被冲走。冷却按 (规则, 对象) 计，只看时间**不看状态**——
// 按状态放宽（如"处理完就允许再报"）会让人一点「已处理」就立刻冒出同一条。
const (
	DefaultAlertCooldownSec = 1800
	MinAlertCooldownSec     = 60
	MaxAlertCooldownSec     = 86400
)

// ClampAlertCooldown 把冷却期钳进 [Min,Max]；0（未填）取默认值。
func ClampAlertCooldown(sec int) int {
	if sec <= 0 {
		return DefaultAlertCooldownSec
	}
	if sec < MinAlertCooldownSec {
		return MinAlertCooldownSec
	}
	if sec > MaxAlertCooldownSec {
		return MaxAlertCooldownSec
	}
	return sec
}

// AlertKindSpec 一种告警规则的元信息：它读哪份真实信号、有哪些可调阈值。
// 前端的规则编辑器与后端的保存校验都吃这一份——两处各写一份阈值清单，
// 迟早出现"界面上能填、后端不认"或反过来。
type AlertKindSpec struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Category string `json:"category"`
	// Severity 该 kind 产生的告警严重度（固定，不由管理员改——严重度是语义不是偏好）。
	Severity string `json:"severity"`
	// Signal 触发源的**事实描述**：这条规则到底在读什么。写给排障的人看。
	Signal string `json:"signal"`
	// Thresholds 可调阈值键 → 默认值。空 map = 该规则无阈值。
	Thresholds map[string]float64 `json:"thresholds"`
	// ThresholdZh 阈值键的中文说明（前端表单标签）。
	ThresholdZh map[string]string `json:"thresholdZh"`
}

// 阈值键（字符串常量集中一处，评估侧与默认值表都引用它，拼错就编译不过）。
const (
	ThreshOfflineSec   = "offlineSec"
	ThreshCPUPercent   = "cpuPercent"
	ThreshMemPercent   = "memPercent"
	ThreshDiskPercent  = "diskPercent"
	ThreshBeforeMin    = "beforeMinutes"
	ThreshGraceMinutes = "graceMinutes"
	ThreshSkewSec      = "skewSec"
	ThreshExpireDays   = "expireDays"
	ThreshSeatPercent  = "seatPercent"
	ThreshWithinMin    = "withinMinutes"
	// ThreshBacklogPercent 队列积压占上界的比例（%）。
	ThreshBacklogPercent = "backlogPercent"
)

// alertKindSpecs 全部规则种类。**新增一项前先回答：它读的那份数据现在真的存在吗？**
var alertKindSpecs = []AlertKindSpec{
	{
		Kind: AlertKindGatewayOffline, Name: "网关心跳超时离线", Category: AlertCategoryDevice,
		Severity:   AlertSevCritical,
		Signal:     "控制面 mTLS 注册表里该网关的 lastSeen 超过阈值未刷新（与在线判据 gatewayOnlineWindow 同源）",
		Thresholds: map[string]float64{ThreshOfflineSec: 120},
		ThresholdZh: map[string]string{
			ThreshOfflineSec: "心跳超时（秒）",
		},
	},
	{
		Kind: AlertKindGatewayLoad, Name: "网关资源水位超阈值", Category: AlertCategoryDevice,
		Severity: AlertSevWarning,
		Signal:   "gateway_metrics 表中该网关最近一次上报的 CPU / 内存 / 磁盘占用（该表由数据面指标上报任务建立，未接入时如实回「等待数据面上报」）",
		Thresholds: map[string]float64{
			ThreshCPUPercent: 85, ThreshMemPercent: 85, ThreshDiskPercent: 90,
		},
		ThresholdZh: map[string]string{
			ThreshCPUPercent: "CPU 占用（%）", ThreshMemPercent: "内存占用（%）", ThreshDiskPercent: "磁盘占用（%）",
		},
	},
	{
		Kind: AlertKindGrantExpiring, Name: "JIT 授予即将到期", Category: AlertCategoryAuthz,
		Severity:   AlertSevInfo,
		Signal:     "jit_grants 中 status=active 且 expires_at 落在提前量窗口内的授予",
		Thresholds: map[string]float64{ThreshBeforeMin: 30},
		ThresholdZh: map[string]string{
			ThreshBeforeMin: "提前提醒（分钟）",
		},
	},
	{
		Kind: AlertKindGrantStale, Name: "JIT 授予已过期未回收", Category: AlertCategoryAuthz,
		Severity:   AlertSevWarning,
		Signal:     "jit_grants 中 expires_at 已过、status 仍为 active 的行（网关侧已不再放行，但授权清单显示的是失真状态）",
		Thresholds: map[string]float64{ThreshGraceMinutes: 10},
		ThresholdZh: map[string]string{
			ThreshGraceMinutes: "过期宽限（分钟）",
		},
	},
	{
		Kind: AlertKindAppUnlinked, Name: "应用未关联受控资源", Category: AlertCategoryAuthz,
		Severity: AlertSevWarning,
		Signal: "apps 中 status=running、mode≠global，且「未关联资源」或「关联的资源已不存在」的应用" +
			"（与客户端接入剖面的 warnings 同一条判据；直连书签不经网关、本就不需要资源，故排除）",
		Thresholds:  map[string]float64{},
		ThresholdZh: map[string]string{},
	},
	{
		Kind: AlertKindAccountLockout, Name: "账号爆破锁定", Category: AlertCategorySecurity,
		Severity:    AlertSevWarning,
		Signal:      "登录防爆破守卫（internal/lockout.Guard）当前生效的锁定条目——就是登录链路正在执行的那一份",
		Thresholds:  map[string]float64{},
		ThresholdZh: map[string]string{},
	},
	{
		Kind: AlertKindPostureBlock, Name: "终端合规判定阻断", Category: AlertCategorySecurity,
		Severity:    AlertSevCritical,
		Signal:      "posture_reports 中任一设备最新判定为 block 的账号（与拒发敲门令牌、撤窗断隧道同一份名单）",
		Thresholds:  map[string]float64{},
		ThresholdZh: map[string]string{},
	},
	{
		Kind: AlertKindClockSkew, Name: "网关时钟偏差超阈值", Category: AlertCategoryDevice,
		Severity: AlertSevWarning,
		Signal: "注册心跳里网关自报的本机时钟（now 字段）与控制面收包时刻的差；" +
			"旧网关不上报该字段则不参与判定（不可判定，不是偏差 0）",
		Thresholds: map[string]float64{ThreshSkewSec: 10},
		ThresholdZh: map[string]string{
			ThreshSkewSec: "允许偏差（秒）",
		},
	},
	{
		Kind: AlertKindLicenseExpiry, Name: "License 将到期 / 已失效", Category: AlertCategorySecurity,
		Severity: AlertSevWarning,
		Signal: "settings 里的 license 记录经 license.Evaluate 现算的状态——与 License 页、" +
			"建号/签证书的容量闸完全同一份判定；demo（未导入）不产生候选",
		Thresholds:  map[string]float64{ThreshExpireDays: 15},
		ThresholdZh: map[string]string{ThreshExpireDays: "到期前提醒（天）"},
	},
	{
		Kind: AlertKindLicenseSeats, Name: "License 席位将满", Category: AlertCategorySecurity,
		Severity: AlertSevWarning,
		Signal: "users 全表计数 / 未吊销证书的去重网关数，对照 license 容量上限——" +
			"与 GET /api/v1/license 的 usage 同口径；该维不限（0）时不判",
		Thresholds:  map[string]float64{ThreshSeatPercent: 90},
		ThresholdZh: map[string]string{ThreshSeatPercent: "占用率提醒（%）"},
	},
	{
		Kind: AlertKindAuditWriteFail, Name: "审计写入失败", Category: AlertCategorySecurity,
		Severity: AlertSevCritical,
		Signal: "控制面进程内计数：auditAs/auditBG 调 RecordAudit 返回错误的次数（= 丢失的审计条数）。" +
			"★不查库——库本身可能就是坏掉的那一环；也正因如此，整盘写满时这条规则自己也产生不出来，" +
			"那种情况看进程日志与 /diag 的「审计写入链路」",
		Thresholds:  map[string]float64{ThreshWithinMin: 60},
		ThresholdZh: map[string]string{ThreshWithinMin: "最近多少分钟内失败才报（分钟）"},
	},
	{
		Kind: AlertKindAuditForwardFail, Name: "审计外送投递失败", Category: AlertCategorySecurity,
		Severity: AlertSevCritical,
		Signal: "audit_forward_targets 里**启用中**出口的 last_status / last_ok_at，" +
			"以及现算的队列积压（audit_forward_queue 计数）与累计丢弃数 dropped。" +
			"★没有启用中的出口时一条候选都不产生——别给没用这个功能的部署常年挂告警",
		Thresholds: map[string]float64{
			ThreshWithinMin:      30,
			ThreshBacklogPercent: 50,
		},
		ThresholdZh: map[string]string{
			ThreshWithinMin:      "多久没有成功投递过才报（分钟）",
			ThreshBacklogPercent: "队列积压占上界多少比例才报（%）",
		},
	},
	{
		Kind: AlertKindAuditChain, Name: "审计防篡改链校验失败", Category: AlertCategorySecurity,
		Severity:    AlertSevCritical,
		Signal:      "周期性重算 audit_log 的 HMAC-SM3 全链（与 GET /api/v1/audit/verify 同一实现）",
		Thresholds:  map[string]float64{},
		ThresholdZh: map[string]string{},
	},
}

// AlertKindSpecs 返回全部规则种类元信息（副本，调用方改不到内部状态）。
func AlertKindSpecs() []AlertKindSpec {
	out := make([]AlertKindSpec, 0, len(alertKindSpecs))
	for _, s := range alertKindSpecs {
		out = append(out, cloneKindSpec(s))
	}
	return out
}

// AlertKindSpecOf 按 kind 取元信息。
func AlertKindSpecOf(kind string) (AlertKindSpec, bool) {
	for _, s := range alertKindSpecs {
		if s.Kind == kind {
			return cloneKindSpec(s), true
		}
	}
	return AlertKindSpec{}, false
}

func cloneKindSpec(s AlertKindSpec) AlertKindSpec {
	th := make(map[string]float64, len(s.Thresholds))
	for k, v := range s.Thresholds {
		th[k] = v
	}
	zh := make(map[string]string, len(s.ThresholdZh))
	for k, v := range s.ThresholdZh {
		zh[k] = v
	}
	s.Thresholds, s.ThresholdZh = th, zh
	return s
}

// ErrUnknownAlertKind 规则 kind 不在 alertKindSpecs 里——它背后没有任何信号，拒绝保存。
var ErrUnknownAlertKind = errors.New("未知的告警规则种类")

// ErrUnknownThreshold 阈值键不属于该 kind。★不静默丢弃：丢掉的话管理员以为自己调了阈值，
// 实际评估用的还是默认值——又一处"配置齐全却不生效"。
var ErrUnknownThreshold = errors.New("该规则不支持此阈值项")

// ErrThresholdRange 阈值超出该键的取值区间。用 errors.Is 判（错误正文里带的是
// 具体哪一项、越了哪一边、后果是什么——那句话要原样进 400 body 给管理员看）。
var ErrThresholdRange = errors.New("告警阈值超出取值区间")

// thresholdBound 一个阈值键的取值区间与"越界后果"。
//
// ★为什么必须有下界：改造前 NormalizeThresholds **只校验键认不认识、完全不看值**，
// 于是控制台那个阈值输入框被清空的瞬间（Arco InputNumber emit change(undefined)，
// 前端兜成 0）就会把 0 落库，接口回 200、toast 说「规则「网关离线」已保存」、
// 绿色「已启用」开关一字不变，而规则的行为已经翻到了另一端：
// expireDays 15 → 0：License 到期前不再有任何提醒（到期那天容量闸 fail-closed 直接咬人）；
// beforeMinutes 30 → 0：JIT 将到期提醒永不触发；
// withinMinutes 30 → 0：审计外送"投不出去"那一支在 alerting 里被 `within > 0` 挡住，永不触发；
// offlineSec 120 → 0：每台在线网关每轮都被判离线，冷却一到就刷一条告警 + 一封邮件。
// 两个方向（永不触发 / 每轮都触发）都不报错，都是"配置齐全却不生效"那一族。
//
// ★区间是**拒绝**不是夹取：夹取会让管理员拿到 200 OK 而实际生效的是另一个数，
// 与 IdlePolicy.Validate 那条「入口不许比实现宽」同源。
//
// Max<=0 表示不设上界（秒/分/天这类没有天然天花板；冷却期另有 ClampAlertCooldown 管）。
type thresholdBound struct {
	Min, Max float64
	// Why 低于下界会发生什么（进 400 正文——只说"不合法"会让管理员反复换数字试）。
	Why string
}

// thresholdBounds 逐键的取值区间。**没有一条通用规则**：同一个 0，对 graceMinutes
// 是合法配置（过期即报，不留宽限），对 beforeMinutes 是"提醒永不触发"。
// 谁能取 0 必须逐个照着 internal/alerting 里那段判定读出来，不许拍脑袋统一。
var thresholdBounds = map[string]thresholdBound{
	// 网关心跳每 15s 一次。低于两个心跳周期，所有在线网关都会在心跳间隙被判成离线。
	// ★0 的真实后果是**静默回落**不是误报：alerting 里 `limit := thresh(...)` 之后紧跟
	// `if limit <= 0 { limit = snap.OfflineAfterSec }`，判定按全局默认走，一点没变。
	// 文案必须说这个——写成"每轮都误报"会把管理员支去调冷却期，而该看的是这个值本身。
	ThreshOfflineSec: {Min: 30, Why: "0 会被静默回落成全局默认值：你改了配置、页面显示已保存，而判定一点没变；" +
		"30 以下（但大于 0）则低于两个心跳周期，每一台在线网关都会在心跳间隙被判成离线"},
	// 占用率三项：0 表示"任何占用都超标"（恒触发），>100 表示永不触发。
	ThreshCPUPercent:  {Min: 1, Max: 100, Why: "0 表示任何占用都算超标，该规则会对每台网关恒触发"},
	ThreshMemPercent:  {Min: 1, Max: 100, Why: "0 表示任何占用都算超标，该规则会对每台网关恒触发"},
	ThreshDiskPercent: {Min: 1, Max: 100, Why: "0 表示任何占用都算超标，该规则会对每台网关恒触发"},
	// 提前量 0 = 窗口为空，"即将到期"这条规则永不触发（到期后由 grant_stale 接手，但那已经晚了）。
	ThreshBeforeMin: {Min: 1, Why: "提前量为 0 时窗口为空，「即将到期」永不触发，等于关掉了这条规则"},
	// ★宽限期 0 是**合法**的：alerting 里判的是 overdue < grace，0 = 过期即报。不设下界。
	ThreshGraceMinutes: {Min: 0},
	// 偏差 0 = 任何亚秒级抖动都算超标，每轮每台网关都报。
	// ★同 offlineSec：`if limit <= 0 { limit = 10 }`，0 是静默回落不是恒触发。
	ThreshSkewSec: {Min: 1, Why: "0 会被静默回落成默认的 10 秒：你改了配置、页面显示已保存，而判定一点没变"},
	// 到期前提醒 0 天 = 只有真的过期了才叫，而过期那一刻容量闸已经在拒建号拒签证书。
	ThreshExpireDays: {Min: 1, Why: "0 天表示不做任何到期前预警，等 License 过期那天容量闸直接拒建号、拒签网关证书"},
	ThreshSeatPercent: {Min: 1, Max: 100,
		Why: "0% 表示任何占用都算将满，该规则恒触发"},
	// ★同一个键在两条规则里语义相反：audit_write_fail 的 `within > 0` 是"不看时间窗、一直报"，
	// audit_forward_fail 的 `within > 0` 是那一支的**前置条件**，取 0 直接让"投不出去"永不触发。
	// 一个在两处含义相反的 0 不该是可配置的值。
	ThreshWithinMin: {Min: 1, Why: "0 分钟在「审计外送投递失败」里会让「持续投不出去」那一支永不触发"},
	// ★方向与直觉相反：alerting 那一支的条件是 `if pct > 0 && …`，0 直接被短路。
	// 旧文案写的是"恒触发"，**完全说反了**——管理员照着理解会以为调低是"更灵敏"，
	// 实际是把这条判定整条关掉，而队列丢新保旧的丢弃是不可逆的。
	ThreshBacklogPercent: {Min: 1, Max: 100,
		Why: "0% 会让「队列积压」那一支被 `pct > 0` 短路，该条件永不触发（不是恒触发）"},
}

// checkThresholdRange 校验单个阈值取值。zh 是该键的中文标签（进错误正文——
// 报 "backlogPercent 超范围" 管理员要回去对着代码猜是页面上哪一栏）。
func checkThresholdRange(key, zh string, v float64) error {
	b, ok := thresholdBounds[key]
	if !ok {
		// 新增阈值键忘了登记区间：不拦（保持可用），但这是个应当补上的疏漏。
		return nil
	}
	label := zh
	if label == "" {
		label = key
	}
	if v < b.Min {
		msg := fmt.Sprintf("阈值「%s」不能小于 %s（当前 %s）", label, trimNum(b.Min), trimNum(v))
		if b.Why != "" {
			msg += "：" + b.Why
		}
		return fmt.Errorf("%w：%s", ErrThresholdRange, msg)
	}
	if b.Max > 0 && v > b.Max {
		return fmt.Errorf("%w：阈值「%s」不能大于 %s（当前 %s）：超过上界后该条件永远不成立，规则看着是启用的却永不触发",
			ErrThresholdRange, label, trimNum(b.Max), trimNum(v))
	}
	return nil
}

// trimNum 阈值是 float64 但管理员填的都是整数：把 "30" 印成 30 而不是 30.000000。
func trimNum(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// ErrAlertDecided 告警已被处置（非 pending），不接受二次处置。调用方回 409。
var ErrAlertDecided = errors.New("该告警已处置")

// ErrAlertNotFound 告警不存在。
var ErrAlertNotFound = errors.New("告警不存在")

// NormalizeThresholds 校验并补齐某 kind 的阈值：未知键报错、**越界报错**、缺失键补默认值。
//
// ★取值区间这一道是后端兜底：前端那个输入框此前被清空就会提交 0，而这里只看键、
// 不看值，于是 0 一路落库。前端已改成"清空即不提交"，但客户端不是唯一入口
// （API 可以直接 POST），且下一次改前端的人不一定记得这条——判据必须在执行侧也成立。
func NormalizeThresholds(kind string, in map[string]float64) (map[string]float64, error) {
	spec, ok := AlertKindSpecOf(kind)
	if !ok {
		return nil, ErrUnknownAlertKind
	}
	out := make(map[string]float64, len(spec.Thresholds))
	for k, v := range spec.Thresholds {
		out[k] = v
	}
	for k, v := range in {
		if _, known := spec.Thresholds[k]; !known {
			return nil, ErrUnknownThreshold
		}
		if err := checkThresholdRange(k, spec.ThresholdZh[k], v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

// AlertRule 一条告警规则。
type AlertRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Threshold 阈值（threshold_json）。键集合由 kind 决定，见 NormalizeThresholds。
	Threshold map[string]float64 `json:"threshold"`
	Enabled   bool               `json:"enabled"`
	// Channels 通知通道（channels_json）。留空=发往全部启用中的通道；点名则只发这几条。
	// 保存时校验通道是否存在（点名不存在的通道即拒），发送经 internal/notify 真实投递，
	// 失败/通道停用/通道已删三种情况都落审计——不存在「假的已发送」。
	Channels []string `json:"channels"`
	// CooldownSec 冷却期。不是塞进 threshold_json 而是独立成列：它对所有 kind 都生效，
	// 且是告警页可用性的硬约束，混进各 kind 自己的阈值里迟早被某个 kind 漏掉。
	CooldownSec int    `json:"cooldownSec"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

// Alert 一条已产生的告警（待办实体）。
type Alert struct {
	ID       string `json:"id"`
	RuleID   string `json:"ruleId"`
	Kind     string `json:"kind"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	// ObjectKey 告警对象的稳定标识（如 gw:gw-01 / grant:g-123 / posture:ext.zhao）。
	// 去重键是 (rule_id, object_key)：没有它就只能按规则去重，于是"三台网关同时离线"
	// 只会留下一条告警，另外两台在页面上根本不存在。
	ObjectKey   string `json:"objectKey"`
	Status      string `json:"status"`
	TriggeredAt int64  `json:"triggeredAt"`
	HandledAt   int64  `json:"handledAt,omitempty"`
	HandledBy   string `json:"handledBy,omitempty"`
}

// AlertQuery 告警列表过滤条件。零值 = 不限。
type AlertQuery struct {
	Status   string // pending | ignored | handled
	Category string // device | authz | security
	From     int64  // triggered_at >= From（Unix 秒）
	To       int64  // triggered_at <= To
	Limit    int    // 0 = 默认上限
}

// AlertCounts 按状态的计数（角标与页头统计的唯一来源）。
type AlertCounts struct {
	Pending int `json:"pending"`
	Ignored int `json:"ignored"`
	Handled int `json:"handled"`
}

// MetricsProbe 网关资源指标数据源的**运行时探测**结论。
//
// ★为什么要运行时探测而不是写死一个开关：gateway_metrics 由数据面指标上报那条链路建立，
// 它可能先于、也可能后于本模块合入。写死"没有"会让链路接上后规则依然不动（静默失效）；
// 写死"有"则会在表不存在时每轮报错。探测的另一半价值是**如实告诉管理员为什么不触发**——
// 表不存在 / 表里还没有数据 / 表结构对不上，三种情况的下一步动作完全不同。
type MetricsProbe struct {
	// Ready 数据源可用（表存在、列齐全、且至少有一条上报）。
	Ready bool `json:"ready"`
	// Reason Ready=false 时的事实说明（直接呈现给管理员）。
	Reason string `json:"reason"`
	// Samples 各网关最近一次上报（Ready=false 时为空）。
	Samples []GatewayMetricSample `json:"samples,omitempty"`
}

// GatewayMetricSample 一台网关最近一次资源指标上报。
//
// ★三项都是**可空**的：nil = 网关如实报告"这一项采不到"，不是 0。
// 塌缩成 0 会让一台采集失明的网关看起来永远空闲，超阈值规则对它永久沉默——
// 与终端 posture 的 unknown 三态是同一条纪律。评估侧只比较非 nil 的项。
type GatewayMetricSample struct {
	GatewayID string   `json:"gatewayId"`
	CPU       *float64 `json:"cpu"`  // 百分比 0-100
	Mem       *float64 `json:"mem"`  // 百分比 0-100
	Disk      *float64 `json:"disk"` // 百分比 0-100
	TS        int64    `json:"ts"`   // 上报时刻 Unix 秒
}

// ── Memory 空实现（真实数据域：没有种子告警）──
//
// ★刻意不给种子：编造几条"未处理告警"会让这一页在没接后端时看起来正在工作，
// 而告警恰恰是那种"看起来有=以为被监控着"的页面，假数据在这里的代价比别处大。

func (m *Memory) Alerts(context.Context, AlertQuery) ([]Alert, error)  { return []Alert{}, nil }
func (m *Memory) CountAlerts(context.Context, AlertQuery) (int, error) { return 0, nil }
func (m *Memory) AlertRules(context.Context) ([]AlertRule, error)      { return []AlertRule{}, nil }
func (m *Memory) AlertCounts(context.Context) (AlertCounts, error)     { return AlertCounts{}, nil }

// StaleGrants Memory 空实现（JIT 授予只有 SQLite 承载真实数据）。
func (m *Memory) StaleGrants(context.Context, int64) ([]JitGrant, error) { return []JitGrant{}, nil }
