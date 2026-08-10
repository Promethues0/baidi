package store

import (
	"context"
	"errors"
)

// MaxPostureDevices 单账号最多留存的终端设备报告数（防用随机 device 无界撑大 posture_reports）。
const MaxPostureDevices = 20

// ── 风险处置四档：每一档的**可执行**语义 ──
//
// 四个常量不是标签，每一档都有确定的执行方（无执行方的档位就是 config-only，本项目已吃过亏）：
//
//	DisposalAllow   放行。不做任何收缩。
//	DisposalGray    灰度观察。**访问权一字不改**，但控制面每轮下发策略时为该账号记一条
//	                 observing 审计（api.handleGatewayPolicy → auditGrayObserved），
//	                 用户状态页据此显示「灰度观察」。它是"看着"，不是"拦着"。
//	DisposalDegrade 降权而非断连。该账号仍可访问 low/normal 敏感度的资源，但**高敏资源
//	                 （Resource.Sensitivity=high）被摘除**：网关侧经 gwResource.DenyUsers
//	                 否决、客户端剖面侧同步剔除路由（两处同构，见 api/subjects.go）。
//	DisposalBlock   全断。拒发敲门令牌 + 并入撤销名单撤放行窗 + 断隧道（既有行为，未改）。
//
// ★排序是 allow < gray < degrade < block，gray **低于** degrade：灰度观察不改变任何
// 访问权，而降权真的摘掉了高敏资源。这两档在有执行方之前谁前谁后无所谓，现在有了——
// 若把 gray 排在 degrade 之上，一台同时命中「gray 基线」与「degrade 基线」的终端会被判成
// gray，降权于是静默失效（页面上看不出任何异常，因为判定本身"成功"了）。
const (
	DisposalAllow   = "allow"
	DisposalGray    = "gray"
	DisposalDegrade = "degrade"
	DisposalBlock   = "block"
)

// disposalRank 处置严厉度排序的**唯一定义处**。
// 此前这张表在 risk.go、posture_sqlite.go、monitor_sqlite.go 各抄了一份，
// 三份口径靠人肉保持一致；改一处漏两处的后果是"跨设备取最差"在不同页面给出不同答案。
var disposalRank = map[string]int{
	DisposalAllow: 0, DisposalGray: 1, DisposalDegrade: 2, DisposalBlock: 3,
}

// DisposalRank 处置严厉度排序值（block 最严）；未知处置视为 allow。
func DisposalRank(d string) int { return disposalRank[d] }

// ErrPostureDeviceCap 新设备写入超出单账号上限。上限判定与写入在同一条 SQL 里原子完成
// （见 SQLiteStore.SavePostureReport），而非 handler 层 check-then-act——后者在并发突发下会越过上限。
var ErrPostureDeviceCap = errors.New("单账号终端设备数超限")

// PostureCheckResult 终端上报的一条检查结果（客户端机械布尔化 + 原始值，策略判定在控制面）。
//
// ★三态而非两态：Unknown 表示这项**探不到**（命令缺失 / 权限不足 / 输出无法解释），
// 既不是合规也不是不合规。塌缩成 OK=false 会把真实合规的终端误拒（Linux 非 root 读不到
// 防火墙状态是常态），塌缩成 OK=true 则是误放行。两种错法都很难从页面上看出来，
// 因为报告本身长得完全正常。判定见 risk.Evaluate：observe 下不抬处置、只单列可见，
// strict（BAIDI_POSTURE_ENFORCE=strict）下视为不合规。
//
// 无补列迁移：checks 整列以 JSON 落库（posture_sqlite.go），旧行反序列化后 Unknown=false，
// 恰好等于旧的两态语义。
type PostureCheckResult struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	OK      bool   `json:"ok"`
	Unknown bool   `json:"unknown"` // 探测不可判定（优先于 OK：Unknown=true 时 OK 无意义）
	Value   string `json:"value"`
}

// PostureReport 一台终端设备的最新环境报告 + 风险引擎判定（每 (user,device) 只存最新）。
type PostureReport struct {
	User          string               `json:"user"`   // 规范化账号
	Device        string               `json:"device"` // 设备指纹
	Platform      string               `json:"platform"`
	OS            string               `json:"os"`
	ClientVersion string               `json:"clientVersion"`
	Checks        []PostureCheckResult `json:"checks"`
	Verdict       string               `json:"verdict"` // allow | degrade | gray | block
	Score         int                  `json:"score"`
	Level         string               `json:"level"` // low | medium | high
	Reasons       []string             `json:"reasons"`
	TS            int64                `json:"ts"`
}

// Memory 无 posture 来源（posture 只来自真实上报，不造种子）。
func (m *Memory) PostureReports(_ context.Context) ([]PostureReport, error) {
	return []PostureReport{}, nil
}

func (m *Memory) PostureVerdict(_ context.Context, _ string) (PostureReport, bool, error) {
	return PostureReport{}, false, nil
}

func (m *Memory) PostureReportFor(_ context.Context, _, _ string) (PostureReport, bool, error) {
	return PostureReport{}, false, nil
}

func (m *Memory) PostureBlockedUsers(_ context.Context) ([]string, error) { return nil, nil }

func (m *Memory) PostureUsersByDisposal(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (m *Memory) PostureFreshest(_ context.Context, _ string) (PostureReport, bool, error) {
	return PostureReport{}, false, nil
}
