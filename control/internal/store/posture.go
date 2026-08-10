package store

import (
	"context"
	"errors"
)

// MaxPostureDevices 单账号最多留存的终端设备报告数（防用随机 device 无界撑大 posture_reports）。
const MaxPostureDevices = 20

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

func (m *Memory) PostureFreshest(_ context.Context, _ string) (PostureReport, bool, error) {
	return PostureReport{}, false, nil
}
