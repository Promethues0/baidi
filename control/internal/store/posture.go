package store

import "context"

// PostureCheckResult 终端上报的一条检查结果（客户端机械布尔化 + 原始值，策略判定在控制面）。
type PostureCheckResult struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	OK    bool   `json:"ok"`
	Value string `json:"value"`
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

func (m *Memory) PostureDeviceCount(_ context.Context, _ string) (int, error) { return 0, nil }
