package store

import (
	"context"
	"time"
)

// Memory 内存实现（首版演示数据）。线程安全由调用方在 HTTP 层天然串行化的读场景下保证；
// 写入能力将随模块落地补充锁与持久化。
type Memory struct{}

// NewMemory 构造内存 store。
func NewMemory() *Memory { return &Memory{} }

// Overview 返回一份贴近 PRD 监控中心语义的演示态势数据。
func (m *Memory) Overview(_ context.Context) (Overview, error) {
	return Overview{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Devices:     DeviceStat{Online: 186, Total: 240, Rate: 0.775},
		Users:       UserStat{Total: 312, Disabled: 7, Locked: 4},
		Threats:     ThreatStat{Rejected: 173, Failed: 62, Secondary: 53},
		Sessions:    186,
		AuditByKind: []KV{
			{Name: "访问决策", Value: 1284},
			{Name: "登录认证", Value: 642},
			{Name: "策略变更", Value: 73},
			{Name: "配置变更", Value: 41},
		},
		Verdicts: []KV{
			{Name: "允许", Value: 1102},
			{Name: "二次鉴权", Value: 128},
			{Name: "拒绝", Value: 173},
			{Name: "降权", Value: 39},
		},
		Defense: []DefenseLine{
			{Key: "device", Name: "设备防线", Risk: 28, Trend: "down", Top: []string{"203.0.113.7", "198.51.100.22", "203.0.113.91"}},
			{Key: "account", Name: "账号防线", Risk: 41, Trend: "up", Top: []string{"li.fang", "外包-zhao", "svc-bot-04"}},
			{Key: "endpoint", Name: "终端防线", Risk: 19, Trend: "flat", Top: []string{"WIN-诊室-12", "MAC-研发-08", "未授信-Android-3"}},
		},
	}, nil
}
