// Package store 定义白帝控制中心的数据访问接口与内存实现（首版 mock，
// 后续替换为 SQLite/PostgreSQL，接口不变）。
package store

import "context"

// Store 控制中心数据访问接口。模块处理器只依赖此接口，便于切换持久化后端。
type Store interface {
	Overview(ctx context.Context) (Overview, error)
	PolicyBundle(ctx context.Context) (PolicyBundle, error)
	Apps(ctx context.Context) (AppBundle, error)
	Users(ctx context.Context) (UserDirBundle, error)
	Devices(ctx context.Context) (DeviceBundle, error)
	Audit(ctx context.Context) (AuditBundle, error)
	Gateway(ctx context.Context) (GatewayBundle, error)
	System(ctx context.Context) (SystemBundle, error)
	AuthSrc(ctx context.Context) (AuthSrcBundle, error)
	Security(ctx context.Context) (SecurityBundle, error)
	Resources(ctx context.Context) ([]Resource, error)
	OnlineSessions(ctx context.Context) ([]OnlineSession, error)
	UserStates(ctx context.Context) (UserStateBundle, error)
	Ipsec(ctx context.Context) ([]IpsecSite, error)
	Objects(ctx context.Context) (ObjectBundle, error)
}

// Overview 态势总览（对应 PRD 第 5 章监控中心的一屏聚合）。
type Overview struct {
	GeneratedAt string        `json:"generatedAt"`
	Devices     DeviceStat    `json:"devices"`
	Users       UserStat      `json:"users"`
	Threats     ThreatStat    `json:"threats"`
	Sessions    int           `json:"sessions"`
	AuditByKind []KV          `json:"auditByKind"`
	Verdicts    []KV          `json:"verdicts"`
	Defense     []DefenseLine `json:"defense"`
}

type DeviceStat struct {
	Online int     `json:"online"`
	Total  int     `json:"total"`
	Rate   float64 `json:"rate"`
}

type UserStat struct {
	Total    int `json:"total"`
	Disabled int `json:"disabled"`
	Locked   int `json:"locked"`
}

type ThreatStat struct {
	Rejected  int `json:"rejected"`
	Failed    int `json:"failed"`
	Secondary int `json:"secondary"`
}

// KV 通用的「名称→计数」对，供图表使用。
type KV struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// DefenseLine 三道防线之一（设备/账号/终端）的风险态势。
type DefenseLine struct {
	Key   string   `json:"key"`   // device | account | endpoint
	Name  string   `json:"name"`  // 设备防线 / 账号防线 / 终端防线
	Risk  int      `json:"risk"`  // 0-100 风险分
	Trend string   `json:"trend"` // up | down | flat
	Top   []string `json:"top"`   // TOP 风险实体
}
