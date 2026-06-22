package store

import "context"

// AuditBundle 审计中心页：分类聚合 + 磁盘水位 + 日志条目。
type AuditBundle struct {
	Categories []KV        `json:"categories"`
	TodayTotal int         `json:"todayTotal"`
	Disk       DiskStat    `json:"disk"`
	Logs       []AuditEntry `json:"logs"`
}

type DiskStat struct {
	UsedPct    int `json:"usedPct"`
	TotalGB    int `json:"totalGB"`
	RetainDays int `json:"retainDays"`
}

type AuditEntry struct {
	Time     string `json:"time"`
	Category string `json:"category"` // access | auth | admin | security
	User     string `json:"user"`
	SrcIP    string `json:"srcIp"`
	Event    string `json:"event"`
	Verdict  string `json:"verdict"` // allow | deny | mfa | ok | fail
}

func (m *Memory) Audit(_ context.Context) (AuditBundle, error) {
	return AuditBundle{
		Categories: []KV{
			{Name: "访问决策", Value: 1284},
			{Name: "登录认证", Value: 642},
			{Name: "管理操作", Value: 73},
			{Name: "安全事件", Value: 41},
		},
		TodayTotal: 2040,
		Disk:       DiskStat{UsedPct: 62, TotalGB: 512, RetainDays: 180},
		Logs: []AuditEntry{
			{Time: "2026-06-22 20:11:03", Category: "access", User: "zhang.wei", SrcIP: "10.8.2.31", Event: "访问 研发 Git 仓库", Verdict: "allow"},
			{Time: "2026-06-22 20:10:48", Category: "auth", User: "li.fang", SrcIP: "10.8.5.12", Event: "SAML SSO 登录成功", Verdict: "ok"},
			{Time: "2026-06-22 20:09:55", Category: "security", User: "ext.zhou", SrcIP: "203.0.113.7", Event: "异地登录触发增强认证", Verdict: "mfa"},
			{Time: "2026-06-22 20:08:30", Category: "access", User: "wang.qiang", SrcIP: "10.8.5.40", Event: "访问 财务核算系统 被拒（无授权）", Verdict: "deny"},
			{Time: "2026-06-22 20:07:12", Category: "admin", User: "security-admin", SrcIP: "10.0.0.9", Event: "修改 销售部 用户策略", Verdict: "ok"},
			{Time: "2026-06-22 20:05:40", Category: "auth", User: "zhao.min", SrcIP: "10.8.7.9", Event: "密码连续错误 5 次，账号锁定", Verdict: "fail"},
			{Time: "2026-06-22 20:03:18", Category: "security", User: "—", SrcIP: "198.51.100.22", Event: "SPA 敲门失败，源 IP 不响应", Verdict: "deny"},
			{Time: "2026-06-22 20:01:02", Category: "access", User: "liu.yang", SrcIP: "10.8.7.21", Event: "访问 客服工单系统", Verdict: "allow"},
		},
	}, nil
}
