package store

import "context"

// SystemBundle 系统管理页：三权分立管理员 + 集群拓扑。
type SystemBundle struct {
	AdminGroups []AdminGroup   `json:"adminGroups"`
	Admins      []AdminAccount `json:"admins"`
	Cluster     ClusterInfo    `json:"cluster"`
}

type AdminGroup struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Power   string `json:"power"` // root | system | security | audit | custom
	Builtin bool   `json:"builtin"`
	Members int    `json:"members"`
	Scope   string `json:"scope"` // 权限范围摘要
}

type AdminAccount struct {
	Name      string `json:"name"`
	Account   string `json:"account"`
	Group     string `json:"group"`
	Auth      string `json:"auth"`
	TwoFA     bool   `json:"twoFa"`
	LastLogin string `json:"lastLogin"`
}

type ClusterInfo struct {
	LocalNodes []ClusterNode `json:"localNodes"`
	DistNodes  []ClusterNode `json:"distNodes"`
}

type ClusterNode struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Role   string `json:"role"` // master | backup | center | branch
	Status string `json:"status"`
}

func (m *Memory) System(_ context.Context) (SystemBundle, error) {
	return SystemBundle{
		AdminGroups: []AdminGroup{
			{Key: "root", Name: "根管理组", Power: "root", Builtin: true, Members: 1, Scope: "全局（超级管理员）"},
			{Key: "sys", Name: "系统管理组", Power: "system", Builtin: true, Members: 3, Scope: "系统配置 / 网络 / 集群 / 升级"},
			{Key: "sec", Name: "安全管理组", Power: "security", Builtin: true, Members: 2, Scope: "认证 / 应用 / 策略 / 终端"},
			{Key: "aud", Name: "审计管理组", Power: "audit", Builtin: true, Members: 2, Scope: "审计日志 / 管理员行为（只读）"},
			{Key: "east-op", Name: "华东运维组", Power: "custom", Builtin: false, Members: 4, Scope: "华东大区 用户 / 应用（分级分权）"},
		},
		Admins: []AdminAccount{
			{Name: "超级管理员", Account: "admin", Group: "根管理组", Auth: "密码 + 商密证书", TwoFA: true, LastLogin: "2026-06-22 09:01"},
			{Name: "系统运维-小李", Account: "ops.li", Group: "系统管理组", Auth: "密码 + 短信", TwoFA: true, LastLogin: "2026-06-22 14:20"},
			{Name: "安全管理-老郑", Account: "sec.zheng", Group: "安全管理组", Auth: "密码 + UKey", TwoFA: true, LastLogin: "2026-06-22 19:42"},
			{Name: "审计员-王", Account: "audit.wang", Group: "审计管理组", Auth: "密码", TwoFA: false, LastLogin: "2026-06-21 17:05"},
		},
		Cluster: ClusterInfo{
			LocalNodes: []ClusterNode{
				{Name: "ctl-master", IP: "10.0.0.11", Role: "master", Status: "healthy"},
				{Name: "ctl-backup", IP: "10.0.0.12", Role: "backup", Status: "healthy"},
			},
			DistNodes: []ClusterNode{
				{Name: "中心单元（华东）", IP: "10.0.0.11", Role: "center", Status: "healthy"},
				{Name: "分支单元（华南）", IP: "10.1.0.11", Role: "branch", Status: "healthy"},
				{Name: "分支单元（西南）", IP: "10.2.0.11", Role: "branch", Status: "degraded"},
			},
		},
	}, nil
}
