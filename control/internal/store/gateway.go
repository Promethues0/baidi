package store

import "context"

// GatewayBundle 网关与隐身页：代理网关区域/节点拓扑 + SPA 服务隐身状态。
type GatewayBundle struct {
	Zones []GwZone  `json:"zones"`
	Spa   SpaStatus `json:"spa"`
}

type GwZone struct {
	Key     string   `json:"key"`
	Name    string   `json:"name"`
	Status  string   `json:"status"` // healthy | degraded | down
	Apps    int      `json:"apps"`   // 后接受保护业务数
	Clients int      `json:"clients"`
	Nodes   []GwNode `json:"nodes"`
}

type GwNode struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Role    string `json:"role"` // primary | backup
	Status  string `json:"status"`
	LoadPct int    `json:"loadPct"`
}

type SpaStatus struct {
	Generation     string   `json:"generation"` // G2 | G3 | G4
	AuthMode       string   `json:"authMode"`
	ProtectedPorts []string `json:"protectedPorts"`
	Hidden         bool     `json:"hidden"`
	KnockOK        bool     `json:"knockOk"`
}

func (m *Memory) Gateway(_ context.Context) (GatewayBundle, error) {
	return GatewayBundle{
		Zones: []GwZone{
			{Key: "east", Name: "华东出口", Status: "healthy", Apps: 4, Clients: 146, Nodes: []GwNode{
				{Name: "gw-east-01", IP: "10.0.1.11", Role: "primary", Status: "healthy", LoadPct: 38},
				{Name: "gw-east-02", IP: "10.0.1.12", Role: "backup", Status: "healthy", LoadPct: 12},
			}},
			{Key: "south", Name: "华南出口", Status: "degraded", Apps: 2, Clients: 40, Nodes: []GwNode{
				{Name: "gw-south-01", IP: "10.0.2.11", Role: "primary", Status: "degraded", LoadPct: 81},
				{Name: "gw-south-02", IP: "10.0.2.12", Role: "backup", Status: "down", LoadPct: 0},
			}},
		},
		Spa: SpaStatus{
			Generation:     "G3",
			AuthMode:       "先认证后连接（SPA 敲门 + 双向证书）",
			ProtectedPorts: []string{"443 用户接入", "112 设备通信", "4434 控制信道"},
			Hidden:         true,
			KnockOK:        true,
		},
	}, nil
}
