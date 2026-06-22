package store

import "context"

// AppBundle 应用管理页：分类 + 应用清单。
type AppBundle struct {
	Categories []AppCategory `json:"categories"`
	Apps       []App         `json:"apps"`
}

type AppCategory struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// App 受控应用资源。
type App struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Addr        string `json:"addr"`
	Mode        string `json:"mode"`     // tunnel | web | global
	Category    string `json:"category"` // 分类 key
	Node        string `json:"node"`     // 所属网关区域
	AuthedUsers int    `json:"authedUsers"`
	Status      string `json:"status"` // running | stopped
}

func (m *Memory) Apps(_ context.Context) (AppBundle, error) {
	apps := []App{
		{ID: "a1", Name: "OA 协同办公", Addr: "10.20.1.10:8080", Mode: "web", Category: "office", Node: "华东出口", AuthedUsers: 860, Status: "running"},
		{ID: "a2", Name: "财务核算系统", Addr: "10.20.3.21:443", Mode: "web", Category: "finance", Node: "华东出口", AuthedUsers: 64, Status: "running"},
		{ID: "a3", Name: "研发 Git 仓库", Addr: "10.30.5.8:22", Mode: "tunnel", Category: "dev", Node: "华东出口", AuthedUsers: 210, Status: "running"},
		{ID: "a4", Name: "数据库运维 (SSH)", Addr: "10.30.9.4:22", Mode: "tunnel", Category: "dev", Node: "华南出口", AuthedUsers: 18, Status: "running"},
		{ID: "a5", Name: "客服工单系统", Addr: "10.40.2.7:8000", Mode: "web", Category: "office", Node: "华南出口", AuthedUsers: 64, Status: "stopped"},
		{ID: "a6", Name: "知网文献 (全网资源)", Addr: "*.cnki.net", Mode: "global", Category: "global", Node: "华东出口", AuthedUsers: 1284, Status: "running"},
	}
	return AppBundle{
		Categories: []AppCategory{
			{Key: "all", Label: "全部应用", Count: len(apps)},
			{Key: "office", Label: "办公协同", Count: 2},
			{Key: "finance", Label: "财务高敏", Count: 1},
			{Key: "dev", Label: "研发运维", Count: 2},
			{Key: "global", Label: "全网资源", Count: 1},
		},
		Apps: apps,
	}, nil
}
