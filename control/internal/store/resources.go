package store

import "context"

// Resource 受 SPA 门控的后端资源 + 细粒度授权。
// 网关数据面向控制面拉取后，据此做"目标前导→后端"路由与角色/用户鉴权（替代静态 resources.json）。
type Resource struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Backend    string   `json:"backend"`    // host:port
	AllowRoles []string `json:"allowRoles"` // 空=不限角色
	AllowUsers []string `json:"allowUsers"` // 空=不限用户
}

// Resources 返回受控资源清单（内存种子；SQLiteStore 覆盖为落库版）。
func (m *Memory) Resources(_ context.Context) ([]Resource, error) {
	return []Resource{
		{ID: "oa", Name: "OA 协同办公", Backend: "10.20.1.10:8080", AllowRoles: []string{"admin", "user"}},
		{ID: "finance", Name: "财务核算系统", Backend: "10.20.3.21:443", AllowRoles: []string{"admin"}},
		{ID: "git", Name: "研发 Git 仓库", Backend: "10.30.5.8:22", AllowRoles: []string{"admin", "user"}},
	}, nil
}
