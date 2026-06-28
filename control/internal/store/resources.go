package store

import "context"

// Resource 受 SPA 门控的后端资源 + 细粒度授权。
// 网关数据面向控制面拉取后，据此做"目标前导→后端"路由与角色/用户鉴权（替代静态 resources.json）。
type Resource struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Backend    string   `json:"backend"`    // host:port（权威拨号目标，数据面只读此字段）
	AllowRoles []string `json:"allowRoles"` // 空=不限角色
	AllowUsers []string `json:"allowUsers"` // 空=不限用户
	// 对象库引用（可选，仅控制面 / 编辑器用，绝不进数据面拨号路径）：
	// 编辑时据此自动回填 backend，并支撑对象库「被引用」反查与删除守卫。
	AddrRef string `json:"addrRef,omitempty"` // 地址对象 id → backend 主机
	SvcRef  string `json:"svcRef,omitempty"`  // 服务对象 id → backend 端口
}

// Resources 返回受控资源清单（内存种子；SQLiteStore 覆盖为落库版）。
func (m *Memory) Resources(_ context.Context) ([]Resource, error) {
	return []Resource{
		// OA 资源的后端主机引用「OA 服务器」地址对象（addr-oa = 10.20.1.10）——演示对象库复用闭环
		{ID: "oa", Name: "OA 协同办公", Backend: "10.20.1.10:8080", AllowRoles: []string{"admin", "user"}, AddrRef: "addr-oa"},
		{ID: "finance", Name: "财务核算系统", Backend: "10.20.3.21:443", AllowRoles: []string{"admin"}},
		{ID: "git", Name: "研发 Git 仓库", Backend: "10.30.5.8:22", AllowRoles: []string{"admin", "user"}},
	}, nil
}
