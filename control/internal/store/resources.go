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
	// ── 主体维度扩展（PRD ch8 AppAuthorization.subjectType = org|group|user）──
	//
	// 这两维**只存在于控制面**：下发网关前会被展开成账号集合并进 AllowUsers
	// （见 SubjectIndex.SubjectAccounts），数据面的 resource.Resource 至今仍只有
	// 角色/账号两维，一个字节都没改。理由是判定权必须留在控制面——只有控制面
	// 同时知道组织树长什么样、谁在哪个部门；把树推给网关等于让被保护方自己推导策略。
	AllowGroups []string `json:"allowGroups"` // 用户组 id；空=不按用户组授权
	AllowOrgs   []string `json:"allowOrgs"`   // 组织 id；空=不按组织授权。★含子树：授权给某组织即涵盖其全部后代组织的用户
	// 对象库引用（可选，仅控制面 / 编辑器用，绝不进数据面拨号路径）：
	// 编辑时据此自动回填 backend，并支撑对象库「被引用」反查与删除守卫。
	AddrRef string `json:"addrRef,omitempty"` // 地址对象 id → backend 主机
	SvcRef  string `json:"svcRef,omitempty"`  // 服务对象 id → backend 端口
}

// Restricted 报告该资源是否设了访问限制（四个主体维度里任意一维非空）。
//
// ★「四维全空 = 不限」这条语义只在这里写一次。此前它散落在 authorizeRes 与
// JIT 申请闸两处各写一遍 `len(AllowRoles)==0 && len(AllowUsers)==0`，
// 加维度时漏改任何一处的症状都是**静默放行**：新加的组织限制被当成"没限制"。
func (r Resource) Restricted() bool {
	return len(r.AllowRoles) > 0 || len(r.AllowUsers) > 0 || len(r.AllowGroups) > 0 || len(r.AllowOrgs) > 0
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
