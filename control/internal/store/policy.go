package store

import "context"

// PolicyBundle 策略管理页所需的组织/组继承树 + 用户策略清单。
type PolicyBundle struct {
	Tree []OrgNode    `json:"tree"`
	List []UserPolicy `json:"list"`
}

// OrgNode 组织/用户组节点，承载"是否有自定义策略"用于继承可视化。
type OrgNode struct {
	Key       string    `json:"key"`
	Title     string    `json:"title"`
	HasCustom bool      `json:"hasCustom"` // 该节点是否定义了自定义策略（否则继承父级）
	Members   int       `json:"members"`
	Children  []OrgNode `json:"children,omitempty"`
}

// UserPolicy 用户策略清单项。
type UserPolicy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Scope         string `json:"scope"`         // 适用范围（组/用户）
	Status        string `json:"status"`        // custom | inherited
	InheritedFrom string `json:"inheritedFrom"` // 继承自的节点名（inherited 时）
	Members       int    `json:"members"`
	Updated       string `json:"updated"`
}

// PolicyBundle 返回演示用的继承树与策略清单。
func (m *Memory) PolicyBundle(_ context.Context) (PolicyBundle, error) {
	return PolicyBundle{
		Tree: []OrgNode{
			{Key: "root", Title: "根策略（全局兜底）", HasCustom: true, Members: 1284, Children: []OrgNode{
				{Key: "east", Title: "华东大区", HasCustom: true, Members: 420, Children: []OrgNode{
					{Key: "east-sales", Title: "销售部", HasCustom: true, Members: 86},
					{Key: "east-dev", Title: "研发部", HasCustom: false, Members: 210},
				}},
				{Key: "south", Title: "华南大区", HasCustom: false, Members: 300, Children: []OrgNode{
					{Key: "south-cs", Title: "客服中心", HasCustom: true, Members: 64},
				}},
				{Key: "contractor", Title: "外包人员", HasCustom: true, Members: 48},
			}},
		},
		List: []UserPolicy{
			{ID: "p-sales", Name: "销售部高敏策略", Scope: "销售部", Status: "custom", InheritedFrom: "华东大区", Members: 86, Updated: "2026-06-20 14:32"},
			{ID: "p-dev", Name: "研发部（继承华东大区）", Scope: "研发部", Status: "inherited", InheritedFrom: "华东大区", Members: 210, Updated: "2026-06-18 09:10"},
			{ID: "p-contractor", Name: "外包最小授权", Scope: "外包人员", Status: "custom", InheritedFrom: "根策略（全局兜底）", Members: 48, Updated: "2026-06-21 17:05"},
			{ID: "p-cs", Name: "客服夜班时段限制", Scope: "客服中心", Status: "custom", InheritedFrom: "华南大区", Members: 64, Updated: "2026-06-19 21:48"},
			{ID: "p-south", Name: "华南大区（继承根策略）", Scope: "华南大区", Status: "inherited", InheritedFrom: "根策略（全局兜底）", Members: 300, Updated: "2026-06-15 11:20"},
		},
	}, nil
}
