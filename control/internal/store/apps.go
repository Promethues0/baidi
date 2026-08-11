package store

import "context"

// AppBundle 应用管理页：分类 + 应用清单。
type AppBundle struct {
	Categories []AppCategory `json:"categories"`
	Apps       []App         `json:"apps"`
}

// AppCategory 应用页分类筛选条的一项。
//
// ★它不等于分类字典行（AppCategoryDef）：数组首项「全部应用」是现拼的合成项、不入表，
// 其 Count 是应用总数而非某个分类的归属数。字典的增删改走 AppCategoryDef 那套。
type AppCategory struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// App 受控应用资源。ResourceID 关联 resources.id——门户高敏应用自助申请(JIT)据此把磁贴解析成
// 真实受控资源；空=该应用不接入 JIT 自助申请。apps 与 resources 是两套 id 空间，靠此列显式桥接。
type App struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Addr string `json:"addr"`
	Mode string `json:"mode"` // tunnel | web | global
	// Category 分类 key，取值必须是 app_categories 表里真实存在的一行
	// （校验在 SQLiteStore.CreateApp，见 ErrUnknownAppCategory）。
	// ★注意它与 Mode 的 "global" 毫无关系：Mode 是发布形态（决定走不走隧道），
	// Category 只是管理台上的归类维度，两者恰好都有一个叫 global 的取值。
	Category    string `json:"category"`
	Node        string `json:"node"` // 所属网关区域
	AuthedUsers int    `json:"authedUsers"`
	Status      string `json:"status"`     // running | stopped
	ResourceID  string `json:"resourceId"` // 关联 resources.id（JIT 申请解析用；空=不接入自助申请）
}

// seedApps 内存种子应用清单（未连库时的降级演示数据，也是首启播种的来源）。
func seedApps() []App {
	return []App{
		{ID: "a1", Name: "OA 协同办公", Addr: "10.20.1.10:8080", Mode: "web", Category: "office", Node: "华东出口", AuthedUsers: 860, Status: "running", ResourceID: "oa"},
		{ID: "a2", Name: "财务核算系统", Addr: "10.20.3.21:443", Mode: "web", Category: "finance", Node: "华东出口", AuthedUsers: 64, Status: "running", ResourceID: "finance"},
		{ID: "a3", Name: "研发 Git 仓库", Addr: "10.30.5.8:22", Mode: "tunnel", Category: "dev", Node: "华东出口", AuthedUsers: 210, Status: "running", ResourceID: "git"},
		{ID: "a4", Name: "数据库运维 (SSH)", Addr: "10.30.9.4:22", Mode: "tunnel", Category: "dev", Node: "华南出口", AuthedUsers: 18, Status: "running"},
		{ID: "a5", Name: "客服工单系统", Addr: "10.40.2.7:8000", Mode: "web", Category: "office", Node: "华南出口", AuthedUsers: 64, Status: "stopped"},
		{ID: "a6", Name: "知网文献 (全网资源)", Addr: "*.cnki.net", Mode: "global", Category: "global", Node: "华东出口", AuthedUsers: 1284, Status: "running"},
	}
}

// Apps 种子版本：分类计数**现算**，不再写死。
// ★写死的话，改一行种子应用的 category 就会让分类计数与清单对不上，而两者就在同一屏上。
func (m *Memory) Apps(_ context.Context) (AppBundle, error) {
	apps := seedApps()
	counts := map[string]int{}
	for _, a := range apps {
		counts[a.Category]++
	}
	cats := []AppCategory{{Key: AppCategoryAllKey, Label: AppCategoryAllLabel, Count: len(apps)}}
	for _, d := range builtinAppCategories() {
		cats = append(cats, AppCategory{Key: d.Key, Label: d.Label, Count: counts[d.Key]})
	}
	return AppBundle{Categories: cats, Apps: apps}, nil
}
