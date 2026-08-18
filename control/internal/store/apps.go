package store

import (
	"context"
	"strings"
)

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
	Category string `json:"category"`
	// ★这里曾经有 Node（"所属网关区域"）。已摘除（wave8 行动 14）：管理员在发布向导里
	// **根本没有这个输入项**，CreateApp 一律写死「华东出口」，而唯一的消费方是应用表里
	// 一列恒定显示同一个值的表头。真实的「这个应用经哪台网关接入」由网关落点清单决定
	// （剖面下发有序落点 + 客户端故障转移），与应用无关，也不该由应用来声明。
	// AuthedUsers / AuthScope 是**现算**的授权面，不是存储值：以本应用关联资源的
	// 静态 ACL（allow_users ∪ allow_roles 展开 ∪ 组织/用户组展开）为准，每次读现算。
	//
	// ★apps.authed_users 那一列已废弃（与 ipsec_sites 的 status/rx_bytes 同款处理）：
	// 它是种子里写死的数字（860/64/210/1284…），全库没有任何 UPDATE，与真实授权毫无
	// 关系——一个 8 个用户的系统显示「OA 协同办公 · 860 用户」。列留着不读，避免为
	// 删列做表重建；读端只认这里现算的结果，不存在第二个真相来源。
	//
	// 刻意**不含 JIT 临时授予**：那是有时限的，计进来会让同一个应用的授权数随时间
	// 跳动，管理员无法据此判断「我到底授权给了谁」。
	AuthedUsers int `json:"authedUsers"`
	// AuthScope 授权面性质，决定 AuthedUsers 该怎么读：
	//   unlinked  未关联受控资源 —— 根本无法经隧道访问，AuthedUsers 无意义
	//   unlimited 关联资源未设任何 ACL —— 对全部登录用户开放（AuthedUsers=当前用户总数）
	//   limited   按 ACL 限定 —— AuthedUsers 是展开后的真实账号数
	AuthScope  string `json:"authScope"`
	Status     string `json:"status"`     // running | stopped
	ResourceID string `json:"resourceId"` // 关联 resources.id（JIT 申请解析用；空=不接入自助申请）
}

// 应用授权面的三种性质。
const (
	AuthScopeUnlinked  = "unlinked"
	AuthScopeUnlimited = "unlimited"
	AuthScopeLimited   = "limited"
)

// seedApps 内存种子应用清单（未连库时的降级演示数据，也是首启播种的来源）。
func seedApps() []App {
	return []App{
		{ID: "a1", Name: "OA 协同办公", Addr: "10.20.1.10:8080", Mode: "web", Category: "office", Status: "running", ResourceID: "oa"},
		{ID: "a2", Name: "财务核算系统", Addr: "10.20.3.21:443", Mode: "web", Category: "finance", Status: "running", ResourceID: "finance"},
		{ID: "a3", Name: "研发 Git 仓库", Addr: "10.30.5.8:22", Mode: "tunnel", Category: "dev", Status: "running", ResourceID: "git"},
		{ID: "a4", Name: "数据库运维 (SSH)", Addr: "10.30.9.4:22", Mode: "tunnel", Category: "dev", Status: "running"},
		{ID: "a5", Name: "客服工单系统", Addr: "10.40.2.7:8000", Mode: "web", Category: "office", Status: "stopped"},
		{ID: "a6", Name: "知网文献 (直连书签)", Addr: "https://www.cnki.net", Mode: "global", Category: "global", Status: "running"},
	}
}

// resolveAppAuth 现算一批应用的授权面。判据与真正的鉴权出口同构——
// api.authorizeRes 与网关 registry.Authorize 都是「AllowUsers ∪ AllowRoles ∪ 组织/组展开，
// 四维皆空则不限」，这里只是把同一套语义按资源数一遍而不是按用户判一次。
//
// roleAccounts：鉴权角色（users.role，admin|user）→ 账号列表；totalUsers：可登录账号总数。
func resolveAppAuth(apps []App, resByID map[string]Resource, ix SubjectIndex, roleAccounts map[string][]string, totalUsers int) {
	for i := range apps {
		res, ok := resByID[apps[i].ResourceID]
		if apps[i].ResourceID == "" || !ok {
			// 未关联资源（或关联到一个已被删除的资源）：这个应用**根本进不了隧道**，
			// 谈不上授权给谁。剖面也会为它回一条 warnings，两处口径一致。
			apps[i].AuthScope, apps[i].AuthedUsers = AuthScopeUnlinked, 0
			continue
		}
		if !res.Restricted() {
			apps[i].AuthScope, apps[i].AuthedUsers = AuthScopeUnlimited, totalUsers
			continue
		}
		set := map[string]bool{}
		for _, u := range res.AllowUsers {
			if u = normAccount(u); u != "" && u != DenyAllSubject {
				set[u] = true
			}
		}
		for _, r := range res.AllowRoles {
			for _, a := range roleAccounts[strings.ToLower(strings.TrimSpace(r))] {
				set[a] = true
			}
		}
		for _, a := range ix.SubjectAccounts(res) {
			set[a] = true
		}
		apps[i].AuthScope, apps[i].AuthedUsers = AuthScopeLimited, len(set)
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
