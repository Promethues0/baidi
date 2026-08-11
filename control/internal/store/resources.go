package store

import (
	"context"
	"strings"
)

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
	// Sensitivity 资源敏感度：low | normal | high。**风险降权（disposal=degrade）的唯一判据**。
	//
	// ★它此前不存在，"哪些是高敏资源"靠 `apps.Category == "finance"` 这一行硬编码派生出来
	// （api.go 的门户磁贴与 clientprofile.go 的剖面各写了一遍）。那个派生有两处致命问题：
	//   ① 挂在**应用**上，而授权与路由的单位是**资源**——同一资源被多个应用引用时，
	//      敏感度会随"从哪个磁贴看过来"而变；
	//   ② 只认 finance 一个分类，管理员新建的任何高敏资源（人事、代码签名机…）
	//      都被静默当成普通资源，降权对它们形同虚设。
	// 现在敏感度是资源上的一等字段，控制面两个判定点（网关策略下发 / 客户端剖面）
	// 都只读它，见 api/subjects.go。
	//
	// 空值按 SensitivityNormal 处理（读侧 NormalizeSensitivity 兜底），
	// 但库里的既有行由 backfillResourceSensitivity 显式回填，不留 NULL。
	Sensitivity string `json:"sensitivity"`
	// ── 七层 Web 代理（PRD 8.3.3，B/S 免客户端接入）──
	//
	// WebScheme 是**内网后端的协议**（http | https），网关七层代理据此拨号。
	// ★它必须是一等字段而不是"按端口猜"：猜法在 8443/8080 这类端口上必然出错，
	// 而症状是网关拿 HTTP 去撞一个 TLS 端口——浏览器上看到的是一个空白页或
	// 乱码，日志里只有一条读失败，没人会想到是协议猜错了。
	// L4 隧道路径完全不读它（隧道是字节透传，协议由两端自己谈）。
	WebScheme string `json:"webScheme"`
	// WebEntry 对外访问入口基址覆盖（如 https://oa.corp.example），空 = 用网关默认落点。
	//
	// 只影响**控制面发给浏览器的跳转地址**，不影响网关的路由（七层按 /app/<资源id>/
	// 路径前缀分流，与域名无关）。用途是给某个应用配一条专属域名/split-horizon DNS。
	// 校验见 api.validateWebEntry：必须是 http(s):// + 主机[:端口]，不带路径与查询。
	WebEntry string `json:"webEntry"`
	// 对象库引用（可选，仅控制面 / 编辑器用，绝不进数据面拨号路径）：
	// 编辑时据此自动回填 backend，并支撑对象库「被引用」反查与删除守卫。
	AddrRef string `json:"addrRef,omitempty"` // 地址对象 id → backend 主机
	SvcRef  string `json:"svcRef,omitempty"`  // 服务对象 id → backend 端口
}

// 资源敏感度枚举。三档而非两档：low 与 normal 今天在判定上等价（都不被降权摘除），
// 但把"明确评估过、确认不敏感"与"没特别标注"分开，才让管理员的评估结论在库里留得下。
const (
	SensitivityLow    = "low"
	SensitivityNormal = "normal"
	SensitivityHigh   = "high"
)

// ValidSensitivity 报告取值是否合法（空串不合法，由调用方决定是否补默认值）。
func ValidSensitivity(s string) bool {
	return s == SensitivityLow || s == SensitivityNormal || s == SensitivityHigh
}

// NormalizeSensitivity 把空/未知取值收敛到 normal。
//
// ★未知值绝不能收敛到 high：那会让一个拼写错误把整批资源对降级用户关掉，
// 而管理员在页面上看到的仍是"已配置"。也不收敛到 low——low 与 normal 判定等价，
// 但 normal 才是"没标注"的诚实表述。
func NormalizeSensitivity(s string) string {
	if ValidSensitivity(s) {
		return s
	}
	return SensitivityNormal
}

// HighSensitivity 该资源是否属高敏（风险降权时被摘除的那一类）。
// ★「什么算高敏」这句判断只在这里写一次：网关下发侧与剖面侧都调它，
// 两处各写 `res.Sensitivity == "high"` 迟早会有一处漏掉大小写/空值兜底。
func (r Resource) HighSensitivity() bool {
	return NormalizeSensitivity(r.Sensitivity) == SensitivityHigh
}

// Web 后端协议枚举。
const (
	WebSchemeHTTP  = "http"
	WebSchemeHTTPS = "https"
)

// NormalizeWebScheme 把 web_scheme 收敛成 http|https。
//
// ★空值（旧库补列后的 NULL、以及没填这一项的保存请求）按 **backend 端口** 推一个默认：
// 443/8443 → https，其余 → http。推导规则**只写在这一处**：迁移回填、保存落库、
// 读侧兜底三条路都调它，否则三处各写一遍 CASE，改一处漏两处的结果是同一个资源
// 在"刚保存"和"重启后"表现不同——那是最难自证的一类缺陷。
//
// 推导只是默认值不是判据：管理员在发布向导里显式选过的值一律优先，且落库后
// 不再被任何回填覆盖（回填的 WHERE 只碰空值）。
func NormalizeWebScheme(scheme, backend string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case WebSchemeHTTPS:
		return WebSchemeHTTPS
	case WebSchemeHTTP:
		return WebSchemeHTTP
	}
	if i := strings.LastIndex(backend, ":"); i >= 0 {
		switch strings.TrimSpace(backend[i+1:]) {
		case "443", "8443":
			return WebSchemeHTTPS
		}
	}
	return WebSchemeHTTP
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
		{ID: "oa", Name: "OA 协同办公", Backend: "10.20.1.10:8080", AllowRoles: []string{"admin", "user"}, Sensitivity: SensitivityNormal, AddrRef: "addr-oa"},
		{ID: "finance", Name: "财务核算系统", Backend: "10.20.3.21:443", AllowRoles: []string{"admin"}, Sensitivity: SensitivityHigh},
		{ID: "git", Name: "研发 Git 仓库", Backend: "10.30.5.8:22", AllowRoles: []string{"admin", "user"}, Sensitivity: SensitivityNormal},
	}, nil
}
