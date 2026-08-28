// Package resource 是网关的资源注册表：把"目标资源 id"映射到后端 host:port，并按身份做授权。
//
// 防 SSRF 的核心不变量：网关**只**按已登记的 resource-id 取后端地址，host:port 100% 来自服务端配置，
// 绝不取自客户端给的任意 host:port。客户端在隧道里只能引用注册表里登记的 id，无法让网关直连内网任意地址。
package resource

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// Resource 一个受保护资源：id → 后端，附带细粒度授权。
type Resource struct {
	ID         string   `json:"id"`
	Backend    string   `json:"backend"`     // host:port，仅来自配置
	AllowRoles []string `json:"allow_roles"` // 空=不限角色
	AllowUsers []string `json:"allow_users"` // 空=不限用户
	// DenyUsers 否决名单：命中即拒，优先于一切允许来源。
	//
	// 由控制面**算好后下发**（当前唯一来源是终端风险降权对高敏资源的收缩），
	// 网关只做机械比对——不知道谁为什么被降权，也不做任何推导。这与「组织/用户组在
	// 控制面展开成账号后才下发」是同一条纪律：判定权全在控制面。
	//
	// ★为什么需要"否决"这一维而不是让控制面收窄 AllowUsers：绝大多数资源没设 ACL
	// （两维皆空 = 不限），没有允许名单可收窄；要用允许名单表达"除了这几个人"就得
	// 枚举全体账号，漏一个就是静默放行。
	DenyUsers []string `json:"deny_users"`
	// WebScheme 七层 Web 代理拨后端时用的协议（http | https）。空 = http。
	//
	// ★这是**拨号参数**而不是策略：网关必须知道内网应用是 http 还是 https 才连得上，
	// 而它无从推导（按端口猜 443 会在 8443 上静默连错协议）。判定权仍全在控制面——
	// 「哪些资源是 Web 应用、谁能访问」由控制面回答，这里只回答"怎么拨"。
	// L4 隧道路径完全不读它。
	WebScheme string `json:"web_scheme,omitempty"`

	// idx 主体清单的预计算查找表（Replace 时构建，JSON 里不存在）。
	//
	// ★为什么需要：Authorize 原先是线性扫 + strings.EqualFold，而 AllowUsers 的长度
	// **由控制面的组织授权展开决定**——一条授权给根组织的资源，在 5000 人目录下会
	// 带着 5000 个账号下发（api.expandForGateway）。实测（BenchmarkAuthorize_*）
	// 5000 人时一次判定约 35μs，且成本随账号的**公共前缀长度**上升（同组织账号
	// 往往共享前缀，EqualFold 要逐字符比到分歧位）。L4 每连接一次尚可，
	// 而 L7 是**每个 HTTP 请求**都判一次（webproxy 的逐请求鉴权）——
	// 一个页面五十个请求就是毫秒级的纯授权开销。
	//
	// nil 时回落线性扫：直接构造 Resource（测试、以及任何没走 Replace 的路径）
	// 仍然可用，行为一字不差。
	idx *subjectSets
}

// subjectSets 预计算的主体查找表。键一律 strings.ToLower，**不做 TrimSpace**。
//
// ★口径必须与它取代的 strings.EqualFold 逐字一致，否则就是在悄悄改变授权判定。
// 具体到 TrimSpace：`EqualFold(" zhang.wei ", "zhang.wei")` 是 **false**——
// 名单里带空白的条目匹配不上，那个人进不来（fail-closed）。第一版实现顺手加了
// TrimSpace，方向正好相反：**放宽**授权。对照用例（TestAuthorize两条路径同真同假
// 的「首尾空白」一条）当场抓住了它。
//
// 大小写：ToLower 后查表 vs EqualFold，对 ASCII 与中文账号完全等价（中文无大小写），
// 差异只在个别 Unicode 特例（土耳其语无点 i 之类）。控制面下发的账号本来就经
// normUser 规范化过，实际不会踩到。
type subjectSets struct {
	deny, users, roles map[string]struct{}
}

func newSet(ss []string) map[string]struct{} {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(ss))
	for _, v := range ss {
		m[strings.ToLower(v)] = struct{}{}
	}
	return m
}

// withIndex 返回带预计算查找表的副本。Replace 时调一次，之后热路径只查表。
func (r Resource) withIndex() Resource {
	r.idx = &subjectSets{
		deny:  newSet(r.DenyUsers),
		users: newSet(r.AllowUsers),
		roles: newSet(r.AllowRoles),
	}
	return r
}

// DialScheme 返回七层代理拨后端用的协议，空值收敛到 http。
func (r Resource) DialScheme() string {
	if strings.EqualFold(strings.TrimSpace(r.WebScheme), "https") {
		return "https"
	}
	return "http"
}

// Registry 资源注册表（并发安全）。
type Registry struct {
	mu      sync.RWMutex
	byID    map[string]Resource
	Default string // 无前导时回退的后端 host:port（**仅在 AllowNoPreamble 为真时可达**）
	// AllowNoPreamble 是否允许「不带 CONNECT 前导的连接直连 Default」。**默认 false（fail-closed）**。
	//
	// ★为什么必须默认关：那条路径上 Lookup / Authorize / DenyUsers 一个都不执行——
	// 资源 ACL、组织与用户组展开、JIT 授予、风险降权全部跳过，即「五道门」的第 5 道
	// 在这条路上根本不存在。而参考部署把 Default 设成了**控制面自身的回环监听**
	// （deploy/systemd/baidi-gateway.service 的 -backend 127.0.0.1:<CONTROL_PORT>），
	// 于是任意一个能敲开门的 role=user 账号都能把请求直接送进控制面：
	//   - 绕过 nginx 那份登录/API 限流（它只在 nginx 那一跳生效）；
	//   - 控制面看到的对端是 127.0.0.1，落在 defaultTrustedProxies 内，于是采信
	//     请求方自带的 X-Forwarded-For——审计源 IP、攻击源统计、以及认证策略里
	//     trustedNetwork 那条**削弱二次认证**的豁免判据，全都可被伪造；
	//   - 反过来还能给某个正常办公出口 IP 刷失败登录，把整段办公网锁掉。
	// 同一个文件里「前导不完整」那条分支早就是 fail-closed 的，注释写着
	// 「绝不降级回退默认后端」——只是当初没把「根本没有前导」也归进同一条纪律。
	//
	// 置真是**过渡逃生舱**（老客户端/demo 场景），与 BAIDI_GW_KNOCK_STRICT=0 同族：
	// 开着就等于宣布"本网关的默认后端对所有已敲门的账号开放"，网关启动期会当面告警。
	AllowNoPreamble bool
}

// New 建注册表，def 为默认回退后端。
func New(def string) *Registry { return &Registry{byID: map[string]Resource{}, Default: def} }

// LoadFile 从 JSON 文件加载资源列表（[]Resource）。
func (r *Registry) LoadFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var list []Resource
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, res := range list {
		if res.ID != "" && res.Backend != "" {
			r.byID[res.ID] = res
		}
	}
	return nil
}

// Replace 原子替换全部资源（控制面拉到新策略后热更新）。
func (r *Registry) Replace(list []Resource) {
	m := make(map[string]Resource, len(list))
	for _, res := range list {
		if res.ID != "" && res.Backend != "" {
			// 主体清单在这里预计算一次（每轮策略下发一次），热路径不再线性扫。
			m[res.ID] = res.withIndex()
		}
	}
	r.mu.Lock()
	r.byID = m
	r.mu.Unlock()
}

// Lookup 按 id 取资源（白名单查表——唯一允许的取后端途径）。
func (r *Registry) Lookup(id string) (Resource, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res, ok := r.byID[id]
	return res, ok
}

// Count 已登记资源数。
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// List 当前全部资源的快照（可达性拨测遍历用；返回副本，调用方随便拿）。
func (r *Registry) List() []Resource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Resource, 0, len(r.byID))
	for _, res := range r.byID {
		out = append(out, res)
	}
	return out
}

// Authorize 判断身份是否可访问该资源：
// DenyUsers 命中即拒（先判，压过一切允许来源）；
// 其后 AllowRoles/AllowUsers 都空 = 不限（等价默认后端语义），任一非空则须命中其一。
//
// ★否决必须排在最前。控制面下发时会把有效期内的 JIT 授予并进 AllowUsers，
// 若先判允许，一张审批单就能让被降权的终端照样打开高敏资源——而那恰恰是最该收缩的时刻。
func (r *Registry) Authorize(user, role string, res Resource) bool {
	// 走 Replace 进来的资源带预计算查找表；直接构造的（测试等）回落线性扫，
	// 两条路径的判定顺序与结果必须完全一致——有对照用例钉住。
	if ix := res.idx; ix != nil {
		u := strings.ToLower(user)
		if len(ix.deny) > 0 {
			if _, hit := ix.deny[u]; hit {
				return false
			}
		}
		if len(ix.users) > 0 {
			if _, hit := ix.users[u]; hit {
				return true
			}
		}
		if len(ix.roles) > 0 {
			if _, hit := ix.roles[strings.ToLower(role)]; hit {
				return true
			}
		}
		return len(ix.users) == 0 && len(ix.roles) == 0
	}
	if len(res.DenyUsers) > 0 && contains(res.DenyUsers, user) {
		return false
	}
	if len(res.AllowUsers) > 0 && contains(res.AllowUsers, user) {
		return true
	}
	if len(res.AllowRoles) > 0 && contains(res.AllowRoles, role) {
		return true
	}
	return len(res.AllowUsers) == 0 && len(res.AllowRoles) == 0
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}
