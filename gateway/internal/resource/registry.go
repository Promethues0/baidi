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
}

// Registry 资源注册表（并发安全）。
type Registry struct {
	mu      sync.RWMutex
	byID    map[string]Resource
	Default string // 无前导/未命中前导时回退的后端 host:port（兼容旧 demo）
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
			m[res.ID] = res
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

// Authorize 判断身份是否可访问该资源：
// DenyUsers 命中即拒（先判，压过一切允许来源）；
// 其后 AllowRoles/AllowUsers 都空 = 不限（等价默认后端语义），任一非空则须命中其一。
//
// ★否决必须排在最前。控制面下发时会把有效期内的 JIT 授予并进 AllowUsers，
// 若先判允许，一张审批单就能让被降权的终端照样打开高敏资源——而那恰恰是最该收缩的时刻。
func (r *Registry) Authorize(user, role string, res Resource) bool {
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
