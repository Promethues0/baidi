package store

import (
	"errors"
	"sort"
	"strings"
)

// ── 管理员分级分权 / 三权分立（PRD ch15.1）──
//
// 此前这一页整页是 Memory 种子：五张编造的管理组卡片 + 八个不存在的管理员账号，
// 而权限模型实际只有 admin|user 两级——任何管理员都能改用户、改策略、读全量审计。
// 现在角色落 admin_roles 表、账号归属落 users.admin_role，判定在 api.requirePerm。
//
// ★权限键（Perm*）才是执行方真正读的那份：admin_roles.scope_json 存的就是这些字符串，
// requirePerm 逐端点比对。Power 只是「这一权叫什么」的预置标签，判定一律走 Perms——
// 否则 power 就又是一个没有消费方的展示字段（本项目最不该再犯的错）。

// 权限键。粒度刻意粗（四个面），细到端点会让清单与路由表两处漂移而没人察觉。
const (
	// PermSystem 系统配置面：网关证书 / IPSec 组网 / 对象库 / 锁定阈值 / 运维体检。
	PermSystem = "system"
	// PermSecurity 安全与业务策略面：认证源 / 认证策略 / 资源与应用 / 用户与组织 / 基线 / JIT 审批。
	PermSecurity = "security"
	// PermAudit 审计面：全量审计日志读取、防篡改链校验、导出。**只读**。
	PermAudit = "audit"
	// PermAdmins 管理员与角色管理面：谁能当管理员、谁是哪一权。只有超管持有。
	PermAdmins = "admins"
	// PermAll 通配（超管）。只允许内置 root 角色持有——自定义角色拿到它等于自造超管，
	// 「最后一个 root 不可删/不可降权」这道防自锁闸就绕过去了。
	PermAll = "*"
)

// 权别（admin_roles.power）。三权分立的三权 + 超管 + 自定义收缩角色。
const (
	PowerRoot     = "root"
	PowerSystem   = "system"
	PowerSecurity = "security"
	PowerAudit    = "audit"
	PowerCustom   = "custom"
)

var (
	// ErrLastRootAdmin 防自锁：最后一个超管不可删除、不可降权、不可禁用。
	// 没有这道闸，一次「把自己降成审计员」就让整个系统再也没有人能分配权限——
	// 而且是完全静默的：操作成功、审计正常，下一次要改权限时才发现无人有权。
	ErrLastRootAdmin = errors.New("系统必须保留至少一名超级管理员，不可删除/降权/禁用最后一名")
	// ErrAdminRoleNotFound 指定的管理员角色不存在。
	ErrAdminRoleNotFound = errors.New("管理员角色不存在")
	// ErrAdminRoleBuiltin 内置三权角色不可改名/改权/删除。
	ErrAdminRoleBuiltin = errors.New("内置角色不可修改或删除")
	// ErrAdminRoleInUse 角色仍有成员，不可删除（不做级联降权：静默失去权限比报错难查得多）。
	ErrAdminRoleInUse = errors.New("角色仍有管理员成员，请先改派后再删除")
	// ErrAdminRolePerm 自定义角色的权限键非法（未知键，或试图拿 * / admins 自造超管）。
	ErrAdminRolePerm = errors.New("自定义角色只能在 system/security/audit 三权内收缩")
	// ErrNotAdminAccount 目标账号不是管理员（撤销/改派管理员角色时）。
	ErrNotAdminAccount = errors.New("该账号不是管理员")
)

// AdminRole 一个管理员角色（三权分立的一权、超管，或自定义收缩角色）。
type AdminRole struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Power   string `json:"power"`   // root | system | security | audit | custom
	Builtin bool   `json:"builtin"` // 内置四角色：不可改、不可删
	// Perms 权限键集合（admin_roles.scope_json 的内容）。这是 requirePerm 的**唯一**判据。
	Perms []string `json:"perms"`
	// Members 该角色下的管理员数（实算，不是配置值）。
	Members int `json:"members"`
	// Scope 权限范围摘要，由 Perms 派生，仅供展示——不落库，避免出现「文案说能做、
	// 判定却不让做」的两份真相。
	Scope string `json:"scope"`
}

// Allows 报告该角色是否持有某权限键。
func (r AdminRole) Allows(perm string) bool {
	for _, p := range r.Perms {
		if p == PermAll || p == perm {
			return true
		}
	}
	return false
}

// IsRoot 报告该角色是否超管（防自锁闸的判据）。
func (r AdminRole) IsRoot() bool { return r.Power == PowerRoot }

// PowerPerms 内置权别的预置权限键。自定义角色不走这里（权限由管理员显式给）。
func PowerPerms(power string) []string {
	switch power {
	case PowerRoot:
		return []string{PermAll}
	case PowerSystem:
		return []string{PermSystem}
	case PowerSecurity:
		return []string{PermSecurity}
	case PowerAudit:
		return []string{PermAudit}
	default:
		return nil
	}
}

// permZh 权限键的中文名（摘要文案用）。
var permZh = map[string]string{
	PermAll:      "全部权限（超级管理员）",
	PermSystem:   "系统配置（网关证书 / 组网 / 对象库 / 运维体检）",
	PermSecurity: "安全策略（认证源 / 策略 / 资源应用 / 用户组织 / 审批）",
	PermAudit:    "审计日志只读（含链校验与导出）",
	PermAdmins:   "管理员与角色分配",
}

// ScopeText 由权限键集合派生的中文摘要。
func ScopeText(perms []string) string {
	if len(perms) == 0 {
		return "无任何权限（未分配）"
	}
	parts := make([]string, 0, len(perms))
	for _, p := range perms {
		if zh, ok := permZh[p]; ok {
			parts = append(parts, zh)
		} else {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " · ")
}

// NormalizeCustomPerms 校验并规范自定义角色的权限键：
// 去重排序，只接受 system/security/audit 三权，**拒绝 `*` 与 admins**。
//
// ★拒绝的理由不是洁癖：自定义角色若能拿到 `*` 或 admins，它就等价于一个不叫 root
// 的超管，而「最后一个 root」的防自锁计数只认 power=root——于是删光 root 之后
// 系统看起来还有人能管权限，防自锁却已经形同虚设。
func NormalizeCustomPerms(perms []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range perms {
		p = strings.TrimSpace(p)
		switch p {
		case PermSystem, PermSecurity, PermAudit:
		default:
			return nil, ErrAdminRolePerm
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, ErrAdminRolePerm
	}
	sort.Strings(out)
	return out, nil
}

// BuiltinAdminRoles 内置四角色（超管 + 三权分立）。每次启动按 power 重算 Perms 覆盖
// 内置行——将来新增权限键时，内置角色自动跟上，不需要再写一次数据迁移。
func BuiltinAdminRoles() []AdminRole {
	return []AdminRole{
		{Key: "root", Name: "超级管理员", Power: PowerRoot, Builtin: true, Perms: PowerPerms(PowerRoot)},
		{Key: "system", Name: "系统管理员", Power: PowerSystem, Builtin: true, Perms: PowerPerms(PowerSystem)},
		{Key: "security", Name: "安全管理员", Power: PowerSecurity, Builtin: true, Perms: PowerPerms(PowerSecurity)},
		{Key: "audit", Name: "审计管理员", Power: PowerAudit, Builtin: true, Perms: PowerPerms(PowerAudit)},
	}
}

// SystemBundle 系统管理页：管理员角色（三权分立）+ 管理员账号。
//
// ★集群状态**不在这里**：它是「主机此刻怎么看备机」，判定要用当前时间与落后阈值，
// 而 store 层既不该持有时钟口径也不该持有阈值配置。api.handleSystem 把
// standby.ClusterView 与本 bundle 拼在同一份响应里下发（见 api/standby.go 的 clusterView），
// /diag 的 checkCluster 读的是同一个函数——两处口径不可能再分叉。
type SystemBundle struct {
	Roles  []AdminRole    `json:"roles"`
	Admins []AdminAccount `json:"admins"`
}

// AdminAccount 一名管理员（users 表里 role='admin' 的行 + 其 admin_role 归属）。
type AdminAccount struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Account  string `json:"account"`
	RoleKey  string `json:"roleKey"`
	RoleName string `json:"roleName"`
	Power    string `json:"power"`
	// Auth / TwoFA / Factors 按**真实注册过的认证器**实算，不是配置里写的认证方式。
	//
	// ★三者同源但用途不同（照 AdminRole 的 Perms/Scope 那条分工）：
	//   Factors 是**机读**的因子清单，页面据它渲染；Auth 是它的中文摘要；
	//   TwoFA 是"有没有第二因子"的布尔。页面拿摘要去猜因子就会出现
	//   「只绑了 TOTP 的管理员被显示成已注册 passkey」——那正是改造前的形态。
	Auth  string `json:"auth"`
	TwoFA bool   `json:"twoFa"`
	// Factors 已注册的第二因子（"passkey" / "totp"），机读，空 = 没有第二因子。
	Factors   []string `json:"factors"`
	LastLogin string   `json:"lastLogin"`
	Status    string   `json:"status"` // active | disabled | locked | idle
}

// ★曾经这里有一对 ClusterInfo / ClusterNode 类型与一个恒回「未部署」的构造函数。
// 温备落地后，集群状态改由 standby.ClusterView 承载（真读 standby_nodes 表），
// 这两个类型再留着就是第二份前后端契约——留一个"将来也许用得上"的空壳，
// 下一个人会以为它才是真的那份。
