package store

import "context"

// UserDirBundle 访问者目录页：身份源 + 组织树 + 用户组目录 + 用户清单。
type UserDirBundle struct {
	Directories []Directory `json:"directories"`
	OrgTree     []OrgUnit   `json:"orgTree"`
	// Groups 用户组目录。随用户清单一起下发，前端才能把 DirUser.GroupIDs 显示成组名，
	// 不必为每个用户再查一次组。
	Groups []UserGroup `json:"groups"`
	Users  []DirUser   `json:"users"`
}

// Directory 访问者目录页顶部的身份源分栏。
//
// ★这是 AuthSource 的投影，**同一份 auth_sources 真实行**（见 SQLiteStore.userDirectories）。
// 它曾经是本项目最后一处「方法实现了、字段仍来自种子」的残留：Users() 以
// s.Memory.Users(ctx) 打底、只覆盖组织树/用户组/用户清单，Directories 原样继承种子的
// 「本地目录 124 / 总部 AD 域 1160」——库里明明只有 8 个用户，页面顶部却挂着两个凭空数字，
// 而且没有配置过任何认证源的部署也会显示一个并不存在的 AD 域。
//
// ★刻意没有 Online 与 LastSync 两个字段：
//   - Online：users.online 那一列只在建号时写过一次，登录/登出都不更新，按它数出来的
//     「在线 88」是一个冻结在建库那一刻的数字。真实在线只有网关上报的会话知道
//     （api 层 gwSess，见在线用户页），而那份数据没有"属于哪个目录"这一维。
//   - LastSync：白帝**不做目录周期同步**——外部账号是首次登录时按 subject 绑定建号的
//     （BindExternalUser）。显示「上次同步 5 分钟前」等于宣称一个不存在的同步任务在跑。
type Directory struct {
	Key   string `json:"key"`  // = auth_sources.id
	Name  string `json:"name"` // = auth_sources.name
	Type  string `json:"type"` // local | ldap | ad | oidc（= auth_sources.kind）
	Users int    `json:"users"`
}

type OrgUnit struct {
	Key      string    `json:"key"`
	Title    string    `json:"title"`
	Members  int       `json:"members"`
	Children []OrgUnit `json:"children,omitempty"`
}

// DirUser 目录中的用户（含实时在线态供池化卡片展示）。
type DirUser struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Account string `json:"account"`
	Org     string `json:"org"`
	OrgKey  string `json:"orgKey"`
	// OrgID 组织归属（org_units.id）。org / orgKey 是组织表出现前的展示遗物，
	// OrgID 有值时以组织表为准回填那两列（见 SQLiteStore.Users）。
	OrgID string `json:"orgId"`
	// GroupIDs 所属用户组 id（含角色组的派生归属）。读取时实算，写入走 SetUserGroups。
	GroupIDs  []string `json:"groups"`
	Device    string   `json:"device"`
	IP        string   `json:"ip"`
	Auth      string   `json:"auth"`
	LastLogin string   `json:"lastLogin"`
	Online    bool     `json:"online"`
	Status    string   `json:"status"` // active | locked | disabled | idle
	Risk      string   `json:"risk"`   // none | low | high | unknown（不可判定，见 api.enrichDirUsers）
	Roles     []string `json:"roles"`
	Role      string   `json:"role,omitempty"` // 权威鉴权角色 admin | user（≠展示用 Roles）
	PassHash  string   `json:"-"`              // bcrypt 口令哈希；绝不序列化进 API 响应
	// MustChangePw 首次登录须改密标志。管理员新建/重置口令置 1，自助改密成功清 0；
	// 置位期间登录只拿到 15min 受限令牌（Use=pwreset），调不到任何业务端点。
	// 不序列化：消费方是登录链路（Credential），目录 API 无人读它。
	MustChangePw bool `json:"-"`
	// PwStrength 口令强度标记 weak | strong | unknown（auth.Pw*）。建号时由 API 层按明文判定，
	// 之后只由 SetUserPassword 更新。消费方是认证策略的「弱密码」增强规则——登录链路
	// 只有 bcrypt 哈希，判不出强度，只能消费这个在设密码那一刻落下的标记。
	// 不序列化：它是判定材料，不是目录展示字段（管理台另有专门口径展示）。
	PwStrength string `json:"-"`
	// Email 外部认证源带回的邮箱（本地账号暂无采集入口，恒空=未知）。
	Email string `json:"email"`
	// AdminRole 管理员角色 key（admin_roles."key"，三权分立），非管理员为空。
	// **刻意不序列化**：能从 POST /api/v1/users 的请求体里塞进来的话，
	// 持 security 权的管理员就能凭"新建用户"给自己造一个超管——提权只需一次请求。
	// 分派管理员角色的唯一入口是 /api/v1/admins（需 admins 权限）。
	AdminRole string `json:"-"`
	// SourceID 这个账号属于哪个**用户目录**：外部源 id，或 DirectoryLocal（本地口令目录）。
	//
	// ★这一维此前整个不存在，于是「用户与角色」页那排身份源选项卡是纯装饰的：
	// 选项卡上写着「总部 AD 域 3」，点进去表头却是全量表，本地账号与各外部目录的
	// 账号混在同一张表里，顶部四个聚合数也永远是全库口径。
	// PRD FR-USER-01 的「目录间相互独立、以选项卡形式分目录管理」在界面上完全不成立。
	//
	// 判据与目录计数（authSourceAccountCounts）**同源**：绑定表里有行 = 属于该源，
	// 没有 = 本地。两处各写一套的话，选项卡上的数与点进去的行数会对不上。
	SourceID string `json:"sourceId"`
}

// DirectoryLocal 本地口令目录的 id（DirUser.SourceID 的取值之一）。
//
// ★必须与 authsrc.KindLocal 以及 authsrc_sqlite 里那几处 "local" 字面量一致：
// 选项卡的 key 来自 userDirectories（那边用的就是 "local"），列表的过滤键来自
// DirUser.SourceID——两边对不上的话，点「本地用户目录」会筛出**零行**，
// 而选项卡徽标上明明写着 9 人。store 不能 import authsrc（那边反向依赖 store），
// 所以这里留一份常量而不是继续散落字面量。
const DirectoryLocal = "local"

// Credential 登录校验所需的账号凭据（含口令哈希，仅内部使用）。
type Credential struct {
	ID       string
	Name     string
	Account  string
	Role     string // admin | user
	Status   string // active | locked | disabled | idle
	PassHash string
	// MustChangePw 首登强制改密标志：为真时登录链路不发会话令牌，改签受限改密令牌。
	MustChangePw bool
	// PwStrength 口令强度标记 weak | strong | unknown（auth.Pw*），认证策略「弱密码」规则的判据。
	PwStrength string
}

func (m *Memory) Users(_ context.Context) (UserDirBundle, error) {
	users := []DirUser{
		{ID: "u1", Name: "张伟", Account: "zhang.wei", Org: "研发部", OrgKey: "dev", Device: "Windows 11", IP: "10.8.2.31", Auth: "密码+短信", LastLogin: "2026-06-22 19:42", Online: true, Status: "active", Risk: "none", Roles: []string{"研发", "管理员"}},
		{ID: "u2", Name: "李芳", Account: "li.fang", Org: "销售部", OrgKey: "sales", Device: "macOS 14", IP: "10.8.5.12", Auth: "SAML SSO", LastLogin: "2026-06-22 18:10", Online: true, Status: "active", Risk: "high", Roles: []string{"销售"}},
		{ID: "u3", Name: "王强", Account: "wang.qiang", Org: "销售部", OrgKey: "sales", Device: "iPhone", IP: "10.8.5.40", Auth: "密码", LastLogin: "2026-06-22 14:05", Online: true, Status: "active", Risk: "none", Roles: []string{"销售"}},
		{ID: "u4", Name: "赵敏", Account: "zhao.min", Org: "客服中心", OrgKey: "cs", Device: "Windows 10", IP: "10.8.7.9", Auth: "密码+UKey", LastLogin: "2026-06-22 09:30", Online: false, Status: "locked", Risk: "low", Roles: []string{"客服"}},
		{ID: "u5", Name: "外包-周", Account: "ext.zhou", Org: "外包人员", OrgKey: "ext", Device: "未授信终端", IP: "203.0.113.7", Auth: "密码+短信", LastLogin: "2026-06-22 11:18", Online: false, Status: "disabled", Risk: "high", Roles: []string{"外包"}},
		{ID: "u6", Name: "陈静", Account: "chen.jing", Org: "研发部", OrgKey: "dev", Device: "Ubuntu 22", IP: "10.8.2.55", Auth: "密码", LastLogin: "2026-05-20 16:00", Online: false, Status: "idle", Risk: "none", Roles: []string{"研发"}},
		{ID: "u7", Name: "刘洋", Account: "liu.yang", Org: "客服中心", OrgKey: "cs", Device: "Windows 11", IP: "10.8.7.21", Auth: "密码+短信", LastLogin: "2026-06-22 20:01", Online: true, Status: "active", Risk: "none", Roles: []string{"客服", "组长"}},
	}
	// ★这里**不给 Directories**：身份源只有 auth_sources 真实行说了算
	// （SQLiteStore.userDirectories）。种子里那两条「本地目录 124 / 总部 AD 域 1160」
	// 曾经原样漏进真实部署的页面顶部，理由见 Directory 的注释。
	//
	// ★组织树只留结构（key/标题/父子），**不带 Members 计数**：这棵树的唯一消费方是
	// backfillOrgUnits（把它建成真实 org_units 行），成员数由 buildOrgTree 按 users 实算。
	// 在这里写一个 210，只会在某天有人拿种子树直接渲染时变成第二个"看起来是真的"的数字。
	return UserDirBundle{
		OrgTree: []OrgUnit{
			{Key: "root", Title: "ACME 集团", Children: []OrgUnit{
				{Key: "dev", Title: "研发部"},
				{Key: "sales", Title: "销售部"},
				{Key: "cs", Title: "客服中心"},
				{Key: "ext", Title: "外包人员"},
			}},
		},
		Users: users,
	}, nil
}
