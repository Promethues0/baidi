package store

import "context"

// AuthSrcBundle 认证源接入页顶部的聚合视图。
//
// ★这个 Bundle 曾经是全项目最误导的一块：同一个页面下半截已经在读真实的
// auth_sources（LDAP/OIDC 真落库、真探测、真参与登录），上半截却还渲染着
// 6 条硬编码认证源和「总部 AD 域 1160 用户」这种凭空数字——代码层根本拒绝
// 创建的 radius/短信/证书源，在这里被报成"在线"。现在它只由 auth_sources
// 真实行构建，与 GET /api/v1/authsrc/sources **同一份数据**。
//
// 「自适应认证规则」那一段（原 Rules 字段）已从本 Bundle 删除：白帝真实生效的
// 自适应认证是 auth_policies（Enhance/Exempt 由 internal/authpolicy.Evaluate 在
// 登录链路求值），Rules 是与之无关的第二套编造规则，既不落库也不参与任何判定。
// 保留它等于给同一件事维护两个互相矛盾的展示口径。
type AuthSrcBundle struct {
	Sources []AuthSource `json:"sources"`
}

// AuthSource 一条认证源的页面投影（配置事实，不含任何推断出来的运行态）。
//
// ★刻意没有 status（online/warning）字段：控制面并不持续探测目录可达性，
// 可达与否只有点「测试连接」（POST …/probe）那一刻才知道。存一个恒为 online
// 的状态列，等于让页面替一台可能早已宕掉的 AD 打包票。
type AuthSource struct {
	Key      string `json:"key"` // = auth_sources.id
	Name     string `json:"name"`
	Type     string `json:"type"`    // local | ldap | ad | oidc（与 AuthSourceRec.Kind 同口径）
	Enabled  bool   `json:"enabled"` // 管理意图：是否参与登录
	Priority int    `json:"priority"`
	// BoundAccounts 本系统内归属该源的账号数。**不是目录纳管用户数**——
	// 后者要遍历整个 LDAP 目录才数得出来，白帝没有也不该有那个能力，
	// 原实现里的 1160 就是凭空写的。这里的口径是可验证的库内事实：
	//   - 外部源：auth_source_bindings 里该源的绑定条数（登录过一次即建绑定）；
	//   - 本地目录：users 里没有任何外部绑定的账号数。
	BoundAccounts int `json:"boundAccounts"`
}

// AuthSrc Memory 没有 auth_sources 表，返回空集合而不是种子。
// 真实现见 (*SQLiteStore).AuthSrc。
func (m *Memory) AuthSrc(_ context.Context) (AuthSrcBundle, error) {
	return AuthSrcBundle{Sources: []AuthSource{}}, nil
}
