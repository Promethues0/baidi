package store

import "context"

// ── 认证源落库（替代原来那一整页内存种子）──
//
// 原实现 `Memory.AuthSrc` 返回 6 条硬编码认证源，连「总部 AD 域 1160 用户」
// 这个数字都是凭空写的；控制台上的「接入认证源 / 同步」按钮背后没有任何东西。
// 现在配置真落库、连通性真探测、登录真走外部目录。
//
// ★留下的只有 local 一条。其余 5 条（AD/RADIUS/OAuth/短信/商密证书）已删除——
// 留着一个编造用户数的磁贴，比没有这个磁贴更不诚实。RADIUS/短信/证书三种类型
// 至今没有实现，`authsrc.Kind.Supported()` 会在 API 层把它们挡回去。

// AuthSourceRec 一条认证源配置。
//
// ★凭据（LDAP 的 bind 口令、OIDC 的 client_secret）**不在这个结构体里**：
// 它们走 auth_source_secrets 独立表并加密落盘，只写不读（见 IpsecSecret 同款推理）。
// 物理分表的意义不是"防拖库"这种口号，而是让"某天有人写了 SELECT *"或忘加
// requireAdmin 时，泄露需要显式写代码，而不是默认发生。
type AuthSourceRec struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`    // local | ldap | ad | oidc
	Enabled bool   `json:"enabled"` // 管理意图
	// Priority 多个源时的询问顺序，小的先问。本地目录恒为最高优先级，不参与排序。
	Priority int `json:"priority"`
	// Config 该类型的非敏感配置 JSON（地址、BaseDN、issuer、client_id…）。
	// 敏感项一律不在这里——放进来就等于绕开了上面那道分表。
	Config string `json:"config"`

	// HasSecret / SecretFingerprint 是只写不读语义下的唯一回显：
	// 管理员能确认"配过了"并核对两端是不是同一把，但拿不到原文。
	HasSecret         bool   `json:"hasSecret"`
	SecretFingerprint string `json:"secretFingerprint,omitempty"`

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// AuthSourceSecret 一条加密落盘的认证源凭据。
type AuthSourceSecret struct {
	SourceID string
	Nonce    []byte
	Cipher   []byte
	// Fingerprint 凭据的截断哈希（前 8 位），**由写入方算好存进来**。
	//
	// ★为什么不在读列表时解密算：那会在一条人人可读的路径上引入解密调用，
	// 与整个「只写不读」的姿态自相矛盾。指纹本身只是个截断哈希、不敏感，
	// 它的唯一用途是让管理员核对"两端配的是不是同一把"。
	Fingerprint string
}

// AuthSourceStore 认证源的读写。
//
// ★与 IpsecStore 同款考虑：把"读凭据密文"这种只该被两个 handler 调用的能力
// 收在一个独立接口里，而不是挂到人人可得的 Writer 上。
type AuthSourceStore interface {
	AuthSources(ctx context.Context) ([]AuthSourceRec, error)
	AuthSourceByID(ctx context.Context, id string) (AuthSourceRec, bool, error)
	SaveAuthSource(ctx context.Context, rec AuthSourceRec) (AuthSourceRec, error)
	DeleteAuthSource(ctx context.Context, id string) error
	// SaveAuthSourceSecret 写入（或替换）凭据密文。
	SaveAuthSourceSecret(ctx context.Context, sec AuthSourceSecret) error
	// AuthSourceSecret 取凭据密文。★调用点必须极少：只有"构造 Provider"这一处。
	AuthSourceSecret(ctx context.Context, id string) (AuthSourceSecret, bool, error)

	// ── 外部身份绑定 ──

	// UserBySubject 按认证源 id + 权威 subject 查已绑定的本地用户。
	UserBySubject(ctx context.Context, sourceID, subject string) (Credential, bool, error)
	// BindExternalUser 建立（或更新）外部身份 → 本地用户的绑定，并按需建本地用户。
	BindExternalUser(ctx context.Context, sourceID string, ext ExternalIdentity) (Credential, error)
}

// ExternalIdentity 外部认证源回来的身份（store 侧的投影，避免 store 反向依赖 authsrc 包）。
type ExternalIdentity struct {
	// Subject 认证源侧的权威标识（OIDC 的 sub / LDAP 的 entryDN）。
	//
	// ★账号绑定必须以它为键，不能用 Username。只按用户名匹配的话，
	// 谁能在外部目录里新建一个叫 admin 的账号，谁就能登录成本地管理员，
	// 而审计日志里看到的是一次完全正常的"admin 登录成功"。
	Subject     string
	Username    string
	DisplayName string
	Email       string
	Groups      []string
}
