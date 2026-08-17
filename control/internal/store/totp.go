package store

import "context"

// ── TOTP 二次认证（RFC 6238，wave7 行动 4）──
//
// 与 passkey 并列的第二种真二因子。分工：算法在 internal/totp（纯函数），
// 密钥加解密在 api 层（secret 盒，AAD="totp:"+account），本层只存密文行
// 与防重放计数——store 看不到密钥原文，与 auth_source_secrets 同一条纪律。

// TotpRecord 一条 TOTP 注册（密文行原样，解密在 api 层）。
type TotpRecord struct {
	Account string
	Nonce   []byte
	Cipher  []byte
	// Confirmed 用户是否已用一个正确验证码完成确认。未确认的行不参与登录判定：
	// 「点了注册但没扫码」不该把人锁在门外。
	Confirmed   bool
	LastCounter uint64
	CreatedAt   string
}

// TotpStatus 状态投影（门户安全设置页展示用，永不携带密钥材料）。
type TotpStatus struct {
	Enrolled  bool   `json:"enrolled"`  // 有密文行（可能尚未确认）
	Confirmed bool   `json:"confirmed"` // 已确认——登录起即强制 TOTP
	CreatedAt string `json:"createdAt,omitempty"`
}

// Memory 空实现：TOTP 是真实数据域，只有 SQLite 承载（与 webauthn 同款）。
func (m *Memory) TotpFor(context.Context, string) (TotpRecord, bool, error) {
	return TotpRecord{}, false, nil
}
