package store

import (
	"context"
	"errors"
)

// ── WebAuthn / passkey 二次认证（FIDO2）──
// 从 Teleport 的 WebAuthn 二次因子取形：用抗钓鱼的公钥凭据取代硬编码演示验证码。
// 三个仪式：注册（attestation 落库公钥）→ 登录断言（口令通过后的第二因子）→ 凭据管理。
//
// 判定权全在控制面：challenge 服务端生成/存储/单次消费，断言校验用库中公钥，
// 网关零改动（与 posture、JIT 同一套路）。

// WebauthnCredential 一条已注册的 passkey 凭据（公钥 + 计数器 + 元信息）。
// 绑 UserID（users.id 稳定主键）而非 account——account 靠 lower(trim) 规范化匹配、改名会失联。
type WebauthnCredential struct {
	ID           string `json:"id"`
	UserID       string `json:"userId"`       // → users.id
	Account      string `json:"account"`      // 规范化账号（冗余，便于按登录名查凭据）
	CredentialID string `json:"credentialId"` // base64url(rawId)，断言查找键，全局唯一
	PublicKey    string `json:"-"`            // base64 COSE 公钥；绝不出接口
	SignCount    uint32 `json:"signCount"`
	Transports   string `json:"transports"` // JSON 数组 ["internal","usb",…]
	AAGUID       string `json:"aaguid"`
	Name         string `json:"name"` // 用户可读别名（Touch ID / YubiKey 5）
	CreatedAt    string `json:"createdAt"`
	LastUsedAt   string `json:"lastUsedAt"`
}

// WebauthnChallenge 一次仪式的服务端 challenge（单次消费 + 短 TTL，防重放）。
// 补上登录路径完全无状态、begin/finish 之间无处存 challenge 的结构缺口。
type WebauthnChallenge struct {
	ID          string `json:"id"`
	Account     string `json:"account"`   // 归属账号（登录断言时=已验口令的账号，绝不为空）
	Challenge   string `json:"challenge"` // base64url 32 字节随机
	Type        string `json:"type"`      // register | login
	SessionData string `json:"-"`         // go-webauthn SessionData JSON 快照
	ExpiresAt   int64  `json:"expiresAt"` // unix 秒
	Consumed    int    `json:"-"`
}

// challengeTTL 仪式两回合之间的窗口：够用户摸一次认证器，又短到不给重放留空间。
const challengeTTL = 120 // 秒

var (
	// ErrChallengeInvalid challenge 不存在/已消费/已过期/类型不匹配——单次消费守卫命中。
	ErrChallengeInvalid = errors.New("挑战已失效，请重新发起")
	// ErrCredentialNotFound 按 credentialID 查不到已注册凭据。
	ErrCredentialNotFound = errors.New("凭据不存在")
	// ErrCredentialExists 该 credentialID 已被注册（同一认证器重复注册）。
	ErrCredentialExists = errors.New("该认证器已注册")
	// ErrSignCountRegression 签名计数器倒退——疑似凭据克隆，拒绝本次断言。
	ErrSignCountRegression = errors.New("签名计数器异常，疑似凭据克隆")
	// ErrLastCredential 拒绝删除账号最后一个 passkey（否则开启强制 2FA 后会把自己锁在门外）。
	ErrLastCredential = errors.New("不能删除最后一个 passkey")
)

// ── Memory 空实现（真实数据域：无种子，只有 SQLite 覆盖版承载真实数据）──

func (m *Memory) WebauthnCredentialsFor(context.Context, string) ([]WebauthnCredential, error) {
	return []WebauthnCredential{}, nil
}
func (m *Memory) WebauthnCredentialByID(context.Context, string) (WebauthnCredential, bool, error) {
	return WebauthnCredential{}, false, nil
}
func (m *Memory) WebauthnCredentialCount(context.Context, string) (int, error) { return 0, nil }
