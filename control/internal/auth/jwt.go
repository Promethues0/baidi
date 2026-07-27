// Package auth 提供基于 HMAC-SHA256 的极简 JWT（stdlib，无外部依赖）与认证中间件。
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// UseKnock 敲门令牌的用途标记（Claims.Use）。数据面据此拒绝一切非敲门令牌，
// 见 gateway/internal/spa.checkKnock——这是"长效会话令牌可直接敲门"旁路的根治判据。
const UseKnock = "knock"

// Claims 令牌载荷。
//
// Use 字段是令牌的用途自证：只有 /knock-token 签发的短时效一次性敲门令牌填 UseKnock，
// 会话令牌与 MFA 半程票据一律留空。故意不用 jti 有无做判据——passkey 登录签发的 8h
// 会话令牌也带 jti（见 api/webauthn.go 断言成功处），按 jti 区分会给 passkey 用户留后门。
type Claims struct {
	Sub  string `json:"sub"`           // 账号
	Role string `json:"role"`          // admin | user
	Name string `json:"name"`          // 显示名
	Exp  int64  `json:"exp"`           // 过期 Unix 秒
	Iat  int64  `json:"iat,omitempty"` // 签发 Unix 秒
	Jti  string `json:"jti,omitempty"` // 令牌唯一 id（短时效敲门令牌用，网关按它一次性去重）
	Use  string `json:"use,omitempty"` // 令牌用途：knock=敲门令牌；空=会话令牌/MFA 票据
}

var b64 = base64.RawURLEncoding

// RandJTI 生成随机令牌 id（短时效敲门令牌单次有效的去重键）。
func RandJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

// Sign 用 secret 签发 JWT（HS256）；自动填充 Iat。
func Sign(secret []byte, c Claims, ttl time.Duration) string {
	now := time.Now()
	c.Iat = now.Unix()
	c.Exp = now.Add(ttl).Unix()
	header := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(c)
	body := header + "." + b64.EncodeToString(payload)
	return body + "." + mac(secret, body)
}

// Verify 校验签名与有效期，返回 Claims。
func Verify(secret []byte, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("malformed token")
	}
	body := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(mac(secret, body)), []byte(parts[2])) {
		return Claims{}, errors.New("bad signature")
	}
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		return Claims{}, errors.New("bad payload")
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, errors.New("bad claims")
	}
	if c.Exp < time.Now().Unix() {
		return Claims{}, errors.New("token expired")
	}
	return c, nil
}

func mac(secret []byte, body string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(body))
	return b64.EncodeToString(h.Sum(nil))
}
