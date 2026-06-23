// Package auth 提供基于 HMAC-SHA256 的极简 JWT（stdlib，无外部依赖）与认证中间件。
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Claims 令牌载荷。
type Claims struct {
	Sub  string `json:"sub"`  // 账号
	Role string `json:"role"` // admin | user
	Name string `json:"name"` // 显示名
	Exp  int64  `json:"exp"`  // 过期 Unix 秒
}

var b64 = base64.RawURLEncoding

// Sign 用 secret 签发 JWT（HS256）。
func Sign(secret []byte, c Claims, ttl time.Duration) string {
	c.Exp = time.Now().Add(ttl).Unix()
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
