// Package auth 校验 baidi-control 签发的 HS256 JWT（与 control/internal/auth 同算法、共享密钥）。
// 网关据此把"身份"绑定到 SPA 授权：只有持有效 JWT 的访问者才能敲开门。
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

type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Name string `json:"name"`
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat,omitempty"`
	Jti  string `json:"jti,omitempty"` // 短时效敲门令牌的唯一 id，网关据此一次性去重
}

var b64 = base64.RawURLEncoding

// Verify 校验签名与有效期。
func Verify(secret []byte, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("malformed token")
	}
	body := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(body))
	if !hmac.Equal([]byte(b64.EncodeToString(h.Sum(nil))), []byte(parts[2])) {
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
