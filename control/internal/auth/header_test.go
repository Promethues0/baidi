package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// 阶段 0：Verify 必须先解析并锁定 JWT header 的 alg，再验签。
// 这是引入公钥（EdDSA）验证分支的前置——否则攻击者可把 alg 改成 HS256、
// 拿公钥（公开信息）当 HMAC 密钥伪造签名，即经典的 alg-confusion。
func TestVerifyRejectsBadHeader(t *testing.T) {
	secret := []byte("s3cret")
	good := Sign(secret, Claims{Sub: "u", Role: "user", Name: "u"}, time.Hour)
	if _, err := Verify(secret, good); err != nil {
		t.Fatalf("正常令牌应通过: %v", err)
	}

	// 用同一密钥重签，但把 header 换成其它 alg —— 必须被拒
	forge := func(hdr string) string {
		h := base64.RawURLEncoding.EncodeToString([]byte(hdr))
		payload := strings.Split(good, ".")[1]
		body := h + "." + payload
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(body))
		return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	}
	cases := map[string]string{
		"alg=none":      `{"alg":"none","typ":"JWT"}`,
		"alg=EdDSA":     `{"alg":"EdDSA","typ":"JWT"}`,
		"alg=RS256":     `{"alg":"RS256","typ":"JWT"}`,
		"alg 空":         `{"typ":"JWT"}`,
		"typ 非 JWT":     `{"alg":"HS256","typ":"JWE"}`,
		"header 非 JSON": `not-json`,
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(secret, forge(hdr)); err == nil {
				t.Fatalf("header %s 应被拒绝", hdr)
			}
		})
	}
}

// header 里带 kid 不影响校验（阶段 1 轮换要用它定位公钥）。
func TestVerifyAcceptsKidInHeader(t *testing.T) {
	secret := []byte("s3cret")
	c := Claims{Sub: "u", Role: "user", Name: "u", Exp: time.Now().Add(time.Hour).Unix(), Iat: time.Now().Unix()}
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"sess-abc"}`))
	pj, _ := json.Marshal(c)
	body := h + "." + base64.RawURLEncoding.EncodeToString(pj)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(body))
	tok := body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))

	if _, err := Verify(secret, tok); err != nil {
		t.Fatalf("带 kid 的令牌应通过: %v", err)
	}
}
