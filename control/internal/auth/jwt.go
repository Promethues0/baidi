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

// UseWeb 七层 Web 代理访问票据的用途标记（Claims.Use）。
//
// 浏览器做不了 SPA 敲门（那是带签名令牌的 UDP 包），所以 B/S 免客户端接入需要另一条
// 「控制面签、数据面验」的入场路径。它与敲门令牌**同款纪律**：短时效（≤60s）、带 jti、
// 一次性、且用 Res 字段把票据钉死在某一个资源上。
//
// ★用途闸必须双向：敲门路径拒 use=web，L7 路径拒 use=knock。二者还各用一把独立密钥
// 签（见 Keys.web），所以拿错路径的票据在对面**连签名都验不过**——use 判断退化成纵深。
const UseWeb = "web"

// UsePwReset 首登强制改密的受限令牌用途标记（Claims.Use）。
// 口令验证通过但 must_change_pw=1 时签发（15min），中间件只放行改密与查身份两个端点；
// 它由 sess 密钥签出且 use≠knock，故既调不到业务 API，也从密码学与语义两层都敲不开门。
const UsePwReset = "pwreset"

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
	Use  string `json:"use,omitempty"` // 令牌用途：knock=敲门令牌；web=L7 访问票据；空=会话令牌/MFA 票据
	// Res 票据绑定的受控资源 id（只有 Use=UseWeb 时有值）。
	//
	// ★它是「一张票只开一扇门」的载体：网关据此把 Cookie 绑到 (账号, 资源)，
	// 一个应用的会话凭据换不到另一个应用。不带资源维度的票据等于一张万能通行证——
	// 而 L7 端点是对浏览器可达的入站面，万能通行证的爆炸半径是全部已发布 Web 应用。
	Res string `json:"res,omitempty"`
}

var b64 = base64.RawURLEncoding

// header JWT 头。kid 供多密钥/轮换时定位公钥（阶段 1 起使用）。
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// parseHeader 解析并校验 JWT 头：alg 必须在白名单内、typ 必须是 JWT。
//
// ★这是引入公钥验证分支的前置：若不锁定 alg，攻击者可把 alg 改成 HS256 并拿
// 公钥（公开信息）当 HMAC 密钥伪造签名——经典的 alg-confusion。当前单算法下
// 不构成漏洞，但必须先于任何 EdDSA 分支落地。
func parseHeader(seg string, allow ...string) (header, error) {
	raw, err := b64.DecodeString(seg)
	if err != nil {
		return header{}, errors.New("bad header")
	}
	var h header
	if err := json.Unmarshal(raw, &h); err != nil {
		return header{}, errors.New("bad header")
	}
	if h.Typ != "" && h.Typ != "JWT" {
		return header{}, errors.New("unexpected typ")
	}
	for _, a := range allow {
		if h.Alg == a {
			return h, nil
		}
	}
	return header{}, errors.New("unexpected alg: " + h.Alg)
}

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
	// 先锁 alg，再验签：杜绝 alg-confusion（见 parseHeader）。
	if _, err := parseHeader(parts[0], "HS256"); err != nil {
		return Claims{}, err
	}
	body := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(mac(secret, body)), []byte(parts[2])) {
		return Claims{}, errors.New("bad signature")
	}
	return decodeClaims(parts[1])
}

// decodeClaims 解析 payload 并校验有效期（EdDSA / HS256 两条验签路径共用）。
func decodeClaims(seg string) (Claims, error) {
	raw, err := b64.DecodeString(seg)
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

// hmacEqual 常量时间比较两个 base64 签名串。
func hmacEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }
