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

// UseKnock 敲门令牌的用途标记（Claims.Use）。必须与 control/internal/auth 的同名常量一致——
// 两份 Claims 是手抄的，字段/取值不同步会导致解析静默丢失、strict 校验全线拒绝。
const UseKnock = "knock"

// UseWeb 七层 Web 代理访问票据的用途标记（Claims.Use）。
//
// ★用途闸双向：SPA 敲门路径拒 use=web（见 spa.checkKnock），L7 路径拒 use=knock
// （见 webproxy.VerifyTicket）。两条路径还各装一把独立公钥，故拿错票据在对面
// 连签名都验不过——use 判断是纵深，不是唯一防线。
const UseWeb = "web"

type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Name string `json:"name"`
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat,omitempty"`
	Jti  string `json:"jti,omitempty"` // 短时效敲门/Web 票据的唯一 id，网关据此一次性去重
	Use  string `json:"use,omitempty"` // 令牌用途：knock=敲门令牌；web=L7 访问票据；空=会话令牌/MFA 票据（strict 下拒绝）
	// Res 票据绑定的受控资源 id（只有 Use=UseWeb 时有值）。网关据此把会话 Cookie
	// 钉死在 (账号, 资源) 上——一个应用的 Cookie 换不到另一个应用。
	Res string `json:"res,omitempty"`
	// Gw 票据绑定的网关 id（= mTLS 证书 CN）。控制面按落点算出入口 URL 时一并写进票据，
	// 网关只收 Gw 为空或等于自己 id 的票。
	//
	// ★这条绑定是**一次性去重的前提**：去重缓存是每台网关自己的内存，没有网关维度的话，
	// 同一张票在每台装了 web 公钥的网关上都能各换一次会话——去重看起来做了，
	// 实际按网关台数被整除掉。空值（控制面走 BAIDI_WEB_ENTRY_BASE / 资源专属域名，
	// 不知道票会落到哪台）仍放行，那条路的边界写在 docs/ARCHITECTURE.md 第七节。
	Gw string `json:"gw,omitempty"`
}

var b64 = base64.RawURLEncoding

// header JWT 头。kid 供多密钥/轮换时定位公钥（阶段 1 起使用）。
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// parseHeader 解析并校验 JWT 头：alg 必须在白名单内、typ 必须是 JWT。
// 与 control/internal/auth 的同名函数保持一致——引入公钥验证分支前必须先锁 alg，
// 否则攻击者可把 alg 改成 HS256、拿公钥（公开信息）当 HMAC 密钥伪造签名。
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

// ★本包刻意不提供 Sign：数据面只验证、不签发（CA 身份迁移 阶段 4）。
// 网关的机器身份走 mTLS 客户端证书（internal/cplane），用户令牌由 control 私钥签发、
// 网关持公钥验证（verifier.go）。留一个 Sign 在这里，就等于把签发能力留在被保护方。

// Verify 校验签名与有效期。
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
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(body))
	if !hmac.Equal([]byte(b64.EncodeToString(h.Sum(nil))), []byte(parts[2])) {
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
