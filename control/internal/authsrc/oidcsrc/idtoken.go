package oidcsrc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256" // 注册 SHA-256
	_ "crypto/sha512" // 注册 SHA-384/512，否则 crypto.Hash.New() 会 panic("requested hash function is unavailable")
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// algSpec 一个签名算法的全部要素。
//
// ★ 这张表就是「算法白名单」本体，也是本包最重要的一处安全边界：
// **验签用哪个算法，由我们的配置决定，不由令牌头里的 alg 决定**。
// 令牌头的 alg 只被允许做一件事——在我们已经批准的集合里"选一个"，
// 选中的算法还必须与选出的公钥类型/曲线自洽。任何"按令牌自称的算法去验"的实现
// 本身就是漏洞，无论它后面又补了多少校验。
//
// 表里刻意**没有** HS*（对称）与 none：
//   - none：JWT 最著名的绕过，去掉签名段即可伪造任意身份。
//   - HS*：算法混淆。HS256 会拿一个字节串当 HMAC 密钥，而在 OIDC 语境下这个字节串
//     就是 client_secret——那是我们和 IdP **双方都知道**的秘密。把它变成签名密钥，
//     意味着任何持有 client_secret 的一方（包括 IdP 侧任何能读到集成配置的人、
//     以及任何一次配置泄露）都能凭空签出"任意用户已登录"的 ID Token。
//     更糟的经典变体是：攻击者把 RS256 换成 HS256，用**公开的**公钥当 HMAC 密钥伪造。
//     防法只有一条——从白名单里彻底移除对称算法，而不是"如果 alg 是 HS 就多校验几下"。
type algSpec struct {
	hash crypto.Hash
	kty  string // 允许的 JWK kty
	// curve 仅 EC 有值：把 alg 与曲线钉死（ES256 只配 P-256）。
	// 留空表示"该算法不涉及曲线"，pickKey 据此跳过曲线校验。
	curve elliptic.Curve
	pss   bool // RSASSA-PSS（PS*）
}

var supportedAlgs = map[string]algSpec{
	"RS256": {hash: crypto.SHA256, kty: "RSA"},
	"RS384": {hash: crypto.SHA384, kty: "RSA"},
	"RS512": {hash: crypto.SHA512, kty: "RSA"},
	"PS256": {hash: crypto.SHA256, kty: "RSA", pss: true},
	"PS384": {hash: crypto.SHA384, kty: "RSA", pss: true},
	"PS512": {hash: crypto.SHA512, kty: "RSA", pss: true},
	"ES256": {hash: crypto.SHA256, kty: "EC", curve: elliptic.P256()},
	"ES384": {hash: crypto.SHA384, kty: "EC", curve: elliptic.P384()},
	"ES512": {hash: crypto.SHA512, kty: "EC", curve: elliptic.P521()},
}

// defaultAlgs 未显式配置时接受的算法集合。RS256 是 OIDC 事实标准，ES256 次之。
var defaultAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// jwtHeader JWS 头。只认我们要用的三个字段。
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// numericDate 兼容「数字」与「字符串数字」两种时间戳写法。
// 规范说是 NumericDate（数字），但确有 IdP 下发字符串；不兼容的症状是
// json.Unmarshal 直接失败 → 所有登录都报"令牌格式错误"，而令牌其实完全合法。
type numericDate int64

func (n *numericDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	// 有 IdP 会给出带小数的秒（1700000000.5），截断到秒即可。
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("时间戳字段格式非法：%s", string(b))
	}
	*n = numericDate(v)
	return nil
}

func (n numericDate) time() time.Time { return time.Unix(int64(n), 0) }

// audience 兼容 aud 的两种形态：字符串 或 字符串数组。
// ★ 只按字符串解会在多受众 IdP（Azure AD 常见）上直接解析失败，
// 而只按数组解则在绝大多数 IdP 上失败——两种都必须接住。
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud 字段格式非法")
	}
	*a = many
	return nil
}

func (a audience) has(v string) bool {
	for _, s := range a {
		// 受众是精确匹配，不做大小写折叠：aud 是 client_id，由 IdP 原样下发。
		if subtle.ConstantTimeCompare([]byte(s), []byte(v)) == 1 {
			return true
		}
	}
	return false
}

// idTokenClaims ID Token 里**安全关键**的注册声明。业务属性走另一份 map（见 verifyIDToken），
// 两者分开是刻意的：安全判据必须是强类型的，属性映射才需要动态取值。
type idTokenClaims struct {
	Iss   string       `json:"iss"`
	Sub   string       `json:"sub"`
	Aud   audience     `json:"aud"`
	Azp   string       `json:"azp"`
	Exp   numericDate  `json:"exp"`
	Iat   numericDate  `json:"iat"`
	Nbf   *numericDate `json:"nbf"`
	Nonce string       `json:"nonce"`
}

// verifyIDToken 完整校验一枚 ID Token，返回注册声明与全部原始声明（供属性映射）。
//
// 校验顺序是有讲究的：先锁算法（不然后面全白搭）→ 再验签（不然声明都是攻击者写的）
// → 最后才看声明。任何"先信一下声明再说"的实现（比如先读 iss 去挑配置）都会把
// 未验签的数据当成决策依据。
func (p *Provider) verifyIDToken(ctx context.Context, raw, expectNonce string) (idTokenClaims, map[string]any, error) {
	var zero idTokenClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return zero, nil, errInvalidToken("ID Token 结构非法（不是三段式 JWS）")
	}

	// ── ① 头：算法白名单 ──
	hdrRaw, err := b64raw.DecodeString(parts[0])
	if err != nil {
		return zero, nil, errInvalidToken("ID Token 头不是合法 base64url")
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return zero, nil, errInvalidToken("ID Token 头不是合法 JSON")
	}
	// typ 允许缺省或 JWT。明确拒 at+jwt：那是**访问令牌**的类型标记，
	// 把访问令牌当 ID Token 用会绕过 aud/nonce 的全部语义（access token 的 aud 是资源，不是我们）。
	if t := strings.ToUpper(strings.TrimSpace(hdr.Typ)); t != "" && t != "JWT" {
		return zero, nil, errInvalidToken("ID Token 的 typ=%q 不是 JWT", hdr.Typ)
	}
	alg := strings.TrimSpace(hdr.Alg)
	switch {
	case alg == "" || strings.EqualFold(alg, "none"):
		// ★ 单独一条分支，只为了让日志里能明确看到"有人在试 alg=none"。
		// 合并进下面的通用拒绝也不会有漏洞，但会丢掉这个非常值钱的信号。
		return zero, nil, errInvalidToken("ID Token 使用 alg=none（无签名），已拒绝")
	case strings.HasPrefix(strings.ToUpper(alg), "HS"):
		// ★ 同上，单列一条：HS* 出现在 ID Token 上要么是 IdP 配置错误，
		// 要么就是有人在试算法混淆，两种都需要被看见。
		return zero, nil, errInvalidToken("ID Token 使用对称算法 %s，已拒绝（对称签名会把 client_secret 变成签名密钥）", alg)
	}
	if !p.algAllowed(alg) {
		return zero, nil, errInvalidToken("ID Token 签名算法 %s 不在白名单内", alg)
	}
	spec := supportedAlgs[alg]

	// ── ② 验签 ──
	sig, err := b64raw.DecodeString(parts[2])
	if err != nil {
		return zero, nil, errInvalidToken("ID Token 签名段不是合法 base64url")
	}
	pub, err := p.jwks.key(ctx, p.fetchJWKS, hdr.Kid, alg, p.now())
	if err != nil {
		return zero, nil, err
	}
	signingInput := parts[0] + "." + parts[1]
	if err := verifySignature(spec, pub, []byte(signingInput), sig); err != nil {
		return zero, nil, err
	}

	// ── ③ 声明（到这一步才允许相信 payload）──
	payload, err := b64raw.DecodeString(parts[1])
	if err != nil {
		return zero, nil, errInvalidToken("ID Token 载荷不是合法 base64url")
	}
	var c idTokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return zero, nil, errInvalidToken("ID Token 载荷解析失败：%v", err)
	}
	all := map[string]any{}
	if err := json.Unmarshal(payload, &all); err != nil {
		return zero, nil, errInvalidToken("ID Token 载荷不是 JSON 对象")
	}

	if err := p.checkClaims(c, expectNonce); err != nil {
		return zero, nil, err
	}
	return c, all, nil
}

// checkClaims 校验 iss / aud / azp / exp / iat / nbf / nonce / sub。
// 抽出来单独一个函数，是为了让测试能逐条打靶——每一条漏掉都是一个独立的绕过。
func (p *Provider) checkClaims(c idTokenClaims, expectNonce string) error {
	now := p.now()
	skew := p.cfg.ClockSkew

	// iss：必须与**发现文档里的 issuer** 精确一致。
	// ★ 不校验 iss 一致性 = 允许「A 家 IdP 签的令牌拿到 B 家的配置下用」：
	// 攻击者在自己控制的 IdP 上把 sub 设成受害者的 sub、aud 设成我们的 client_id，
	// 签出来的令牌在缺少 iss 校验时会完全合法地通过。
	if c.Iss != p.expectedIssuer() {
		return errInvalidToken("ID Token 的 iss=%q 与认证源 issuer=%q 不符", c.Iss, p.expectedIssuer())
	}

	// aud：必须包含我们的 client_id。
	if len(c.Aud) == 0 || !c.Aud.has(p.cfg.ClientID) {
		return errInvalidToken("ID Token 的 aud=%v 不包含本应用 client_id", []string(c.Aud))
	}
	// 多受众时 azp（授权方）必须是我们自己。
	// ★ 场景：IdP 给 A 应用签的令牌把 B 也列进 aud（跨应用共享受众是真实存在的配置），
	// 只查"aud 含我"就会接受一枚**本不是发给我们**的令牌。
	if len(c.Aud) > 1 {
		if c.Azp == "" {
			return errInvalidToken("ID Token 含多个 aud 却缺少 azp，无法确认授权方")
		}
		if c.Azp != p.cfg.ClientID {
			return errInvalidToken("ID Token 的 azp=%q 不是本应用", c.Azp)
		}
	} else if c.Azp != "" && c.Azp != p.cfg.ClientID {
		return errInvalidToken("ID Token 的 azp=%q 不是本应用", c.Azp)
	}

	// exp：过期即拒。允许一点时钟偏移，但偏移是**双向容忍**不是"顺延有效期"，
	// 所以容忍量必须小（默认 2 分钟），大了等于变相延长令牌寿命。
	if c.Exp == 0 {
		return errInvalidToken("ID Token 缺少 exp")
	}
	if !now.Before(c.Exp.time().Add(skew)) {
		return errInvalidToken("ID Token 已过期（exp=%s）", c.Exp.time().Format(time.RFC3339))
	}
	// iat：必须存在且不能来自未来。
	// 同时限制"太旧"：授权码换令牌是秒级动作，一枚签发于半小时前的 ID Token
	// 只可能是重放（nonce 校验是主防线，这是纵深）。
	if c.Iat == 0 {
		return errInvalidToken("ID Token 缺少 iat")
	}
	if c.Iat.time().After(now.Add(skew)) {
		return errInvalidToken("ID Token 的 iat 来自未来（iat=%s）", c.Iat.time().Format(time.RFC3339))
	}
	if maxAge := p.cfg.MaxIDTokenAge; maxAge > 0 && now.Sub(c.Iat.time()) > maxAge+skew {
		return errInvalidToken("ID Token 签发时间过旧（iat=%s，超过 %s）", c.Iat.time().Format(time.RFC3339), maxAge)
	}
	// nbf：可选，给了就得生效。
	if c.Nbf != nil && now.Add(skew).Before(c.Nbf.time()) {
		return errInvalidToken("ID Token 尚未生效（nbf=%s）", c.Nbf.time().Format(time.RFC3339))
	}

	// nonce：必须与本次会话生成的一致。
	// ★ 这是防重放的**唯一**手段。不验 nonce 的话，任何一枚历史上合法的 ID Token
	// （从日志里捞的、从浏览器缓存里翻的、从另一个应用那里拿到的）都能被重新提交完成登录，
	// 而且这次"登录"在审计日志里和正常登录一模一样，事后完全无从分辨。
	// 期望值为空时**不是**跳过校验，而是直接失败——见 Exchange 里的前置检查。
	if expectNonce == "" {
		return errInvalidToken("内部错误：未提供期望的 nonce，拒绝校验")
	}
	if subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(expectNonce)) != 1 {
		return errInvalidToken("ID Token 的 nonce 与本次登录会话不匹配（疑似重放）")
	}

	// sub：身份的权威标识，空了后面整条账号映射都无从谈起。
	if strings.TrimSpace(c.Sub) == "" {
		return errInvalidToken("ID Token 缺少 sub")
	}
	return nil
}

// verifySignature 按 spec 指定的算法验签。注意入参 spec 来自**我们的白名单**，
// 公钥来自 JWKS 且已按 spec 过滤过类型/曲线，两者在此汇合。
func verifySignature(spec algSpec, pub crypto.PublicKey, signingInput, sig []byte) error {
	h := spec.hash.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	switch spec.kty {
	case "RSA":
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errInvalidToken("公钥类型与签名算法不符")
		}
		if spec.pss {
			// PS* 的盐长度按规范等于摘要长度。
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash}
			if err := rsa.VerifyPSS(rp, spec.hash, digest, sig, opts); err != nil {
				return errInvalidToken("ID Token 签名校验失败（PSS）")
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(rp, spec.hash, digest, sig); err != nil {
			return errInvalidToken("ID Token 签名校验失败")
		}
		return nil
	case "EC":
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errInvalidToken("公钥类型与签名算法不符")
		}
		// ★ JWS 的 ECDSA 签名是 R‖S **定长拼接**，不是 ASN.1 DER。
		// 用 ecdsa.VerifyASN1 去验会一律失败（症状：ES256 全线验不过、RS256 却正常），
		// 反过来把 DER 当定长解则会读出错误的 R/S。长度必须严格等于 2×曲线字节长，
		// 不能只判 ">="——多余字节会让 R/S 的切分位置整体错位。
		size := (ep.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errInvalidToken("ID Token 的 ECDSA 签名长度非法（%d，应为 %d）", len(sig), 2*size)
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(ep, digest, r, s) {
			return errInvalidToken("ID Token 签名校验失败（ECDSA）")
		}
		return nil
	}
	return errInvalidToken("不支持的密钥类型 %q", spec.kty)
}

// algAllowed 报告某算法是否被本认证源接受。白名单是 cfg.SigningAlgs 与内建表的交集，
// 配置只能**收窄**不能扩宽（New 里已校验配置项都在内建表内）。
func (p *Provider) algAllowed(alg string) bool {
	for _, a := range p.algs {
		if a == alg {
			return true
		}
	}
	return false
}

// ★ 刻意**没有**校验 at_hash：授权码流下访问令牌是我们自己从令牌端点经 TLS 直接取回的，
// 中间没有前端参与，不存在令牌替换的窗口，at_hash 在这条路径上是冗余的。
// 若将来支持 implicit / hybrid 流（access token 经浏览器地址栏回传），at_hash 立刻变成**必须**
// ——那条路径上访问令牌可被替换，而 UserInfo 的 sub 比对只能事后发现、不能事前阻止。
