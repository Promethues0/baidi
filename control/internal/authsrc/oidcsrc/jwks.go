package oidcsrc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"sync"
	"time"
)

// jsonWebKey JWKS 里的一把公钥。只解析我们真正会用到的字段——
// 多余字段（key_ops、x5c 链等）刻意不碰：x5c 里的证书链看着"更权威"，
// 但 JWKS 的信任根是**取回它的那条 https 链路**，不是链里的证书，
// 解析 x5c 只会给人一种"我们校验了证书"的错觉。
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`

	// RSA
	N string `json:"n"`
	E string `json:"e"`

	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksDoc struct {
	Keys []jsonWebKey `json:"keys"`
}

// parsedKey 已解析成 crypto 公钥的一把 JWKS 键。
type parsedKey struct {
	kid string
	alg string // JWK 自带的 alg，可能为空（多数 IdP 会填）
	kty string // RSA | EC
	pub crypto.PublicKey
}

// jwksCache JWKS 缓存 + 轮换自愈。
//
// 两条刷新路径，语义完全不同，别混：
//
//	① TTL 到期的**主动**刷新：拉失败时**继续用旧键**。JWKS 端点抖一下就让全站登录挂掉
//	   不是可接受的姿态；而 IdP 真轮换了密钥时，新令牌会带新 kid，走 ② 立刻自愈。
//	② kid 未命中的**被动**刷新：这是轮换自愈的主路径，但必须限流。
//
// ★ ② 不限流的后果是一个开放的放大器：攻击者构造一堆 kid 随机的垃圾令牌打过来，
// 每一个都会触发一次对 IdP 的 JWKS 拉取——我们自己把控制面变成了打 IdP 的炮台，
// 而且 IdP 一旦限流我们，**合法**登录也跟着一起挂。故 minRefresh 内不再重复拉取，
// 未命中就直接判失败（fail-closed）。
type jwksCache struct {
	mu         sync.Mutex
	keys       []parsedKey
	fetchedAt  time.Time
	ttl        time.Duration // 主动刷新周期
	minRefresh time.Duration // 被动刷新的最小间隔
}

// fetchFunc 拉取并解析一次 JWKS。
type fetchFunc func(ctx context.Context) ([]parsedKey, error)

// key 按 kid + alg 选出验签公钥。now 由调用方注入（便于测试控制时钟）。
func (c *jwksCache) key(ctx context.Context, fetch fetchFunc, kid, alg string, now time.Time) (crypto.PublicKey, error) {
	spec, ok := supportedAlgs[alg]
	if !ok { // 理论上到不了这里：alg 白名单在解析头时已经过一道
		return nil, errInvalidToken("不支持的签名算法 %q", alg)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// ── ① 冷启动 / TTL 到期 ──
	if len(c.keys) == 0 || now.Sub(c.fetchedAt) >= c.ttl {
		keys, err := fetch(ctx)
		switch {
		case err == nil:
			c.keys, c.fetchedAt = keys, now
		case len(c.keys) == 0:
			// 一把键都没有，没得降级，只能把源不可用报上去。
			return nil, err
		default:
			// 有旧键：继续用（理由见类型注释）。不更新 fetchedAt，
			// 这样下一次调用会立刻再试一次，而不是傻等一个 TTL。
		}
	}

	if k := pickKey(c.keys, kid, spec, alg); k != nil {
		return k, nil
	}

	// ── ② kid 未命中：允许刷新一次（IdP 轮换密钥是常态，不是异常）──
	if now.Sub(c.fetchedAt) < c.minRefresh {
		// 限流窗口内，直接判失败。这条路径要能被观察到——它同时是
		//「刚被轮换、还没到刷新窗口」和「有人在拿伪造 kid 打我们」的共同表现。
		return nil, errInvalidToken("JWKS 中找不到 kid=%q 的公钥，且距上次拉取不足 %s（防拉取风暴限流）", kid, c.minRefresh)
	}
	keys, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	c.keys, c.fetchedAt = keys, now
	if k := pickKey(c.keys, kid, spec, alg); k != nil {
		return k, nil
	}
	return nil, errInvalidToken("JWKS 中找不到 kid=%q（alg=%s）的公钥", kid, alg)
}

// pickKey 在键集里挑一把能用于 alg 的键。
//
// kid 为空时的处理是个取舍：规范允许令牌不带 kid，此时只有在**候选唯一**时才敢用。
// ★ 绝不能"挨个试到验签通过为止"——那等于让攻击者在多密钥场景下自由选择验签密钥，
// 只要 IdP 的 JWKS 里存在任何一把攻击者能控制/预测的键（比如给别的用途放进来的），
// 就构成绕过。宁可报错让运维去补 kid。
func pickKey(keys []parsedKey, kid string, spec algSpec, alg string) crypto.PublicKey {
	var cands []parsedKey
	for _, k := range keys {
		if k.kty != spec.kty {
			continue
		}
		// JWK 自带 alg 时必须与令牌 alg 一致：IdP 明说了这把键是 RS256 用的，
		// 就不该拿它去验 PS256（同为 RSA 键，算法却不同，属于用途混用）。
		if k.alg != "" && k.alg != alg {
			continue
		}
		// EC 键还要求曲线与 alg 匹配（ES256↔P-256）。不校验的话虽然验签也会失败，
		// 但错误会变成"签名不对"，掩盖真正的原因是"IdP 配错了曲线"。
		if spec.curve != nil {
			ec, ok := k.pub.(*ecdsa.PublicKey)
			if !ok || ec.Curve != spec.curve {
				continue
			}
		}
		if kid != "" {
			if k.kid == kid {
				return k.pub
			}
			continue
		}
		cands = append(cands, k)
	}
	if kid == "" && len(cands) == 1 {
		return cands[0].pub
	}
	return nil
}

// parseJWKS 把 JWKS 文档解析成可用公钥集。解析不了的单把键**跳过而不是整体失败**——
// IdP 常在同一份 JWKS 里混入加密键（use=enc）或我们不支持的类型（OKP/Ed25519），
// 因为一把不认识的键就拒绝整个文档，会让本来能用的 IdP 直接接不上。
func parseJWKS(doc jwksDoc) []parsedKey {
	out := make([]parsedKey, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		// use=enc 是加密键，拿它验签属于用途混用，直接排除。use 为空视为签名键（规范默认）。
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parseJWK(k)
		if err != nil {
			continue
		}
		out = append(out, parsedKey{kid: k.Kid, alg: k.Alg, kty: k.Kty, pub: pub})
	}
	return out
}

func parseJWK(k jsonWebKey) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64urlBig(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64urlBig(k.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() < 3 {
			return nil, errInvalidToken("RSA 公钥指数非法")
		}
		// 拒收过短的 RSA 模数：2048 位以下的键在今天已经不该用于身份签名，
		// 而"能验通"会让这个问题永远没人发现。
		if n.BitLen() < 2048 {
			return nil, errInvalidToken("RSA 公钥长度不足 2048 位")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve, size, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		xb, err := b64urlBytes(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := b64urlBytes(k.Y)
		if err != nil {
			return nil, err
		}
		// 坐标必须是固定长度的定长编码（左侧补零），长度不对说明不是这条曲线的点。
		if len(xb) != size || len(yb) != size {
			return nil, errInvalidToken("EC 公钥坐标长度与曲线 %s 不符", k.Crv)
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		// ★ 必须确认点在曲线上。接受一个不在曲线上的点会打开 invalid-curve 攻击面；
		// 这里公钥来自 https 取回的 JWKS，风险较低，但校验成本几乎为零，没有不做的理由。
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errInvalidToken("EC 公钥不在曲线 %s 上", k.Crv)
		}
		return pub, nil
	default:
		// OKP(Ed25519) 等类型刻意不支持：真实企业 IdP 几乎不用它签 ID Token，
		// 支持一个用不上的算法只会扩大验签代码的攻击面。
		return nil, errInvalidToken("不支持的密钥类型 %q", k.Kty)
	}
}

func ecCurve(crv string) (elliptic.Curve, int, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		return elliptic.P521(), 66, nil // 521 位 → 66 字节（向上取整），不是 65
	}
	return nil, 0, errInvalidToken("不支持的 EC 曲线 %q", crv)
}

// b64urlBytes 解 base64url。规范要求无填充，但现实中确有 IdP 带填充下发，
// 这里做兼容——**只在解 JWKS 公钥参数时兼容**，验签段与 PKCE 挑战不兼容
// （那两处宽松会掩盖真正的编码 bug，见 pkce.go 的说明）。
func b64urlBytes(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errInvalidToken("JWKS 参数不是合法的 base64url")
	}
	return b, nil
}

func b64urlBig(s string) (*big.Int, error) {
	b, err := b64urlBytes(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
