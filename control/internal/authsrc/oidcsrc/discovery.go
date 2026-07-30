package oidcsrc

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"
)

// discoveryDoc OpenID Provider Metadata（/.well-known/openid-configuration）。
// 只解析我们会用到的字段；未知字段被忽略是刻意的——发现文档是**对面**写的，
// 多解析一个字段就多一处让对面影响我们行为的入口。
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// discoveryCache 发现文档缓存。发现文档变化频率以月计，缓存 TTL 主要是为了
// 让端点迁移能在一个可接受的时间窗内被感知，而不是为了性能。
type discoveryCache struct {
	mu        sync.Mutex
	doc       *discoveryDoc
	fetchedAt time.Time
	ttl       time.Duration
}

// discover 取（可能是缓存的）发现文档。
func (p *Provider) discover(ctx context.Context) (*discoveryDoc, error) {
	p.disc.mu.Lock()
	defer p.disc.mu.Unlock()
	if p.disc.doc != nil && p.now().Sub(p.disc.fetchedAt) < p.disc.ttl {
		return p.disc.doc, nil
	}
	doc, err := p.fetchDiscovery(ctx)
	if err != nil {
		if p.disc.doc != nil {
			// TTL 到期但拉不动：继续用旧文档。端点地址不会因为一次网络抖动而改变，
			// 而让全站登录跟着 IdP 的一次 5xx 一起挂掉是不成比例的。
			return p.disc.doc, nil
		}
		return nil, err
	}
	p.disc.doc, p.disc.fetchedAt = doc, p.now()
	return doc, nil
}

// fetchDiscovery 强制拉取并校验发现文档（Probe 走这条，绕过缓存）。
func (p *Provider) fetchDiscovery(ctx context.Context) (*discoveryDoc, error) {
	u := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	var doc discoveryDoc
	if err := p.getJSON(ctx, u, nil, &doc); err != nil {
		return nil, err
	}

	// ★ issuer 一致性：文档里自称的 issuer 必须与我们配置的 issuer 相同。
	// 不校验的后果不是"多一层保险没了"，而是整个信任模型塌掉——我们后面用
	// doc.Issuer 作为 ID Token 的 iss 期望值，若它可以是任意值，那么一个被
	// 篡改/错配的发现文档就能让我们接受**别家 IdP** 签的令牌。
	// 尾斜杠差异做归一（`https://idp/` vs `https://idp` 是同一个 issuer 的常见写法差异，
	// 按字面精确比对会把完全正常的配置判死，且报错信息看起来两个串一模一样，极难归因）。
	if !sameIssuer(doc.Issuer, p.cfg.Issuer) {
		return nil, errNotConfigured("发现文档的 issuer=%q 与配置的 issuer=%q 不一致（可能配错了地址，或该地址不是该 IdP 的签发者）", doc.Issuer, p.cfg.Issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, errNotConfigured("发现文档缺少必要端点（authorization_endpoint/token_endpoint/jwks_uri）")
	}
	// 端点必须是 https。
	// ★ 刻意**不**要求端点与 issuer 同源：Google 的 issuer 是 accounts.google.com，
	// jwks_uri 却在 www.googleapis.com 上——加同源限制会把最主流的 IdP 直接挡死。
	// 端点的可信性由「发现文档本身经 https 从 issuer 取回」保证。
	for name, ep := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"jwks_uri":               doc.JWKSURI,
	} {
		if err := p.checkHTTPS(name, ep); err != nil {
			return nil, err
		}
	}
	if doc.UserInfoEndpoint != "" {
		if err := p.checkHTTPS("userinfo_endpoint", doc.UserInfoEndpoint); err != nil {
			return nil, err
		}
	}

	// PKCE 支持性：字段**缺省**视为支持（大量 IdP 不下发这个字段却完全支持 S256），
	// 但字段给了却不含 S256 就必须报错——那种 IdP 会静默忽略 code_challenge，
	// PKCE 一点作用都不起，而流程照样跑通：我们会以为有防护，其实没有。
	if len(doc.CodeChallengeMethodsSupported) > 0 && !contains(doc.CodeChallengeMethodsSupported, "S256") {
		return nil, errNotConfigured("IdP 不支持 PKCE S256（code_challenge_methods_supported=%v），本实现拒绝在无 PKCE 保护下走授权码流", doc.CodeChallengeMethodsSupported)
	}
	return &doc, nil
}

// fetchJWKS 拉取并解析 JWKS。
func (p *Provider) fetchJWKS(ctx context.Context) ([]parsedKey, error) {
	doc, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	var jd jwksDoc
	if err := p.getJSON(ctx, doc.JWKSURI, nil, &jd); err != nil {
		return nil, err
	}
	keys := parseJWKS(jd)
	if len(keys) == 0 {
		return nil, errUnavailable("JWKS(%s) 中没有任何可用于验签的公钥", doc.JWKSURI)
	}
	return keys, nil
}

// expectedIssuer ID Token 的 iss 期望值。取**发现文档**里的 issuer 原样值
// （它已在 fetchDiscovery 里与配置比对过），这样尾斜杠等写法差异不会造成误判。
func (p *Provider) expectedIssuer() string {
	p.disc.mu.Lock()
	defer p.disc.mu.Unlock()
	if p.disc.doc != nil && p.disc.doc.Issuer != "" {
		return p.disc.doc.Issuer
	}
	return p.cfg.Issuer
}

// sameIssuer 归一尾斜杠后比对 issuer。
func sameIssuer(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
}

// checkHTTPS 校验 URL 必须是 https。
//
// ★ 明文 http 下，发现文档与 JWKS 都可被中间人替换成攻击者自己的公钥——
// 那样后面所有验签都会"成功"，因为验的是攻击者的键。这是"校验全做了但全无意义"的
// 典型形态，所以它必须是一道硬闸，而不是一条警告。
// AllowInsecureHTTP 是唯一逃生舱，只给本机 mock/联调用，注释里写死"生产禁用"。
func (p *Provider) checkHTTPS(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errNotConfigured("%s=%q 不是合法 URL", name, raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if p.cfg.AllowInsecureHTTP && u.Scheme == "http" {
		return nil
	}
	return errNotConfigured("%s=%q 必须使用 https（明文下 JWKS 可被替换，一切验签都会形同虚设）", name, raw)
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
