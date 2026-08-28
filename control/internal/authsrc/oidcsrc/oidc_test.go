package oidcsrc

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/authsrc"
)

// newProvider 起一个指向 mock 的 Provider，tweak 可改配置。
func newProvider(t *testing.T, m *mockIDP, tweak func(*Config)) *Provider {
	t.Helper()
	cfg := m.config()
	if tweak != nil {
		tweak(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败：%v", err)
	}
	return p
}

// runLogin 跑一次完整往返：AuthURL → 用户授权 → Exchange。
// state 的比对在这里做，模拟调用方**必须**做的那一步。
func runLogin(t *testing.T, p *Provider, m *mockIDP) (authsrc.Identity, error) {
	t.Helper()
	state, err := NewState()
	if err != nil {
		t.Fatalf("NewState：%v", err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce：%v", err)
	}
	verifier, err := NewCodeVerifier()
	if err != nil {
		t.Fatalf("NewCodeVerifier：%v", err)
	}
	authURL, err := p.AuthURL(context.Background(), state, nonce, verifier)
	if err != nil {
		return authsrc.Identity{}, err
	}
	code, gotState := m.authorize(authURL)
	if gotState != state {
		t.Fatalf("IdP 回带的 state=%q 与发出的 %q 不一致", gotState, state)
	}
	return p.Exchange(context.Background(), code, verifier, nonce)
}

// ── 成功流程 ─────────────────────────────────────────────────────────────

func TestExchange_完整成功流程_RS256(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil)

	id, err := runLogin(t, p, m)
	if err != nil {
		t.Fatalf("登录应成功，实际：%v", err)
	}
	if id.Subject != "u-1001" {
		t.Errorf("Subject=%q，期望 sub 值 u-1001（绝不能取 email/preferred_username）", id.Subject)
	}
	if id.Username != "zhangsan" {
		t.Errorf("Username=%q，期望 zhangsan", id.Username)
	}
	// Normalized 会把邮箱转小写：IdP 下发的是 ZhangSan@Corp.Example。
	if id.Email != "zhangsan@corp.example" {
		t.Errorf("Email=%q，期望已规范化为小写", id.Email)
	}
	if id.DisplayName != "张三" {
		t.Errorf("DisplayName=%q", id.DisplayName)
	}
	if !reflect.DeepEqual(id.Groups, []string{"研发中心", "运维组"}) {
		t.Errorf("Groups=%v", id.Groups)
	}
}

func TestExchange_成功流程_ES256(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) { m.signAlg = "ES256" })
	p := newProvider(t, m, nil)

	// ES 的签名是 R‖S 定长拼接而非 DER，这条用例专门守住那个坑：
	// 若实现误用 VerifyASN1，RS256 一路正常、只有 ES256 全线验不过。
	id, err := runLogin(t, p, m)
	if err != nil {
		t.Fatalf("ES256 登录应成功，实际：%v", err)
	}
	if id.Subject != "u-1001" {
		t.Errorf("Subject=%q", id.Subject)
	}
}

// ── 算法白名单 ───────────────────────────────────────────────────────────

func TestExchange_拒绝alg_none(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) { m.signAlg = "none" })
	p := newProvider(t, m, nil)

	_, err := runLogin(t, p, m)
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("alg=none 必须被拒且归入凭据错误，实际：%v", err)
	}
	if !strings.Contains(err.Error(), "alg=none") {
		t.Errorf("错误信息应能指认 alg=none（否则日志里看不出有人在打这个洞）：%v", err)
	}
}

func TestExchange_拒绝HS256对称算法(t *testing.T) {
	m := newMockIDP(t)
	// 攻击者用双方共知的 client_secret 当 HMAC 密钥伪造了一枚"合法" ID Token。
	m.set(func(m *mockIDP) { m.signAlg = "HS256" })
	p := newProvider(t, m, nil)

	_, err := runLogin(t, p, m)
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("HS256 必须被拒，实际：%v", err)
	}
	if !strings.Contains(err.Error(), "对称算法") {
		t.Errorf("错误信息应指明是对称算法被拒：%v", err)
	}
}

func TestNew_拒绝把对称算法配进白名单(t *testing.T) {
	m := newMockIDP(t)
	cfg := m.config()
	cfg.SigningAlgs = []string{"RS256", "HS256"}
	if _, err := New(cfg); !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("配置层就该挡住 HS256（否则一句『加上试试』就能重开算法混淆的门），实际：%v", err)
	}
}

// ── 声明校验：iss / aud / nonce / exp ────────────────────────────────────

func TestExchange_拒绝错误的aud(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) { m.claimOverride = map[string]any{"aud": "另一个应用"} })
	p := newProvider(t, m, nil)

	if _, err := runLogin(t, p, m); !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("aud 不含本应用 client_id 必须被拒，实际：%v", err)
	}
}

func TestExchange_拒绝多aud缺azp(t *testing.T) {
	m := newMockIDP(t)
	// aud 里含我们，但同时含别人，且没有 azp——无法确认这枚令牌是发给谁的。
	m.set(func(m *mockIDP) {
		m.claimOverride = map[string]any{"aud": []string{m.clientID, "另一个应用"}}
	})
	p := newProvider(t, m, nil)

	if _, err := runLogin(t, p, m); !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("多受众且缺 azp 必须被拒，实际：%v", err)
	}
}

func TestExchange_拒绝错误的iss(t *testing.T) {
	m := newMockIDP(t)
	// 发现文档仍是本 IdP，但令牌自称由别家签发——正是"A 家签的令牌拿到 B 家用"。
	m.set(func(m *mockIDP) {
		m.claimOverride = map[string]any{"iss": "https://evil.example.com"}
	})
	p := newProvider(t, m, nil)

	if _, err := runLogin(t, p, m); !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("iss 不一致必须被拒，实际：%v", err)
	}
}

func TestExchange_拒绝错误的nonce(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil)

	state, _ := NewState()
	nonce, _ := NewNonce()
	verifier, _ := NewCodeVerifier()
	authURL, err := p.AuthURL(context.Background(), state, nonce, verifier)
	if err != nil {
		t.Fatalf("AuthURL：%v", err)
	}
	code, _ := m.authorize(authURL)

	// 模拟重放：拿到一枚 nonce 为 A 的合法令牌，却在期望 nonce 为 B 的会话里提交。
	otherNonce, _ := NewNonce()
	_, err = p.Exchange(context.Background(), code, verifier, otherNonce)
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("nonce 不匹配必须被拒（否则等于没有防重放），实际：%v", err)
	}
}

func TestExchange_空nonce硬失败而不是跳过校验(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil)
	// 这是最危险的实现缺陷形态：调用方忘了传 nonce，若实现"没给就不校验"，
	// 流程照样跑通、登录照样成功，防重放静默失效。
	_, err := p.Exchange(context.Background(), "code-x", strings.Repeat("a", 43), "")
	if !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("空 nonce 必须直接拒绝，实际：%v", err)
	}
}

func TestExchange_拒绝过期令牌(t *testing.T) {
	m := newMockIDP(t)
	now := time.Now()
	m.set(func(m *mockIDP) {
		m.claimOverride = map[string]any{
			"iat": now.Add(-2 * time.Hour).Unix(),
			"exp": now.Add(-1 * time.Hour).Unix(),
		}
	})
	p := newProvider(t, m, nil)

	_, err := runLogin(t, p, m)
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("过期令牌必须被拒，实际：%v", err)
	}
	if !strings.Contains(err.Error(), "过期") {
		t.Errorf("错误信息应指明过期：%v", err)
	}
}

func TestExchange_拒绝签发过旧的令牌(t *testing.T) {
	m := newMockIDP(t)
	now := time.Now()
	// exp 还没到，但 iat 是一小时前：授权码换令牌是秒级动作，这只可能是重放。
	m.set(func(m *mockIDP) {
		m.claimOverride = map[string]any{
			"iat": now.Add(-time.Hour).Unix(),
			"exp": now.Add(time.Hour).Unix(),
		}
	})
	p := newProvider(t, m, nil)

	if _, err := runLogin(t, p, m); !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("iat 过旧应被拒，实际：%v", err)
	}
}

func TestExchange_拒绝缺少sub(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) { m.dropClaims = []string{"sub"} })
	p := newProvider(t, m, nil)

	if _, err := runLogin(t, p, m); !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("缺 sub 必须被拒（Subject 是账号映射的唯一依据），实际：%v", err)
	}
}

// ── JWKS 轮换与限流 ──────────────────────────────────────────────────────

func TestJWKS_密钥轮换后自愈(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil) // config() 里已关掉被动刷新限流

	if _, err := runLogin(t, p, m); err != nil {
		t.Fatalf("首次登录应成功：%v", err)
	}
	m.mu.Lock()
	hits1 := m.jwksHits
	m.mu.Unlock()
	if hits1 != 1 {
		t.Fatalf("首次登录应只拉一次 JWKS，实际 %d 次", hits1)
	}

	// IdP 轮换密钥：换私钥同时换 kid（真实 IdP 的常规动作）。
	_, rotated, _ := testKeys(t)
	m.set(func(m *mockIDP) {
		m.rsaKey = rotated
		m.rsaKid = "rsa-2"
	})

	if _, err := runLogin(t, p, m); err != nil {
		t.Fatalf("轮换后应能自愈（按新 kid 重拉一次 JWKS），实际：%v", err)
	}
	m.mu.Lock()
	hits2 := m.jwksHits
	m.mu.Unlock()
	if hits2 != 2 {
		t.Errorf("轮换后应恰好重拉一次 JWKS，实际累计 %d 次", hits2)
	}
}

func TestJWKS_伪造kid不会打成拉取风暴(t *testing.T) {
	m := newMockIDP(t)
	// 令牌头写一个 JWKS 里根本没有的 kid——攻击者可以每次都换一个。
	m.set(func(m *mockIDP) { m.kidOverride = "ghost-" })
	p := newProvider(t, m, func(c *Config) { c.JWKSMinRefresh = time.Minute })

	for i := 0; i < 5; i++ {
		if _, err := runLogin(t, p, m); !errors.Is(err, authsrc.ErrInvalidCredentials) {
			t.Fatalf("第 %d 次：未知 kid 必须判失败，实际：%v", i, err)
		}
	}
	m.mu.Lock()
	hits := m.jwksHits
	m.mu.Unlock()
	// 只有冷启动那一次真的拉了；之后都被最小刷新间隔挡住。
	if hits != 1 {
		t.Errorf("5 次伪造 kid 只应触发 1 次 JWKS 拉取，实际 %d 次（不限流就是把控制面变成打 IdP 的炮台）", hits)
	}
}

// ── PKCE ────────────────────────────────────────────────────────────────

func TestExchange_PKCE_verifier不匹配则失败(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil)

	state, _ := NewState()
	nonce, _ := NewNonce()
	verifier, _ := NewCodeVerifier()
	authURL, err := p.AuthURL(context.Background(), state, nonce, verifier)
	if err != nil {
		t.Fatalf("AuthURL：%v", err)
	}
	code, _ := m.authorize(authURL)

	// 模拟"授权码被劫持"：攻击者拿到了 code，却拿不到只存在于受害者会话里的 verifier。
	other, _ := NewCodeVerifier()
	_, err = p.Exchange(context.Background(), code, other, nonce)
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("PKCE 不匹配应归入凭据错误（invalid_grant），实际：%v", err)
	}
}

func TestPKCE_S256符合RFC7636测试向量(t *testing.T) {
	// RFC 7636 附录 B 的官方向量。这条用例守的是"多一个 = 号"那类症状极不友好的坑：
	// 编码错了 IdP 只回 invalid_grant，错误描述完全指不到编码上。
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := CodeChallengeS256(verifier); got != want {
		t.Fatalf("code_challenge=%q，期望 %q", got, want)
	}
	if strings.ContainsAny(want, "=+/") {
		t.Fatal("挑战值不得含填充或非 URL 安全字符")
	}
	if !validCodeVerifier(verifier) {
		t.Fatal("RFC 官方向量应被判为合法 verifier")
	}
}

func TestAuthURL_缺少state或nonce时拒绝构造(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil)
	v, _ := NewCodeVerifier()

	if _, err := p.AuthURL(context.Background(), "", "n", v); !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Errorf("缺 state 应拒绝：%v", err)
	}
	if _, err := p.AuthURL(context.Background(), "s", "", v); !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Errorf("缺 nonce 应拒绝：%v", err)
	}
	if _, err := p.AuthURL(context.Background(), "s", "n", "太短"); !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Errorf("非法 verifier 应拒绝：%v", err)
	}
}

func TestAuthURL_IdP不支持S256时拒绝(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) { m.pkceMethods = []string{"plain"} })
	p := newProvider(t, m, nil)

	state, _ := NewState()
	nonce, _ := NewNonce()
	v, _ := NewCodeVerifier()
	// 这类 IdP 会静默忽略 code_challenge：流程照样跑通，PKCE 却一点作用没有。
	if _, err := p.AuthURL(context.Background(), state, nonce, v); !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("IdP 明示不支持 S256 时应拒绝，实际：%v", err)
	}
}

// ── 传输与 issuer 一致性 ────────────────────────────────────────────────

func TestNew_拒绝明文http_issuer(t *testing.T) {
	_, err := New(Config{
		Issuer:      "http://idp.example.com",
		ClientID:    "x",
		RedirectURI: "https://console.example.com/cb",
	})
	if !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("明文 issuer 必须被拒（JWKS 可被替换则所有验签形同虚设），实际：%v", err)
	}
}

func TestProbe_发现文档issuer不一致时拒绝(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) { m.docIssuer = "https://evil.example.com" })
	p := newProvider(t, m, nil)

	if err := p.Probe(context.Background()); !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("发现文档 issuer 与配置不符必须被拒，实际：%v", err)
	}
}

// ── Probe ───────────────────────────────────────────────────────────────

func TestProbe_成功(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil)
	if err := p.Probe(context.Background()); err != nil {
		t.Fatalf("Probe 应成功：%v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.discoveryHits == 0 || m.jwksHits == 0 {
		t.Errorf("Probe 应真的访问发现文档与 JWKS（discovery=%d jwks=%d）", m.discoveryHits, m.jwksHits)
	}
}

func TestProbe_源不可用(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil)
	m.srv.Close() // 模拟 IdP 宕机 / 网络不通

	err := p.Probe(context.Background())
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("IdP 不可达应归入 ErrSourceUnavailable（不是凭据错，不该让用户以为密码记错了），实际：%v", err)
	}
}

func TestProbe_算法无交集时报配置错误(t *testing.T) {
	m := newMockIDP(t)
	// IdP 只支持对称算法——我们永远不会接受，必须在「测试连接」阶段就说清楚，
	// 否则会出现"测试连接通过、每次真登录都被拒"的极难归因状态。
	m.set(func(m *mockIDP) { m.signingAlgsAdv = []string{"HS256"} })
	p := newProvider(t, m, nil)

	if err := p.Probe(context.Background()); !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("算法无交集应报配置错误，实际：%v", err)
	}
}

// ── UserInfo ────────────────────────────────────────────────────────────

func TestUserInfo_补全缺失属性(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) {
		m.dropClaims = []string{"email", "groups"} // 精简型 IdP 只在 UserInfo 里给
		m.userinfo = map[string]any{
			"sub":    "u-1001",
			"email":  "zhangsan@corp.example",
			"groups": []any{"研发中心"},
		}
	})
	p := newProvider(t, m, func(c *Config) { c.UseUserInfo = true })

	id, err := runLogin(t, p, m)
	if err != nil {
		t.Fatalf("登录应成功：%v", err)
	}
	if id.Email != "zhangsan@corp.example" || !reflect.DeepEqual(id.Groups, []string{"研发中心"}) {
		t.Errorf("UserInfo 属性未补全：email=%q groups=%v", id.Email, id.Groups)
	}
}

func TestUserInfo_sub不一致必须硬失败(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) {
		m.userinfo = map[string]any{"sub": "u-9999", "email": "lisi@corp.example"}
	})
	p := newProvider(t, m, func(c *Config) { c.UseUserInfo = true })

	// 若不校验，就会出现"以 A 的身份登录、却带着 B 的邮箱与组"，权限判定直接错乱。
	_, err := runLogin(t, p, m)
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("UserInfo 的 sub 与 ID Token 不一致必须失败，实际：%v", err)
	}
}

func TestUserInfo_取不到时不影响登录(t *testing.T) {
	m := newMockIDP(t)
	m.set(func(m *mockIDP) { m.userinfoStatus = http.StatusInternalServerError })
	p := newProvider(t, m, func(c *Config) { c.UseUserInfo = true })

	// 身份判定已由 ID Token 完成，补全失败不该把整次登录判死。
	id, err := runLogin(t, p, m)
	if err != nil {
		t.Fatalf("UserInfo 故障不应导致登录失败：%v", err)
	}
	if id.Subject != "u-1001" {
		t.Errorf("Subject=%q", id.Subject)
	}
}

// ── 令牌端点错误映射 ────────────────────────────────────────────────────

func TestExchange_授权码复用被拒(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, nil)

	state, _ := NewState()
	nonce, _ := NewNonce()
	v, _ := NewCodeVerifier()
	authURL, err := p.AuthURL(context.Background(), state, nonce, v)
	if err != nil {
		t.Fatalf("AuthURL：%v", err)
	}
	code, _ := m.authorize(authURL)

	if _, err := p.Exchange(context.Background(), code, v, nonce); err != nil {
		t.Fatalf("首次换码应成功：%v", err)
	}
	if _, err := p.Exchange(context.Background(), code, v, nonce); !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("授权码复用应归入凭据错误，实际：%v", err)
	}
}

func TestExchange_客户端密钥错误归为配置错误(t *testing.T) {
	m := newMockIDP(t)
	p := newProvider(t, m, func(c *Config) { c.ClientSecret = "写错的密钥" })

	_, err := runLogin(t, p, m)
	if !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("invalid_client 是配置错误而非用户凭据错误（报错方向错了会让所有人查错地方），实际：%v", err)
	}
}

func TestExchange_令牌端点认证方式_post(t *testing.T) {
	m := newMockIDP(t)
	// client_secret 里含 '+' 与 '/'，basic 编码没做 form-urlencode 的话这里会挂。
	p := newProvider(t, m, func(c *Config) { c.TokenAuthMethod = "client_secret_post" })
	if _, err := runLogin(t, p, m); err != nil {
		t.Fatalf("client_secret_post 应可用：%v", err)
	}

	p2 := newProvider(t, m, func(c *Config) { c.TokenAuthMethod = "client_secret_basic" })
	if _, err := runLogin(t, p2, m); err != nil {
		t.Fatalf("client_secret_basic 应可用（特殊字符需 form-urlencode）：%v", err)
	}
}
