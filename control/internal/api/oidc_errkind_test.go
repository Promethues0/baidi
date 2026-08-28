package api

// OIDC 链路的错误分类（wave9）。oidcsrc 内部一直把错误分成三类，而 api 侧此前
// 一次 errors.Is 都没调，把它们全部塌缩成 verdict=deny +「登录校验失败」。
// 后果与口令路径要消灭的完全一样：运维照着「被拒绝」去查用户，而问题在 IdP。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

// errStub Exchange 恒回指定错误的桩。
type errStub struct {
	err   error
	nap   time.Duration // >0 时先睡，用来验预算
	state string
}

func (f *errStub) AuthURL(_ context.Context, state, _, _ string) (string, error) {
	f.state = state
	return "https://idp.example/authorize", nil
}
func (f *errStub) Exchange(ctx context.Context, _, _, _ string) (authsrc.Identity, error) {
	if f.nap > 0 {
		select {
		case <-time.After(f.nap):
		case <-ctx.Done():
			return authsrc.Identity{}, fmt.Errorf("拉令牌超时：%w", authsrc.ErrSourceUnavailable)
		}
	}
	return authsrc.Identity{}, f.err
}
func (f *errStub) Probe(context.Context) error { return nil }

func oidcErrFixture(t *testing.T, stub authsrc.RedirectAuthenticator) (http.Handler, *Server) {
	t.Helper()
	h, s, _ := oidcFixture(t)
	s.testRedirectAuth = func(store.AuthSourceRec) (authsrc.RedirectAuthenticator, error) { return stub, nil }
	return h, s
}

// 三类错误必须落成不同的 verdict 与文案。
//
// ★这是本次改动的核心。IdP 抖动（运维信号）与 nonce 重放（攻击信号）此前在审计里
// **完全同形**——都是 `OIDC 令牌校验失败（源 X）` / deny。
func TestOIDC三类错误分开落审计(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantVerdict string
		wantInEvent string
		wantInBody  string
	}{
		{"IdP 不可用", fmt.Errorf("连不上：%w", authsrc.ErrSourceUnavailable), "fail", "身份提供方不可用", "稍后重试"},
		{"配置有误", fmt.Errorf("issuer 不符：%w", authsrc.ErrNotConfigured), "fail", "认证源配置有误", "联系管理员"},
		{"令牌校验失败", fmt.Errorf("nonce 不匹配：%w", authsrc.ErrInvalidCredentials), "deny", "令牌校验失败", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &errStub{err: c.err}
			h, s := oidcErrFixture(t, stub)

			getRaw(t, h, "/api/v1/auth/oidc/oidc-1/authorize") // 拿一个真 state
			if stub.state == "" {
				t.Fatal("authorize 没有登记 state")
			}
			getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?state="+stub.state+"&code=x")

			var hit *store.AuditEntry
			for i, e := range authAudits(t, s) {
				if strings.Contains(e.Event, "OIDC 令牌校验") {
					hit = &authAudits(t, s)[i]
				}
			}
			if hit == nil {
				t.Fatalf("没有落审计：%+v", authAudits(t, s))
			}
			if hit.Verdict != c.wantVerdict {
				t.Fatalf("verdict 应为 %q，实得 %q（事件：%s）——"+
					"把 IdP 故障记成 deny 会让运维去查用户", c.wantVerdict, hit.Verdict, hit.Event)
			}
			if !strings.Contains(hit.Event, c.wantInEvent) {
				t.Fatalf("审计正文没说清归类，应含 %q，实得 %q", c.wantInEvent, hit.Event)
			}
		})
	}
}

// 用户文案要按类别给出**不同的下一步动作**：「稍后重试」与「联系管理员」不能混。
func TestOIDC用户文案按类别区分(t *testing.T) {
	unavail := fmt.Errorf("x：%w", authsrc.ErrSourceUnavailable)
	notconf := fmt.Errorf("x：%w", authsrc.ErrNotConfigured)
	invalid := fmt.Errorf("x：%w", authsrc.ErrInvalidCredentials)

	if got := oidcUserMessage(unavail, "兜底"); !strings.Contains(got, "稍后重试") {
		t.Fatalf("源不可用应让用户稍后重试，实得 %q", got)
	}
	if got := oidcUserMessage(notconf, "兜底"); !strings.Contains(got, "联系管理员") {
		t.Fatalf("配置有误应让用户找管理员（自己重试一万次也没用），实得 %q", got)
	}
	// 凭据类不泄露细节：走兜底文案。
	if got := oidcUserMessage(invalid, "兜底"); got != "兜底" {
		t.Fatalf("凭据类应走兜底文案，不暴露 alg/aud/nonce 细节，实得 %q", got)
	}
	// 未分类的错误不编造原因。
	if zh, v := oidcErrKind(errors.New("谁知道呢")); zh != "登录失败" || v != "deny" {
		t.Fatalf("未分类错误不该编造原因，实得 %q/%q", zh, v)
	}
}

// 出网预算对 OIDC 生效，且超时被归为「源不可用」而不是「令牌校验失败」。
func TestOIDC预算切断慢IdP(t *testing.T) {
	stub := &errStub{nap: 10 * time.Second}
	h, s := oidcErrFixture(t, stub)
	s.SetAuthTimeouts(200*time.Millisecond, 0, 0)

	getRaw(t, h, "/api/v1/auth/oidc/oidc-1/authorize")
	start := time.Now()
	getRaw(t, h, "/api/v1/auth/oidc/oidc-1/callback?state="+stub.state+"&code=x")
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("回调耗时 %v，预算对 OIDC 没有生效", el)
	}

	var ok bool
	for _, e := range authAudits(t, s) {
		if strings.Contains(e.Event, "身份提供方不可用") {
			ok = true
			if e.Verdict != "fail" {
				t.Fatalf("超时应落 fail，实得 %q", e.Verdict)
			}
			// 耗时埋点（NFR-PERF-03）与口令路径同款。
			if !strings.Contains(e.Event, "外部认证耗时 ") {
				t.Fatalf("审计里没有耗时：%q", e.Event)
			}
		}
	}
	if !ok {
		t.Fatalf("超时没有被归为「身份提供方不可用」：%+v", authAudits(t, s))
	}
}

// 授权入口（AuthURL）失败此前**一条审计都不落**：用户在登录页反复点「用 XX 登录」
// 没反应，而审计里什么都没有。
type authURLFailStub struct{ err error }

func (f authURLFailStub) AuthURL(context.Context, string, string, string) (string, error) {
	return "", f.err
}
func (f authURLFailStub) Exchange(context.Context, string, string, string) (authsrc.Identity, error) {
	return authsrc.Identity{}, nil
}
func (f authURLFailStub) Probe(context.Context) error { return nil }

func TestOIDC授权入口失败要留痕(t *testing.T) {
	h, s := oidcErrFixture(t, authURLFailStub{err: fmt.Errorf("连不上：%w", authsrc.ErrSourceUnavailable)})
	getRaw(t, h, "/api/v1/auth/oidc/oidc-1/authorize")

	for _, e := range authAudits(t, s) {
		if strings.Contains(e.Event, "OIDC 授权入口") {
			if e.Verdict != "fail" {
				t.Fatalf("授权入口的 IdP 故障应落 fail，实得 %q", e.Verdict)
			}
			return
		}
	}
	t.Fatalf("授权入口失败没有留痕——用户点不动登录按钮而审计里什么都没有：%+v", authAudits(t, s))
}
