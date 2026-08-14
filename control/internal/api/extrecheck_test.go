package api

// 外部账号状态回验循环的编排面（协议路径另有 gldap 真服务端用例）。
// 最要钉的是三条方向：源不可用绝不动手 / 只单向禁用 / 幂等不刷屏。

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

type stubChecker struct {
	states map[string]authsrc.AccountState // subject → 状态
	err    error                           // 非 nil = 源不可用
	calls  int
}

func (f *stubChecker) CheckAccount(_ context.Context, subject string) (authsrc.AccountState, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	if st, ok := f.states[subject]; ok {
		return st, nil
	}
	return authsrc.StateActive, nil
}

// recheckFixture：SQLite 栈 + 一个 LDAP 源 + 一个 OIDC 源 + 各自绑定的外部账号。
func recheckFixture(t *testing.T) (http.Handler, *Server, *store.SQLiteStore, *stubChecker) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "recheck.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	for _, rec := range []store.AuthSourceRec{
		{ID: "ldap-1", Name: "总部 AD", Kind: "ad", Enabled: true, Config: `{}`},
		{ID: "oidc-1", Name: "公司 IdP", Kind: "oidc", Enabled: true, Config: `{}`},
	} {
		if _, err := st.SaveAuthSource(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	// 两个 LDAP 账号 + 一个 OIDC 账号。
	mustBind := func(src, subject, user string) store.Credential {
		c, err := st.BindExternalUser(ctx, src, store.ExternalIdentity{Subject: subject, Username: user})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	mustBind("ldap-1", "cn=alice,dc=corp", "rc.alice")
	mustBind("ldap-1", "cn=bob,dc=corp", "rc.bob")
	mustBind("oidc-1", "idp|sub-1", "rc.oidc")

	stub := &stubChecker{states: map[string]authsrc.AccountState{}}
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	s.testStatusChecker = func(rec store.AuthSourceRec) (authsrc.StatusChecker, error) { return stub, nil }
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), s, st, stub
}

func statusOf(t *testing.T, h http.Handler, account string) string {
	t.Helper()
	_, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	for _, raw := range out["users"].([]any) {
		u := mapOf(t, raw)
		if u["account"] == account {
			return u["status"].(string)
		}
	}
	t.Fatalf("目录里没有 %s", account)
	return ""
}

func TestRecheckDisablesOnDirectoryEvidence(t *testing.T) {
	h, s, _, stub := recheckFixture(t)
	stub.states["cn=alice,dc=corp"] = authsrc.StateDisabled
	stub.states["cn=bob,dc=corp"] = authsrc.StateActive

	checked, acted := s.RecheckExternalAccounts(context.Background())
	if acted != 1 {
		t.Fatalf("应恰处置 1 个（alice），实得 checked=%d acted=%d", checked, acted)
	}
	if got := statusOf(t, h, "rc.alice"); got != "disabled" {
		t.Fatalf("目录侧禁用应落为本地 disabled，实得 %s", got)
	}
	if got := statusOf(t, h, "rc.bob"); got != "active" {
		t.Fatalf("正常账号不该被动，实得 %s", got)
	}
	// 数据面联动：撤销名单里应有该账号（拒发敲门令牌 + 撤窗断隧道走既有通道）。
	s.mu.Lock()
	_, revoked := s.revoked["rc.alice"]
	s.mu.Unlock()
	if !revoked {
		t.Fatal("处置应并入撤销名单（撤窗断隧道），只改状态不断连等于禁了个寂寞")
	}
	// ★幂等：第二轮不重复处置（否则每周期都刷一条审计）。
	if _, acted2 := s.RecheckExternalAccounts(context.Background()); acted2 != 0 {
		t.Fatalf("已禁用的行不该重复处置，实得 acted=%d", acted2)
	}
	// ★OIDC 源整体跳过：桩对 oidc subject 也报 disabled 也轮不到它。
	stub.states["idp|sub-1"] = authsrc.StateDisabled
	s.RecheckExternalAccounts(context.Background())
	if got := statusOf(t, h, "rc.oidc"); got != "disabled" {
		// 注意语义：期望**没被禁**——OIDC 无回验通道。
		_ = got
	} else {
		t.Fatal("OIDC 源没有回验通道，不该被处置")
	}
}

// ★方向红线：源不可用绝不动手——AD 抖一下就禁光全部外部账号，
// 是比 8h 失效窗大得多的自伤。
func TestRecheckNeverActsOnOutage(t *testing.T) {
	h, s, _, stub := recheckFixture(t)
	stub.err = authsrc.ErrSourceUnavailable
	stub.states["cn=alice,dc=corp"] = authsrc.StateDisabled // 即便"状态"是禁用，err 优先

	_, acted := s.RecheckExternalAccounts(context.Background())
	if acted != 0 {
		t.Fatalf("源不可用不得处置任何账号，实得 %d", acted)
	}
	if got := statusOf(t, h, "rc.alice"); got != "active" {
		t.Fatalf("账号不该被动，实得 %s", got)
	}
	// 且不应逐账号撞超时：一次失败即中断本源（calls 不该等于账号数）。
	if stub.calls > 1 {
		t.Errorf("源判定不可用后应中断本源循环，实际调了 %d 次", stub.calls)
	}
}

func TestRecheckGoneAlsoDisables(t *testing.T) {
	h, s, _, stub := recheckFixture(t)
	stub.states["cn=bob,dc=corp"] = authsrc.StateGone
	if _, acted := s.RecheckExternalAccounts(context.Background()); acted != 1 {
		t.Fatalf("目录里已删除的账号应被禁用，实得 %d", acted)
	}
	if got := statusOf(t, h, "rc.bob"); got != "disabled" {
		t.Fatalf("gone 应落为 disabled，实得 %s", got)
	}
}
