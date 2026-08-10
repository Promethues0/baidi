package store

import (
	"context"
	"testing"
)

// 认证源页顶部聚合必须来自 auth_sources 真实行，不是种子。
//
// 钉住的是这一页最误导的那个状态：下半截已经在读真实配置，上半截还渲染着
// 6 条硬编码源和「总部 AD 域 1160 用户」。任何一条编造的源重新出现在 Bundle 里，
// 这个用例都会红。
func TestAuthSrcBundleComesFromTable(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	b, err := st.AuthSrc(ctx)
	if err != nil {
		t.Fatalf("读认证源聚合失败：%v", err)
	}
	if len(b.Sources) != 1 || b.Sources[0].Key != "local" || b.Sources[0].Type != "local" {
		t.Fatalf("全新库应只有回填出的 local 一条，实得 %+v", b.Sources)
	}
	if !b.Sources[0].Enabled {
		t.Error("local 源应为启用（它参与登录链路的第一跳）")
	}

	// 真配一个 LDAP 源 → 立刻出现在聚合里，且字段与落库的那份一致。
	if _, err := st.SaveAuthSource(ctx, AuthSourceRec{
		ID: "as-ldap", Name: "研发 LDAP", Kind: "ldap", Enabled: true, Priority: 5, Config: "{}",
	}); err != nil {
		t.Fatalf("保存认证源失败：%v", err)
	}
	b, err = st.AuthSrc(ctx)
	if err != nil {
		t.Fatalf("读认证源聚合失败：%v", err)
	}
	if len(b.Sources) != 2 {
		t.Fatalf("应有 local + ldap 两条，实得 %+v", b.Sources)
	}
	if b.Sources[0].Key != "local" {
		t.Errorf("本地目录必须恒排最前（登录按本地→外部顺序询问），实得 %s", b.Sources[0].Key)
	}
	ldap := b.Sources[1]
	if ldap.Key != "as-ldap" || ldap.Name != "研发 LDAP" || ldap.Type != "ldap" || !ldap.Enabled || ldap.Priority != 5 {
		t.Errorf("聚合字段与落库那份不一致：%+v", ldap)
	}
	if ldap.BoundAccounts != 0 {
		t.Errorf("新源还没有人登录过，绑定账号数应为 0，实得 %d", ldap.BoundAccounts)
	}

	// 停用后仍应列出（管理意图 = 停用，不是"这个源消失了"）。
	if _, err := st.SaveAuthSource(ctx, AuthSourceRec{
		ID: "as-ldap", Name: "研发 LDAP", Kind: "ldap", Enabled: false, Priority: 5, Config: "{}",
	}); err != nil {
		t.Fatalf("停用认证源失败：%v", err)
	}
	b, _ = st.AuthSrc(ctx)
	if len(b.Sources) != 2 || b.Sources[1].Enabled {
		t.Errorf("停用的源应仍在列表里且 enabled=false，实得 %+v", b.Sources)
	}
}

// BoundAccounts 必须是可验证的库内事实（绑定条数），而不是"目录纳管用户数"那种猜数。
func TestAuthSrcBoundAccountsCountsRealBindings(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	if _, err := st.SaveAuthSource(ctx, AuthSourceRec{
		ID: "as-oidc", Name: "企业 IdP", Kind: "oidc", Enabled: true, Priority: 1, Config: "{}",
	}); err != nil {
		t.Fatalf("保存认证源失败：%v", err)
	}

	before, err := st.AuthSrc(ctx)
	if err != nil {
		t.Fatalf("读认证源聚合失败：%v", err)
	}
	localBefore := 0
	for _, s := range before.Sources {
		if s.Key == "local" {
			localBefore = s.BoundAccounts
		}
	}
	if localBefore == 0 {
		t.Fatal("种子目录里有本地账号，本地目录的账号数不该是 0")
	}

	// 两个不同 subject 登录一次 → 两条绑定。
	for _, sub := range []string{"sub-1", "sub-2"} {
		if _, err := st.BindExternalUser(ctx, "as-oidc", ExternalIdentity{
			Subject: sub, Username: sub, DisplayName: sub,
		}); err != nil {
			t.Fatalf("绑定外部身份失败：%v", err)
		}
	}
	// 同一 subject 再登录一次不该重复计数。
	if _, err := st.BindExternalUser(ctx, "as-oidc", ExternalIdentity{
		Subject: "sub-1", Username: "sub-1",
	}); err != nil {
		t.Fatalf("重复绑定失败：%v", err)
	}

	after, err := st.AuthSrc(ctx)
	if err != nil {
		t.Fatalf("读认证源聚合失败：%v", err)
	}
	var oidc, local AuthSource
	for _, s := range after.Sources {
		switch s.Key {
		case "as-oidc":
			oidc = s
		case "local":
			local = s
		}
	}
	if oidc.BoundAccounts != 2 {
		t.Errorf("外部源应计出 2 个已绑定账号，实得 %d", oidc.BoundAccounts)
	}
	// ★外部账号建在 users 表里，但它们归外部源；本地目录的计数不能把它们算进来，
	// 否则同一个人会在两张卡片上各被数一次。
	if local.BoundAccounts != localBefore {
		t.Errorf("外部账号不该被算进本地目录：绑定前 %d、绑定后 %d", localBefore, local.BoundAccounts)
	}
}
