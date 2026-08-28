package api

// UseUserInfo 的接线（wave9）。oidcsrc 的 userInfo() 全套代码一直都在，
// 注释也点名了它要解决的场景（「有些 IdP 不把 groups/email 放进 ID Token，
// 只在 UserInfo 里给」），但 api 层的配置 DTO 里没有这一项 → 恒 false →
// 整条能力在生产路径上不可达。这类缺陷（能力在、配置面没接）最对症的测试
// 就是直接断言接线存在。

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

// DTO 必须认得 useUserInfo，否则管理员在页面上打开的开关落库后读不回来。
func TestOIDC配置解析useUserInfo(t *testing.T) {
	var c oidcConfigDTO
	raw := `{"issuer":"https://idp.example","clientId":"baidi",` +
		`"redirectUri":"https://x/cb","useUserInfo":true}`
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	if !c.UseUserInfo {
		t.Fatal("useUserInfo 没被解析出来——页面上的开关落库后读不回来")
	}
	// 缺省（存量配置）必须是 false：多打一次 UserInfo 是真出网，
	// 不该对所有存量部署无声生效。
	var d oidcConfigDTO
	if err := json.Unmarshal([]byte(`{"issuer":"https://i","clientId":"c"}`), &d); err != nil {
		t.Fatal(err)
	}
	if d.UseUserInfo {
		t.Fatal("存量配置缺省应为 false")
	}
}

// buildProvider 必须真的把它传给 oidcsrc。
//
// ★这条是源码文本断言（同 gateway 的 TestSweepRunsBeforeTunCreation）：
// Provider 的 cfg 是私有字段，行为侧要一台假 IdP 才验得到（那 30 条在 oidcsrc 包里）。
// 而这里要防的恰恰是「字段加了、忘了传下去」——那种缺陷编译得过、测试也全绿。
func TestOIDC接线真的把useUserInfo传给了oidcsrc(t *testing.T) {
	b, err := os.ReadFile("login_authsrc.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "oidcsrc.New(oidcsrc.Config{")
	if i < 0 {
		t.Fatal("找不到 oidcsrc.New 的构造点")
	}
	j := strings.Index(s[i:], "})")
	if j < 0 {
		t.Fatal("oidcsrc.Config 字面量没有结束")
	}
	if !strings.Contains(s[i:i+j], "UseUserInfo: c.UseUserInfo") {
		t.Fatal("oidcsrc.Config 里没有传 UseUserInfo——DTO 加了字段但没接线，" +
			"整条 UserInfo 补属性的能力在生产路径上依然不可达")
	}
}

// 拿不到属性时，拒绝原因要指出下一步动作；判定不通过（属性拿到了、不在白名单里）不加提示。
func TestOIDC属性缺失的拒绝原因指向解决办法(t *testing.T) {
	oidcRec := store.AuthSourceRec{ID: "s1", Kind: "oidc"}
	ldapRec := store.AuthSourceRec{ID: "s2", Kind: "ldap"}

	// 拿不到 groups：OIDC 要点出 UserInfo 这条路。
	if h := admitAttrHint(oidcRec, authsrc.Identity{Email: "a@x.com"}); !strings.Contains(h, "UserInfo") {
		t.Fatalf("OIDC 属性缺失应指向 UserInfo 开关，实得 %q——"+
			"不点出来的话，管理员会反复核对一份本来就正确的白名单", h)
	}
	// LDAP 的成因不同：属性名对不上。
	if h := admitAttrHint(ldapRec, authsrc.Identity{}); !strings.Contains(h, "属性名") {
		t.Fatalf("LDAP 属性缺失应指向属性名配置，实得 %q", h)
	}
	// 属性齐全 = 判定不通过，不该提示「去补属性」——那时该改的是白名单。
	full := authsrc.Identity{Email: "a@x.com", Groups: []string{"dev"}}
	if h := admitAttrHint(oidcRec, full); h != "" {
		t.Fatalf("属性齐全时不该加补属性提示（该改的是白名单），实得 %q", h)
	}
}
