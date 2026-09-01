package api

import (
	"net/http"
	"strings"
	"testing"
)

// 「认证方式」这一列必须**按实算**，不发库里那列自由文本。
//
// ★缺陷原样：users.auth 是一列谁也不读的自由文本，种子给它填的是
// 「SAML SSO」「密码+UKey」「密码+短信」——白帝一种都没实现，而「用户与角色」页
// 把它当作事实展示在用户详情里，新建用户的表单还让人从这几项里挑一个。
// 同一条纪律早已用在**管理员**那张表上（admins_sqlite.System 的注释写得很清楚），
// 只是没做到用户目录这半边——本项目出现频率最高的「纪律只做了一半」。
func TestUserAuthLabelIsDerivedNotSeeded(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /users http %d", code)
	}
	users, _ := out["users"].([]any)
	if len(users) == 0 {
		t.Fatal("种子用户目录不该为空")
	}
	// 白帝从未实现的认证方式，一个都不该出现在这一列里。
	never := []string{"SAML", "UKey", "短信", "商密证书", "RADIUS"}
	for _, u := range users {
		m, _ := u.(map[string]any)
		auth, _ := m["auth"].(string)
		acct, _ := m["account"].(string)
		if auth == "" {
			t.Fatalf("%s 的认证方式为空", acct)
		}
		for _, bad := range never {
			if strings.Contains(auth, bad) {
				t.Fatalf("%s 的认证方式显示为 %q，其中 %q 是白帝从未实现的方式——"+
					"这一列又读回了 users.auth 那份自由文本", acct, auth, bad)
			}
		}
		// 只允许由真实判据拼出来的形态。
		base := auth
		if i := strings.Index(auth, " + "); i >= 0 {
			base = auth[:i]
		}
		if base != "本地口令" && base != "外部目录" {
			t.Fatalf("%s 的认证方式基底是 %q，只应为「本地口令」或「外部目录」", acct, base)
		}
	}
}

// 管理员那一列同样要覆盖 TOTP：只数 passkey 的话，一名只绑了 TOTP 的管理员
// 会显示成「二次认证：否」，而他每次登录都真的在输动态码。
func TestAdminAuthLabelCoversTotp(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "GET", "/api/v1/system", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /system http %d", code)
	}
	admins, _ := out["admins"].([]any)
	if len(admins) == 0 {
		t.Fatal("至少应有种子超管")
	}
	for _, a := range admins {
		m, _ := a.(map[string]any)
		auth, _ := m["auth"].(string)
		if !strings.HasPrefix(auth, "本地口令") {
			t.Fatalf("管理员认证方式基底应为「本地口令」，实际 %q", auth)
		}
		twoFa, _ := m["twoFa"].(bool)
		hasMFA := strings.Contains(auth, "passkey") || strings.Contains(auth, "TOTP")
		if twoFa != hasMFA {
			t.Fatalf("twoFa=%v 与认证方式文案 %q 不一致——两者必须同源", twoFa, auth)
		}
	}
}
