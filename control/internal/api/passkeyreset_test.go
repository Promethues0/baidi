package api

import (
	"net/http"
	"testing"

	"baidi.dev/control/internal/store"
)

// 管理员侧 passkey 重置（helpdesk 通道）的回归。
//
// ★缺陷原样——三条独立正确的规则合起来把账号锁死：
//
//	① passkey 没有恢复码；
//	② store.DeleteWebauthnCredential 拒绝删**最后一个**（为"别把自己锁在门外"设的，
//	   前提是本人还能登录）；
//	③ api.secondFactor 规定「已注册 passkey 即无条件强制断言，策略豁免碰不到它」。
//
// 于是认证器一丢，本人删不掉、管理员也没有任何端点可调，唯一出路是运维直接删库——
// 而 TOTP 那边（handleAdminResetTotp）的注释早就把这条路判过死刑。
//
// 断言三向：能清、清完真的没了、权限与重置口令同档（且管理员目标要 admins 权）。
func TestAdminCanResetPasskeys(t *testing.T) {
	h, st := newTestServerWithStore(t)
	ctx := t.Context()

	// 给 li.fang 塞两个 passkey（直接落库：注册仪式需要真实认证器）。
	for _, id := range []string{"cred-a", "cred-b"} {
		if _, err := st.SaveWebauthnCredential(ctx, store.WebauthnCredential{
			ID: id, Account: "li.fang", CredentialID: "raw-" + id,
			PublicKey: "pk-" + id, Name: "测试认证器 " + id,
		}); err != nil {
			t.Fatalf("造 passkey %s: %v", id, err)
		}
	}
	creds, err := st.WebauthnCredentialsFor(ctx, "li.fang")
	if err != nil || len(creds) != 2 {
		t.Fatalf("前置条件不成立：应有 2 个 passkey，got %d (%v)", len(creds), err)
	}

	// 本人删到只剩一个之后就删不动了——这正是缺陷的成因之一，先钉住它还在。
	if err := st.DeleteWebauthnCredential(ctx, "li.fang", "cred-a"); err != nil {
		t.Fatalf("删第一个应成功: %v", err)
	}
	if err := st.DeleteWebauthnCredential(ctx, "li.fang", "cred-b"); err == nil {
		t.Fatal("本人不该删得掉最后一个 passkey（那道守卫仍在）")
	}

	// 管理员清空：出口在这里。
	id := idOf(t, h, "li.fang")
	code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+id+"/passkeys", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("管理员重置 passkey http %d: %v", code, out)
	}
	if n, _ := out["removed"].(float64); int(n) != 1 {
		t.Fatalf("应清掉 1 个认证器，got %v", out["removed"])
	}
	left, _ := st.WebauthnCredentialsFor(ctx, "li.fang")
	if len(left) != 0 {
		t.Fatalf("清空后不该还剩 passkey，got %d —— 账号仍然登不进来", len(left))
	}

	// 幂等：再清一次回 0，不报错（helpdesk 会重复点）。
	code, out = doJSON(t, h, "DELETE", "/api/v1/users/"+id+"/passkeys", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("重复重置应 200，got %d", code)
	}
	if n, _ := out["removed"].(float64); int(n) != 0 {
		t.Fatalf("已经没有认证器时应回 0，got %v", out["removed"])
	}
}

// 权限：与重置口令 / 重置 TOTP 同一档——清二因子是**削弱**目标防护的方向，
// 能清 root 的 passkey 再重置其口令就是全权接管。
func TestAdminResetPasskeysPermissions(t *testing.T) {
	h := newTestServer(t)
	secTok := makeAdmin(t, h, "sec.pk", "security")
	audTok := makeAdmin(t, h, "aud.pk", "audit")

	normalID := idOf(t, h, "li.fang")
	// 审计管理员：没有 security 权，直接拒。
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/users/"+normalID+"/passkeys", audTok, nil); code != http.StatusForbidden {
		t.Fatalf("审计管理员不该重置得了 passkey，got %d", code)
	}
	// 安全管理员：普通账号可以。
	if code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+normalID+"/passkeys", secTok, nil); code != http.StatusOK {
		t.Fatalf("安全管理员应能重置普通账号的 passkey，got %d %v", code, out)
	}
	// 安全管理员：目标是**管理员**时须 admins 权（guardAdminTarget 同一道闸）。
	adminID := idOf(t, h, "admin")
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/users/"+adminID+"/passkeys", secTok, nil); code != http.StatusForbidden {
		t.Fatalf("安全管理员不该清得掉超管的 passkey（清完再重置口令 = 全权接管），got %d", code)
	}
	// 超管可以。
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/users/"+adminID+"/passkeys", adminToken(), nil); code != http.StatusOK {
		t.Fatal("超管应能重置管理员的 passkey")
	}
}
