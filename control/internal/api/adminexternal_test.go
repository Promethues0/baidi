package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// 外部目录账号不得被提升为管理员（FR-ADMIN-01/03/16）。
//
// ★缺陷原样：提权入口对任何已存在账号一律放行、不看口令来源，于是管理员填一个
// AD/OIDC 账号名，拿到 200 +「已落库」，那个人出现在管理员表里、角色状态一应俱全，
// **但他在管理台登录页永远登不进去**——外部账号 pass_hash 恒空，而管理台登录
// 没有认证域路由，只查本地 bcrypt 哈希。更坏的是这条路径**计入防爆破**：
// 他多试几次就把自己锁掉，同 NAT 出口的同事跟着被 IP 维度锁。
func TestExternalAccountCannotBePromotedToAdmin(t *testing.T) {
	h, st := newTestServerWithStore(t)
	ctx := context.Background()

	// 造一个外部目录账号：pass_hash 恒空（BindExternalUser 的设计）。
	if _, err := st.CreateUser(ctx, store.DirUser{
		Name: "AD 张三", Account: "ad.zhangsan", Role: "user",
	}); err != nil {
		t.Fatalf("造外部账号: %v", err)
	}

	// ① 经「新建管理员」提权（账号已存在 → 走 SetAdminRole 那一支）
	code, out := doJSON(t, h, "POST", "/api/v1/admins", adminToken(), map[string]any{
		"account": "ad.zhangsan", "roleKey": "audit",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("外部账号提权应被拒（400），got %d %v —— 提上去他也登不进管理台，"+
			"而且每试一次都被记成口令错误并计入防爆破", code, out)
	}
	msg := errMsgOf(out)
	// 拒绝要说得出**下一步动作**：笼统的「操作失败」会让人反复重试。
	if !strings.Contains(msg, "本地口令") || !strings.Contains(msg, "重置") {
		t.Fatalf("拒绝理由要说清原因与补救路径，got %q", msg)
	}

	// 确认真没提上去
	_, sys := doJSON(t, h, "GET", "/api/v1/system", adminToken(), nil)
	for _, a := range sys["admins"].([]any) {
		if a.(map[string]any)["account"] == "ad.zhangsan" {
			t.Fatal("被拒之后不该出现在管理员表里")
		}
	}

	// ② 经「改派角色」提权（同一道闸，不然这就是绕过去的后门）
	if code, out := doJSON(t, h, "PUT", "/api/v1/admins/ad.zhangsan/role", adminToken(),
		map[string]any{"roleKey": "audit"}); code != http.StatusBadRequest {
		t.Fatalf("改派角色这条路同样要拦，got %d %v", code, out)
	}

	// ③ 反向：给他一个本地口令之后就提得上去了
	//    （判据是"有没有本地口令"，不是"是不是外部账号"）
	id := idOf(t, h, "ad.zhangsan")
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+id+"/password", adminToken(),
		map[string]any{"password": "Kx7!mQrTw9Zp"}); code != http.StatusOK {
		t.Fatalf("重置本地口令 http %d: %v", code, out)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/admins", adminToken(), map[string]any{
		"account": "ad.zhangsan", "roleKey": "audit",
	}); code != http.StatusOK {
		t.Fatalf("有本地口令之后应提得上去，got %d %v", code, out)
	}
}
