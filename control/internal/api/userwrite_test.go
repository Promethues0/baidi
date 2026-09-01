package api

import (
	"net/http"
	"strings"
	"testing"
)

// 目录的改（FR-USER-02）与删（FR-USER-15）。
//
// ★两条端点此前整个不存在：`grep` 全仓没有 `PUT /users/{id}`，
// `grep -rn DeleteUser` 只命中 DeleteUserGroup。后果各自是一条死路——
// 建号时姓名打错就永远改不了（只能禁用重建，而重建又删不掉，于是永久多一行僵尸账号）；
// License 席位满时后端 409 文案与闲置治理弹窗都指向「删除闲置账号释放席位」，
// 而那条路根本不存在。

func TestUpdateUserProfile(t *testing.T) {
	h := newTestServer(t)
	id := idOf(t, h, "li.fang")

	// 改姓名 + 邮箱
	code, out := doJSON(t, h, "PUT", "/api/v1/users/"+id, adminToken(),
		map[string]any{"name": "李芳（销售二部）", "email": "li.fang@corp.example"})
	if code != http.StatusOK {
		t.Fatalf("改资料 http %d: %v", code, out)
	}
	if out["name"] != "李芳（销售二部）" || out["email"] != "li.fang@corp.example" {
		t.Fatalf("应回改后的行，got %v / %v", out["name"], out["email"])
	}
	// 回读确认真落库（接口回 200 而库里没变是这类端点最常见的失败形态）
	_, users := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	hit := false
	for _, raw := range users["users"].([]any) {
		u := raw.(map[string]any)
		if u["account"] == "li.fang" {
			hit = true
			if u["name"] != "李芳（销售二部）" {
				t.Fatalf("改动没落库，目录里还是 %v", u["name"])
			}
		}
	}
	if !hit {
		t.Fatal("目录里找不到 li.fang")
	}

	// ★账号名显式拒改：它是令牌主体，也是 JIT / 封禁 / posture / 组成员 / 认证源绑定的关联键。
	code, out = doJSON(t, h, "PUT", "/api/v1/users/"+id, adminToken(),
		map[string]any{"account": "li.fang2"})
	if code != http.StatusBadRequest {
		t.Fatalf("改账号名应被拒（400），got %d %v", code, out)
	}
	if msg := errMsgOf(out); !strings.Contains(msg, "账号名不可修改") {
		t.Fatalf("拒绝要说清为什么，got %q", msg)
	}

	// 不存在的 id 回 404（SQLite 对不存在的 id 不报错，不查 RowsAffected 会静默成功）
	if code, _ := doJSON(t, h, "PUT", "/api/v1/users/no-such-id", adminToken(),
		map[string]any{"name": "幽灵"}); code != http.StatusNotFound {
		t.Fatalf("改一个不存在的账号应 404，got %d", code)
	}

	// 权限：审计管理员改不动
	audTok := makeAdmin(t, h, "aud.uw", "audit")
	if code, _ := doJSON(t, h, "PUT", "/api/v1/users/"+id, audTok,
		map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("审计管理员不该改得动用户资料，got %d", code)
	}
}

func TestDeleteUserAndBlastRadius(t *testing.T) {
	h := newTestServer(t)
	id := idOf(t, h, "li.fang")

	// 预览：删之前就能看见牵动什么
	code, prev := doJSON(t, h, "GET", "/api/v1/users/"+id+"/delete-preview", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("影响面预览 http %d: %v", code, prev)
	}
	if prev["account"] != "li.fang" || str(prev["note"]) == "" {
		t.Fatalf("预览应带账号与人话影响面，got %v", prev)
	}

	// 删
	code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+id, adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("删除 http %d: %v", code, out)
	}
	if str(out["note"]) == "" {
		t.Fatal("删除回执必须带影响面：不说的话管理员以为删账号顺手收回了授权")
	}
	// 真没了
	_, users := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	for _, raw := range users["users"].([]any) {
		if raw.(map[string]any)["account"] == "li.fang" {
			t.Fatal("删除后目录里不该还有这个账号")
		}
	}
	// ★重复删回 404 而不是 200：回 200 会在审计里落一条没发生过的「删除用户」。
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/users/"+id, adminToken(), nil); code != http.StatusNotFound {
		t.Fatalf("重复删除应 404，got %d", code)
	}
}

// 防自锁：最后一名可登录的超管删不掉——否则一次误删就是整套系统再也没人能进管理台。
func TestDeleteUserGuardsLastRootAdmin(t *testing.T) {
	h := newTestServer(t)
	adminID := idOf(t, h, "admin")

	// ★种子里有**两名**超管（admin 与 zhang.wei，后者由 admin.role.backfill.v1 回填）。
	//   先做反向断言：还有第二名超管时**删得掉**——不先验这一步的话，
	//   一个「一律拒绝删超管」的实现也能让下面那条断言通过。
	otherID := idOf(t, h, "zhang.wei")
	if code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+otherID, adminToken(), nil); code != http.StatusOK {
		t.Fatalf("还有第二名超管时应删得掉，got %d %v", code, out)
	}

	// 现在 admin 是最后一名可登录的超管：删不掉。
	code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+adminID, adminToken(), nil)
	if code != http.StatusConflict {
		t.Fatalf("最后一名超管应删不掉（409），got %d %v —— "+
			"一次误删就是整套系统再也没人能进管理台", code, out)
	}
	if msg := errMsgOf(out); !strings.Contains(msg, "超级管理员") {
		t.Fatalf("拒绝要说清原因，got %q", msg)
	}

	// 再建一名超管之后又删得掉了（判据是"还有没有别人"，不是"是不是超管"）。
	makeAdmin(t, h, "root2", "root")
	if code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+adminID, adminToken(), nil); code != http.StatusOK {
		t.Fatalf("已有第二名超管时应删得掉，got %d %v", code, out)
	}
}

// 安全管理员删不掉管理员（清一名审计管理员比禁用他更彻底）。
func TestDeleteUserGuardsAdminTarget(t *testing.T) {
	h := newTestServer(t)
	secTok := makeAdmin(t, h, "sec.del", "security")
	makeAdmin(t, h, "aud.del", "audit")

	audID := idOf(t, h, "aud.del")
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/users/"+audID, secTok, nil); code != http.StatusForbidden {
		t.Fatalf("安全管理员不该删得掉审计管理员，got %d", code)
	}
	// 普通账号可以
	if code, out := doJSON(t, h, "DELETE", "/api/v1/users/"+idOf(t, h, "wang.qiang"), secTok, nil); code != http.StatusOK {
		t.Fatalf("安全管理员应能删普通账号，got %d %v", code, out)
	}
}
