package api

import (
	"context"
	"net/http"
	"testing"

	"baidi.dev/control/internal/store"
)

// 「按用户角色派生」的用户组此前**永远 0 人且不可能变成非 0**：
// users.roles 全仓没有任何写入路径（建号恒发 []、CSV 导入写死 []、membership 只管
// 组织与 static 组、也没有 PUT /users/{id}），唯一写入点是种子回灌。
// 而新建用户组的弹窗恰好写着「改不了成员，只能改角色」——把管理员指向一条死路。
//
// 用这种组授权的后果分两个方向，都很难归因：
//   · 资源侧 → SubjectIndex 展开为空 → 下发 DenyAllSubject 哨兵 → 那条资源对**所有人**
//     拒绝（原本"不限"的人也进不去，表现为「明明授权了却打不开」）；
//   · 认证策略 / 安全基线的 scopeGroups → covers 恒 false → 永不命中（fail-open）。
// 演示库上完全看不出来，因为 7 个种子账号带着 roles。
func TestRoleDerivedGroupGetsMembers(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()

	// 建一个角色派生组（组名即角色名）
	code, out := doJSON(t, f.h, "POST", "/api/v1/groups", adminToken(), map[string]any{
		"name": "安全审计员", "kind": "role",
	})
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("建角色派生组 %d: %v", code, out)
	}
	gid, _ := out["id"].(string)
	if gid == "" {
		if g, ok := out["group"].(map[string]any); ok {
			gid, _ = g["id"].(string)
		}
	}
	if gid == "" {
		t.Fatalf("拿不到组 id: %v", out)
	}

	// 建一个用户
	code, out = doJSON(t, f.h, "POST", "/api/v1/users", adminToken(), map[string]any{
		"name": "周敏", "account": "zhou.min", "org": "安全部",
	})
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("建用户 %d: %v", code, out)
	}
	var uid string
	b, _ := f.st.Users(ctx)
	for _, u := range b.Users {
		if u.Account == "zhou.min" {
			uid = u.ID
		}
	}
	if uid == "" {
		t.Fatal("建出来的用户找不到")
	}

	// 改造前：这个组恒 0 人，且没有任何办法改变它
	if m, _ := f.st.GroupMembers(ctx, gid); len(m) != 0 {
		t.Fatalf("前提不成立：新建的角色派生组应为 0 人，实得 %v", m)
	}

	// ★经 membership 端点赋予展示角色 —— 这正是 UI 上那句「只能改角色」指向的动作
	code, out = doJSON(t, f.h, "PUT", "/api/v1/users/"+uid+"/membership", adminToken(),
		map[string]any{"roles": []string{"安全审计员"}})
	if code != http.StatusOK {
		t.Fatalf("设置展示角色应成功，实得 %d: %v", code, out)
	}

	mem, err := f.st.GroupMembers(ctx, gid)
	if err != nil {
		t.Fatalf("读组成员: %v", err)
	}
	if len(mem) != 1 || mem[0] != "zhou.min" {
		t.Fatalf("角色派生组应因此有了成员，实得 %v —— 否则用它授权会让资源对所有人拒绝"+
			"（空展开 → DenyAllSubject 哨兵），或让策略/基线永不命中", mem)
	}

	// ★去空去重：一个多敲的空行会派生出名为 "" 的角色组——页面上看不见，却真的参与分组
	if code, _ := doJSON(t, f.h, "PUT", "/api/v1/users/"+uid+"/membership", adminToken(),
		map[string]any{"roles": []string{"安全审计员", "", "  ", "安全审计员"}}); code != http.StatusOK {
		t.Fatal("重复/空白角色应被清洗而不是报错")
	}
	b, _ = f.st.Users(ctx)
	for _, u := range b.Users {
		if u.ID == uid && len(u.Roles) != 1 {
			t.Errorf("空白与重复角色应被去掉，实得 %v", u.Roles)
		}
	}

	// 改不存在的用户必须报错，不能静默"成功"
	if code, _ := doJSON(t, f.h, "PUT", "/api/v1/users/不存在的用户/membership", adminToken(),
		map[string]any{"roles": []string{"x"}}); code == http.StatusOK {
		t.Error("改一个不存在的用户不该回 200")
	}

	// 主体索引也要跟着变（资源授权/策略/基线共用它）
	ix, err := f.st.SubjectIndex(ctx)
	if err == nil {
		if got := ix.GroupAccounts[gid]; len(got) != 1 {
			t.Errorf("SubjectIndex 里该组应展开出 1 个账号，实得 %v —— "+
				"那才是资源授权与策略适用范围真正读的那份", got)
		}
	}
	_ = store.GroupKindRole
}
