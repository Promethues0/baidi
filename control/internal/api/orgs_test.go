package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// 组织与用户组 REST：admin 门、CRUD、删除守卫 409、环形父子 400、
// 用户目录带上 org 与 groups。

func mapOf(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("期望对象，得到 %T", v)
	}
	return m
}

func orgList(t *testing.T, h http.Handler) []map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/orgs", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /orgs http %d", code)
	}
	raw, _ := out["orgs"].([]any)
	var res []map[string]any
	for _, r := range raw {
		res = append(res, mapOf(t, r))
	}
	return res
}

// 非 admin 一律 403（读也不放行——组织树本身就是内部结构信息）。
func TestOrgEndpointsRequireAdmin(t *testing.T) {
	h := newTestServer(t)
	tok := userToken("li.fang")
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/orgs"}, {"POST", "/api/v1/orgs"}, {"DELETE", "/api/v1/orgs/dev"},
		{"GET", "/api/v1/groups"}, {"POST", "/api/v1/groups"}, {"DELETE", "/api/v1/groups/g1"},
		{"PUT", "/api/v1/groups/g1/members"}, {"PUT", "/api/v1/users/u1/membership"},
	} {
		if code, _ := doJSON(t, h, c.method, c.path, tok, map[string]any{}); code != http.StatusForbidden {
			t.Errorf("%s %s 非 admin 应 403，得到 %d", c.method, c.path, code)
		}
	}
}

// 组织 CRUD + 删除守卫（有成员 409）+ 环形父子（400）。
func TestOrgCRUDOverREST(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	code, out := doJSON(t, h, "POST", "/api/v1/orgs", adm, map[string]any{"name": "华东大区", "parentId": "root", "sort": 1})
	if code != http.StatusOK {
		t.Fatalf("新建组织 http %d: %v", code, out)
	}
	east := mapOf(t, out["org"])
	eastID, _ := east["id"].(string)
	if eastID == "" || east["path"] != "/root/"+eastID+"/" {
		t.Fatalf("新建组织返回不对: %v", east)
	}
	// 子节点
	code, out = doJSON(t, h, "POST", "/api/v1/orgs", adm, map[string]any{"name": "杭州分部", "parentId": eastID})
	if code != http.StatusOK {
		t.Fatalf("新建子部门 http %d: %v", code, out)
	}
	hz := mapOf(t, out["org"])
	hzID, _ := hz["id"].(string)

	// 环形：把华东的父设成它的子节点
	code, out = doJSON(t, h, "POST", "/api/v1/orgs", adm,
		map[string]any{"id": eastID, "name": "华东大区", "parentId": hzID})
	if code != http.StatusBadRequest {
		t.Fatalf("环形父子应 400，得到 %d: %v", code, out)
	}

	// 有子部门 → 409
	if code, out = doJSON(t, h, "DELETE", "/api/v1/orgs/"+eastID, adm, nil); code != http.StatusConflict {
		t.Fatalf("有子部门删除应 409，得到 %d: %v", code, out)
	}
	// 有成员 → 409（种子里 dev 有人）
	if code, out = doJSON(t, h, "DELETE", "/api/v1/orgs/dev", adm, nil); code != http.StatusConflict {
		t.Fatalf("有成员删除应 409，得到 %d: %v", code, out)
	}
	// 空叶子可删
	if code, out = doJSON(t, h, "DELETE", "/api/v1/orgs/"+hzID, adm, nil); code != http.StatusOK {
		t.Fatalf("空叶子应可删，得到 %d: %v", code, out)
	}
	for _, o := range orgList(t, h) {
		if o["id"] == hzID {
			t.Fatal("已删组织仍在清单里")
		}
	}
}

// 用户组 CRUD + 成员覆写 + 角色组只读（409）。
func TestGroupCRUDOverREST(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	code, out := doJSON(t, h, "POST", "/api/v1/groups", adm,
		map[string]any{"name": "高敏访问组", "kind": "static", "description": "财务白名单"})
	if code != http.StatusOK {
		t.Fatalf("建组 http %d: %v", code, out)
	}
	gid, _ := mapOf(t, out["group"])["id"].(string)

	// 未知 kind 拒绝（避免存进一个永远不生效的类型）
	if code, _ = doJSON(t, h, "POST", "/api/v1/groups", adm, map[string]any{"name": "X", "kind": "dynamic"}); code != http.StatusBadRequest {
		t.Errorf("非法 kind 应 400，得到 %d", code)
	}
	// 重名 409
	if code, _ = doJSON(t, h, "POST", "/api/v1/groups", adm, map[string]any{"name": "高敏访问组"}); code != http.StatusConflict {
		t.Errorf("重名应 409，得到 %d", code)
	}

	// 成员覆写
	code, out = doJSON(t, h, "PUT", "/api/v1/groups/"+gid+"/members", adm,
		map[string]any{"accounts": []string{"li.fang", "zhang.wei"}})
	if code != http.StatusOK {
		t.Fatalf("设成员 http %d: %v", code, out)
	}
	if mem, _ := out["memberAccounts"].([]any); len(mem) != 2 {
		t.Fatalf("成员应 2 人: %v", out)
	}
	// 未知账号 400
	if code, _ = doJSON(t, h, "PUT", "/api/v1/groups/"+gid+"/members", adm,
		map[string]any{"accounts": []string{"nobody"}}); code != http.StatusBadRequest {
		t.Errorf("未知账号应 400，得到 %d", code)
	}

	// 角色组成员只读
	code, out = doJSON(t, h, "POST", "/api/v1/groups", adm, map[string]any{"name": "研发", "kind": "role"})
	if code != http.StatusOK {
		t.Fatalf("建角色组 http %d: %v", code, out)
	}
	rid, _ := mapOf(t, out["group"])["id"].(string)
	if code, _ = doJSON(t, h, "PUT", "/api/v1/groups/"+rid+"/members", adm,
		map[string]any{"accounts": []string{"li.fang"}}); code != http.StatusConflict {
		t.Errorf("角色组显式设成员应 409，得到 %d", code)
	}
	// 但它有派生成员
	code, out = doJSON(t, h, "GET", "/api/v1/groups", adm, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /groups http %d", code)
	}
	found := false
	for _, raw := range out["groups"].([]any) {
		g := mapOf(t, raw)
		if g["id"] == rid {
			found = true
			if n, _ := g["members"].(float64); n != 2 {
				t.Errorf("角色组「研发」应派生出 2 人，得到 %v", g["members"])
			}
		}
	}
	if !found {
		t.Fatal("角色组不在清单里")
	}

	if code, _ = doJSON(t, h, "DELETE", "/api/v1/groups/"+gid, adm, nil); code != http.StatusOK {
		t.Errorf("删组应 200，得到 %d", code)
	}
	if code, _ = doJSON(t, h, "DELETE", "/api/v1/groups/"+gid, adm, nil); code != http.StatusNotFound {
		t.Errorf("重复删应 404，得到 %d", code)
	}
}

// GET /users 带 org 与 groups；POST /users 与用户编辑能设置 org_id/groups。
func TestUsersCarryOrgAndGroups(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	code, out := doJSON(t, h, "POST", "/api/v1/groups", adm, map[string]any{"name": "值班组"})
	if code != http.StatusOK {
		t.Fatalf("建组 http %d", code)
	}
	gid, _ := mapOf(t, out["group"])["id"].(string)

	// 新建用户直接带 org + group
	code, out = doJSON(t, h, "POST", "/api/v1/users", adm, map[string]any{
		"name": "钱七", "account": "qian.qi", "orgId": "sales", "groups": []string{gid},
	})
	if code != http.StatusCreated {
		t.Fatalf("新建用户 http %d: %v", code, out)
	}
	// 组织不存在 → 404（不是 500）
	if code, _ = doJSON(t, h, "POST", "/api/v1/users", adm,
		map[string]any{"name": "错组织", "account": "bad.org", "orgId": "nope"}); code != http.StatusNotFound {
		t.Errorf("组织不存在应 404，得到 %d", code)
	}

	users := usersBundle(t, h, adm)
	if len(users.OrgTree) == 0 {
		t.Fatal("用户目录应带真实组织树")
	}
	if len(users.Groups) != 1 || users.Groups[0].ID != gid {
		t.Fatalf("用户目录应带用户组目录: %+v", users.Groups)
	}
	var qian, li dirUserView
	for _, u := range users.Users {
		switch u.Account {
		case "qian.qi":
			qian = u
		case "li.fang":
			li = u
		}
	}
	if qian.OrgID != "sales" || qian.Org != "销售部" {
		t.Errorf("新建用户应挂在销售部: %+v", qian)
	}
	if len(qian.Groups) != 1 || qian.Groups[0] != gid {
		t.Errorf("新建用户应已入值班组: %+v", qian)
	}
	if li.OrgID != "sales" {
		t.Errorf("种子用户 li.fang 应已回填组织归属，得到 %q", li.OrgID)
	}

	// 用户编辑：改组织 + 改组
	if code, out = doJSON(t, h, "PUT", "/api/v1/users/"+li.ID+"/membership", adm,
		map[string]any{"orgId": "dev", "groups": []string{gid}}); code != http.StatusOK {
		t.Fatalf("改归属 http %d: %v", code, out)
	}
	users = usersBundle(t, h, adm)
	for _, u := range users.Users {
		if u.Account != "li.fang" {
			continue
		}
		if u.OrgID != "dev" || u.Org != "研发部" {
			t.Errorf("改归属后展示组织应跟随组织表: %+v", u)
		}
		if len(u.Groups) != 1 {
			t.Errorf("改归属后应在值班组: %+v", u)
		}
	}
	// 清空归属（显式空串）
	if code, _ = doJSON(t, h, "PUT", "/api/v1/users/"+li.ID+"/membership", adm,
		map[string]any{"orgId": ""}); code != http.StatusOK {
		t.Errorf("清空归属应 200，得到 %d", code)
	}
	// 不存在的用户 404
	if code, _ = doJSON(t, h, "PUT", "/api/v1/users/u-nope/membership", adm,
		map[string]any{"orgId": "dev"}); code != http.StatusNotFound {
		t.Errorf("用户不存在应 404，得到 %d", code)
	}
}

// ★这里原有 TestPoliciesTreeFollowsOrgUnits（断言 GET /api/v1/policies 的组织树
// 跟随 org_units）。那个端点随「用户策略 · 继承编辑器」一并摘除（wave8 行动 13-①）——
// 树本身仍由 store.PolicyBundle 真实构建，覆盖它的用例是
// store.TestPolicyBundleTreeFromDB，这里不再重复一份对着已删端点的断言。

// ── 解码 helper ──

type dirUserView struct {
	ID      string   `json:"id"`
	Account string   `json:"account"`
	Org     string   `json:"org"`
	OrgID   string   `json:"orgId"`
	Groups  []string `json:"groups"`
}

type groupView2 struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type usersBundleView struct {
	OrgTree []map[string]any `json:"orgTree"`
	Groups  []groupView2     `json:"groups"`
	Users   []dirUserView    `json:"users"`
}

func usersBundle(t *testing.T, h http.Handler, tok string) usersBundleView {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/users", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /users http %d", code)
	}
	raw, _ := json.Marshal(out)
	var b usersBundleView
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("decode users bundle: %v", err)
	}
	return b
}
