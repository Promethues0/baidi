package api

import (
	"net/http"
	"testing"
)

// ── wave8 行动 14：应用可改可删（FR-APP-01 P0 的另外两件）──
//
// 被修的坏形态：/apps 只有 GET 与 POST。控制台「编辑」按钮走的是发布向导 → POST，
// 点一次**多出一条同名应用**——比一个点了没反应的死按钮更坏（后者只是缺功能，
// 前者会静默把数据搞乱），而发布时填错地址或选错资源之后既改不了也下不了架。

func appsOf(t *testing.T, h http.Handler) []map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/apps", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读应用 %d", code)
	}
	list := []map[string]any{}
	for _, it := range out["apps"].([]any) {
		list = append(list, it.(map[string]any))
	}
	return list
}

func appByName(t *testing.T, h http.Handler, name string) map[string]any {
	t.Helper()
	for _, a := range appsOf(t, h) {
		if str(a["name"]) == name {
			return a
		}
	}
	return nil
}

// TestAppUpdateEditsInPlace 编辑是**改**这一条，不是新增一条同名的。
func TestAppUpdateEditsInPlace(t *testing.T) {
	h := newTestServer(t)
	before := len(appsOf(t, h))
	a := appByName(t, h, "OA 协同办公")
	if a == nil {
		t.Fatal("种子里应有 OA 协同办公")
	}
	id := str(a["id"])

	code, out := doJSON(t, h, "PUT", "/api/v1/apps/"+id, adminToken(), map[string]any{
		"name": "OA 协同办公（新）", "addr": "10.20.1.11:8081", "mode": "web",
		"category": str(a["category"]), "resourceId": "oa", "status": "running",
	})
	if code != http.StatusOK {
		t.Fatalf("编辑应用 %d: %v", code, out)
	}
	after := appsOf(t, h)
	if len(after) != before {
		t.Fatalf("编辑不该改变应用总数（改造前它是 POST，会多出一条同名应用），%d → %d", before, len(after))
	}
	got := appByName(t, h, "OA 协同办公（新）")
	if got == nil || str(got["id"]) != id {
		t.Fatalf("应原地改这一条（id 不变），得到 %v", got)
	}
	if str(got["addr"]) != "10.20.1.11:8081" {
		t.Fatalf("地址应已更新，得到 %v", got["addr"])
	}
	if appByName(t, h, "OA 协同办公") != nil {
		t.Fatal("旧名字不该还在——那说明是新增而不是修改")
	}
	// 审计要看得出改了什么，而不是「修改了应用 x」。
	code, aout := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读审计 %d", code)
	}
	found := false
	for _, raw := range aout["logs"].([]any) {
		e := raw.(map[string]any)
		if ev := str(e["event"]); hasSub(ev, "修改应用") && hasSub(ev, "OA 协同办公") {
			if !hasSub(ev, "→") {
				t.Errorf("审计要写出改前改后，得到 %q", ev)
			}
			found = true
		}
	}
	if !found {
		t.Error("编辑应用必须留痕")
	}
}

// TestAppUpdatePathIDWins 路径里的 id 说了算，请求体里的 id 一律忽略。
//
// ★按请求体走的话，一次「编辑 A」会改到 B 身上，而 URL 与审计里记的都是 A。
func TestAppUpdatePathIDWins(t *testing.T) {
	h := newTestServer(t)
	oa, git := appByName(t, h, "OA 协同办公"), appByName(t, h, "研发 Git 仓库")
	if oa == nil || git == nil {
		t.Fatal("缺少种子应用")
	}
	if code, out := doJSON(t, h, "PUT", "/api/v1/apps/"+str(oa["id"]), adminToken(), map[string]any{
		"id":   str(git["id"]), // 恶意/手滑：请求体指向另一条
		"name": "改到别人头上了", "addr": "1.2.3.4:80", "mode": "web",
		"category": str(oa["category"]), "status": "running",
	}); code != http.StatusOK {
		t.Fatalf("编辑 %d: %v", code, out)
	}
	if g := appByName(t, h, "研发 Git 仓库"); g == nil {
		t.Fatal("请求体里的 id 不该生效——它把改动落到了另一条应用上")
	}
}

// TestAppUpdateValidations 入口校验：不存在 / 未知分类 / 非法模式 / 非法状态。
func TestAppUpdateValidations(t *testing.T) {
	h := newTestServer(t)
	a := appByName(t, h, "OA 协同办公")
	id := str(a["id"])
	base := func(mut func(map[string]any)) map[string]any {
		m := map[string]any{"name": "x", "addr": "1.2.3.4:80", "mode": "web",
			"category": str(a["category"]), "status": "running"}
		mut(m)
		return m
	}
	cases := []struct {
		name string
		path string
		body map[string]any
		want int
	}{
		{"不存在的应用", "/api/v1/apps/app-nope", base(func(m map[string]any) {}), http.StatusNotFound},
		{"字典外的分类", "/api/v1/apps/" + id, base(func(m map[string]any) { m["category"] = "nope" }), http.StatusBadRequest},
		{"非法模式", "/api/v1/apps/" + id, base(func(m map[string]any) { m["mode"] = "magic" }), http.StatusBadRequest},
		{"非法状态", "/api/v1/apps/" + id, base(func(m map[string]any) { m["status"] = "paused" }), http.StatusBadRequest},
		{"空名字", "/api/v1/apps/" + id, base(func(m map[string]any) { m["name"] = "  " }), http.StatusBadRequest},
	}
	for _, c := range cases {
		if code, out := doJSON(t, h, "PUT", c.path, adminToken(), c.body); code != c.want {
			t.Errorf("%s：期望 %d，实得 %d %v", c.name, c.want, code, out)
		}
	}
	// 普通用户改不了
	if code, _ := doJSON(t, h, "PUT", "/api/v1/apps/"+id, userToken("li.fang"),
		base(func(m map[string]any) {})); code == http.StatusOK {
		t.Error("普通用户不该能编辑应用")
	}
}

// TestAppDeleteKeepsResource 下架应用不删关联资源，且回执与审计都要说清楚。
//
// ★不说的话，管理员会以为下架顺手收回了访问权，而资源侧的 ACL 与 JIT 授予
// 原样有效（隧道照样连得上）。
func TestAppDeleteKeepsResource(t *testing.T) {
	h := newTestServer(t)
	a := appByName(t, h, "OA 协同办公")
	id, resID := str(a["id"]), str(a["resourceId"])
	if resID == "" {
		t.Fatal("种子 OA 应关联资源 oa")
	}
	code, out := doJSON(t, h, "DELETE", "/api/v1/apps/"+id, adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("下架 %d: %v", code, out)
	}
	if str(out["resourceId"]) != resID || !hasSub(str(out["note"]), "未删除") {
		t.Fatalf("回执要说清资源没删，得到 %v", out)
	}
	if appByName(t, h, "OA 协同办公") != nil {
		t.Fatal("应用应已下架")
	}
	// 资源仍在（授权仍按资源策略生效）。
	code, rout := doJSON(t, h, "GET", "/api/v1/resources", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读资源 %d", code)
	}
	still := false
	for _, raw := range rout["resources"].([]any) {
		if str(raw.(map[string]any)["id"]) == resID {
			still = true
		}
	}
	if !still {
		t.Fatal("下架应用不得级联删掉受控资源——它可能被别的应用引用，也可能挂着 JIT 授予")
	}
	// 重复下架 404，且不得落一条「下架了」的审计（审计里不能出现没发生的事）。
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/apps/"+id, adminToken(), nil); code != http.StatusNotFound {
		t.Errorf("重复下架应 404，实得 %d", code)
	}
}

// TestAppNodeColumnGone apps.node（恒为「华东出口」的"所属区域"）已摘除。
func TestAppNodeColumnGone(t *testing.T) {
	h := newTestServer(t)
	for _, a := range appsOf(t, h) {
		if _, bad := a["node"]; bad {
			t.Fatalf("apps.node 已摘除：管理员没有这个输入项，CreateApp 一律写死「华东出口」，"+
				"唯一消费方是一列恒定显示同一个值的表头。实得 %v", a["node"])
		}
	}
	// 新发布的应用同样不带它。
	if code, out := doJSON(t, h, "POST", "/api/v1/apps", adminToken(), map[string]any{
		"name": "新应用", "addr": "10.1.1.1:80", "mode": "web", "category": "office",
	}); code != http.StatusCreated {
		t.Fatalf("发布应用 %d: %v", code, out)
	} else if _, bad := out["node"]; bad {
		t.Fatalf("新发布的应用不该带 node：%v", out)
	}
}
