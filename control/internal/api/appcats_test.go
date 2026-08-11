package api

import (
	"net/http"
	"strings"
	"testing"
)

// 应用分类字典 REST：权限门、CRUD、删除守卫、内置保护、格式与唯一、
// 以及「改了分类，应用页跟着变」。

func catsOf(t *testing.T, h http.Handler, tok string) []map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/app-categories", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /app-categories http %d: %v", code, out)
	}
	raw, _ := out["categories"].([]any)
	var res []map[string]any
	for _, r := range raw {
		res = append(res, mapOf(t, r))
	}
	return res
}

func catRow(t *testing.T, rows []map[string]any, key string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if r["key"] == key {
			return r
		}
	}
	t.Fatalf("分类 %s 不在返回里: %v", key, rows)
	return nil
}

// 读=任意管理员（角色现算）；普通用户连读都不行——分类字典本身就是内部结构信息。
func TestAppCategoryEndpointsRequireAdmin(t *testing.T) {
	h := newTestServer(t)
	tok := userToken("li.fang")
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/app-categories"},
		{"POST", "/api/v1/app-categories"},
		{"PUT", "/api/v1/app-categories/office"},
		{"DELETE", "/api/v1/app-categories/office"},
	} {
		if code, _ := doJSON(t, h, c.method, c.path, tok, map[string]any{}); code != http.StatusForbidden {
			t.Errorf("%s %s 非 admin 应 403，得到 %d", c.method, c.path, code)
		}
	}
}

// 写=PermSecurity（与 POST /apps 同权）：系统管理员与审计管理员一律 403，
// 安全管理员放行——只测拒绝的话，一个把所有人都拒掉的实现也能全绿。
func TestAppCategoryWritesNeedSecurityPerm(t *testing.T) {
	h := newTestServer(t)
	sysTok := makeAdmin(t, h, "sys.cat", "system")
	audTok := makeAdmin(t, h, "aud.cat", "audit")
	secTok := makeAdmin(t, h, "sec.cat", "security")

	for role, tok := range map[string]string{"system": sysTok, "audit": audTok} {
		if code, _ := doJSON(t, h, "POST", "/api/v1/app-categories", tok,
			map[string]any{"key": "hr", "label": "人力资源"}); code != http.StatusForbidden {
			t.Errorf("%s 管理员建分类应 403，得到 %d", role, code)
		}
		// 但读得到（角色现算，三权都能看应用分类）
		if code, _ := doJSON(t, h, "GET", "/api/v1/app-categories", tok, nil); code != http.StatusOK {
			t.Errorf("%s 管理员应能读分类字典，得到 %d", role, code)
		}
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/app-categories", secTok,
		map[string]any{"key": "hr", "label": "人力资源"}); code != http.StatusCreated {
		t.Fatalf("安全管理员建分类应 201，得到 %d: %v", code, out)
	}
}

// CRUD over REST + 落审计。
func TestAppCategoryCRUDOverREST(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	code, out := doJSON(t, h, "POST", "/api/v1/app-categories", adm, map[string]any{"key": "hr", "label": "人力资源"})
	if code != http.StatusCreated {
		t.Fatalf("建分类 http %d: %v", code, out)
	}
	if c := mapOf(t, out["category"]); c["builtin"] != false {
		t.Errorf("REST 建出来的分类不能是内置的: %v", c)
	}
	// key 唯一：重复即 409，且不能把既有分类静默改名
	if code, out = doJSON(t, h, "POST", "/api/v1/app-categories", adm,
		map[string]any{"key": "hr", "label": "另一个名字"}); code != http.StatusConflict {
		t.Fatalf("重复 key 应 409，得到 %d: %v", code, out)
	}
	if got := catRow(t, catsOf(t, h, adm), "hr")["label"]; got != "人力资源" {
		t.Fatalf("重复 key 的请求把既有分类改名了: %v", got)
	}
	// 格式非法 → 400
	for _, bad := range []string{"All", "有中文", "under_score", ""} {
		if code, _ = doJSON(t, h, "POST", "/api/v1/app-categories", adm,
			map[string]any{"key": bad, "label": "x"}); code != http.StatusBadRequest {
			t.Errorf("key=%q 应 400，得到 %d", bad, code)
		}
	}

	// 改名与排序
	if code, out = doJSON(t, h, "PUT", "/api/v1/app-categories/hr", adm,
		map[string]any{"label": "人力与行政", "sort": 15}); code != http.StatusOK {
		t.Fatalf("改分类 http %d: %v", code, out)
	}
	rows := catsOf(t, h, adm)
	if rows[1]["key"] != "hr" || rows[1]["label"] != "人力与行政" {
		t.Fatalf("改名与排序未生效: %v", rows)
	}
	// 不存在的分类 → 404
	if code, _ = doJSON(t, h, "PUT", "/api/v1/app-categories/nope", adm,
		map[string]any{"label": "x", "sort": 1}); code != http.StatusNotFound {
		t.Errorf("改不存在的分类应 404，得到 %d", code)
	}

	// 删除
	if code, out = doJSON(t, h, "DELETE", "/api/v1/app-categories/hr", adm, nil); code != http.StatusOK {
		t.Fatalf("删分类 http %d: %v", code, out)
	}
	for _, r := range catsOf(t, h, adm) {
		if r["key"] == "hr" {
			t.Fatal("删除后仍在字典里")
		}
	}
	if code, _ = doJSON(t, h, "DELETE", "/api/v1/app-categories/hr", adm, nil); code != http.StatusNotFound {
		t.Errorf("删不存在的分类应 404，得到 %d", code)
	}

	// 审计：三次成功操作都要留痕，且措辞只记已发生的事实。
	for _, want := range []string{"新建应用分类「人力资源」(hr)", "名称「人力资源」→「人力与行政」", "删除应用分类 hr"} {
		if !auditHasEvent(t, h, want) {
			t.Errorf("审计里缺少 %q：%v", want, auditEvents(t, h))
		}
	}
}

// 内置分类：可改名，不可删（key 被种子应用引用）。
func TestBuiltinAppCategoryProtectionOverREST(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	if code, out := doJSON(t, h, "PUT", "/api/v1/app-categories/finance", adm,
		map[string]any{"label": "财务与结算", "sort": 20}); code != http.StatusOK {
		t.Fatalf("内置分类应允许改名 http %d: %v", code, out)
	}
	row := catRow(t, catsOf(t, h, adm), "finance")
	if row["label"] != "财务与结算" || row["builtin"] != true {
		t.Fatalf("改名后内置标记应保持: %v", row)
	}
	if code, out := doJSON(t, h, "DELETE", "/api/v1/app-categories/finance", adm, nil); code != http.StatusConflict {
		t.Fatalf("内置分类应拒删 409，得到 %d: %v", code, out)
	}
	// 拒删也是发生过的事，要落一条 fail 审计。
	if !auditHasEvent(t, h, "删除应用分类 finance 被拒") {
		t.Error("拒删未落审计")
	}
}

// 删除守卫：分类下还有应用 → 409 且说清还有几个；不做级联置空。
func TestDeleteAppCategoryInUseOverREST(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	if code, out := doJSON(t, h, "POST", "/api/v1/app-categories", adm,
		map[string]any{"key": "hr", "label": "人力资源"}); code != http.StatusCreated {
		t.Fatalf("建分类 http %d: %v", code, out)
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/apps", adm, map[string]any{
		"name": "招聘系统", "mode": "web", "addr": "10.5.0.1:80", "category": "hr",
	}); code != http.StatusCreated {
		t.Fatalf("建应用 http %d: %v", code, out)
	}
	code, out := doJSON(t, h, "DELETE", "/api/v1/app-categories/hr", adm, nil)
	if code != http.StatusConflict {
		t.Fatalf("有应用在用应 409，得到 %d: %v", code, out)
	}
	if msg := errMsg(out); !strings.Contains(msg, "1 个应用") {
		t.Errorf("409 应说清还有几个应用在用，得到 %q", msg)
	}
	// 分类与应用都还在
	if catRow(t, catsOf(t, h, adm), "hr")["count"] != float64(1) {
		t.Error("拒删后分类应原样保留")
	}
}

// 发布应用时分类必须在字典里；分类改名后应用页的筛选条跟随。
func TestAppsFollowCategoryDictionary(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	if code, out := doJSON(t, h, "POST", "/api/v1/apps", adm, map[string]any{
		"name": "野应用", "mode": "web", "addr": "10.6.0.1:80", "category": "not-exist",
	}); code != http.StatusBadRequest {
		t.Fatalf("字典外的分类应 400，得到 %d: %v", code, out)
	}
	// 改名 → /apps 的分类栏跟随
	if code, out := doJSON(t, h, "PUT", "/api/v1/app-categories/dev", adm,
		map[string]any{"label": "研发与运维", "sort": 30}); code != http.StatusOK {
		t.Fatalf("改名 http %d: %v", code, out)
	}
	code, out := doJSON(t, h, "GET", "/api/v1/apps", adm, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /apps http %d", code)
	}
	raw, _ := out["categories"].([]any)
	if len(raw) == 0 {
		t.Fatal("应用页没有分类栏")
	}
	first := mapOf(t, raw[0])
	if first["key"] != "all" || first["label"] != "全部应用" {
		t.Fatalf("合成项「全部应用」应排在首位: %v", first)
	}
	var found bool
	for _, r := range raw {
		if m := mapOf(t, r); m["key"] == "dev" {
			found = m["label"] == "研发与运维"
		}
	}
	if !found {
		t.Fatalf("分类改名后应用页未跟随: %v", raw)
	}
}
