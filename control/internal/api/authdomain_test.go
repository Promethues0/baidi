package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

// ── wave8 行动 12：认证域路由 ──
//
// 被修的坏形态：`authenticateExternal` 遍历全部 enabled 外部源逐个 Authenticate。
// 单目录部署无区别，但只要接第二个源，A 目录员工的**明文口令**就会被真实投递到
// 排在前面的每一台 LDAP 服务器去 simple bind（本地口令输错那次也算）。
// 关键不变式：**一次登录只把口令交给一台服务器**。

func srcRec(id, name, kind string, enabled bool) store.AuthSourceRec {
	return store.AuthSourceRec{ID: id, Name: name, Kind: kind, Enabled: enabled, Config: `{}`}
}

// TestRouteDirectoryNeverAsksMoreThanOne 核心不变式：路由结果恒 ≤1 台。
func TestRouteDirectoryNeverAsksMoreThanOne(t *testing.T) {
	srcs := []store.AuthSourceRec{
		srcRec("local", "本地目录", "local", true),
		srcRec("ad1", "总部 AD", "ad", true),
		srcRec("ldap2", "供应商 LDAP", "ldap", true),
		srcRec("ldap3", "已停用", "ldap", false),
	}
	for _, dir := range []string{"", "ad1", "ldap2", "不存在"} {
		got, err := routeDirectory(srcs, dir)
		if !ensureDirectoryContext(context.Background(), got) {
			t.Fatalf("directory=%q 路由出了 %d 台服务器——一次登录只能问一台，"+
				"多问一台就是把明文口令投递给一台不该看到它的服务器", dir, len(got))
		}
		_ = err
	}
}

// TestRouteDirectoryExplicit 显式指定即只问它。
func TestRouteDirectoryExplicit(t *testing.T) {
	srcs := []store.AuthSourceRec{
		srcRec("local", "本地", "local", true),
		srcRec("ad1", "总部 AD", "ad", true),
		srcRec("ldap2", "供应商 LDAP", "ldap", true),
	}
	got, err := routeDirectory(srcs, "ldap2")
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if len(got) != 1 || got[0].ID != "ldap2" {
		t.Fatalf("应只问 ldap2，得到 %+v", got)
	}
	// 大小写不敏感（id 是配置里抄进来的，别为一个大小写把人挡在门外）。
	if got, _ := routeDirectory(srcs, "LDAP2"); len(got) != 1 || got[0].ID != "ldap2" {
		t.Fatalf("id 匹配应大小写不敏感，得到 %+v", got)
	}
}

// TestRouteDirectoryUnknownIsRejected 指定了但没命中 → 拒绝，**不回退到问全部**。
//
// ★静默回退正是要消灭的外溢；而且用户明明表达了意图，替他改成另一个意思比报错糟得多。
func TestRouteDirectoryUnknownIsRejected(t *testing.T) {
	srcs := []store.AuthSourceRec{
		srcRec("ad1", "总部 AD", "ad", true),
		srcRec("ldap2", "供应商", "ldap", true),
	}
	got, err := routeDirectory(srcs, "nope")
	if err == nil {
		t.Fatal("未知认证域必须拒绝，不能静默回退到问全部")
	}
	if len(got) != 0 {
		t.Fatalf("拒绝时不该带出任何源，得到 %+v", got)
	}
	// 停用的源同样不接受（它不在候选里）。
	if _, err := routeDirectory([]store.AuthSourceRec{srcRec("x", "停用源", "ldap", false)}, "x"); err == nil {
		t.Fatal("已停用的源不该能被指定")
	}

	// ★按 **kind** 路由必须不成立。两条 ldap 源的 kind 一样，按 kind 匹配等于
	// 在两台服务器之间随机挑一台——外溢没消掉，只是从"问全部"变成"问错一台"，
	// 而且更隐蔽（日志上看只问了一台，看起来是对的）。
	twoSame := []store.AuthSourceRec{
		srcRec("ldapA", "A 部门 LDAP", "ldap", true),
		srcRec("ldapB", "B 供应商 LDAP", "ldap", true),
	}
	if got, err := routeDirectory(twoSame, "ldap"); err == nil {
		t.Fatalf("directory 必须按 id 匹配而不是 kind，否则两条同类源之间是随机挑的：%+v", got)
	}
}

// TestRouteDirectorySingleSourceNeedsNoChoice 单源部署不必指定——老客户端不受影响。
func TestRouteDirectorySingleSourceNeedsNoChoice(t *testing.T) {
	srcs := []store.AuthSourceRec{
		srcRec("local", "本地", "local", true),
		srcRec("ad1", "总部 AD", "ad", true),
	}
	got, err := routeDirectory(srcs, "")
	if err != nil {
		t.Fatalf("单源不该要求选择：%v", err)
	}
	if len(got) != 1 || got[0].ID != "ad1" {
		t.Fatalf("应问唯一那个源，得到 %+v", got)
	}
	// 一个外部源都没有：不报错、也不问谁。
	if got, err := routeDirectory([]store.AuthSourceRec{srcRec("local", "本地", "local", true)}, ""); err != nil || len(got) != 0 {
		t.Fatalf("无外部源应静默返回空：got=%+v err=%v", got, err)
	}
}

// TestRouteDirectoryAmbiguousIsRejected 多源且未指定 → 拒绝并带回候选。
func TestRouteDirectoryAmbiguousIsRejected(t *testing.T) {
	srcs := []store.AuthSourceRec{
		srcRec("local", "本地", "local", true),
		srcRec("ad1", "总部 AD", "ad", true),
		srcRec("ldap2", "供应商 LDAP", "ldap", true),
	}
	got, err := routeDirectory(srcs, "")
	if err == nil {
		t.Fatal("多个认证域又没指定时必须拒绝——挨个去问正是凭据外溢本身")
	}
	if len(got) != 0 {
		t.Fatalf("拒绝时不该带出任何源，得到 %+v", got)
	}
	amb := asAmbiguousDirectory(err)
	if amb == nil {
		t.Fatalf("应是歧义错误，得到 %T", err)
	}
	if len(amb.Domains()) != 2 {
		t.Fatalf("候选应是 2 个外部源（本地目录不算），得到 %+v", amb.Domains())
	}
	for _, d := range amb.Domains() {
		if d.Kind == string(authsrc.KindLocal) {
			t.Error("本地目录不该出现在认证域候选里——它不参与外部询问")
		}
	}
	if !strings.Contains(amb.Error(), "总部 AD") {
		t.Fatalf("文案要点名候选，得到 %q", amb.Error())
	}
}

// TestAuthDomainsEndpoint 免认证端点：单源回空、多源回列表、不含连接细节。
func TestAuthDomainsEndpoint(t *testing.T) {
	h := newTestServer(t)
	// 无外部源
	code, out := doJSON(t, h, "GET", "/api/v1/auth/domains", "", nil)
	if code != http.StatusOK {
		t.Fatalf("免认证端点应可匿名访问，得到 %d", code)
	}
	if arr, _ := out["domains"].([]any); len(arr) != 0 {
		t.Fatalf("无外部源应回空，得到 %v", out["domains"])
	}

	mk := func(id, name string) {
		t.Helper()
		if c, o := doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
			"id": id, "name": name, "kind": "ad", "enabled": true,
			"config": map[string]any{"host": "dc." + id + ".example", "baseDn": "DC=x"},
		}); c != http.StatusOK {
			t.Fatalf("建源 %s 失败 %d: %v", id, c, o)
		}
	}
	mk("ad1", "总部 AD")
	// ★单源仍回空：没有选择的必要，也就没必要把那一个目录的名字告诉匿名访问者。
	_, out = doJSON(t, h, "GET", "/api/v1/auth/domains", "", nil)
	if arr, _ := out["domains"].([]any); len(arr) != 0 {
		t.Fatalf("单源应回空（无需选择），得到 %v", out["domains"])
	}

	mk("ldap2", "供应商 LDAP")
	_, out = doJSON(t, h, "GET", "/api/v1/auth/domains", "", nil)
	arr, _ := out["domains"].([]any)
	if len(arr) != 2 {
		t.Fatalf("两个外部源应回 2 条，得到 %v", out["domains"])
	}
	// ★不得泄露连接细节。
	for _, it := range arr {
		m, _ := it.(map[string]any)
		for _, leak := range []string{"host", "baseDn", "config", "bindDn", "issuer"} {
			if _, bad := m[leak]; bad {
				t.Errorf("免认证端点泄露了连接细节 %q：%v", leak, m)
			}
		}
		if str(m["id"]) == "" || str(m["name"]) == "" {
			t.Errorf("候选缺少 id/name：%v", m)
		}
	}
}

// TestLoginAmbiguousDirectoryAsksForChoice 登录端点：多源未指定时回可操作的提示。
func TestLoginAmbiguousDirectoryAsksForChoice(t *testing.T) {
	h := newTestServer(t)
	for _, s := range []struct{ id, name string }{{"ad1", "总部 AD"}, {"ldap2", "供应商 LDAP"}} {
		doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
			"id": s.id, "name": s.name, "kind": "ad", "enabled": true,
			"config": map[string]any{"host": "dc.example", "baseDn": "DC=x"},
		})
	}
	// 用一个本地目录里不存在的账号触发外部询问。
	code, out := doJSON(t, h, "POST", "/api/v1/portal/login", "", map[string]string{
		"username": "someone.external", "password": "whatever",
	})
	if code != http.StatusOK {
		t.Fatalf("应回 200 + ok:false，得到 %d", code)
	}
	if out["ok"] != false {
		t.Fatalf("不该放行：%v", out)
	}
	if out["needDirectory"] != true {
		t.Fatalf("应告诉前端需要选择认证域（否则用户只会以为口令错了）：%v", out)
	}
	if arr, _ := out["domains"].([]any); len(arr) != 2 {
		t.Fatalf("应带回候选供前端渲染下拉，得到 %v", out["domains"])
	}
	if r := str(out["reason"]); !strings.Contains(r, "认证域") {
		t.Fatalf("文案要说清是认证域没选，而不是口令错，得到 %q", r)
	}
}
