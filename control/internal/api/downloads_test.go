package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// newDownloadsServer 建测试 server 并返回可写的下载目录（manifest/安装包放这里）。
func newDownloadsServer(t *testing.T) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", dir, nil, nil, true)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), dir
}

func getManifest(t *testing.T, h http.Handler) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/portal/downloads", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("解析响应: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

// manifest 缺失 → 200 + 六平台全占位（available 全 false），不 500
func TestDownloadsManifestMissing(t *testing.T) {
	h, _ := newDownloadsServer(t)
	code, body := getManifest(t, h)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	clients := body["clients"].([]any)
	if len(clients) != 6 {
		t.Fatalf("占位清单应含 6 平台, got %d", len(clients))
	}
	for _, c := range clients {
		if c.(map[string]any)["available"].(bool) {
			t.Fatalf("manifest 缺失时不应有 available=true 条目: %v", c)
		}
	}
}

// manifest 损坏（非法 JSON）→ 同样回占位，不 500
func TestDownloadsManifestCorrupt(t *testing.T) {
	h, dir := newDownloadsServer(t)
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{not json"), 0o644)
	code, body := getManifest(t, h)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if n := len(body["clients"].([]any)); n != 6 {
		t.Fatalf("损坏 manifest 应回 6 平台占位, got %d", n)
	}
}

// manifest 正常 → 原样返回；且免认证（无 Authorization 头）
func TestDownloadsManifestOK(t *testing.T) {
	h, dir := newDownloadsServer(t)
	m := `{"clients":[{"platform":"macos","label":"macOS 桌面客户端","version":"0.1.0","file":"baidi-desktop_0.1.0_universal.dmg","size":123,"sha256":"ab","available":true}]}`
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644)
	code, body := getManifest(t, h)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	clients := body["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("应原样返回 1 条, got %d", len(clients))
	}
	c := clients[0].(map[string]any)
	if c["file"] != "baidi-desktop_0.1.0_universal.dmg" || c["available"] != true {
		t.Fatalf("条目内容不符: %v", c)
	}
}

func getFile(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// 写一份 manifest + 真实文件，返回 handler
func downloadsFixture(t *testing.T) (http.Handler, string) {
	t.Helper()
	h, dir := newDownloadsServer(t)
	os.WriteFile(filepath.Join(dir, "baidi-mobile_0.1.0_debug.apk"), []byte("APKBYTES"), 0o644)
	m := `{"clients":[
	  {"platform":"android","label":"Android 客户端","version":"0.1.0","file":"baidi-mobile_0.1.0_debug.apk","size":8,"sha256":"x","available":true},
	  {"platform":"macos","label":"macOS 桌面客户端","version":"0.1.0","file":"baidi-desktop_0.1.0_universal.dmg","size":9,"sha256":"y","available":true},
	  {"platform":"windows","label":"Windows 桌面客户端","file":"ghost.exe","available":false}
	]}`
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644)
	return h, dir
}

// 白名单内且在盘 → 200 + attachment + 字节一致
func TestDownloadFileOK(t *testing.T) {
	h, _ := downloadsFixture(t)
	rec := getFile(t, h, "/downloads/baidi-mobile_0.1.0_debug.apk")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "APKBYTES" {
		t.Fatalf("body = %q", got)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="baidi-mobile_0.1.0_debug.apk"` {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if cl := rec.Header().Get("Content-Length"); cl != "8" {
		t.Fatalf("Content-Length = %q, want 8", cl)
	}
}

// 不在 manifest → 404（manifest.json 自身也不可下）
func TestDownloadFileNotListed(t *testing.T) {
	h, _ := downloadsFixture(t)
	for _, p := range []string{"/downloads/evil.bin", "/downloads/manifest.json"} {
		if rec := getFile(t, h, p); rec.Code != http.StatusNotFound {
			t.Fatalf("%s code = %d, want 404", p, rec.Code)
		}
	}
}

// available:false 的条目即使列了 file 也不可下
func TestDownloadFileUnavailable(t *testing.T) {
	h, _ := downloadsFixture(t)
	if rec := getFile(t, h, "/downloads/ghost.exe"); rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}

// 穿越攻击：..、编码 ..、绝对路径式 → 全部 404/301/400，绝不读出 manifest 外内容
func TestDownloadFileTraversal(t *testing.T) {
	h, _ := downloadsFixture(t)
	for _, p := range []string{
		"/downloads/../manifest.json",
		"/downloads/..%2Fmanifest.json",
		"/downloads/%2e%2e%2fmanifest.json",
		"/downloads/..%5Cmanifest.json",
	} {
		rec := getFile(t, h, p)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusBadRequest {
			t.Fatalf("%s code = %d, want 404/301/400", p, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, "baidi-desktop_0.1.0") || strings.Contains(body, "baidi-mobile_0.1.0") || strings.Contains(body, "APKBYTES") {
			t.Fatalf("%s 响应泄露 manifest/文件内容: %q", p, body)
		}
	}
}

// 白名单内但盘上缺文件 → 404
func TestDownloadFileMissingOnDisk(t *testing.T) {
	h, _ := downloadsFixture(t)
	if rec := getFile(t, h, "/downloads/baidi-desktop_0.1.0_universal.dmg"); rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}

// 文件名含引号（只可能来自被污染的 manifest）时，Content-Disposition 中剔除引号防头畸形
func TestDownloadFileQuoteStripped(t *testing.T) {
	h, dir := newDownloadsServer(t)
	weird := `evil"name.apk`
	os.WriteFile(filepath.Join(dir, weird), []byte("X"), 0o644)
	m := `{"clients":[{"platform":"android","label":"a","version":"0.1.0","file":"evil\"name.apk","size":1,"sha256":"x","available":true}]}`
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644)
	rec := getFile(t, h, "/downloads/evil%22name.apk")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="evilname.apk"` {
		t.Fatalf("Content-Disposition = %q, 引号未剔除", cd)
	}
}

// ── 构建溯源三态（安装包与源码的漂移必须可见）──
//
// 回归背景：manifest 此前只有 version+size+sha256，看起来很权威却不说这包出自哪份源码。
// 真实发生过的形态是安装包停在三周前、客户端源码此后改了 11 次，而页面上
// available=true、有版本号有校验和，一切正常——用户装下去是个旧客户端。
// 版本号救不了：源码改了但 package.json 没动，两边看起来还"一致"。
func TestDownloadProvenanceThreeStates(t *testing.T) {
	base := downloadsManifest{Clients: []ClientDownload{
		{Platform: "macos", Available: true, File: "a.dmg", SourceCommit: "abc1234"},
		{Platform: "android", Available: true, File: "b.apk", SourceCommit: ""},
		{Platform: "linux", Available: false, Note: "构建中"},
	}}

	// ① 溯源一致：什么都不提示（正常情况不该打扰人）
	got := annotateProvenance(clone(base), "abc1234")
	if got.Clients[0].Stale || got.Clients[0].ProvenanceUnknown || got.Clients[0].StaleReason != "" {
		t.Errorf("溯源一致时不该有任何提示：%+v", got.Clients[0])
	}

	// ② 溯源对不上：必须标过期并说清差在哪
	got = annotateProvenance(clone(base), "def5678")
	if !got.Clients[0].Stale {
		t.Fatal("源码已前进，包必须被标为过期")
	}
	for _, want := range []string{"abc1234", "def5678"} {
		if !strings.Contains(got.Clients[0].StaleReason, want) {
			t.Errorf("过期理由要点明新旧两个版本，缺 %q：%s", want, got.Clients[0].StaleReason)
		}
	}

	// ③ 无溯源（老 manifest / 别处构建的包）：报**不可判定**，绝不报 Stale=false。
	//    报 false 等于替一个我们无从验证的包背书，与 posture「采不到就说不可判定」同纪律。
	if !got.Clients[1].ProvenanceUnknown || got.Clients[1].Stale {
		t.Errorf("无溯源应报不可判定而非「不过期」：%+v", got.Clients[1])
	}
	if got.Clients[1].StaleReason == "" {
		t.Error("不可判定也要说清为什么")
	}

	// 服务端读不到当前源码版本时同样是不可判定，而不是「一切正常」
	got = annotateProvenance(clone(base), "")
	if !got.Clients[0].ProvenanceUnknown || got.Clients[0].Stale {
		t.Errorf("读不到当前源码版本时应不可判定：%+v", got.Clients[0])
	}

	// 占位条目没有包，谈不上新旧，不该被打扰
	if got.Clients[2].Stale || got.Clients[2].ProvenanceUnknown {
		t.Errorf("占位条目不该有溯源结论：%+v", got.Clients[2])
	}
}

func clone(m downloadsManifest) downloadsManifest {
	out := downloadsManifest{Clients: make([]ClientDownload, len(m.Clients))}
	copy(out.Clients, m.Clients)
	return out
}
