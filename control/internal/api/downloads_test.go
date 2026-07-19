package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	s := New(st, st, testSecret, "test", dir)
	return auth.Middleware(testSecret, s.IsOpen)(s.Routes()), dir
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
