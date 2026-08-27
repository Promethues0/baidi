package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsProbe(t *testing.T, conf, origin string) http.Header {
	t.Helper()
	h := CORS(conf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest("GET", "/api/v1/x", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("CORS 中间件改变了响应码：%d——同源请求与非浏览器客户端会被一起误伤", w.Code)
	}
	return w.Header()
}

// 白名单形态：命中回显该来源并发 Vary，不命中不发 CORS 头（但不动响应码）。
func TestCORS白名单(t *testing.T) {
	const conf = "https://zt.example.com,tauri://localhost"

	h := corsProbe(t, conf, "tauri://localhost")
	if got := h.Get("Access-Control-Allow-Origin"); got != "tauri://localhost" {
		t.Fatalf("白名单内的来源应被回显，实得 %q", got)
	}
	// ★Vary 不可省：回显值随请求变，中间缓存少了它会把 A 站命中的那份响应发给 B 站。
	if h.Get("Vary") != "Origin" {
		t.Fatalf("回显来源时必须发 Vary: Origin，实得 %q", h.Get("Vary"))
	}

	h = corsProbe(t, conf, "https://evil.example.net")
	if got := h.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("白名单外的来源不得放行，实得 %q", got)
	}
	if h.Get("Vary") != "Origin" {
		t.Fatal("不命中同样要发 Vary: Origin，否则缓存会把「放行」那份复用给它")
	}
}

// "*"（默认）与空配置维持原行为：任意来源放行。
// 这条钉的是**向后兼容**——收紧默认值需要逐平台实测 webview origin，
// 漏掉一个就是那个平台升级即全员连不上控制面。
func TestCORS默认放行任意来源(t *testing.T) {
	for _, conf := range []string{"*", "", "  "} {
		if got := corsProbe(t, conf, "https://anything.example.net").Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("conf=%q 应放行任意来源，实得 %q", conf, got)
		}
	}
}

// 预检必须在两种形态下都回 204，且带上 Allow-Methods/Headers。
func TestCORS预检(t *testing.T) {
	for _, conf := range []string{"*", "tauri://localhost"} {
		h := CORS(conf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("conf=%q 预检不应落到业务 handler", conf)
		}))
		r := httptest.NewRequest("OPTIONS", "/api/v1/x", nil)
		r.Header.Set("Origin", "tauri://localhost")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("conf=%q 预检应回 204，实得 %d", conf, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Headers") == "" {
			t.Fatalf("conf=%q 预检缺 Allow-Headers", conf)
		}
	}
}
