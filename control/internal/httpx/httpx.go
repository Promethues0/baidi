// Package httpx 提供白帝控制中心的 HTTP 中间件与 JSON 响应工具（零外部依赖）。
package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Middleware 是标准的 http.Handler 装饰器。
type Middleware func(http.Handler) http.Handler

// Chain 将多个中间件按声明顺序自外向内包裹 h。
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// RequestID 为每个请求生成 ID，写入 X-Request-Id 并放进 context。
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r)
	})
}

// CORS 跨源放行。conf 取自 BAIDI_CORS_ORIGIN，两种形态：
//
//   - "*"                     任意来源（默认，见 config.Load 与启动告警）
//   - "a://b,c://d"           逗号分隔白名单：只回显命中的那一个，并发 Vary: Origin
//
// ★白名单形态是 wave9 补的能力，默认值**没有**跟着收紧，理由写在
// config.AllowOrigin 与 main 的启动告警里：客户端 webview 的 origin 逐平台不同
// （Tauri mac/Linux 是 tauri://localhost、Windows 是 http://tauri.localhost、
// 安卓 WebViewAssetLoader 是 https://appassets.local、iOS 是 file 派生的 null），
// 漏掉一个就是那个平台升级即全员连不上，而这条的实际暴露面要小得多
// （API 认证走 Bearer 不走 Cookie，跨站页面拿不到已认证响应）。
// 收紧的路径是显式配置 + 逐平台实测，不是把默认值一改了事。
func CORS(conf string) Middleware {
	conf = strings.TrimSpace(conf)
	any := conf == "*" || conf == ""
	allow := map[string]bool{}
	for _, o := range strings.Split(conf, ",") {
		if o = strings.TrimSpace(o); o != "" && o != "*" {
			allow[o] = true
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			switch {
			case any:
				h.Set("Access-Control-Allow-Origin", "*")
			case allow[r.Header.Get("Origin")]:
				h.Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				// ★Vary 不可省：回显值随请求变，中间缓存少了它会把 A 站命中的
				// 那份 CORS 响应发给 B 站，白名单当场失效。
				h.Add("Vary", "Origin")
			default:
				// 不命中：不发 CORS 头（浏览器据此拒绝），但**不改变响应码**——
				// 用 403 挡的话，同源请求与非浏览器客户端（curl / 数据面）会一起被误伤。
				h.Add("Vary", "Origin")
			}
			h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Request-Id")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BodyLimit 为非 GET/HEAD 请求体设上限，挡住超大 JSON 触发的内存耗尽。
func BodyLimit(max int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// statusRecorder 捕获响应状态码用于访问日志。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Logger 结构化访问日志。
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("http",
			"method", r.Method, "path", r.URL.Path,
			"status", rec.status, "dur", time.Since(start).String(),
			"reqid", w.Header().Get("X-Request-Id"))
	})
}

// Recover 兜底 panic，返回 500 而非中断进程。
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				slog.Error("panic", "err", v, "path", r.URL.Path)
				Error(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// JSON 写入 JSON 响应。
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error 写入统一错误信封 {"error":{"message":...}}。
func Error(w http.ResponseWriter, status int, msg string) {
	JSON(w, status, map[string]any{"error": map[string]any{"message": msg}})
}
