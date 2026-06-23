// Command baidi-knock-agent 是开发期本地敲门代理：浏览器（桌面客户端 dev）经 HTTP 调用，
// 由本进程发起真实 SPA UDP 敲门并验证隧道可达性。
// 生产环境此角色由 Tauri sidecar（直接调 baidi-knock + 本地代理）承担；本程序仅供 dev 预览验证。
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"baidi.dev/gateway/internal/knock"
)

func main() {
	addr := flag.String("addr", ":8091", "HTTP 监听")
	spa := flag.String("spa", "127.0.0.1:18201", "网关 SPA 敲门地址")
	proxy := flag.String("proxy", "127.0.0.1:18443", "网关 TLS 代理地址")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	http.HandleFunc("POST /knock", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Token == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "detail": "缺少身份令牌"})
			return
		}
		// ① 真实 SPA 敲门（UDP，携带 JWT，封防重放信封）
		if c, err := net.Dial("udp", *spa); err == nil {
			if sealed, e := knock.Seal(b.Token); e == nil {
				_, _ = c.Write(sealed)
			}
			_ = c.Close()
		} else {
			writeJSON(w, 200, map[string]any{"ok": false, "detail": "网关 SPA 端口不可达"})
			return
		}
		time.Sleep(350 * time.Millisecond)
		// ② 验证隧道是否真开放（TLS 连到代理并取后端响应）
		ok, detail := probe(*proxy)
		slog.Info("dev 敲门", "ok", ok, "detail", detail)
		writeJSON(w, 200, map[string]any{"ok": ok, "detail": detail})
	})

	slog.Info("baidi-knock-agent（dev）启动", "addr", *addr, "spa", *spa, "proxy", *proxy)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func probe(proxy string) (bool, string) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", proxy, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return false, "隧道未开放（敲门未生效或网关未启动）"
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: baidi\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		return true, "SPA 敲门成功 · SSL 隧道已建立 · 后端可达"
	}
	return false, "隧道无响应"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
