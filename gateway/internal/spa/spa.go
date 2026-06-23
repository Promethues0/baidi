// Package spa 实现"单包授权"（Single Packet Authorization）：
// 网关默认对外不可达；收到携带有效 JWT 的 UDP 敲门包后，为该源 IP 开一个 TTL 放行窗口。
package spa

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"baidi.dev/gateway/internal/auth"
)

// Allowlist 源 IP → 放行到期时间 的并发安全表。
type Allowlist struct {
	mu sync.Mutex
	m  map[string]entry
}

type entry struct {
	until time.Time
	user  string
}

func NewAllowlist() *Allowlist { return &Allowlist{m: map[string]entry{}} }

// Allow 放行某源 IP 一段时间。
func (a *Allowlist) Allow(ip, user string, ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.m[ip] = entry{until: time.Now().Add(ttl), user: user}
}

// Allowed 返回该源 IP 是否在有效放行窗口内（及对应身份）。
func (a *Allowlist) Allowed(ip string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.m[ip]
	if !ok || time.Now().After(e.until) {
		return "", false
	}
	return e.user, true
}

// Serve 启动 SPA UDP 监听；每个有效敲门包放行其源 IP。
func Serve(addr string, secret []byte, ttl time.Duration, al *Allowlist) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	slog.Info("SPA 敲门监听", "addr", addr, "ttl", ttl.String())
	buf := make([]byte, 8192)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		ip := hostOf(src.String())
		claims, err := auth.Verify(secret, string(buf[:n]))
		if err != nil {
			slog.Warn("SPA 敲门拒绝（令牌无效）", "src", ip, "err", err.Error())
			continue
		}
		al.Allow(ip, claims.Name, ttl)
		slog.Info("SPA 敲门放行", "src", ip, "user", claims.Name, "role", claims.Role, "ttl", ttl.String())
	}
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
