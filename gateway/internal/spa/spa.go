// Package spa 实现"单包授权"（Single Packet Authorization）：
// 网关默认对外不可达；收到携带有效 JWT 的 UDP 敲门包后，为该源 IP 开一个 TTL 放行窗口。
package spa

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"baidi.dev/gateway/internal/auth"
	"baidi.dev/gateway/internal/knock"
)

// Allowlist 源 IP → 放行到期时间 的并发安全表。
type Allowlist struct {
	mu sync.Mutex
	m  map[string]entry
	// OnAllow 在放行某 IP 时回调（如向防火墙 pf 表写入 pass 规则）。可空。
	OnAllow func(ip, user string)
}

type entry struct {
	until time.Time
	user  string
	role  string
}

func NewAllowlist() *Allowlist { return &Allowlist{m: map[string]entry{}} }

// Allow 放行某源 IP 一段时间（记录身份 user/role）。
func (a *Allowlist) Allow(ip, user, role string, ttl time.Duration) {
	a.mu.Lock()
	a.m[ip] = entry{until: time.Now().Add(ttl), user: user, role: role}
	cb := a.OnAllow
	a.mu.Unlock()
	if cb != nil {
		cb(ip, user)
	}
}

// Reap 删除并返回已过期的源 IP（供防火墙模式回收 pf 放行规则）。
func (a *Allowlist) Reap() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	var expired []string
	for ip, e := range a.m {
		if now.After(e.until) {
			expired = append(expired, ip)
			delete(a.m, ip)
		}
	}
	return expired
}

// Allowed 返回该源 IP 是否在有效放行窗口内（及对应身份 user/role）。
func (a *Allowlist) Allowed(ip string) (user, role string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, found := a.m[ip]
	if !found || time.Now().After(e.until) {
		return "", "", false
	}
	return e.user, e.role, true
}

// Serve 启动 SPA UDP 监听；每个有效敲门包放行其源 IP。
func Serve(addr string, secret []byte, ttl time.Duration, al *Allowlist) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	slog.Info("SPA 敲门监听", "addr", addr, "ttl", ttl.String())
	cache := knock.NewCache()
	const skew = 30 * time.Second // 允许时钟偏移 / 重放窗口
	buf := make([]byte, 8192)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		ip := hostOf(src.String())
		token, protected, err := knock.Open(buf[:n], skew, cache)
		if err != nil {
			slog.Warn("SPA 敲门拒绝（重放/信封无效）", "src", ip, "err", err.Error())
			continue
		}
		claims, err := auth.Verify(secret, token)
		if err != nil {
			slog.Warn("SPA 敲门拒绝（令牌无效）", "src", ip, "err", err.Error())
			continue
		}
		// 一次性敲门令牌（带 jti）：同一 jti 只放行一次——杜绝令牌被解出后用新信封主动重放。
		if claims.Jti != "" {
			dedupTTL := time.Until(time.Unix(claims.Exp, 0)) + skew
			if dedupTTL > 10*time.Minute {
				dedupTTL = 10 * time.Minute
			}
			if cache.Seen("j:"+claims.Jti, dedupTTL) {
				slog.Warn("SPA 敲门拒绝（一次性令牌已用，主动重放被拒）", "src", ip, "jti", claims.Jti)
				continue
			}
		} else {
			slog.Warn("SPA 敲门为长效会话令牌（无 jti，仅被动重放防护），建议改用 /knock-token 短时效一次性令牌", "src", ip)
		}
		if !protected {
			slog.Warn("SPA 敲门为旧式裸令牌、无被动重放防护，建议客户端升级敲门信封", "src", ip)
		}
		al.Allow(ip, claims.Name, claims.Role, ttl)
		slog.Info("SPA 敲门放行", "src", ip, "user", claims.Name, "role", claims.Role, "ttl", ttl.String())
	}
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
