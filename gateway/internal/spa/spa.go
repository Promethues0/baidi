// Package spa 实现"单包授权"（Single Packet Authorization）：
// 网关默认对外不可达；收到携带有效 JWT 的 UDP 敲门包后，为该源 IP 开一个 TTL 放行窗口。
package spa

import (
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"baidi.dev/gateway/internal/auth"
	"baidi.dev/gateway/internal/knock"
)

// normUser 规范化账号（去首尾空格 + 小写），用作封禁/切断的匹配键——
// 企业身份（AD sAMAccountName、邮箱）通常大小写不敏感，规范化后杜绝
// "换大小写/加空格重登即绕过强制下线"。放行表仍存原始显示名，仅键规范化。
func normUser(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Allowlist 源 IP → 放行到期时间 的并发安全表。
type Allowlist struct {
	mu   sync.Mutex
	m    map[string]entry
	deny map[string]time.Time // 账号 → 封禁截止（强制下线：封禁期内拒绝敲门）
	// OnAllow 在放行某 IP 时回调（如向防火墙 pf 表写入 pass 规则）。可空。
	OnAllow func(ip, user string)
}

type entry struct {
	until time.Time
	since time.Time // 首次敲门放行时刻（供上报会话在线时长；重复敲门保活不重置）
	user  string
	role  string
}

// Session 一条活跃放行会话（供网关向控制面上报真实在线用户）。
type Session struct {
	IP    string
	User  string
	Role  string
	Since time.Time
}

func NewAllowlist() *Allowlist {
	return &Allowlist{m: map[string]entry{}, deny: map[string]time.Time{}}
}

// DenyUser 封禁某账号至 until（强制下线：封禁期内拒绝后续敲门）。返回是否为新封禁/延长封禁。
// 注意：数据面处置（撤窗/断隧道）的幂等由调用方按 until 自管，不依赖本返回值——
// 避免网关本地时钟快于控制面时 until 被判过期、导致处置被整段跳过。
func (a *Allowlist) DenyUser(user string, until time.Time) bool {
	if !time.Now().Before(until) {
		return false
	}
	key := normUser(user)
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev, ok := a.deny[key]; ok && !until.After(prev) {
		return false
	}
	a.deny[key] = until
	return true
}

// UserDenied 报告某账号是否在封禁期内（懒清理过期条目）。
func (a *Allowlist) UserDenied(user string) bool {
	key := normUser(user)
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.deny[key]
	if !ok {
		return false
	}
	if !time.Now().Before(until) {
		delete(a.deny, key)
		return false
	}
	return true
}

// RevokeUser 撤销某账号的全部放行窗口，返回被撤的源 IP（供 -pf 模式回收内核放行规则）。
func (a *Allowlist) RevokeUser(user string) []string {
	key := normUser(user)
	a.mu.Lock()
	defer a.mu.Unlock()
	var ips []string
	for ip, e := range a.m {
		if normUser(e.user) == key {
			ips = append(ips, ip)
			delete(a.m, ip)
		}
	}
	return ips
}

// Allow 放行某源 IP 一段时间（记录身份 user/role）。重复敲门刷新 until 但保留首次 since。
// 封禁期内的账号一律拒绝放行（返回 false）——封禁检查与写入放行表在同一把锁内完成，
// 杜绝"UserDenied 检查通过 → 并发封禁 → 仍写入放行窗口"的重开窗竞态。
func (a *Allowlist) Allow(ip, user, role string, ttl time.Duration) bool {
	a.mu.Lock()
	if until, ok := a.deny[normUser(user)]; ok {
		if time.Now().Before(until) {
			a.mu.Unlock()
			return false
		}
		delete(a.deny, normUser(user)) // 懒清理过期封禁
	}
	since := time.Now()
	if prev, ok := a.m[ip]; ok && time.Now().Before(prev.until) {
		since = prev.since // 保活续窗：保留首次敲门时刻
	}
	a.m[ip] = entry{until: time.Now().Add(ttl), since: since, user: user, role: role}
	cb := a.OnAllow
	a.mu.Unlock()
	if cb != nil {
		cb(ip, user)
	}
	return true
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

// Sessions 返回当前仍在放行窗口内的活跃会话（供网关向控制面上报真实在线用户）。
func (a *Allowlist) Sessions() []Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	out := make([]Session, 0, len(a.m))
	for ip, e := range a.m {
		if now.Before(e.until) {
			out = append(out, Session{IP: ip, User: e.user, Role: e.role, Since: e.since})
		}
	}
	return out
}

// ActiveCount 返回当前仍在放行窗口内的源 IP 数（已授权客户端数，供网关向控制面上报）。
func (a *Allowlist) ActiveCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	n := 0
	for _, e := range a.m {
		if now.Before(e.until) {
			n++
		}
	}
	return n
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
		// Allow 内在同一把锁下复核封禁：即便与并发强制下线相撞，也不会重开放行窗口。
		if !al.Allow(ip, claims.Name, claims.Role, ttl) {
			slog.Warn("SPA 敲门拒绝（用户已被强制下线，封禁期内）", "src", ip, "user", claims.Name)
			continue
		}
		slog.Info("SPA 敲门放行", "src", ip, "user", claims.Name, "role", claims.Role, "ttl", ttl.String())
	}
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
