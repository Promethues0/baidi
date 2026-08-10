package api

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// defaultTrustedProxies BAIDI_TRUSTED_PROXIES 未配置时的默认信任网段：
// 仅本机回环——deploy 的 nginx 与 control 同机反代，这是唯一默认可信的 XFF 来源。
const defaultTrustedProxies = "127.0.0.1/32,::1/128"

// parseTrustedProxies 解析逗号分隔的 CIDR 清单。非法条目跳过并告警——
// 跳过是 fail-closed 方向：网段解析不出来 → 该来源的 XFF 不被采信 → 审计记直连地址。
func parseTrustedProxies(env string) []netip.Prefix {
	if strings.TrimSpace(env) == "" {
		env = defaultTrustedProxies
	}
	var out []netip.Prefix
	for _, part := range strings.Split(env, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			slog.Warn("BAIDI_TRUSTED_PROXIES 含非法 CIDR，已跳过（该网段的 XFF 不会被采信）", "cidr", part, "err", err.Error())
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}

// trustedProxy 报告某地址是否落在信任代理网段内（IPv4-mapped IPv6 归一后比对）。
func (s *Server) trustedProxy(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.trustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP 取审计用的请求来源 IP。
//
// ★X-Forwarded-For 是请求方随手可写的普通头：无条件采信等于把审计源 IP 的笔
// 交给对端——直连伪造一条 XFF 就能把攻击行为记到任意 IP 头上。信任边界收紧为：
//   - 直连对端（RemoteAddr）不在 BAIDI_TRUSTED_PROXIES 网段内 → 一律记 RemoteAddr，XFF 忽略；
//   - 在信任网段内（部署形态：同机 nginx 反代）→ 从右向左取第一个不在信任网段内的
//     XFF 地址（最右侧是信任代理亲手追加的真实对端；更左的段可能是客户端伪造的前缀）。
//   - XFF 全为信任地址或含解析不出的脏值 → 回退 RemoteAddr（宁记代理地址，不记伪造值）。
func (s *Server) clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !s.trustedProxy(peer) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		cand := strings.TrimSpace(parts[i])
		a, aerr := netip.ParseAddr(cand)
		if aerr != nil {
			// 信任代理不会追加脏值；解析不出即视为伪造前缀，放弃整条 XFF。
			return host
		}
		if !s.trustedProxy(a) {
			return cand
		}
	}
	return host
}

// auditAs 以指定行为人落一条审计日志（best-effort：写失败绝不影响主操作）。
// 用于尚无 JWT 上下文的场景（如登录，行为人即提交的用户名）。
func (s *Server) auditAs(r *http.Request, actor, category, event, verdict string) {
	if actor == "" {
		actor = "—"
	}
	_ = s.writer.RecordAudit(r.Context(), store.AuditEntry{
		Time:     time.Now().Format("2006-01-02 15:04:05"),
		Category: category,
		User:     actor,
		SrcIP:    s.clientIP(r),
		Event:    event,
		Verdict:  verdict,
	})
}

// audit 落一条审计日志，行为人取自 JWT（显示名优先，回退账号）。
func (s *Server) audit(r *http.Request, category, event, verdict string) {
	actor := ""
	if c, ok := auth.FromContext(r.Context()); ok {
		switch {
		case c.Name != "":
			actor = c.Name
		case c.Sub != "":
			actor = c.Sub
		}
	}
	s.auditAs(r, actor, category, event, verdict)
}
