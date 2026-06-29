package api

import (
	"net"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// clientIP 取请求来源 IP：优先 X-Forwarded-For 首段（经 nginx 反代），否则 RemoteAddr 去端口。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
		SrcIP:    clientIP(r),
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
