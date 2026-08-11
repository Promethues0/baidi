package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey struct{}

// FromContext 取出经中间件注入的 Claims。
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(Claims)
	return c, ok
}

// Middleware 校验 Bearer JWT；isOpen 命中的路径放行（如登录/健康检查）。
// 失败返回 401，未携带角色判定（角色由处置点自行检查 FromContext）。
//
// keys 做入站双验（EdDSA 新令牌 + 迁移期 HS256 存量令牌）：控制面入站是全部请求
// 的唯一校验点，若只认新算法，升级瞬间所有在线会话（8h TTL）与网关自签的
// role=gateway 令牌会同时 401——管理台掉线 + 数据面断联。
func Middleware(keys *Keys, isOpen func(method, path string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions || isOpen(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			tok := bearer(r)
			c, err := keys.Verify(tok)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"message":"未认证或令牌已失效"}}`))
				return
			}
			// ── 用途闸（控制面入站这一侧）──
			//
			// ★白名单而不是黑名单：只有会话令牌（Use 空）能调控制面 API，其余用途一律拒。
			// 此前这里只拦 pwreset，于是 Keys.Verify 按 kid 认下的 use=web / use=knock
			// 票据可以直接当 Bearer 用——一张本该"只开一扇门 60s"的资源级票据，
			// 等价于该账号 60s 的全量 API 会话（admin 的票就是 60s 全权管理台），
			// 而且能拿它再调一次 /portal/web-ticket 自我续签，"短时效"被结构性抵消。
			// 数据面那两条路径各有自己的 use 闸（spa.checkKnock / webproxy.VerifyTicket），
			// 这一侧此前是缺的那一半，且爆炸半径最大。
			//
			// 默认拒绝还有个作用：将来新增任何用途的票据，默认进不了控制面，不会漏。
			switch c.Use {
			case "": // 会话令牌 / MFA 半程票据（半程态的收口在各 handler 的 requireUser）
			case UsePwReset:
				// 首登强制改密的受限令牌：只放行自助改密与查身份，其余端点
				// （含 /knock-token——受限态绝不能拿到能触达数据面的令牌）一律 403。
				if !pwResetAllowed(r.Method, r.URL.Path) {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":{"message":"须先修改初始口令"}}`))
					return
				}
			default:
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"message":"该令牌只用于数据面入场（敲门 / 七层访问票据），不能调用控制面接口"}}`))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
		})
	}
}

// pwResetAllowed 受限改密令牌的端点白名单：自助改密本身 + 查当前身份（前端渲染用）。
func pwResetAllowed(method, path string) bool {
	return (method == http.MethodPost && path == "/api/v1/auth/password") ||
		(method == http.MethodGet && path == "/api/v1/auth/me")
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}
