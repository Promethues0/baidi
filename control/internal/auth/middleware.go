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
			// 首登强制改密的受限令牌（Use=pwreset）：只放行自助改密与查身份，
			// 其余端点（含 /knock-token——受限态绝不能拿到能触达数据面的令牌）一律 403。
			// 闸设在中间件而非各 handler：新增端点默认在禁行列表内，不会漏。
			if c.Use == UsePwReset && !pwResetAllowed(r.Method, r.URL.Path) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"message":"须先修改初始口令"}}`))
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
