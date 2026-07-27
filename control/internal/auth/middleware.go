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
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
		})
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}
