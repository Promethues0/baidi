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
func Middleware(secret []byte, isOpen func(method, path string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions || isOpen(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			tok := bearer(r)
			c, err := Verify(secret, tok)
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
