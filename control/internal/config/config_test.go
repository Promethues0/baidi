package config

import "testing"

// 生产环境用默认（可猜）JWT 密钥必须被判为不安全——否则任何人都能伪造 admin 令牌。
func TestInsecureProdSecret(t *testing.T) {
	cases := []struct {
		env, secret string
		want        bool
	}{
		{"prod", DefaultJWTSecret, true},   // 生产 + 默认密钥 → 不安全
		{"prod", "a-real-random-secret", false}, // 生产 + 真随机 → 安全
		{"dev", DefaultJWTSecret, false},   // 开发 + 默认 → 放行（仅告警）
		{"dev", "whatever", false},
		{"prod", "", true},                 // 生产 + 空密钥 → 不安全
	}
	for _, c := range cases {
		if got := InsecureProdSecret(c.env, c.secret); got != c.want {
			t.Errorf("InsecureProdSecret(%q,%q)=%v, want %v", c.env, c.secret, got, c.want)
		}
	}
}
