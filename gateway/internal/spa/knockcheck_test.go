package spa

import (
	"testing"
	"time"

	"baidi.dev/gateway/internal/auth"
)

// 敲门令牌用途闸：只放行 control /knock-token 签发的短时效一次性令牌。
// 这是"长效会话令牌可直接敲门、绕过控制面三道闸"旁路的根治判据。
func TestCheckKnock(t *testing.T) {
	const maxTTL = 5 * time.Minute
	now := time.Now().Unix()

	// control 的 /knock-token 签发形态：use=knock + jti + 90s 寿命
	good := auth.Claims{
		Sub: "li.fang", Role: "user", Name: "li.fang",
		Iat: now, Exp: now + 90, Jti: "j-1", Use: auth.UseKnock,
	}
	if err := checkKnock(good, true, maxTTL); err != nil {
		t.Fatalf("合规敲门令牌应放行: %v", err)
	}

	cases := []struct {
		name      string
		mutate    func(*auth.Claims)
		protected bool
	}{
		// ★核心：口令登录的 8h 会话令牌（无 use、无 jti）
		{"口令登录会话令牌", func(c *auth.Claims) { c.Use, c.Jti, c.Exp = "", "", now+8*3600 }, true},
		// ★核心：passkey 登录的 8h 会话令牌——带 jti！按 jti 区分会漏掉它，故必须用 use 判据
		{"passkey 会话令牌(带 jti)", func(c *auth.Claims) { c.Use, c.Exp = "", now+8*3600 }, true},
		// MFA 半程票据：口令过了但二次因子没过，绝不能开数据面窗口
		{"MFA 半程票据", func(c *auth.Claims) { c.Use, c.Role, c.Exp = "", "mfa", now+180 }, true},
		// 网关自签的机器身份令牌
		{"gateway 机器令牌", func(c *auth.Claims) { c.Use, c.Role = "", "gateway" }, true},
		{"use 取值不对", func(c *auth.Claims) { c.Use = "session" }, true},
		{"缺 jti(无法去重)", func(c *auth.Claims) { c.Jti = "" }, true},
		{"寿命超上界", func(c *auth.Claims) { c.Exp = now + int64(maxTTL/time.Second) + 60 }, true},
		{"缺 iat(寿命不可判)", func(c *auth.Claims) { c.Iat = 0 }, true},
		{"角色不得敲门", func(c *auth.Claims) { c.Role = "gateway" }, true},
		{"旧式裸令牌(无重放防护)", func(c *auth.Claims) {}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mutate(&c)
			if err := checkKnock(c, tc.protected, maxTTL); err == nil {
				t.Fatalf("应被拒绝，却放行了: %+v", c)
			}
		})
	}
}

// 边界：寿命恰好等于上界应放行（避免把合法令牌卡在边界外）。
func TestCheckKnockTTLBoundary(t *testing.T) {
	const maxTTL = 5 * time.Minute
	now := time.Now().Unix()
	c := auth.Claims{
		Sub: "u", Role: "user", Name: "u", Jti: "j", Use: auth.UseKnock,
		Iat: now, Exp: now + int64(maxTTL/time.Second),
	}
	if err := checkKnock(c, true, maxTTL); err != nil {
		t.Fatalf("寿命等于上界应放行: %v", err)
	}
	c.Exp++
	if err := checkKnock(c, true, maxTTL); err == nil {
		t.Fatal("寿命超上界 1 秒应被拒")
	}
}

// admin 也能敲门（管理员自身接入数据面）。
func TestCheckKnockAdminAllowed(t *testing.T) {
	now := time.Now().Unix()
	c := auth.Claims{
		Sub: "admin", Role: "admin", Name: "admin", Jti: "j", Use: auth.UseKnock,
		Iat: now, Exp: now + 90,
	}
	if err := checkKnock(c, true, 5*time.Minute); err != nil {
		t.Fatalf("admin 应可敲门: %v", err)
	}
}
