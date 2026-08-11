package auth

import (
	"strings"
	"testing"
	"time"
)

// 阶段 3：按用途分密钥——Sign 依 Claims.Use 自动路由到对应密钥。
func TestSignRoutesByUse(t *testing.T) {
	k := NewTestKeys(nil, false)

	sess := k.Sign(Claims{Sub: "u", Role: "user", Name: "u"}, time.Hour)
	knock := k.Sign(Claims{Sub: "u", Role: "user", Name: "u", Use: UseKnock, Jti: "j"}, 90*time.Second)
	ticket := k.Sign(Claims{Sub: "u", Role: "mfa", Name: "u"}, 3*time.Minute)

	kidOfTok := func(tok string) string {
		h, err := parseHeader(strings.Split(tok, ".")[0], "EdDSA")
		if err != nil {
			t.Fatalf("解析 header: %v", err)
		}
		return h.Kid
	}
	if got := kidOfTok(sess); got != k.SessKid() {
		t.Fatalf("会话令牌应用 sess 密钥: %s", got)
	}
	if got := kidOfTok(ticket); got != k.SessKid() {
		t.Fatalf("MFA 票据应用 sess 密钥: %s", got)
	}
	if got := kidOfTok(knock); got != k.KnockKid() {
		t.Fatalf("敲门令牌应用 knock 密钥: %s", got)
	}
	// control 自己两把都认
	for name, tok := range map[string]string{"会话": sess, "敲门": knock, "票据": ticket} {
		if _, err := k.Verify(tok); err != nil {
			t.Fatalf("control 应能验 %s令牌: %v", name, err)
		}
	}
}

// ★阶段 3 的核心性质：只持 knock 公钥的一方，验不过会话令牌。
// 这里用另一个只含 knock 密钥的 Keys 模拟「网关的 kid 白名单」——
// 会话令牌的 kid 查不到 → 从密码学上被拒，而不是靠 use 语义闸。
func TestSessionTokenUnverifiableWithKnockKeyOnly(t *testing.T) {
	k := NewTestKeys(nil, false)
	sess := k.Sign(Claims{Sub: "u", Role: "admin", Name: "u"}, 8*time.Hour)
	knock := k.Sign(Claims{Sub: "u", Role: "user", Name: "u", Use: UseKnock, Jti: "j"}, 90*time.Second)

	// 模拟只安装了 knock 公钥的验证方：把 sess 槽也填成 knock 密钥，
	// 于是白名单里只有 knock 那一个 kid。
	knockOnly := &Keys{sess: k.knock, knock: k.knock}

	if _, err := knockOnly.Verify(knock); err != nil {
		t.Fatalf("敲门令牌应可验: %v", err)
	}
	if _, err := knockOnly.Verify(sess); err == nil {
		t.Fatal("★只持 knock 公钥时，会话令牌必须验不过（kid 查不到）")
	} else if !strings.Contains(err.Error(), "unknown kid") {
		t.Fatalf("应因 kid 未知而拒，得: %v", err)
	}
}

// 两把密钥不可互签：knock 密钥签的东西不能冒充 sess 令牌，反之亦然。
func TestKeysAreIndependent(t *testing.T) {
	k := NewTestKeys(nil, false)
	if k.SessKid() == k.KnockKid() {
		t.Fatal("两把密钥必须不同")
	}
	// 拿会话令牌的 payload 套上 knock 的 kid header，签名必然对不上
	sess := k.Sign(Claims{Sub: "u", Role: "admin", Name: "u"}, time.Hour)
	parts := strings.Split(sess, ".")
	fakeHdr := b64.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"` + k.KnockKid() + `"}`))
	if _, err := k.Verify(fakeHdr + "." + parts[1] + "." + parts[2]); err == nil {
		t.Fatal("换 kid 后签名必须验不过")
	}
}

// 七层 Web 代理票据走第三把密钥：Sign 按 Use 路由到 web，且**只**持 web 公钥的一方
// 验不过敲门令牌、只持 knock 公钥的一方验不过 web 票据。
//
// ★这条性质是「两条数据面入场路径互不越界」的密码学底座。少了它，两条路径的隔离
// 就只剩 Claims.Use 一个字符串判断——那正是阶段 3 花力气从"唯一防线"降级掉的东西。
func TestWebTicketUsesItsOwnKey(t *testing.T) {
	k := NewTestKeys(nil, false)
	knock := k.Sign(Claims{Sub: "u", Role: "user", Name: "u", Use: UseKnock, Jti: "j"}, 90*time.Second)
	web := k.Sign(Claims{Sub: "u", Role: "user", Name: "u", Use: UseWeb, Jti: "j", Res: "oa"}, time.Minute)

	kidOfTok := func(tok string) string {
		h, err := parseHeader(strings.Split(tok, ".")[0], "EdDSA")
		if err != nil {
			t.Fatalf("解析 header: %v", err)
		}
		return h.Kid
	}
	if got := kidOfTok(web); got != k.WebKid() {
		t.Fatalf("Web 票据应用 web 密钥: %s", got)
	}
	if k.WebKid() == k.KnockKid() || k.WebKid() == k.SessKid() {
		t.Fatal("三把密钥必须互不相同")
	}

	// 模拟只装了 web 公钥的 L7 监听 / 只装了 knock 公钥的 SPA 监听。
	webOnly := &Keys{sess: k.web, knock: k.web, web: k.web}
	knockOnly := &Keys{sess: k.knock, knock: k.knock, web: k.knock}
	if _, err := webOnly.Verify(web); err != nil {
		t.Fatalf("L7 侧应能验 web 票据: %v", err)
	}
	if _, err := webOnly.Verify(knock); err == nil {
		t.Fatal("★只持 web 公钥时，敲门令牌必须验不过")
	}
	if _, err := knockOnly.Verify(web); err == nil {
		t.Fatal("★只持 knock 公钥时，Web 票据必须验不过")
	}
}
