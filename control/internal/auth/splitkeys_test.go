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
