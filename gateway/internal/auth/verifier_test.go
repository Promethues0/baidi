package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 造一把 Ed25519 密钥并把公钥写成 PEM 文件（模拟 control 分发的 <私钥>.pub）。
func writePub(t *testing.T, dir, name string) (ed25519.PrivateKey, string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return priv, path, kidOf(pub)
}

// signWith 用给定私钥签一个 EdDSA 令牌（模拟 control 的 Keys.Sign）。
func signWith(t *testing.T, priv ed25519.PrivateKey, kid string, c Claims, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	c.Iat, c.Exp = now.Unix(), now.Add(ttl).Unix()
	hj, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	pj, _ := json.Marshal(c)
	body := b64.EncodeToString(hj) + "." + b64.EncodeToString(pj)
	return body + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(body)))
}

// ★阶段 3 的核心性质：网关只装 knock 公钥，会话令牌（另一把 sess 密钥签）
// 在此从**密码学上**验不过——kid 查不到，压根走不到 use 语义闸。
func TestOnlyKnockKeyInstalled(t *testing.T) {
	dir := t.TempDir()
	sessPriv, _, sessKid := writePub(t, dir, "sess.pub") // 这把公钥故意不装
	knockPriv, knockPath, knockKid := writePub(t, dir, "knock.pub")

	v, err := NewVerifier(knockPath, nil, false)
	if err != nil {
		t.Fatalf("构造校验器: %v", err)
	}
	if v.PublicKeyCount() != 1 {
		t.Fatalf("应只装 1 把公钥, 得 %d", v.PublicKeyCount())
	}

	knockTok := signWith(t, knockPriv, knockKid,
		Claims{Sub: "u", Role: "user", Name: "u", Jti: "j", Use: UseKnock}, 90*time.Second)
	if _, err := v.Verify(knockTok); err != nil {
		t.Fatalf("敲门令牌应验通过: %v", err)
	}

	sessTok := signWith(t, sessPriv, sessKid, Claims{Sub: "u", Role: "admin", Name: "u"}, 8*time.Hour)
	if _, err := v.Verify(sessTok); err == nil {
		t.Fatal("★只装 knock 公钥时，会话令牌必须验不过")
	}
}

// 多把公钥并存（轮换期同时装新旧两把），逗号分隔。
func TestMultiplePublicKeys(t *testing.T) {
	dir := t.TempDir()
	oldPriv, oldPath, oldKid := writePub(t, dir, "old.pub")
	newPriv, newPath, newKid := writePub(t, dir, "new.pub")

	v, err := NewVerifier(oldPath+","+newPath, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if v.PublicKeyCount() != 2 {
		t.Fatalf("应装 2 把公钥, 得 %d", v.PublicKeyCount())
	}
	for name, tok := range map[string]string{
		"旧密钥": signWith(t, oldPriv, oldKid, Claims{Sub: "u", Role: "user", Name: "u"}, time.Hour),
		"新密钥": signWith(t, newPriv, newKid, Claims{Sub: "u", Role: "user", Name: "u"}, time.Hour),
	} {
		if _, err := v.Verify(tok); err != nil {
			t.Fatalf("%s签的令牌应验通过: %v", name, err)
		}
	}
}

// 收口态（不接受 HS256）：HS256 令牌一律拒，且 alg 白名单里根本没有它。
func TestLegacyClosed(t *testing.T) {
	dir := t.TempDir()
	_, path, _ := writePub(t, dir, "k.pub")
	v, err := NewVerifier(path, []byte("old-shared"), false)
	if err != nil {
		t.Fatal(err)
	}
	if v.AcceptsLegacy() {
		t.Fatal("收口后不应接受 HS256")
	}
	// 用共享密钥伪造（阶段 4 之前这能过）
	hj, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	pj, _ := json.Marshal(Claims{Sub: "attacker", Role: "admin", Name: "a",
		Iat: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()})
	body := b64.EncodeToString(hj) + "." + b64.EncodeToString(pj)
	if _, err := v.Verify(body + ".whatever"); err == nil {
		t.Fatal("收口后 HS256 令牌必须被拒")
	}
}

// 既无公钥又关掉 HS256 → 构造失败（没有任何验证材料，早失败好过静默全拒）。
func TestNoVerificationMaterial(t *testing.T) {
	if _, err := NewVerifier("", nil, false); err == nil {
		t.Fatal("无公钥且不接受 HS256 时应构造失败")
	}
	// 迁移期：无公钥但接受 HS256 是合法形态
	if _, err := NewVerifier("", []byte("s"), true); err != nil {
		t.Fatalf("迁移期形态应可构造: %v", err)
	}
}
