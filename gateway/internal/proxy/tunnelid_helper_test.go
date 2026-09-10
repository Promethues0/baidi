package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"baidi.dev/gateway/internal/auth"
)

// ── 隧道身份票据的测试脚手架 ──
//
// ★用真密钥真签名，不打桩 Verifier：这条链的价值就在"网关只持公钥、验得过才算数"，
// 用一个假 Verifier 测出来的绿灯与"根本没验"无法区分。

var tkB64 = base64.RawURLEncoding

// signTunnel 签一张 use=tunnel 票据的函数类型。
type signTunnel func(account, role string) string

// newTestTunnelID 造一把 Ed25519 密钥、把公钥写成 PEM 交给 Verifier，
// 返回严格姿态的 TunnelID 与对应的签票函数。
func newTestTunnelID(t testing.TB) (TunnelID, signTunnel) {
	t.Helper()
	id, sign, _ := newTestTunnelIDWithSigner(t)
	return id, sign
}

// newTestTunnelIDWithSigner 同上，另外返回一个**没有被网关装载**的签票函数
// （用另一把密钥签），用于"拿别处签的票来" 的反例。
func newTestTunnelIDWithSigner(t testing.TB) (TunnelID, signTunnel, signTunnel) {
	t.Helper()
	dir := t.TempDir()
	trusted, trustedPath := genTunnelKey(t, dir, "tunnel.pub")
	rogue, _ := genTunnelKey(t, dir, "rogue.pub") // 公钥故意不装
	v, err := auth.NewVerifier(trustedPath, nil, false)
	if err != nil {
		t.Fatalf("构造隧道票据校验器失败：%v", err)
	}
	return TunnelID{Verifier: v, Strict: true, MaxTTL: 15 * time.Minute}, trusted, rogue
}

// looseTunnelID 逃生舱姿态（BAIDI_GW_TUNNEL_ID_STRICT=0）：允许不带票据的连接。
func looseTunnelID(t testing.TB) TunnelID {
	t.Helper()
	id, _ := newTestTunnelID(t)
	id.Strict = false
	return id
}

func genTunnelKey(t testing.TB, dir, name string) (signTunnel, string) {
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
	sum := sha256.Sum256(pub) // kid 与 control.KidOf / auth.kidOf 同算法
	kid := tkB64.EncodeToString(sum[:8])
	return func(account, role string) string {
		return signClaims(priv, kid, auth.Claims{
			Sub: account, Role: role, Name: account, Use: auth.UseTunnel,
		}, 5*time.Minute)
	}, path
}

// signClaims 手工签一张 EdDSA JWT（模拟 control 的 Keys.Sign）。
func signClaims(priv ed25519.PrivateKey, kid string, c auth.Claims, ttl time.Duration) string {
	now := time.Now()
	c.Iat, c.Exp = now.Unix(), now.Add(ttl).Unix()
	hj, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	pj, _ := json.Marshal(c)
	body := tkB64.EncodeToString(hj) + "." + tkB64.EncodeToString(pj)
	return body + "." + tkB64.EncodeToString(ed25519.Sign(priv, []byte(body)))
}
