package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Ed25519 签发/校验往返，且 header 带 kid、alg=EdDSA。
func TestKeysSignVerify(t *testing.T) {
	k := NewTestKeys(nil, false)
	tok := k.Sign(Claims{Sub: "li.fang", Role: "user", Name: "li.fang"}, time.Hour)

	h, err := parseHeader(strings.Split(tok, ".")[0], "EdDSA")
	if err != nil {
		t.Fatalf("header 应为 EdDSA: %v", err)
	}
	if h.Kid != k.Kid() {
		t.Fatalf("header 应带 kid=%s, 得 %s", k.Kid(), h.Kid)
	}
	c, err := k.Verify(tok)
	if err != nil || c.Sub != "li.fang" || c.Role != "user" {
		t.Fatalf("校验应通过并还原 claims: %+v %v", c, err)
	}
}

// 篡改载荷必须验签失败（公钥验签真的在起作用，不是摆设）。
func TestKeysRejectsTampered(t *testing.T) {
	k := NewTestKeys(nil, false)
	tok := k.Sign(Claims{Sub: "u", Role: "user", Name: "u"}, time.Hour)
	parts := strings.Split(tok, ".")

	// 换成 admin 载荷、保留原签名
	forged := k.Sign(Claims{Sub: "u", Role: "admin", Name: "u"}, time.Hour)
	mixed := parts[0] + "." + strings.Split(forged, ".")[1] + "." + parts[2]
	if _, err := k.Verify(mixed); err == nil {
		t.Fatal("篡改载荷必须验签失败")
	}
}

// 另一把私钥签的令牌验不过（网关只信 control 那把公钥的基础）。
func TestKeysRejectsForeignKey(t *testing.T) {
	a, b := NewTestKeys(nil, false), NewTestKeys(nil, false)
	tok := b.Sign(Claims{Sub: "u", Role: "admin", Name: "u"}, time.Hour)
	if _, err := a.Verify(tok); err == nil {
		t.Fatal("他人私钥签的令牌必须被拒")
	}
}

// ★迁移窗口：开启时接受存量 HS256 令牌，收口后必须拒绝。
// 这是升级不断线的关键——若不接受，升级瞬间所有在线会话(8h)与网关自签令牌全部 401。
func TestKeysLegacyHS256Window(t *testing.T) {
	legacy := []byte("old-shared-secret")
	old := Sign(legacy, Claims{Sub: "u", Role: "admin", Name: "u"}, time.Hour)

	open := NewTestKeys(legacy, true)
	if _, err := open.Verify(old); err != nil {
		t.Fatalf("迁移期应接受存量 HS256 令牌: %v", err)
	}
	if !open.AcceptsLegacy() {
		t.Fatal("AcceptsLegacy 应为 true")
	}

	closed := NewTestKeys(legacy, false)
	if _, err := closed.Verify(old); err == nil {
		t.Fatal("收口后必须拒绝 HS256 令牌")
	}
	// 收口后 EdDSA 仍正常
	if _, err := closed.Verify(closed.Sign(Claims{Sub: "u", Role: "user", Name: "u"}, time.Hour)); err != nil {
		t.Fatalf("收口后 EdDSA 应仍可用: %v", err)
	}
}

// 私钥持久化：首启生成、二次载入同一把（kid 稳定），权限 0600，公钥旁路落盘。
func TestLoadOrCreateKeysPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "jwt.pem")

	k1, err := LoadOrCreateKeys(path, nil, false)
	if err != nil {
		t.Fatalf("首启应生成密钥: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("私钥权限应为 0600, 得 %o", fi.Mode().Perm())
	}
	pubPEM, err := os.ReadFile(path + ".pub")
	if err != nil || !strings.Contains(string(pubPEM), "PUBLIC KEY") {
		t.Fatalf("公钥应旁路落盘供分发: %v", err)
	}

	k2, err := LoadOrCreateKeys(path, nil, false)
	if err != nil {
		t.Fatalf("二次载入应成功: %v", err)
	}
	if k1.Kid() != k2.Kid() {
		t.Fatalf("重启后 kid 应稳定: %s vs %s", k1.Kid(), k2.Kid())
	}
	// k1 签的令牌 k2 能验（同一把密钥）
	if _, err := k2.Verify(k1.Sign(Claims{Sub: "u", Role: "user", Name: "u"}, time.Hour)); err != nil {
		t.Fatalf("重启后应能验证重启前签发的令牌: %v", err)
	}
}
