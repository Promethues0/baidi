package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/upgrade"
)

// 发布侧签名 → 控制面验签的**端到端**回归（FR-UPG-04）。
//
// ★缺陷原样：验签是 fail-closed 的（没配公钥直接拒，方向正确），但全仓
// **没有任何签名工具**，`BAIDI_UPGRADE_PUBKEY` 也没进任何部署模板。
// 于是升级包校验在任何真实部署上恒为「校验不通过」：功能写完了、也拒得对，
// 只是链路缺了发布侧那一半，管理员永远走不通。
//
// 这条用例真的去跑 cmd/baidi-upgrade，而不是在测试里手搓一次签名——
// 手搓的话，工具本身签错了（比如重新序列化 manifest 导致字节不一致）也测不出来，
// 而那正是这类工具最容易犯的错。
func TestUpgradeSignToolRoundTrip(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "baidi-upgrade")
	build := exec.Command("go", "build", "-o", bin, "baidi.dev/control/cmd/baidi-upgrade")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("构建签名工具失败（无 go 工具链？）：%v %s", err, out)
	}

	pkg := filepath.Join(dir, "baidi-control-v0.4.0.tar.gz")
	if err := os.WriteFile(pkg, []byte("升级包内容占位"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("baidi-upgrade %s 失败：%v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run("-genkey", "-out", dir)
	mf := filepath.Join(dir, "manifest.json")
	run("-manifest", pkg, "-version", "v0.4.0", "-component", "control", "-out", mf)
	run("-sign", mf, "-key", filepath.Join(dir, "upgrade-sign.key"))

	// ★用**控制面这一侧**的实现去验，而不是再调一次工具的 -verify：
	//   工具自己签自己验永远是对的，而真正要保证的是「发布方签出来的东西，控制面认」。
	raw, err := os.ReadFile(mf)
	if err != nil {
		t.Fatal(err)
	}
	sig := mustDecode(t, filepath.Join(dir, "manifest.sig"))
	pub := mustDecode(t, filepath.Join(dir, "upgrade-sign.pub"))
	if err := upgrade.VerifySignature(raw, sig, []ed25519.PublicKey{ed25519.PublicKey(pub)}); err != nil {
		t.Fatalf("控制面应认这份签名，却报：%v —— 发布侧与验签侧的字节口径不一致", err)
	}
	m, err := upgrade.ParseManifest(raw)
	if err != nil {
		t.Fatalf("工具生成的 manifest 未过控制面校验：%v", err)
	}
	if m.Version != "v0.4.0" || m.Component != upgrade.ComponentControl || len(m.SHA256) != 64 {
		t.Fatalf("manifest 内容不对：%+v", m)
	}

	// 反向：改一个字节就必须验不过（否则签名等于没签）。
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-3] ^= 0x20
	if err := upgrade.VerifySignature(tampered, sig, []ed25519.PublicKey{ed25519.PublicKey(pub)}); err == nil {
		t.Fatal("篡改过的 manifest 不该验过")
	}
	// 反向：换一把公钥也必须验不过。
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := upgrade.VerifySignature(raw, sig, []ed25519.PublicKey{otherPub}); err == nil {
		t.Fatal("别人的公钥不该验过")
	}
}

func mustDecode(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("%s 不是合法 base64：%v", path, err)
	}
	return b
}
