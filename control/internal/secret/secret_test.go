package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testBox(t *testing.T) *Box {
	t.Helper()
	b, err := Open(filepath.Join(t.TempDir(), "psk.key"))
	if err != nil {
		t.Fatalf("open box: %v", err)
	}
	return b
}

// 往返：加密再解密应还原原文，且密文里不得出现原文（最朴素也最难造假的证据）。
func TestSealOpenRoundTrip(t *testing.T) {
	b := testBox(t)
	psk := []byte("this-is-a-long-enough-preshared-key")

	nonce, ct, err := b.Seal("site-sh", psk)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(ct, psk) {
		t.Fatal("密文里能直接找到明文——这不是加密")
	}
	// GCM 的 tag 是 16 字节，密文必然比明文长
	if len(ct) != len(psk)+16 {
		t.Fatalf("密文长度异常：%d（明文 %d + 16 字节 tag）", len(ct), len(psk))
	}
	got, err := b.Open("site-sh", nonce, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, psk) {
		t.Fatalf("往返丢失：%q != %q", got, psk)
	}
}

// ★AAD 绑定的核心断言：把 A 站点的密文行整行搬到 B 站点必须解不开。
//
// 不绑 AAD 时这一步会**成功**，于是「只要能写库就能完成一次密钥转移」——
// 不需要任何密码学突破，把一行 UPDATE 的 site_id 改掉即可。
func TestAADBindsCiphertextToSite(t *testing.T) {
	b := testBox(t)
	psk := []byte("shared-secret-for-site-a-0001")

	nonce, ct, err := b.Seal("site-a", psk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open("site-b", nonce, ct); err == nil {
		t.Fatal("换了 site_id 竟然解开了：AAD 没有真正参与认证，密文行可被跨站点剪贴复用")
	}
	// 报错必须能指导排障：带上 aad 与密文长度，而不是一句 message authentication failed
	_, err = b.Open("site-b", nonce, ct)
	if !strings.Contains(err.Error(), "site-b") || !strings.Contains(err.Error(), DefaultKeyPathEnv) {
		t.Fatalf("错误信息不足以定位根因：%v", err)
	}
	// 空 AAD 直接拒绝：允许空 AAD 等于给「跨记录复用」开了一条合法路径
	if _, _, err := b.Seal("", psk); err == nil {
		t.Fatal("空 AAD 应被拒绝")
	}
}

// 换了主密钥就解不开：这条同时证明「密文真的依赖密钥」与「换密钥的症状是显式报错」。
func TestWrongMasterKeyFails(t *testing.T) {
	b1 := testBox(t)
	b2 := testBox(t)
	nonce, ct, err := b1.Seal("site-sh", []byte("preshared-key-material-x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Open("site-sh", nonce, ct); err == nil {
		t.Fatal("另一把主密钥竟然解开了密文")
	}
}

// 篡改密文任意一个 bit 必须失败——GCM 的完整性不是可选项。
func TestTamperedCiphertextRejected(t *testing.T) {
	b := testBox(t)
	nonce, ct, err := b.Seal("site-sh", []byte("preshared-key-material-y"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range ct {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if _, err := b.Open("site-sh", nonce, bad); err == nil {
			t.Fatalf("翻转第 %d 字节的一个 bit 后仍能解开", i)
		}
	}
}

// nonce 每次重新随机。GCM 复用 nonce 会同时毁掉机密性与完整性，且**不报任何错**。
func TestNonceIsFreshEachSeal(t *testing.T) {
	b := testBox(t)
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		nonce, _, err := b.Seal("site-sh", []byte("same-plaintext-every-time"))
		if err != nil {
			t.Fatal(err)
		}
		if len(nonce) != 12 {
			t.Fatalf("nonce 应 12 字节，实得 %d", len(nonce))
		}
		if seen[string(nonce)] {
			t.Fatal("nonce 复用：GCM 下这是灾难性的，且不会报任何错")
		}
		seen[string(nonce)] = true
	}
}

// 指纹：同一把 PSK 恒等（运维靠它核对两端），不同 PSK 必不同，
// 且**不是**裸 SHA-256——低熵 PSK 的裸哈希前缀可被离线爆破还原。
func TestFingerprintIsKeyedAndStable(t *testing.T) {
	b1 := testBox(t)
	b2 := testBox(t)
	psk := []byte("preshared-key-material-z")

	if b1.Fingerprint(psk) != b1.Fingerprint(psk) {
		t.Fatal("同一把 PSK 的指纹必须稳定，否则「核对两端是否一致」这个唯一用途就没了")
	}
	if b1.Fingerprint(psk) == b1.Fingerprint([]byte("another-preshared-key-aa")) {
		t.Fatal("不同 PSK 的指纹相同")
	}
	// 带密钥：换主密钥后指纹必变。若这里相等，说明退化成了裸哈希。
	if b1.Fingerprint(psk) == b2.Fingerprint(psk) {
		t.Fatal("指纹与主密钥无关：退化成裸哈希后，低熵 PSK 可被离线爆破还原")
	}
	if len(b1.Fingerprint(psk)) != 64 {
		t.Fatalf("指纹应为 SHA-256 的 64 位十六进制，实得 %d", len(b1.Fingerprint(psk)))
	}
}

// 密钥文件：首启自动生成、权限 0600、二次打开复用同一把（否则重启即全部密文报废）。
func TestKeyFileCreatedOnceWithTightPerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "psk.key")
	b1, err := Open(path)
	if err != nil {
		t.Fatalf("首启生成失败: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("密钥文件权限应为 0600，实得 %04o", perm)
	}
	nonce, ct, _ := b1.Seal("site-sh", []byte("preshared-key-material-w"))

	b2, err := Open(path) // 二次打开：必须载入同一把，而不是又生成一把新的
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Open("site-sh", nonce, ct); err != nil {
		t.Fatalf("重开后解不开旧密文——重启一次控制面就会让全部 PSK 报废：%v", err)
	}
	// 半截/损坏的密钥文件必须显式报错，不能悄悄换一把新的（那等于静默作废全部密文）
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("损坏的密钥文件应显式报错，而不是重新生成")
	}
}

// 长度不对的主密钥必须被拒（AES-256 要 32 字节）。
func TestNewFromKeyRejectsWrongLength(t *testing.T) {
	if _, err := NewFromKey(make([]byte, 16)); err == nil {
		t.Fatal("16 字节密钥应被拒绝")
	} else if !strings.Contains(err.Error(), "32") {
		t.Fatalf("错误信息应带上期望长度：%v", err)
	}
}

// DefaultKeyPath 读的是**路径**环境变量而不是密钥值本身。
func TestDefaultKeyPathFromEnv(t *testing.T) {
	t.Setenv(DefaultKeyPathEnv, "/tmp/whatever/psk.key")
	if got := DefaultKeyPath(); got != "/tmp/whatever/psk.key" {
		t.Fatalf("应取环境变量指定的路径，实得 %q", got)
	}
	t.Setenv(DefaultKeyPathEnv, "")
	if got := DefaultKeyPath(); got != "ipsec-psk.key" {
		t.Fatalf("未配置时应回默认相对路径，实得 %q", got)
	}
}
