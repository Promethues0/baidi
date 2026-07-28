package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA 持久化：首启生成、二次载入同一把；私钥 0600。
func TestLoadOrCreatePersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	a, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("首启应生成 CA: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "ca.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("CA 私钥权限应 0600, 得 %o", fi.Mode().Perm())
	}
	b, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("二次载入应成功: %v", err)
	}
	if string(a.CertPEM()) != string(b.CertPEM()) {
		t.Fatal("重启后 CA 应稳定不变")
	}
}

// 签发的客户端证书：CN=网关 id、只含 ClientAuth 用途、能被 CA 池验通过。
func TestIssueClient(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	iss, err := ca.IssueClient("gw-1")
	if err != nil {
		t.Fatalf("签发应成功: %v", err)
	}
	blk, _ := pem.Decode([]byte(iss.CertPEM))
	if blk == nil {
		t.Fatal("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "gw-1" {
		t.Fatalf("CN 应为网关 id, 得 %s", cert.Subject.CommonName)
	}
	// ★只能做客户端认证：这张证书不能拿去冒充服务端
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("应只含 ClientAuth 用途, 得 %v", cert.ExtKeyUsage)
	}
	if iss.Fingerprint != Fingerprint(blk.Bytes) {
		t.Fatal("指纹应与证书 DER 一致")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("应能被本 CA 验通过: %v", err)
	}
	// 两次签发指纹不同（各自独立密钥对）
	iss2, _ := ca.IssueClient("gw-1")
	if iss2.Fingerprint == iss.Fingerprint {
		t.Fatal("两次签发应产生不同证书")
	}
}

// 另一个 CA 签的证书验不过（白名单之外的 CA 不被信任）。
func TestForeignCARejected(t *testing.T) {
	mine, _ := LoadOrCreate(t.TempDir())
	other, _ := LoadOrCreate(t.TempDir())
	iss, _ := other.IssueClient("gw-evil")
	blk, _ := pem.Decode([]byte(iss.CertPEM))
	cert, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: mine.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("他人 CA 签的证书必须验不过")
	}
}

// mTLS 服务端证书：SAN 含监听主机、用途为 ServerAuth。
func TestServerCertFor(t *testing.T) {
	ca, _ := LoadOrCreate(t.TempDir())
	c, err := ServerCertFor(ca, "127.0.0.1:8092")
	if err != nil {
		t.Fatalf("签发服务端证书应成功: %v", err)
	}
	cert, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SAN 应含监听 IP, 得 %v", cert.IPAddresses)
	}
	if cert.NotAfter.Before(time.Now()) {
		t.Fatal("证书不应已过期")
	}
}
