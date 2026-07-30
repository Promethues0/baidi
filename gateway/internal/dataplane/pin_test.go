package dataplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"
)

// 证书钉扎是隧道从「加密」升级为「加密 + 认证」的唯一依据：网关证书自签，链校验必然失败，
// 安全性全靠指纹比对。因此必须有回归防线覆盖三件事：
//   ① 指纹对上 → 握手成功；
//   ② 指纹对不上（中间人换了证书）→ 握手被拒；
//   ③ 未下发指纹 → 退化为不认证（明确记录该降级行为，避免被误当成"已启用钉扎"）。

func selfSigned(t *testing.T, cn string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}

// serveTLS 起一个一次性 TLS 服务端，返回监听地址。
func serveTLS(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// 完成握手后即可关闭：本测试只关心握手是否被接受。
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func dialWith(t *testing.T, addr, pin string) error {
	t.Helper()
	d := &net.Dialer{Timeout: 3 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, tlsClientConfig(pin))
	if err == nil {
		c.Close()
	}
	return err
}

func TestTunnelPin_MatchingFingerprintConnects(t *testing.T) {
	cert, fp := selfSigned(t, "baidi-gateway")
	addr := serveTLS(t, cert)
	if err := dialWith(t, addr, fp); err != nil {
		t.Fatalf("指纹一致时握手应成功，实得: %v", err)
	}
	// 大小写与空白不该影响比对——指纹经配置/JSON 流转，形态难保证。
	if err := dialWith(t, addr, "  "+hexUpper(fp)+"  "); err != nil {
		t.Fatalf("指纹大小写/空白不应影响比对，实得: %v", err)
	}
}

func TestTunnelPin_MismatchIsRejected(t *testing.T) {
	realCert, _ := selfSigned(t, "baidi-gateway")
	_, evilFP := selfSigned(t, "evil-gateway") // 冒充者的指纹
	addr := serveTLS(t, realCert)

	err := dialWith(t, addr, evilFP)
	if err == nil {
		t.Fatal("指纹不匹配时必须拒绝握手（否则中间人可无声接管隧道）")
	}
}

func TestTunnelPin_EmptyPinFallsBackToUnauthenticated(t *testing.T) {
	cert, _ := selfSigned(t, "baidi-gateway")
	addr := serveTLS(t, cert)
	// 空指纹是明确的降级路径（控制面尚未下发），此时仍应连得上，
	// 但 tlsClientConfig 会打 WARN——降级必须可见，不能静默。
	if err := dialWith(t, addr, ""); err != nil {
		t.Fatalf("未下发指纹时应退化为不校验并连通，实得: %v", err)
	}
}

func hexUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 32
		}
	}
	return string(b)
}
