// Package gmcert 生成国密 TLCP 服务端双证书（SM2 签名证书 + SM2 加密证书，自签 SM2 CA）。
// 用于网关把隧道从通用 RSA/TLS 换成国密 TLCP（先认证后连接的加密层国密化）。
package gmcert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// Generate 返回 TLCP 服务端用的 [签名证书, 加密证书]（顺序要求：先签名后加密）。
func Generate() ([]tlcp.Certificate, error) {
	now := time.Now()
	notAfter := now.Add(10 * 365 * 24 * time.Hour)

	// —— 自签 SM2 CA ——
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "白帝国密 CA", Organization: []string{"Baidi"}, Country: []string{"CN"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := smx509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := smx509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	hosts := []string{"baidi-gateway", "localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1")}

	// —— 签名证书（KeyUsage: 数字签名）——
	sign, err := leaf("baidi-gateway-sign", x509.KeyUsageDigitalSignature, big.NewInt(2), hosts, ips, now, notAfter, caCert, caKey)
	if err != nil {
		return nil, err
	}
	// —— 加密证书（KeyUsage: 密钥协商/加密）——
	enc, err := leaf("baidi-gateway-enc", x509.KeyUsageKeyAgreement|x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment, big.NewInt(3), hosts, ips, now, notAfter, caCert, caKey)
	if err != nil {
		return nil, err
	}
	return []tlcp.Certificate{sign, enc}, nil
}

func leaf(cn string, ku x509.KeyUsage, serial *big.Int, hosts []string, ips []net.IP, nb, na time.Time, ca *smx509.Certificate, caKey *sm2.PrivateKey) (tlcp.Certificate, error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return tlcp.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Baidi"}, Country: []string{"CN"}},
		NotBefore:    nb.Add(-time.Hour),
		NotAfter:     na,
		KeyUsage:     ku,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     hosts,
		IPAddresses:  ips,
	}
	der, err := smx509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tlcp.Certificate{}, err
	}
	keyDER, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tlcp.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tlcp.X509KeyPair(certPEM, keyPEM)
}
