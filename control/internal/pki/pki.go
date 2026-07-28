// Package pki 是控制面的内部 CA：签发网关的 mTLS 客户端证书，让「机器身份」
// 与「用户身份」在密码学上分家（CA 身份迁移 阶段 2）。
//
// 用标准 X.509（P-256 / ECDSAWithSHA256，纯 stdlib crypto/x509）而不复用国密 SM2 CA：
//   - gmsm 的 smx509 对 SM2 私钥把签名算法锁死为 SM2WithSM3，stdlib 与 nginx 都不认，
//     复用等于 control 整条链要换 gotlcp 监听并绕开 nginx 反代；
//   - 现有 SM2 CA 的私钥是在**网关机**上生成的（deploy 在网关侧跑 baidi-gmca），
//     用它当控制面的信任根等于把根交给被保护方。
//
// SM2 CA 继续只管 TLCP 隧道，两套 PKI 各司其职、互不污染。
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caTTL   = 10 * 365 * 24 * time.Hour // 内部 CA 有效期
	certTTL = 90 * 24 * time.Hour       // 网关客户端证书有效期（短期 + 可续签）
)

// CA 控制面内部证书颁发机构。
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

// LoadOrCreate 载入 dir 下的 CA；不存在则生成（key 0600、cert 0644，原子写）。
func LoadOrCreate(dir string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt.pem"), filepath.Join(dir, "ca.key.pem")
	if cb, err := os.ReadFile(certPath); err == nil {
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("CA 私钥缺失: %w", err)
		}
		cblk, _ := pem.Decode(cb)
		kblk, _ := pem.Decode(kb)
		if cblk == nil || kblk == nil {
			return nil, errors.New("CA PEM 解析失败")
		}
		cert, err := x509.ParseCertificate(cblk.Bytes)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParseECPrivateKey(kblk.Bytes)
		if err != nil {
			return nil, err
		}
		return &CA{cert: cert, key: key, der: cblk.Bytes}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "baidi-control internal CA", Organization: []string{"baidi"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return nil, err
	}
	if err := writeAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, der: der}, nil
}

// CertPEM 返回 CA 证书 PEM（分发给网关做服务端校验锚 + control 做客户端校验池）。
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// Pool 返回只含本 CA 的证书池（校验网关客户端证书）。
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Issued 一次签发的结果。Fingerprint 是证书 DER 的 SHA-256（十六进制），
// 控制面据此做白名单/吊销——比 CRL 轻，且可即刻剔除。
type Issued struct {
	CertPEM     string
	KeyPEM      string
	Fingerprint string
	NotAfter    time.Time
}

// IssueClient 给网关签一张客户端证书（CN=网关 id，仅 ClientAuth 用途）。
func (c *CA) IssueClient(gwID string) (Issued, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Issued{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Issued{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: gwID, Organization: []string{"baidi-gateway"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// 只签客户端认证用途：这张证书不能拿去冒充服务端。
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return Issued{}, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Issued{}, err
	}
	return Issued{
		CertPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})),
		Fingerprint: Fingerprint(der),
		NotAfter:    tmpl.NotAfter,
	}, nil
}

// ServerCertFor 为 mTLS 监听签一张服务端证书（CN/SAN 取监听地址的主机部分）。
// 网关用 CA 公证书校验它——双方都由同一内部 CA 背书，构成双向认证。
func ServerCertFor(ca *CA, addr string) (tls.Certificate, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = "127.0.0.1"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "baidi-control mtls", Organization: []string{"baidi"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "baidi-control"},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.der}, PrivateKey: key}, nil
}

// Fingerprint 计算证书 DER 的 SHA-256 十六进制指纹。
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
