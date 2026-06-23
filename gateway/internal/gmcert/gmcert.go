// Package gmcert 管理国密 TLCP 的证书材料：持久化 SM2 根 CA 签发的双证书（签名证书 + 加密证书）。
//
// 相比早期"启动期内存自签 + 客户端 InsecureSkipVerify"，本版把 CA 与 leaf 落盘复用，
// 客户端可用 LoadCAPool 得到 CA 根池，对网关证书链做**真实校验**（校 CA 根 + 主机名），不再裸信。
//
// 落盘文件（dir 目录，私钥 0600、目录 0700）：
//
//	ca.pem / ca.key.pem      —— SM2 根 CA（自签，10 年）
//	sign.pem / sign.key.pem  —— 网关 SM2 签名证书（CA 签发，2 年，KeyUsage=数字签名）
//	enc.pem  / enc.key.pem   —— 网关 SM2 加密证书（CA 签发，2 年，KeyUsage=密钥协商/加密）
//
// 健壮性：EnsureGateway 全程持目录文件锁，串行化并发首启；落盘走"临时文件+rename"原子写，
// 杜绝并发交错产出 cert/key 不配对的损坏库；复用前校验 leaf 未过期、且确由当前 CA 签发，
// 否则自动重签（换 CA / 临近到期都能自愈）。
//
// 注意：gotlcp 的 tlcp.Config.RootCAs/ClientCAs 字段虽标注 *x509.CertPool，但该包内 x509 是
// github.com/emmansun/gmsm/smx509 的别名——故必须用 smx509.NewCertPool()（标准库 x509.CertPool 编译不过）。
package gmcert

import (
	"crypto/rand"
	"crypto/x509" // 标准库，仅用于构造证书 template（smx509.CreateCertificate 接受它）
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

const (
	caCertFile, caKeyFile     = "ca.pem", "ca.key.pem"
	signCertFile, signKeyFile = "sign.pem", "sign.key.pem"
	encCertFile, encKeyFile   = "enc.pem", "enc.key.pem"

	leafRenewWindow = 30 * 24 * time.Hour // leaf 剩余有效期 < 此值即提前重签
	caWarnWindow    = 90 * 24 * time.Hour // CA 剩余有效期 < 此值即告警
)

// 网关证书 SAN：DNS 名 + 回环 IP（客户端 ServerName 命中其一即可）。
var (
	gwHosts = []string{"baidi-gateway", "localhost"}
	gwIPs   = []net.IP{net.ParseIP("127.0.0.1")}
)

// EnsureGateway 确保 dir 下有持久化 CA + 网关双证书；缺/过期/不匹配则（重）生成，有效则复用。
// 返回 TLCP 服务端用的 [签名证书, 加密证书]（顺序要求：先签名后加密）。
// 全程持目录文件锁，可安全并发/多进程首启。
func EnsureGateway(dir string) ([]tlcp.Certificate, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	caCert, caKey, err := ensureCA(dir)
	if err != nil {
		return nil, err
	}
	sign, err := ensureLeaf(dir, signCertFile, signKeyFile, "baidi-gateway-sign",
		x509.KeyUsageDigitalSignature, big.NewInt(2), caCert, caKey)
	if err != nil {
		return nil, err
	}
	enc, err := ensureLeaf(dir, encCertFile, encKeyFile, "baidi-gateway-enc",
		x509.KeyUsageKeyAgreement|x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment,
		big.NewInt(3), caCert, caKey)
	if err != nil {
		return nil, err
	}
	return []tlcp.Certificate{sign, enc}, nil
}

// LoadCAPool 读取 dir 下 CA 根证书，返回 *smx509.CertPool 供客户端 tlcp.Config.RootCAs。
func LoadCAPool(dir string) (*smx509.CertPool, error) {
	pemBytes, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, err
	}
	pool := smx509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("gmcert: 无法解析 CA 根证书 PEM")
	}
	return pool, nil
}

// CAInfo 返回 CA 证书的人读信息（主体/有效期），供 baidi-gmca 打印。
func CAInfo(dir string) (subject string, notAfter time.Time, err error) {
	cb, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return "", time.Time{}, err
	}
	caCert, err := smx509.ParseCertificatePEM(cb)
	if err != nil {
		return "", time.Time{}, err
	}
	return caCert.Subject.String(), caCert.NotAfter, nil
}

func ensureCA(dir string) (*smx509.Certificate, *sm2.PrivateKey, error) {
	cp, kp := filepath.Join(dir, caCertFile), filepath.Join(dir, caKeyFile)
	if fileExists(cp) && fileExists(kp) {
		if caCert, caKey, err := loadCA(cp, kp); err == nil {
			now := time.Now()
			if now.Before(caCert.NotAfter) { // CA 仍有效 → 复用
				if caCert.NotAfter.Sub(now) < caWarnWindow {
					slog.Warn("国密 CA 临近到期，建议续签并重新分发 CA 池", "notAfter", caCert.NotAfter)
				}
				return caCert, caKey, nil
			}
			slog.Warn("国密 CA 已过期，重新生成（客户端需重新分发 CA 池）", "notAfter", caCert.NotAfter)
		} else {
			slog.Warn("国密 CA 加载失败，重新生成", "err", err.Error())
		}
		// 过期/损坏：删除旧 CA，重新生成（旧 leaf 会因签名不匹配在 ensureLeaf 自动重签）
		_ = os.Remove(cp)
		_ = os.Remove(kp)
	}
	now := time.Now()
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "白帝国密 CA", Organization: []string{"Baidi"}, Country: []string{"CN"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	// 自签：parent==tmpl，pub=&caKey.PublicKey(*ecdsa.PublicKey)，priv=caKey(crypto.Signer)
	der, err := smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := smx509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return nil, nil, err
	}
	if err := writePEM(cp, "CERTIFICATE", der, 0o644); err != nil {
		return nil, nil, err
	}
	if err := writePEM(kp, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, nil, err
	}
	caCert, err := smx509.ParseCertificate(der)
	return caCert, caKey, err
}

func ensureLeaf(dir, certFile, keyFile, cn string, ku x509.KeyUsage, serial *big.Int,
	ca *smx509.Certificate, caKey *sm2.PrivateKey) (tlcp.Certificate, error) {
	cp, kp := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	if fileExists(cp) && fileExists(kp) {
		if cert, err := tlcp.LoadX509KeyPair(cp, kp); err == nil && len(cert.Certificate) > 0 {
			if leaf, e := smx509.ParseCertificate(cert.Certificate[0]); e == nil {
				now := time.Now()
				fresh := now.After(leaf.NotBefore) && leaf.NotAfter.Sub(now) > leafRenewWindow
				byCurrentCA := leaf.CheckSignatureFrom(ca) == nil
				if fresh && byCurrentCA {
					return cert, nil // 有效且由当前 CA 签发 → 复用
				}
				slog.Warn("网关证书需重签", "file", certFile, "fresh", fresh, "byCurrentCA", byCurrentCA, "notAfter", leaf.NotAfter)
			}
		}
		// 过期/换 CA/损坏 → 删除后重签（fail-closed，绝不复用不可信 leaf）
		_ = os.Remove(cp)
		_ = os.Remove(kp)
	}
	now := time.Now()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return tlcp.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Baidi"}, Country: []string{"CN"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     ku,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     gwHosts,
		IPAddresses:  gwIPs,
	}
	der, err := smx509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tlcp.Certificate{}, err
	}
	keyDER, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tlcp.Certificate{}, err
	}
	if err := writePEM(cp, "CERTIFICATE", der, 0o644); err != nil {
		return tlcp.Certificate{}, err
	}
	if err := writePEM(kp, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return tlcp.Certificate{}, err
	}
	return tlcp.LoadX509KeyPair(cp, kp)
}

func loadCA(cp, kp string) (*smx509.Certificate, *sm2.PrivateKey, error) {
	cb, err := os.ReadFile(cp)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := smx509.ParseCertificatePEM(cb)
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(kp)
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(kb)
	if blk == nil {
		return nil, nil, errors.New("gmcert: CA 私钥 PEM 解析失败")
	}
	anyKey, err := smx509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	caKey, ok := anyKey.(*sm2.PrivateKey)
	if !ok {
		return nil, nil, errors.New("gmcert: CA 私钥非 SM2")
	}
	return caCert, caKey, nil
}

// writePEM 原子落盘：先写临时文件再 rename，避免读到半截 PEM 或 cert/key 不配对。
func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil { // WriteFile 受 umask 影响，显式收紧
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
