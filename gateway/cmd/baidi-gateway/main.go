// Command baidi-gateway 是白帝安全代理网关（数据面）：SPA 单包授权 + SSL 隧道代理。
// 默认对未授权者隐身；持有效 JWT 敲门后才放行并代理到后端业务。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	"baidi.dev/gateway/internal/proxy"
	"baidi.dev/gateway/internal/spa"
)

func main() {
	spaAddr := flag.String("spa", env("BAIDI_GW_SPA", ":18201"), "SPA 敲门 UDP 监听地址")
	proxyAddr := flag.String("proxy", env("BAIDI_GW_PROXY", ":18443"), "TLS 隧道代理监听地址")
	backend := flag.String("backend", env("BAIDI_GW_BACKEND", "127.0.0.1:9999"), "后端业务 host:port")
	secret := flag.String("secret", env("BAIDI_JWT_SECRET", "baidi-dev-secret-change-me"), "JWT 密钥（须与 baidi-control 一致）")
	ttl := flag.Duration("ttl", 30*time.Second, "SPA 放行窗口")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.Info("baidi-gateway 启动", "spa", *spaAddr, "proxy", *proxyAddr, "backend", *backend, "ttl", ttl.String())

	cert := mustSelfSigned()
	al := spa.NewAllowlist()

	go func() {
		if err := spa.Serve(*spaAddr, []byte(*secret), *ttl, al); err != nil {
			log.Fatalf("SPA 监听失败: %v", err)
		}
	}()

	if err := proxy.Serve(*proxyAddr, cert, *backend, al); err != nil {
		log.Fatalf("代理监听失败: %v", err)
	}
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

// mustSelfSigned 生成启动期自签 TLS 证书（生产换国密 TLCP / 正式证书）。
func mustSelfSigned() tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "baidi-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"baidi-gateway", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}
