package baidimobile

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
)

// controlTLSConfig 按下发的信任锚 PEM 构建「调控制面」用的 TLS 配置。
//
// 语义（**与同结构体上方的 CaPEM 恰好相反，这是本文件存在的首要理由**）：
//   - pem 为空 → 返回 nil，dataplane 据此走**系统信任库**。不是跳过校验。
//   - pem 非空 → 系统池 **∪** 这些锚。解析不出任何一张证书 → **报错**，绝不静默回落。
//
// ★为什么必须是并集而不是替换：部署方哪天把控制面换成受信证书（生产姿态，
// install-remote.sh 的收尾告警里第一条推荐的就是它），若这里用 x509.NewCertPool()
// 从零起池，所有带锚的终端会在同一刻集体连不上——而换证书的人完全预料不到这件事，
// 现场表现是「换了张更好的证书，客户端反而全挂了」。并集下旧锚只是变成一张没人用的多余证书。
//
// ★为什么不给 InsecureSkipVerify 任何入口：这是零信任链路的第一跳（客户端认控制面），
// 一旦开个口子就再也拆不掉；本仓对审计外送、SMTP StartTLS、隧道钉扎都是同一条纪律。
// 演示部署的正确做法是**分发信任锚**，不是关掉校验。
//
// ★锚是叶子还是 CA 都能用：Go 的链校验允许把自签叶子直接当根（install-remote.sh 用
// `openssl req -x509` 签出来的那张带 basicConstraints CA:TRUE）。但**有效期与 SAN 照常校验**
// ——这正是它比「证书指纹钉扎」强的地方：钉扎会连带把这两项一起关掉。
func controlTLSConfig(pem string) (*tls.Config, error) {
	pem = strings.TrimSpace(pem)
	if pem == "" {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// 取不到系统池不是致命的（某些精简运行时没有），退化成只认下发的锚并继续——
		// 但**绝不**因此放宽校验。
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		return nil, errors.New("控制中心信任锚不是有效的 PEM 证书（一张都解析不出来）：" +
			"请确认下发的是 -----BEGIN CERTIFICATE----- 开头的公证书，而不是私钥或 DER 二进制")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
