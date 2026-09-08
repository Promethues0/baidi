package knock

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ControlTLSFromPEM 按部署期分发的信任锚 PEM 构建「客户端 → 控制面 HTTPS」这一跳的 TLS 配置。
//
// 这是**该判据在本仓的唯一实现**：桌面 baidi-tun（-control-ca）与移动端
// （baidimobile.Config.ControlCaPEM）必须同真同假。两端各写一份的话，一端修了另一端零感知，
// 而两处的现场症状毫无共同点（WebView 报 ERR_CERT_AUTHORITY_INVALID、Go 侧报
// x509: certificate signed by unknown authority），会被当成两个不相干的 bug 各修一次。
//
// 语义（三条，缺一条就退化成另一种东西）：
//   - pem 为空 → 返回 nil，调用方据此走**系统信任库**。**不是跳过校验。**
//   - pem 非空 → 系统池 **∪** 这些锚。
//   - 解析不出任何一张证书 → **报错**，绝不静默回落成系统信任库——那正是「配了却不生效」，
//     而现场与"根本没配"完全同形（本仓反复批判的静默失效形态）。
//
// ★为什么必须是并集而不是替换：部署方哪天把控制面换成受信证书（生产姿态，
// install-remote.sh 收尾告警里第一条推荐的就是它），若这里用 x509.NewCertPool() 从零起池，
// 所有带锚的终端会在同一刻集体连不上——而换证书的人完全预料不到这件事，现场表现是
// 「换了张更好的证书，客户端反而全挂了」。并集下旧锚只是变成一张没人用的多余证书。
//
// ★为什么不给 InsecureSkipVerify 任何入口：这是零信任链路的第一跳（客户端认控制面），
// 一旦开个口子就再也拆不掉；本仓对审计外送、SMTP StartTLS、隧道钉扎都是同一条纪律。
// 自签部署的正确做法是**分发信任锚**，不是关掉校验。
//
// ★锚是叶子还是 CA 都能用：Go 的链校验允许把自签叶子直接当根（install-remote.sh 用
// `openssl req -x509` 签出来的那张带 basicConstraints CA:TRUE）。但**有效期与 SAN 照常校验**
// ——这正是它比"证书指纹钉扎"强的地方：钉扎会连带把这两项一起关掉。
func ControlTLSFromPEM(pem string) (*tls.Config, error) {
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
			"请确认给的是 -----BEGIN CERTIFICATE----- 开头的公证书，而不是私钥或 DER 二进制")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// ControlTLSFromFile 是 ControlTLSFromPEM 的文件入口（桌面端 -control-ca 用）。
//
// path 为空 → (nil, nil) = 系统信任库，与 ControlTLSFromPEM("") 同义。
// **读不到文件一律报错**，不当空处理：路径打错时静默走系统信任库，自签部署下的表现是
// 「门永远敲不开」，而管理员手里明明有一条 -control-ca 参数，会一路怀疑到证书本身去。
func ControlTLSFromFile(path string) (*tls.Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取控制中心信任锚 %s 失败：%w", path, err)
	}
	cfg, err := ControlTLSFromPEM(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s：%w", path, err)
	}
	if cfg == nil {
		// 文件存在但内容全是空白：与"没配"在结果上一样，但**意图**完全不同——
		// 管理员显式指了一个文件，静默走系统信任库属于配了却不生效。
		return nil, fmt.Errorf("控制中心信任锚 %s 是空文件", path)
	}
	return cfg, nil
}
