package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/config"
	"baidi.dev/control/internal/pki"
	"baidi.dev/control/internal/store"
)

// ── 网关身份材料的离线签发（部署期 bootstrap）──
//
// 装机时 control 尚未启动、也没有管理员能调 POST /api/v1/pki/gateway-certs，
// 于是给部署脚本一条离线路径：直接读同一套 PKI 目录与库，签一张网关客户端证书、
// 连同敲门公钥一起写到输出目录，然后退出。
//
// 与在线端点签的是同一张 CA 下的证书、同样登记进指纹白名单（吊销随时可用），
// 区别只是身份来自「能读 PKI 目录的本机运维」而非 admin 令牌。

// bootstrapFlags 离线模式的开关；返回 true 表示已处理并应退出。
func runBootstrap() bool {
	gwID := flag.String("issue-gateway-cert", "",
		"离线签发 mTLS 客户端证书（值即证书 CN）：接入网关填网关 id（如 gw-1）；"+
			"站点组网填 ipsec- 前缀；控制面温备节点填 standby- 前缀（主机按前缀分权）。写入 -out 后退出")
	out := flag.String("out", "", "证书输出目录（与 -issue-gateway-cert 搭配）")
	flag.Parse()

	if *gwID == "" {
		return false
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "需同时指定 -out <目录>")
		os.Exit(2)
	}
	if err := issueGatewayBundle(*gwID, *out); err != nil {
		slog.Error("离线签发网关身份材料失败", "gwid", *gwID, "err", err)
		os.Exit(1)
	}
	return true
}

// issueGatewayBundle 签发并落盘网关所需的全部身份材料：
// 客户端证书/私钥（mTLS 机器身份）+ CA 公证书（校验控制面）+ 敲门公钥（验令牌）。
func issueGatewayBundle(gwID, outDir string) error {
	cfg := config.Load()

	// 与 control 运行期用同一套材料：CA 与密钥都是幂等的 LoadOrCreate，
	// 先跑 bootstrap 还是先起 control 都行。
	ca, err := pki.LoadOrCreate(cfg.PKIDir)
	if err != nil {
		return fmt.Errorf("内部 CA: %w", err)
	}
	keys, err := auth.LoadOrCreateKeys(cfg.JWTKeyPath, cfg.JWTKnockKeyPath, cfg.JWTWebKeyPath, nil, false)
	if err != nil {
		return fmt.Errorf("签名密钥: %w", err)
	}

	iss, err := ca.IssueClient(gwID)
	if err != nil {
		return fmt.Errorf("签发客户端证书: %w", err)
	}

	// 登记指纹白名单——不登记的话握手会被 VerifyPeerCertificate 拒（吊销执行点）。
	st, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("打开库: %w", err)
	}
	defer st.Close()
	if err := st.SaveGatewayCert(context.Background(), store.GatewayCert{
		Fingerprint: iss.Fingerprint, GatewayID: gwID,
		NotAfter: iss.NotAfter.Format("2006-01-02 15:04:05"),
	}); err != nil {
		return fmt.Errorf("登记证书指纹: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"gw.crt.pem", []byte(iss.CertPEM), 0o644},
		{"gw.key.pem", []byte(iss.KeyPEM), 0o600}, // 网关私钥
		{"ca.crt.pem", ca.CertPEM(), 0o644},
		{"knock.pub", keys.KnockPublicPEM(), 0o644}, // SPA 敲门监听用；会话令牌在数据面验不过
		// 七层 Web 代理监听用。与 knock.pub 分开签、分开发：拿错路径的票据在对面连签名都验不过。
		{"web.pub", keys.WebPublicPEM(), 0o644},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(outDir, f.name), f.data, f.perm); err != nil {
			return fmt.Errorf("写 %s: %w", f.name, err)
		}
	}

	slog.Info("网关身份材料已签发",
		"gwid", gwID, "out", outDir, "指纹", iss.Fingerprint[:16]+"…",
		"有效期至", iss.NotAfter.Format("2006-01-02"), "knockKid", keys.KnockKid(), "webKid", keys.WebKid())
	fmt.Printf("✓ 网关 %s 的身份材料已写入 %s（gw.crt.pem / gw.key.pem / ca.crt.pem / knock.pub / web.pub）\n", gwID, outDir)
	return nil
}
