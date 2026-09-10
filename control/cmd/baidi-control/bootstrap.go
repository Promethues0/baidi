package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/buildinfo"
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
	// -version 打印本二进制的版本身份后退出（**一行 JSON**）。
	//
	// ★为什么是 JSON 而不是人话：它有两个机器消费方——
	//   ① 主机上的运维/部署脚本（"这台装的到底是哪个包"，改造前主机上没有任何版本戳）；
	//   ② **备机的 baidi-standby**：它要回答"我这台机器上那份 baidi-control 是哪一版"，
	//      而那正是切换那天真正会被启动的进程。人话格式一改，那条链就静默断了。
	// 输出里不含任何配置或凭据，任何用户都能跑。
	showVersion := flag.Bool("version", false, "打印版本身份（一行 JSON：semantic/commit/builtAt）后退出")
	flag.Parse()

	if *showVersion {
		bi := buildinfo.Current()
		b, err := json.Marshal(map[string]string{
			"component": "baidi-control",
			// 三个字段原样输出（**未注入即空串**）：在这里替换成"未注入"三个字，
			// 读它的 baidi-standby 就会把那三个字当成一个版本号往上报。
			"semantic": bi.Semantic, "commit": bi.Commit, "builtAt": bi.BuiltAt,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "序列化版本身份失败："+err.Error())
			os.Exit(1)
		}
		fmt.Println(string(b))
		return true
	}

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
// 客户端证书/私钥（mTLS 机器身份）+ CA 公证书（校验控制面）+ 三把验证公钥
// （敲门 / 七层票据 / L4 隧道身份票据）。
func issueGatewayBundle(gwID, outDir string) error {
	cfg := config.Load()

	// 与 control 运行期用同一套材料：CA 与密钥都是幂等的 LoadOrCreate，
	// 先跑 bootstrap 还是先起 control 都行。
	ca, err := pki.LoadOrCreate(cfg.PKIDir)
	if err != nil {
		return fmt.Errorf("内部 CA: %w", err)
	}
	keys, err := auth.LoadOrCreateKeys(cfg.JWTKeyPath, cfg.JWTKnockKeyPath, cfg.JWTWebKeyPath, cfg.JWTTunnelKeyPath, nil, false)
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
		// L4 隧道监听用（-jwt-tunnel-pubkey）。★这一份**必须随包发**：网关默认严格
		// （BAIDI_GW_TUNNEL_ID_STRICT=1），没装它的网关会拒绝启动而不是静默退回按源 IP 定身份。
		{"tunnel.pub", keys.TunnelPublicPEM(), 0o644},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(outDir, f.name), f.data, f.perm); err != nil {
			return fmt.Errorf("写 %s: %w", f.name, err)
		}
	}

	slog.Info("网关身份材料已签发",
		"gwid", gwID, "out", outDir, "指纹", iss.Fingerprint[:16]+"…",
		"有效期至", iss.NotAfter.Format("2006-01-02"),
		"knockKid", keys.KnockKid(), "webKid", keys.WebKid(), "tunnelKid", keys.TunnelKid())
	fmt.Printf("✓ 网关 %s 的身份材料已写入 %s（gw.crt.pem / gw.key.pem / ca.crt.pem / knock.pub / web.pub / tunnel.pub）\n", gwID, outDir)
	return nil
}
