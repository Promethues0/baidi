// Command baidi-tun 是白帝客户端数据面 CLI：用 TUN（macOS utun / Linux tun / Windows wintun）
// 真正接管系统流量进隧道。引擎在 internal/dataplane（与移动端 gomobile 库共享）。
// 需管理员/root（创建 TUN、配 IP/路由）。平台接口配置见 ifup_{darwin,linux,windows}.go。
// Windows 还需运行目录有 wintun.dll（https://www.wintun.net/）。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"os"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"golang.zx2c4.com/wireguard/tun"

	"baidi.dev/gateway/internal/dataplane"
	"baidi.dev/gateway/internal/gmcert"
)

const mtu = 1420

func main() {
	tunName := flag.String("tun", defaultTunName, "TUN 设备名（macOS 必须 utun*；Linux/Windows 任意如 baidi0）")
	tunIP := flag.String("ip", "10.99.0.2", "TUN 接口 IP")
	route := flag.String("route", "10.99.0.0/24", "引流进隧道的受保护网段")
	spaAddr := flag.String("spa", "127.0.0.1:18201", "网关 SPA 敲门地址")
	proxyAddr := flag.String("proxy", "127.0.0.1:18443", "网关隧道代理地址")
	token := flag.String("token", "", "baidi-control 签发的 JWT")
	gm := flag.Bool("gm", false, "隧道用国密 TLCP，否则通用 TLS")
	caDir := flag.String("ca", "certs", "CA 证书目录（国密隧道校验网关证书链）")
	serverName := flag.String("servername", "baidi-gateway", "校验的服务器名（须在网关证书 SAN 内）")
	insecure := flag.Bool("insecure", false, "跳过证书校验（仅排障）")
	resmapPath := flag.String("resmap", "", "VIP:port→资源id 映射 JSON（多资源路由；空=用 -resource 默认）")
	defaultRes := flag.String("resource", "", "默认资源 id（resmap 未命中时用；空=网关回退默认后端）")
	control := flag.String("control", "", "baidi-control 地址；设了则换短时效一次性令牌 + 定期保活续窗（推荐）")
	reknock := flag.Duration("reknock", 15*time.Second, "敲门保活间隔（须 < 网关 SPA TTL；-control 模式生效）")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	// 令牌优先取 -token；为空则回退 BAIDI_TOKEN 环境变量（避免出现在 ps 进程参数里泄露）。
	if *token == "" {
		*token = os.Getenv("BAIDI_TOKEN")
	}
	if *token == "" {
		log.Fatal("需 -token 或 BAIDI_TOKEN 环境变量（baidi-control 签发的 JWT）")
	}

	// 国密隧道客户端配置：默认 CA 根校验，-insecure 仅排障
	tlcpCfg := &tlcp.Config{ServerName: *serverName}
	if *gm {
		if *insecure {
			tlcpCfg.InsecureSkipVerify = true
		} else {
			if *serverName == "" {
				log.Fatal("非 -insecure 模式必须指定非空 -servername（须命中网关证书 SAN）")
			}
			pool, err := gmcert.LoadCAPool(*caDir)
			if err != nil {
				log.Fatalf("加载 CA 失败（-ca 指目录或 -insecure 跳过）: %v", err)
			}
			tlcpCfg.RootCAs = pool
		}
	}

	resmap := map[string]string{}
	if *resmapPath != "" {
		b, err := os.ReadFile(*resmapPath)
		if err != nil {
			log.Fatalf("读取 resmap 失败: %v", err)
		}
		if err := json.Unmarshal(b, &resmap); err != nil {
			log.Fatalf("解析 resmap 失败: %v", err)
		}
	}

	// ① 创建 utun（需 root）② 配 IP + 把受保护网段路由进 TUN（需 root，平台实现）
	dev, err := tun.CreateTUN(*tunName, mtu)
	if err != nil {
		log.Fatalf("创建 TUN 失败（需 root：sudo）: %v", err)
	}
	name, _ := dev.Name()
	slog.Info("TUN 已创建", "dev", name, "mtu", mtu)
	if err := ifup(name, *tunIP, *route); err != nil {
		log.Fatalf("配置 TUN 失败: %v", err)
	}
	slog.Info("受保护网段已引流进 TUN（系统流量接管）", "route", *route, "via", name)

	// ③ 跑共享数据面引擎（阻塞）
	cfg := &dataplane.Config{
		SpaAddr: *spaAddr, ProxyAddr: *proxyAddr, Token: *token, Control: *control,
		Gm: *gm, TLCPConfig: tlcpCfg, Resmap: resmap, DefaultRes: *defaultRes,
		Reknock: *reknock, MTU: mtu,
	}
	if err := dataplane.Run(dev, cfg); err != nil {
		log.Fatalf("数据面退出: %v", err)
	}
}
