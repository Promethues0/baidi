// Command baidi-knock 是 SPA 敲门器（客户端数据面的一部分）：
// 向网关 SPA 端口发一个携带 JWT 身份令牌的 UDP 包，请求放行本机源 IP。
// 桌面客户端"接入"时由 Tauri sidecar 调用本程序完成真实敲门。
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	spaAddr := flag.String("spa", "127.0.0.1:18201", "网关 SPA 敲门地址")
	token := flag.String("token", "", "baidi-control 签发的 JWT（身份令牌）")
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "用法：baidi-knock -spa <ip:port> -token <JWT>")
		os.Exit(2)
	}
	conn, err := net.Dial("udp", *spaAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法连接网关 SPA 端口:", err)
		os.Exit(1)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(*token)); err != nil {
		fmt.Fprintln(os.Stderr, "敲门包发送失败:", err)
		os.Exit(1)
	}
	fmt.Printf("✓ SPA 敲门已发送 → %s（携带身份令牌；网关将放行本机源 IP 一个 TTL 窗口）\n", *spaAddr)
}
