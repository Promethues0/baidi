// Command baidi-knock 是 SPA 敲门器（客户端数据面的一部分）：
// 向网关 SPA 端口发一个携带 JWT 身份令牌的 UDP 包，请求放行本机源 IP。
// 桌面客户端"接入"时由 Tauri sidecar 调用本程序完成真实敲门。
//
// -control 必填（网关默认 strict）：先用会话令牌向 baidi-control 换取**短时效一次性敲门令牌**
// （带 jti + use=knock），网关按 jti 单次放行——即便令牌被嗅探解出也无法主动重放。
// 会话令牌自身不再能敲门：那会绕过控制面的强制下线/账号禁用/终端合规三道闸。
package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"baidi.dev/gateway/internal/knock"
)

func main() {
	spaAddr := flag.String("spa", "127.0.0.1:18201", "网关 SPA 敲门地址")
	token := flag.String("token", "", "baidi-control 签发的会话 JWT")
	control := flag.String("control", "", "baidi-control 地址(如 http://127.0.0.1:8090)；必填，敲门令牌的唯一合规来源")
	device := flag.String("device", "", "终端硬件指纹（与 posture 上报同一个值）：授信终端准入闸的判据，严格模式下必填")
	flag.Parse()

	if *token == "" || *control == "" {
		fmt.Fprintln(os.Stderr, "用法：baidi-knock -spa <ip:port> -token <JWT> -control <url>")
		os.Exit(2)
	}

	// 会话令牌只用来换取敲门令牌，绝不直接敲门——网关 strict 模式会拒。
	knockTok, ferr := knock.FetchToken(*control, *token, *device)
	if ferr != nil {
		fmt.Fprintln(os.Stderr, "获取短时效敲门令牌失败:", ferr)
		os.Exit(1)
	}

	conn, err := net.Dial("udp", *spaAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法连接网关 SPA 端口:", err)
		os.Exit(1)
	}
	defer conn.Close()
	sealed, err := knock.Seal(knockTok)
	if err != nil {
		fmt.Fprintln(os.Stderr, "封装敲门包失败:", err)
		os.Exit(1)
	}
	if _, err := conn.Write(sealed); err != nil {
		fmt.Fprintln(os.Stderr, "敲门包发送失败:", err)
		os.Exit(1)
	}
	fmt.Printf("✓ SPA 敲门已发送 → %s（短时效一次性令牌；网关将放行本机源 IP 一个 TTL 窗口）\n", *spaAddr)
}
