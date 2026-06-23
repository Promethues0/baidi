// Command baidi-tlcp-probe 验证国密 TLCP 隧道：SPA 敲门(携带 JWT) → 国密 TLCP 握手 → 取后端响应。
// 普通 curl 不支持国密 TLCP，故用本探针验证“先认证后连接 + 国密加密”整链。
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
)

func main() {
	spaAddr := flag.String("spa", "127.0.0.1:18201", "网关 SPA 敲门地址")
	proxyAddr := flag.String("proxy", "127.0.0.1:18443", "网关 TLCP 代理地址")
	token := flag.String("token", "", "baidi-control 签发的 JWT")
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "需 -token")
		os.Exit(2)
	}
	// ① SPA 敲门
	if c, err := net.Dial("udp", *spaAddr); err == nil {
		_, _ = c.Write([]byte(*token))
		_ = c.Close()
	} else {
		fmt.Fprintln(os.Stderr, "SPA 端口不可达:", err)
		os.Exit(1)
	}
	time.Sleep(400 * time.Millisecond)

	// ② 国密 TLCP 握手（自签 CA，演示跳过校验）
	conn, err := tlcp.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}, "tcp", *proxyAddr, &tlcp.Config{InsecureSkipVerify: true})
	if err != nil {
		fmt.Println("✗ 国密 TLCP 握手失败（可能未敲门/网关未启国密）:", err)
		os.Exit(1)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	fmt.Printf("✓ 国密 TLCP 握手成功  version=0x%04X  cipher=0x%04X（%s）\n", st.Version, st.CipherSuite, cipherName(st.CipherSuite))

	// ③ 经国密隧道取后端业务响应
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: baidi\r\n\r\n"))
	buf := make([]byte, 200)
	n, _ := conn.Read(buf)
	if n > 0 {
		fmt.Printf("✓ 经国密隧道取到后端响应：\n%s\n", string(buf[:n]))
	} else {
		fmt.Println("✗ 隧道无响应")
	}
}

func cipherName(id uint16) string {
	switch id {
	case tlcp.ECC_SM4_CBC_SM3:
		return "ECC_SM4_CBC_SM3"
	case tlcp.ECC_SM4_GCM_SM3:
		return "ECC_SM4_GCM_SM3"
	case tlcp.ECDHE_SM4_CBC_SM3:
		return "ECDHE_SM4_CBC_SM3"
	case tlcp.ECDHE_SM4_GCM_SM3:
		return "ECDHE_SM4_GCM_SM3"
	default:
		return "SM 套件"
	}
}
