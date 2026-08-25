package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"

	"baidi.dev/gateway/internal/gmcert"
)

// 国密 TLCP 路径的证书钉扎，与通用 TLS 路径（pin_test.go）同构的三条防线。
//
// ★为什么必须单独测一遍：这条路径此前**完全没有服务端认证**——
//   - 网关侧专门算了 TLCP 签名证书指纹上报（cmd/baidi-gateway/main.go），
//   - 控制面经剖面下发到客户端，
//   - 而 dialEndpoint 的 gm 分支不读它，桌面客户端又恒传 -insecure。
// 三处注释各自看着合理，合起来是「谁都没在校验」，而 gm 是**默认开**的。
// 只测通用 TLS 那条不足以发现它：两条路径的信任材料与代码分支完全不同。
//
// 这里跑的是**真实 TLCP 握手**而不是只调回调：gotlcp 文档说
// 「InsecureSkipVerify 不影响 VerifyPeerCertificate 运行」，这条修复整个建立在
// 那句话上——必须用真握手把它钉死，否则升级 gotlcp 时行为变了这里也不会红。
func tlcpServer(t *testing.T) (addr string, pin string, stop func()) {
	t.Helper()
	certs, err := gmcert.EnsureGateway(t.TempDir())
	if err != nil {
		t.Skipf("本机生成国密双证书失败，跳过：%v", err)
	}
	if len(certs) == 0 || len(certs[0].Certificate) == 0 {
		t.Skip("未拿到国密证书")
	}
	sum := sha256.Sum256(certs[0].Certificate[0]) // 与网关 certFingerprint 同口径：签名证书
	pin = hex.EncodeToString(sum[:])

	ln, err := tlcp.Listen("tcp", "127.0.0.1:0", &tlcp.Config{Certificates: certs})
	if err != nil {
		t.Fatalf("TLCP 监听失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = c.Write([]byte("ok")); _ = c.Close() }()
		}
	}()
	return ln.Addr().String(), pin, func() { _ = ln.Close() }
}

func dialTLCPPinned(addr, pin string) error {
	cfg := &tlcp.Config{InsecureSkipVerify: true} // 参考部署的形态：无国密 CA
	if pin != "" {
		cfg.VerifyPeerCertificate = PinVerifierTLCP(pin)
	}
	c, err := tlcp.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func Test国密隧道_指纹对上则握手成功(t *testing.T) {
	addr, pin, stop := tlcpServer(t)
	defer stop()
	if err := dialTLCPPinned(addr, pin); err != nil {
		t.Fatalf("正确指纹应握手成功，实得: %v", err)
	}
}

// 这条是整个修复的意义所在：改造前它**必然通过**（因为根本没人校验）。
func Test国密隧道_指纹对不上必须拒绝握手(t *testing.T) {
	addr, _, stop := tlcpServer(t)
	defer stop()
	wrong := strings.Repeat("ab", 32) // 64 位 hex，形态合法但不是这张证书
	err := dialTLCPPinned(addr, wrong)
	if err == nil {
		t.Fatal("指纹不匹配必须中止握手——通过即意味着中间人可直接冒充网关（gm 是默认开的）")
	}
	if !strings.Contains(err.Error(), "指纹不匹配") {
		t.Fatalf("拒绝理由要说得出是钉扎不匹配（排障时才不会去查网络），实得: %v", err)
	}
}

// 未下发指纹时退化为不认证——**行为与改造前一致**，但那是有意的降级而非疏漏：
// dialEndpoint 在这条路上会打 WARN，姿态回执也会在启动日志里写明「零认证」。
func Test国密隧道_无指纹时退化为不认证(t *testing.T) {
	addr, _, stop := tlcpServer(t)
	defer stop()
	if err := dialTLCPPinned(addr, ""); err != nil {
		t.Fatalf("无指纹应仍能连（加密不认证），实得: %v", err)
	}
}
