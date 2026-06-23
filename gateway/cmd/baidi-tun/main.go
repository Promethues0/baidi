//go:build darwin

// Command baidi-tun 是白帝客户端数据面：用 utun 真正接管系统流量进隧道。
//
//	受保护网段路由进 utun → gVisor 用户态网络栈终止 TCP → 每条流 SPA 敲门 + 拨网关隧道(TLS/国密TLCP) → 后端业务
//
// 即“先认证后连接”落到真实链路：未敲门时网关隐身；应用访问受保护资源时由本进程透明引流加密。
// 需 root（创建 utun、配 IP/路由）。演示：受保护网段内任一 VIP → 网关 → 其后端业务。
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	mtu    = 1420
	offset = 4 // macOS utun 读写在包前留 4 字节地址族头（见 wireguard tun_darwin）
)

func main() {
	tunName := flag.String("tun", "utun", "utun 设备名（macOS 内核分配 utunN）")
	tunIP := flag.String("ip", "10.99.0.2", "utun 接口 IP")
	route := flag.String("route", "10.99.0.0/24", "引流进隧道的受保护网段")
	spaAddr := flag.String("spa", "127.0.0.1:18201", "网关 SPA 敲门地址")
	proxyAddr := flag.String("proxy", "127.0.0.1:18443", "网关隧道代理地址")
	token := flag.String("token", "", "baidi-control 签发的 JWT")
	gm := flag.Bool("gm", false, "隧道用国密 TLCP，否则通用 TLS")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if *token == "" {
		log.Fatal("需 -token（baidi-control 签发的 JWT）")
	}

	// ① 创建 utun（需 root）
	dev, err := tun.CreateTUN(*tunName, mtu)
	if err != nil {
		log.Fatalf("创建 utun 失败（需 root：sudo）: %v", err)
	}
	name, _ := dev.Name()
	slog.Info("utun 已创建", "dev", name, "mtu", mtu)

	// ② 配 IP + 把受保护网段路由进 utun（需 root）
	if err := ifup(name, *tunIP, *route); err != nil {
		log.Fatalf("配置 utun 失败: %v", err)
	}
	slog.Info("受保护网段已引流进 utun（系统流量接管）", "route", *route, "via", name)

	// ③ gVisor 用户态网络栈：终止从 utun 进来的 TCP
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	linkEP := channel.New(512, uint32(mtu), "")
	if e := s.CreateNIC(1, linkEP); e != nil {
		log.Fatalf("CreateNIC: %v", e)
	}
	_ = s.SetPromiscuousMode(1, true) // 接收发往任意（受保护）地址的包
	_ = s.SetSpoofing(1, true)        // 允许以被访问的目的地址回包
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	cfg := &tunnelCfg{spa: *spaAddr, proxy: *proxyAddr, token: *token, gm: *gm}
	fwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := net.JoinHostPort(id.LocalAddress.String(), fmt.Sprint(id.LocalPort))
		var wq waiter.Queue
		ep, e := r.CreateEndpoint(&wq)
		if e != nil {
			slog.Warn("CreateEndpoint 失败", "dst", dst, "err", e.String())
			r.Complete(true)
			return
		}
		r.Complete(false)
		go cfg.tunnel(gonet.NewTCPConn(&wq, ep), dst)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	slog.Info("数据面就绪：utun→netstack→隧道", "spa", *spaAddr, "proxy", *proxyAddr, "gm", *gm)

	// ④ 双向泵：utun ⇄ 网络栈
	go pumpInbound(dev, linkEP)
	pumpOutbound(dev, linkEP)
}

type tunnelCfg struct {
	spa, proxy, token string
	gm                bool
}

// tunnel 把一条被 utun 捕获的 TCP 流，经 SPA 敲门后拨入网关隧道并双向拷贝。
func (c *tunnelCfg) tunnel(local net.Conn, dst string) {
	defer local.Close()
	// SPA 敲门（携带 JWT），先认证后连接
	if uc, err := net.Dial("udp", c.spa); err == nil {
		_, _ = uc.Write([]byte(c.token))
		_ = uc.Close()
	}
	time.Sleep(120 * time.Millisecond)

	var remote net.Conn
	var err error
	d := &net.Dialer{Timeout: 5 * time.Second}
	if c.gm {
		remote, err = tlcp.DialWithDialer(d, "tcp", c.proxy, &tlcp.Config{InsecureSkipVerify: true})
	} else {
		remote, err = tls.DialWithDialer(d, "tcp", c.proxy, &tls.Config{InsecureSkipVerify: true})
	}
	if err != nil {
		slog.Warn("隧道拨号失败（未敲门成功/网关隐身?）", "dst", dst, "err", err.Error())
		return
	}
	defer remote.Close()
	slog.Info("utun 引流 · 经隧道转发", "captured_dst", dst, "via", c.proxy, "gm", c.gm)
	go func() { _, _ = io.Copy(remote, local) }()
	_, _ = io.Copy(local, remote)
}

// pumpInbound：从 utun 读 IP 包注入网络栈。
func pumpInbound(dev tun.Device, ep *channel.Endpoint) {
	bufs := make([][]byte, dev.BatchSize())
	sizes := make([]int, dev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, offset+mtu+4)
	}
	for {
		n, err := dev.Read(bufs, sizes, offset)
		if err != nil {
			slog.Error("utun 读失败", "err", err.Error())
			return
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			pkt := bufs[i][offset : offset+sizes[i]]
			var proto tcpip.NetworkProtocolNumber
			switch pkt[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
			ep.InjectInbound(proto, pb)
			pb.DecRef()
		}
	}
}

// pumpOutbound：从网络栈取回包写回 utun。
func pumpOutbound(dev tun.Device, ep *channel.Endpoint) {
	for {
		pb := ep.ReadContext(context.Background())
		if pb == nil {
			return
		}
		v := pb.ToView()
		data := v.AsSlice()
		out := make([]byte, offset+len(data))
		copy(out[offset:], data)
		_, err := dev.Write([][]byte{out}, offset)
		v.Release()
		pb.DecRef()
		if err != nil {
			slog.Error("utun 写失败", "err", err.Error())
		}
	}
}

// ifup 配置 utun 接口 IP 并把受保护网段路由进该接口（darwin，需 root）。
func ifup(dev, ip, route string) error {
	if err := sh("ifconfig", dev, "inet", ip, ip, "up"); err != nil {
		return err
	}
	return sh("route", "-q", "-n", "add", "-net", route, "-interface", dev)
}

func sh(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil
}
