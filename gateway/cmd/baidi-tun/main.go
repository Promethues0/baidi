// Command baidi-tun 是白帝客户端数据面：用 TUN（macOS utun / Linux tun / Windows wintun）
// 真正接管系统流量进隧道。
//
//	受保护网段路由进 TUN → gVisor 用户态网络栈终止 TCP → 每条流 SPA 敲门 + 拨网关隧道(TLS/国密TLCP) → 后端业务
//
// 即”先认证后连接”落到真实链路：未敲门时网关隐身；应用访问受保护资源时由本进程透明引流加密。
// 需管理员/root（创建 TUN、配 IP/路由）。平台相关的接口配置见 ifup_{darwin,linux,windows}.go。
// Windows 还需运行目录有 wintun.dll（https://www.wintun.net/）。
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"golang.zx2c4.com/wireguard/tun"

	"baidi.dev/gateway/internal/gmcert"
	"baidi.dev/gateway/internal/knock"

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
	// 入站读缓冲须容纳「去分段后的最大单包」而非链路 MTU：Linux 开 IFF_VNET_HDR(GRO/USO) 时
	// 一次 Read 可吐出 >MTU 的合并包，wireguard 契约缓冲尺寸为 64KiB。若只给 mtu 大小，
	// UDP-USO 大包会令 gsoSplit 写越界 panic、整进程崩。统一用 64KiB（约 128*64KiB≈8MB，可接受）。
	maxSegSize = 65535
)

func main() {
	tunName := flag.String("tun", defaultTunName, "TUN 设备名（macOS 必须 utun*；Linux/Windows 任意如 baidi0）")
	tunIP := flag.String("ip", "10.99.0.2", "utun 接口 IP")
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
	control := flag.String("control", "", "baidi-control 地址；设了则换短时效一次性敲门令牌+定期保活续窗（推荐），否则逐流用会话令牌敲门")
	reknock := flag.Duration("reknock", 15*time.Second, "敲门保活间隔（须 < 网关 SPA TTL；-control 模式生效）")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if *token == "" {
		log.Fatal("需 -token（baidi-control 签发的 JWT）")
	}

	// 国密隧道客户端配置：默认 CA 根校验，-insecure 仅排障
	tlcpCfg := &tlcp.Config{ServerName: *serverName}
	if *gm {
		if *insecure {
			tlcpCfg.InsecureSkipVerify = true
		} else {
			if *serverName == "" {
				log.Fatal("非 -insecure 模式必须指定非空 -servername（须命中网关证书 SAN）；空 ServerName 会静默关闭主机名校验")
			}
			pool, err := gmcert.LoadCAPool(*caDir)
			if err != nil {
				log.Fatalf("加载 CA 失败（-ca 指目录或 -insecure 跳过）: %v", err)
			}
			tlcpCfg.RootCAs = pool
		}
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
	cfg := &tunnelCfg{spa: *spaAddr, proxy: *proxyAddr, token: *token, control: *control, gm: *gm, tlcpCfg: tlcpCfg, resmap: resmap, defaultRes: *defaultRes}
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

	// ④ -control 模式：用短时效一次性令牌敲门并定期保活续窗（逐流不再敲）
	if *control != "" {
		cfg.knock() // 启动即开窗
		go func() {
			t := time.NewTicker(*reknock)
			defer t.Stop()
			for range t.C {
				cfg.knock()
			}
		}()
		slog.Info("敲门保活：定期换短时效一次性令牌续窗", "control", *control, "interval", reknock.String())
	}

	// ⑤ 双向泵：utun ⇄ 网络栈
	go pumpInbound(dev, linkEP)
	pumpOutbound(dev, linkEP)
}

type tunnelCfg struct {
	spa, proxy, token, control string
	gm                         bool
	tlcpCfg                    *tlcp.Config
	resmap                     map[string]string // VIP:port → resource-id
	defaultRes                 string
}

// knock 发一次 SPA 敲门：有 -control 则换取短时效一次性令牌，否则用会话令牌。
func (c *tunnelCfg) knock() {
	tok := c.token
	if c.control != "" {
		if kt, err := knock.FetchToken(c.control, c.token); err == nil {
			tok = kt
		} else {
			slog.Warn("取短时效敲门令牌失败，回退会话令牌", "err", err.Error())
		}
	}
	uc, err := net.Dial("udp", c.spa)
	if err != nil {
		slog.Warn("SPA 拨号失败", "err", err.Error())
		return
	}
	defer uc.Close()
	if sealed, e := knock.Seal(tok); e == nil {
		_, _ = uc.Write(sealed)
	}
}

// tunnel 把一条被 utun 捕获的 TCP 流，经 SPA 敲门后拨入网关隧道并双向拷贝。
func (c *tunnelCfg) tunnel(local net.Conn, dst string) {
	defer local.Close()
	// 无 -control 时退化为逐流敲门（会话令牌）；有 -control 时由后台保活循环持续开窗，此处不再敲。
	if c.control == "" {
		c.knock()
		time.Sleep(120 * time.Millisecond)
	}

	var remote net.Conn
	var err error
	d := &net.Dialer{Timeout: 5 * time.Second}
	if c.gm {
		remote, err = tlcp.DialWithDialer(d, "tcp", c.proxy, c.tlcpCfg)
	} else {
		remote, err = tls.DialWithDialer(d, "tcp", c.proxy, &tls.Config{InsecureSkipVerify: true})
	}
	if err != nil {
		slog.Warn("隧道拨号失败（未敲门成功/网关隐身?）", "dst", dst, "err", err.Error())
		return
	}
	defer remote.Close()
	// 目标前导：把捕获到的 VIP:port 映射成资源 id 告诉网关（多资源路由）；空则网关回退默认后端
	rid := c.resmap[dst]
	if rid == "" {
		rid = c.defaultRes
	}
	if rid != "" {
		_, _ = remote.Write([]byte("CONNECT " + rid + "\n"))
	}
	slog.Info("utun 引流 · 经隧道转发", "captured_dst", dst, "resource", rid, "via", c.proxy, "gm", c.gm)
	go func() { _, _ = io.Copy(remote, local) }()
	_, _ = io.Copy(local, remote)
}

// pumpInbound：从 utun 读 IP 包注入网络栈。
func pumpInbound(dev tun.Device, ep *channel.Endpoint) {
	bufs := make([][]byte, dev.BatchSize())
	sizes := make([]int, dev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, offset+maxSegSize) // 容纳 GRO/USO 合并包，避免 Linux 越界 panic
	}
	for {
		n, err := dev.Read(bufs, sizes, offset)
		if err != nil {
			// 入站泵死掉会让隧道静默半死（出站还活）；宁可整进程退出由 systemd/用户重启
			log.Fatalf("TUN 读失败，数据面退出: %v", err)
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

// ifup（配置 TUN 接口 IP + 受保护网段路由）按平台实现，见 ifup_{darwin,linux,windows}.go。
