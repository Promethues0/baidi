// Package dataplane 是白帝客户端数据面的平台无关引擎：
//
//	TUN 设备 → gVisor 用户态网络栈终止 TCP → 每条流 SPA 敲门 + 拨网关隧道(TLS/国密TLCP) → 后端业务
//
// 桌面 CLI(baidi-tun) 自建 utun 后调 Run；移动端(baidimobile, gomobile)用平台 VPN 扩展给的 TUN fd
// 包成 tun.Device 后调 Run。两者共享同一引擎，只是 TUN 的来源与接口配置不同。
package dataplane

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"golang.zx2c4.com/wireguard/tun"

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
	offset = 4 // macOS utun 读写在包前留 4 字节地址族头；linux/windows 用 4 同样兼容
	// 入站读缓冲须容纳「去分段后的最大单包」(GRO/USO 合并包可 >MTU)，否则 Linux gsoSplit 越界 panic。
	maxSegSize = 65535
)

// Config 数据面运行参数。
type Config struct {
	SpaAddr    string            // 网关 SPA 敲门 host:port
	ProxyAddr  string            // 网关隧道代理 host:port
	Token      string            // baidi-control 签发的会话 JWT
	Control    string            // baidi-control 地址（必填）：敲门令牌的唯一合规来源
	Gm         bool              // 隧道用国密 TLCP
	TLCPConfig *tlcp.Config      // 调用方预构建（CA 池 + ServerName）
	Resmap     map[string]string // VIP:port → 资源 id
	DefaultRes string            // 默认资源 id
	Reknock    time.Duration     // 保活间隔（Control 模式）
	MTU        int               // 链路 MTU（默认 1420）
}

// Run 启动数据面，阻塞直到 dev 关闭/出错（关闭 dev 即可优雅停止）。
func Run(dev tun.Device, cfg *Config) error {
	// Control 是敲门令牌的唯一合规来源：网关 strict 模式只认 /knock-token 签发的
	// use=knock 短时效令牌，没有 control 就无从取得，早失败好过起来后静默连不通。
	if strings.TrimSpace(cfg.Control) == "" {
		return errors.New("必须配置控制中心地址（敲门令牌的唯一合规来源）")
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1420
	}
	if cfg.Reknock <= 0 {
		cfg.Reknock = 15 * time.Second
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	linkEP := channel.New(512, uint32(mtu), "")
	if e := s.CreateNIC(1, linkEP); e != nil {
		return fmt.Errorf("CreateNIC: %s", e)
	}
	_ = s.SetPromiscuousMode(1, true) // 接收发往任意（受保护）地址的包
	_ = s.SetSpoofing(1, true)        // 允许以被访问的目的地址回包
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	t := &tunneler{cfg: cfg, deny: make(chan error, 1)}
	fwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		var wq waiter.Queue
		ep, e := r.CreateEndpoint(&wq)
		if e != nil {
			slog.Warn("CreateEndpoint 失败", "dst", dst, "err", e.String())
			r.Complete(true)
			return
		}
		r.Complete(false)
		go t.tunnel(gonet.NewTCPConn(&wq, ep), dst)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	slog.Info("数据面就绪：TUN→netstack→隧道", "proxy", cfg.ProxyAddr, "gm", cfg.Gm)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 短时效一次性令牌敲门 + 定期保活续窗（逐流不再敲）
	t.knock()
	go func() {
		tk := time.NewTicker(cfg.Reknock)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				t.knock()
			}
		}
	}()
	slog.Info("敲门保活：定期换短时效一次性令牌续窗", "control", cfg.Control, "interval", cfg.Reknock.String())

	go pumpOutbound(ctx, dev, linkEP, offset)

	// pumpInbound 阻塞在 dev.Read；放 goroutine 里，主协程同时监听 control 定性拒绝。
	inbound := make(chan error, 1)
	go func() { inbound <- pumpInbound(dev, linkEP, mtu) }()

	select {
	case err := <-inbound: // dev 关闭/读错（含调用方主动停）
		cancel()
		return err
	case derr := <-t.deny: // 强制下线/账号禁用：停掉数据面并带出原因
		slog.Warn("接入被控制面拒绝，停止数据面", "err", derr.Error())
		cancel()
		_ = dev.Close() // 打断 pumpInbound
		<-inbound       // 等其退出
		return derr
	}
}

type tunneler struct {
	cfg      *Config
	deny     chan error // control 定性拒绝（403：强制下线/账号禁用）单次上报，供 Run 停机
	denyOnce sync.Once
}

// knock 发一次 SPA 敲门：向 control 换取短时效一次性令牌（use=knock），换不到就不敲。
//
// ★绝不回退会话令牌：网关 strict 模式只认 control 签发的敲门令牌，回退包必被丢弃，
// 只会制造"日志显示已敲门、实际窗口到期即断"的假象。控制面不可达时窗口自然过期
// 是 fail-closed 的正确姿态——零信任下失去策略源就该收窗，而不是拿长效令牌硬撑。
// 遇 control 定性拒绝（ErrDenied）向 deny 通道上报一次，让 Run 停机并带出原因。
func (t *tunneler) knock() {
	tok, err := knock.FetchToken(t.cfg.Control, t.cfg.Token)
	switch {
	case err == nil:
	case errors.Is(err, knock.ErrDenied):
		t.denyOnce.Do(func() { t.deny <- err })
		return
	default:
		// 瞬时错误：本轮不敲门，等下一次 reknock 重试（间隔须显著小于网关 SPA 放行 TTL，
		// 否则 control 抖动会直接关窗——这是 fail-closed 的代价，须靠 reknock 频度补偿）。
		slog.Warn("取短时效敲门令牌失败，本轮放弃敲门（等待下轮 reknock 重试）", "err", err.Error())
		return
	}
	uc, err := net.Dial("udp", t.cfg.SpaAddr)
	if err != nil {
		slog.Warn("SPA 拨号失败", "err", err.Error())
		return
	}
	defer uc.Close()
	if sealed, e := knock.Seal(tok); e == nil {
		_, _ = uc.Write(sealed)
	}
}

// tunnel 把一条被 TUN 捕获的 TCP 流，经 SPA 敲门后拨入网关隧道并双向拷贝。
func (t *tunneler) tunnel(local net.Conn, dst string) {
	defer local.Close()
	c := t.cfg

	var remote net.Conn
	var err error
	d := &net.Dialer{Timeout: 5 * time.Second}
	if c.Gm {
		remote, err = tlcp.DialWithDialer(d, "tcp", c.ProxyAddr, c.TLCPConfig)
	} else {
		remote, err = tls.DialWithDialer(d, "tcp", c.ProxyAddr, &tls.Config{InsecureSkipVerify: true})
	}
	if err != nil {
		slog.Warn("隧道拨号失败（未敲门成功/网关隐身?）", "dst", dst, "err", err.Error())
		return
	}
	defer remote.Close()
	rid := c.Resmap[dst]
	if rid == "" {
		rid = c.DefaultRes
	}
	if rid != "" {
		_, _ = remote.Write([]byte("CONNECT " + rid + "\n"))
	}
	slog.Info("引流 · 经隧道转发", "captured_dst", dst, "resource", rid, "via", c.ProxyAddr, "gm", c.Gm)
	go func() { _, _ = io.Copy(remote, local) }()
	_, _ = io.Copy(local, remote)
}

// pumpInbound：从 TUN 读 IP 包注入网络栈；dev 读错（关闭）即返回该错误。
func pumpInbound(dev tun.Device, ep *channel.Endpoint, mtu int) error {
	bufs := make([][]byte, dev.BatchSize())
	sizes := make([]int, dev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, offset+maxSegSize)
	}
	for {
		n, err := dev.Read(bufs, sizes, offset)
		if err != nil {
			return err
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

// pumpOutbound：从网络栈取回包写回 TUN；ctx 取消即返回。
func pumpOutbound(ctx context.Context, dev tun.Device, ep *channel.Endpoint, off int) {
	for {
		pb := ep.ReadContext(ctx)
		if pb == nil {
			return
		}
		v := pb.ToView()
		data := v.AsSlice()
		out := make([]byte, off+len(data))
		copy(out[off:], data)
		_, err := dev.Write([][]byte{out}, off)
		v.Release()
		pb.DecRef()
		if err != nil {
			slog.Error("TUN 写失败", "err", err.Error())
		}
	}
}
