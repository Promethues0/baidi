package ipsec

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// NetstackDatapath 用 gVisor 用户态协议栈冒充"隧道后面的那台主机"。
//
// # 它存在的唯一理由
//
// ★让「真实 TCP 跑过隧道」这件事能在**无 root、无 Docker、无真网卡**的条件下由
// go test 与 e2e 脚本直接验证。
//
// 没有它，验证链条最多只能做到"内存管道里的字节过去了"——而那个断言对
// 「加密其实是恒等变换」「隧道其实没建、流量走了旁路」这类问题几乎没有分辨力。
// 有了它，A 侧可以 `http.Get("http://10.60.0.9/")`、B 侧真的用 net.Listener 提供服务，
// 中间必须完整走过 SPD 选路 → ESP 封装 → UDP → 解封 → 反重放 → TS 校验 → 协议栈重组。
// 任何一环写错都会表现为"连不上"，而不是一个绿色的断言。
//
// # 与 internal/dataplane 的关系
//
// 用法同源（同一套 channel.Endpoint + InjectInbound/ReadContext 姿态），但方向相反：
// dataplane 是"从 TUN 收包注入协议栈、由协议栈终止 TCP 再拨出去"；这里是
// "协议栈自己发起/接受连接，产出的 IP 包交给 ESP 加密送走"。
type NetstackDatapath struct {
	stack *stack.Stack
	ep    *channel.Endpoint
	local netip.Prefix
	mtu   int
	proto tcpip.NetworkProtocolNumber

	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

// nsNICID 本栈里唯一那张网卡的编号。
const nsNICID tcpip.NICID = 1

// NewNetstackDatapath 建一个用户态协议栈，本机地址取 local.Addr()，
// 掩码取 local.Bits()（决定哪些地址算"同网段直连"）。
//
// mtu <= 0 时取 DefaultTunnelMTU。
func NewNetstackDatapath(local netip.Prefix, mtu int) (*NetstackDatapath, error) {
	if !local.IsValid() || !local.Addr().IsValid() {
		return nil, fmt.Errorf("ipsec: netstack 本机地址无效：%v", local)
	}
	if mtu <= 0 {
		mtu = DefaultTunnelMTU
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	ep := channel.New(512, uint32(mtu), "")
	if e := s.CreateNIC(nsNICID, ep); e != nil {
		s.Close()
		return nil, fmt.Errorf("ipsec: netstack CreateNIC 失败：%s", e)
	}

	proto := tcpip.NetworkProtocolNumber(header.IPv4ProtocolNumber)
	if local.Addr().Is6() && !local.Addr().Is4In6() {
		proto = header.IPv6ProtocolNumber
	}
	pa := tcpip.ProtocolAddress{
		Protocol: proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(local.Addr().Unmap().AsSlice()),
			PrefixLen: local.Bits(),
		},
	}
	if e := s.AddProtocolAddress(nsNICID, pa, stack.AddressProperties{}); e != nil {
		s.Close()
		return nil, fmt.Errorf("ipsec: netstack 配置地址 %s 失败：%s", local, e)
	}

	// 混杂 + 允许伪装源地址：本栈扮演的是"一整个受保护网段"，
	// 测试里经常需要它收下发往网段内其它地址的包、或以被访问的地址回包。
	// 关掉这两项的症状是"SYN 进来了但栈直接丢弃"，从外面看就是连接超时。
	_ = s.SetPromiscuousMode(nsNICID, true)
	_ = s.SetSpoofing(nsNICID, true)

	// 默认路由全指向这张网卡：出向包一律交给 channel endpoint，
	// 由 ReadOutbound 取走送进 ESP。到底哪些目的地该进隧道由 esp 的 SPD 决定，
	// ★这里不做二次选路——两处都判会出现"协议栈觉得能发、SPD 觉得不该发"的
	// 静默丢包，而两边日志都认为自己是对的。
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nsNICID},
		{Destination: header.IPv6EmptySubnet, NIC: nsNICID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	return &NetstackDatapath{
		stack: s, ep: ep, local: local, mtu: mtu, proto: proto,
		ctx: ctx, cancel: cancel,
	}, nil
}

// ReadOutbound 取一个协议栈要发出去的 IP 包（完整的、含 IP 头）。
func (d *NetstackDatapath) ReadOutbound(buf []byte) (int, error) {
	pb := d.ep.ReadContext(d.ctx)
	if pb == nil {
		return 0, ErrClosed
	}
	v := pb.ToView()
	data := v.AsSlice()
	if len(data) > len(buf) {
		v.Release()
		pb.DecRef()
		return 0, fmt.Errorf("ipsec: netstack 出向包 %d 字节装不进 %d 字节缓冲（MTU=%d）", len(data), len(buf), d.mtu)
	}
	n := copy(buf, data)
	v.Release()
	pb.DecRef()
	return n, nil
}

// WriteInbound 把解封出来的 IP 包注入协议栈。
func (d *NetstackDatapath) WriteInbound(ipPkt []byte) error {
	if len(ipPkt) == 0 {
		return fmt.Errorf("ipsec: netstack 收到空包")
	}
	var proto tcpip.NetworkProtocolNumber
	switch ipPkt[0] >> 4 {
	case 4:
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		// 解封出来的内层包必须是 IP 包。走到这里说明 ESP 的 NextHeader 或
		// 密钥出了问题——但那一层已经计过数了，这里只需要不把垃圾喂给协议栈。
		return fmt.Errorf("ipsec: netstack 收到非 IP 报文（首字节 0x%02x）", ipPkt[0])
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(ipPkt)})
	d.ep.InjectInbound(proto, pb)
	pb.DecRef()
	return nil
}

// MTU 链路 MTU。
func (d *NetstackDatapath) MTU() int { return d.mtu }

// Close 停掉协议栈并唤醒阻塞中的 ReadOutbound。可重复调用。
func (d *NetstackDatapath) Close() error {
	d.once.Do(func() {
		d.cancel() // 先唤醒 ReadOutbound，否则 stack.Close 会等在那里
		d.ep.Close()
		d.stack.Close()
		d.stack.Wait()
	})
	return nil
}

// Addr 本栈的地址。
func (d *NetstackDatapath) Addr() netip.Addr { return d.local.Addr() }

// DialTCP 在本栈里发起一条 TCP 连接（产生的 IP 包会从 ReadOutbound 出来）。
func (d *NetstackDatapath) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	fa, proto, err := fullAddr(dst)
	if err != nil {
		return nil, err
	}
	c, err := gonet.DialContextTCP(ctx, d.stack, fa, proto)
	if err != nil {
		return nil, fmt.Errorf("ipsec: netstack 拨 %s 失败：%w", dst, err)
	}
	return c, nil
}

// ListenTCP 在本栈里监听一个端口（地址通配，配合混杂模式可接受发往网段内任意地址的连接）。
func (d *NetstackDatapath) ListenTCP(port uint16) (net.Listener, error) {
	l, err := gonet.ListenTCP(d.stack, tcpip.FullAddress{NIC: nsNICID, Port: port}, d.proto)
	if err != nil {
		return nil, fmt.Errorf("ipsec: netstack 监听 :%d 失败：%w", port, err)
	}
	return l, nil
}

// DialContext 形如 net.Dialer.DialContext 的适配器，方便直接塞进 http.Transport。
// e2e 里"A 侧发起真 HTTP 请求"就是靠它接上去的。
func (d *NetstackDatapath) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("ipsec: netstack 只实现了 TCP（收到 network=%q）", network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("ipsec: netstack 目标 %q 解析失败：%w（本栈没有 DNS，只能用 IP:端口）", address, err)
	}
	return d.DialTCP(ctx, ap)
}

func fullAddr(ap netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, error) {
	a := ap.Addr().Unmap()
	if !a.IsValid() {
		return tcpip.FullAddress{}, 0, fmt.Errorf("ipsec: netstack 目标地址无效：%v", ap)
	}
	proto := tcpip.NetworkProtocolNumber(header.IPv4ProtocolNumber)
	if a.Is6() {
		proto = header.IPv6ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  nsNICID,
		Addr: tcpip.AddrFromSlice(a.AsSlice()),
		Port: ap.Port(),
	}, proto, nil
}
