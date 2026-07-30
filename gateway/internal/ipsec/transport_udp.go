package ipsec

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// UDPTransport 是生产用的 Transport：**同时监听 UDP 500 与 4500**，把 4500 上混流的
// IKE / ESP / NAT-keepalive 三类报文分开，并独占 non-ESP marker 的加减。
//
// # 为什么一定要两个端口 + 一条 socket 承载两种协议
//
// 这不是优化，是 NAT 穿越的硬要求：
//
//   - NAT 映射按**五元组**建立。若 ESP 另开一个端口发，NAT 设备上根本没有那条映射，
//     对端回来的包会被直接丢掉。表现是「IKE 协商全绿、隧道显示 up、一个业务包都不通」。
//   - 因此 RFC 3948 规定 ESP 复用 IKE 的 4500 端口，用首字节做区分。
//
// # 4500 上的三分流规则（RFC 3948 §2.1 / §2.2）
//
//	首 4 字节全零        → non-ESP marker，其后是裸 IKE 报文（KindIKE）
//	整包只有 1 字节 0xFF → NAT keepalive（KindKeepalive），内容无意义
//	其余                → ESP 报文，首 4 字节即 SPI（KindESP）
//
// 三者不会撞车的前提是 **ESP SPI 必须排除 0 与 1..255**（见 ChildSAParams.InSPI 的注释）：
// SPI=0 会被当成 marker，SPI=0xFF000000 之类倒不会与单字节 keepalive 混淆（长度不同），
// 但 SPI 落在 0..255 时首 4 字节是 `00 00 00 xx`，前三字节为零会让人误判，故一并排除。
//
// # marker 只存在于本文件
//
// ★Datagram.Payload 对 IKE 而言**永远是不含 marker 的裸报文**。
// 让 marker 泄漏到上层的后果非常隐蔽：IKEv2 的 AUTH 签名字节串（RealMessage1/2）
// 规定从 SPIi 第一字节开始、不含 marker，一旦上层拿到的是带 marker 的报文并直接拿去
// 签名，非 NAT 路径全绿、只有走 4500 的 NAT 路径认证失败——而报错还是那句「认证失败」。
type UDPTransport struct {
	ike *net.UDPConn // 500：只跑 IKE，不加 marker
	nat *net.UDPConn // 4500：IKE(带 marker) / ESP / keepalive 三分流

	ikeAddr netip.AddrPort
	natAddr netip.AddrPort

	in   chan Datagram
	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup

	// 丢弃计数。收到畸形包不该让进程说话（回错误就把自己变成反射放大器），
	// 但也不能完全无声——这些计数是「有人在扫我」与「对端版本不对」的唯一线索。
	dropShort  atomic.Uint64 // 短到不可能是任何一类报文
	dropMarker atomic.Uint64 // 有 marker 但其后不足一个 IKE 头
	keepalives atomic.Uint64 // 收到的 NAT keepalive 数
}

// ikeHeaderLen 是 IKE 固定头长度（RFC 7296 §3.1）。
//
// ★这里写死 28 而不是引用 ike.HeaderLen，是因为契约层**不许 import ike**
// （见 types.go 包注释：依赖必须是单向链）。这是本文件唯一一处重复常量，
// 用途仅是长度下限的理智检查，不参与任何解析。
const ikeHeaderLen = 28

// espHeaderLen ESP 的 SPI(4)+Seq(4)。同样只用于长度下限检查。
const espHeaderLen = 8

// natKeepalive NAT keepalive 的载荷：单字节 0xFF（RFC 3948 §4）。
var natKeepalive = []byte{0xFF}

// readBufLen 单次收包缓冲。IKE 报文上限 64KB，ESP 受 MTU 约束远小于此，
// 取满值可以避免"大包被截断后当成畸形丢掉"这类只在特定对端出现的怪问题。
const readBufLen = 65535

// NewUDPTransport 绑定 local 上的 ikePort 与 natPort 两个 UDP 端口。
//
// local 无效（零值）时绑通配地址。★生产环境建议绑具体地址：通配绑定下无从得知
// 报文是从哪个本机地址收到的，Datagram.Local 的 IP 部分会是 0.0.0.0，
// NAT 检测哈希只能退而用配置里声明的地址。
//
// ikePort/natPort 传 0 表示由内核分配临时端口——这正是 go test 不需要 root 也能跑
// 真 UDP 协商的原因（500/4500 是特权端口）。分配结果用 LocalIKE()/LocalNAT() 取回。
func NewUDPTransport(local netip.Addr, ikePort, natPort uint16) (Transport, error) {
	t := &UDPTransport{
		in:   make(chan Datagram, 256),
		done: make(chan struct{}),
	}
	var err error
	if t.ike, err = listenUDP(local, ikePort); err != nil {
		return nil, fmt.Errorf("绑定 IKE 端口 %d 失败：%w（该机是否已跑着 strongSwan/racoon？可用 -ike-port 换端口）", ikePort, err)
	}
	if t.nat, err = listenUDP(local, natPort); err != nil {
		_ = t.ike.Close()
		return nil, fmt.Errorf("绑定 NAT-T 端口 %d 失败：%w（该机是否已跑着 strongSwan/racoon？可用 -natt-port 换端口）", natPort, err)
	}
	t.ikeAddr = localAddrPort(t.ike)
	t.natAddr = localAddrPort(t.nat)

	t.wg.Add(2)
	go t.readLoop(t.ike, false)
	go t.readLoop(t.nat, true)
	return t, nil
}

func listenUDP(local netip.Addr, port uint16) (*net.UDPConn, error) {
	ua := &net.UDPAddr{Port: int(port)}
	network := "udp"
	if local.IsValid() {
		ua.IP = net.IP(local.AsSlice())
		if local.Is4() {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	return net.ListenUDP(network, ua)
}

func localAddrPort(c *net.UDPConn) netip.AddrPort {
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		// Unmap：双栈通配绑定下 LocalAddr 会是 ::，而 4-in-6 形态的地址
		// 与同值的 IPv4 地址用 == 比不相等，混用必然在某处静默对不上。
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

// LocalIKE 实际绑定的 500 侧地址（端口传 0 时是内核分配的结果）。
func (t *UDPTransport) LocalIKE() netip.AddrPort { return t.ikeAddr }

// LocalNAT 实际绑定的 4500 侧地址。
func (t *UDPTransport) LocalNAT() netip.AddrPort { return t.natAddr }

// Stats 返回三个丢弃/统计计数：短包、marker 后不足一个 IKE 头、收到的 keepalive 数。
// 这些数字是「有人在扫 500/4500」与「对端实现不对版」的唯一线索——
// 静默丢包是对的（不给反射放大器留口子），静默且不计数就是给自己蒙眼。
func (t *UDPTransport) Stats() (short, badMarker, keepalives uint64) {
	return t.dropShort.Load(), t.dropMarker.Load(), t.keepalives.Load()
}

// Send 发一个报文。选哪条 socket、加不加 marker，全部在这里决定：
//
//  1. Local 指明了端口就按它选 socket（状态机切到 4500 后会显式填 Local）；
//  2. Local 为空时按类型推断：ESP/keepalive 只可能走 4500；IKE 看对端端口。
//
// marker 的规则只有一条：**从 4500 发出的 IKE 报文加 marker，其余都不加**。
func (t *UDPTransport) Send(d Datagram) error {
	select {
	case <-t.done:
		return ErrClosed
	default:
	}
	if !d.Remote.IsValid() {
		return fmt.Errorf("ipsec: 发送目标地址无效（kind=%d，payload %d 字节）", d.Kind, len(d.Payload))
	}

	conn, onNAT := t.pick(d)
	payload := d.Payload
	switch d.Kind {
	case KindKeepalive:
		if !onNAT {
			// keepalive 只在 4500 上有意义（它的作用是刷 NAT 映射的老化计时器）。
			return errors.New("ipsec: NAT keepalive 只能从 4500 端口发出")
		}
		payload = natKeepalive
	case KindIKE:
		if onNAT {
			// 加 marker：4 字节全零 + 裸 IKE 报文。
			buf := make([]byte, 4+len(payload))
			copy(buf[4:], payload)
			payload = buf
		}
	case KindESP:
		if !onNAT {
			return errors.New("ipsec: ESP 报文只能从 4500 端口发出（裸 ESP/IP-proto-50 本实现不支持）")
		}
		// ESP 不加 marker：首 4 字节是 SPI，规定非零，据此与 marker 区分。
	}

	_, err := conn.WriteToUDPAddrPort(payload, d.Remote)
	if err != nil {
		return fmt.Errorf("ipsec: 发往 %s 失败：%w", d.Remote, err)
	}
	return nil
}

// pick 选 socket。返回值 onNAT 表示"走的是 4500 那条"。
func (t *UDPTransport) pick(d Datagram) (*net.UDPConn, bool) {
	if p := d.Local.Port(); p != 0 {
		if p == t.natAddr.Port() {
			return t.nat, true
		}
		if p == t.ikeAddr.Port() {
			return t.ike, false
		}
		// Local 填了个本 Transport 没绑的端口：不猜，按下面的类型推断走，
		// 免得把包从一个"看起来像但其实不是"的口发出去。
	}
	switch d.Kind {
	case KindESP, KindKeepalive:
		return t.nat, true
	default: // KindIKE
		if d.Remote.Port() == t.natAddr.Port() {
			return t.nat, true
		}
		return t.ike, false
	}
}

// Recv 阻塞取下一个报文。
func (t *UDPTransport) Recv() (Datagram, error) {
	select {
	case d := <-t.in:
		return d, nil
	case <-t.done:
		return Datagram{}, ErrClosed
	}
}

// Close 关闭两条 socket 并唤醒阻塞中的 Recv。可重复调用。
func (t *UDPTransport) Close() error {
	t.once.Do(func() {
		close(t.done)
		_ = t.ike.Close()
		_ = t.nat.Close()
		t.wg.Wait()
	})
	return nil
}

// readLoop 一条 socket 的收包循环。onNAT 决定是否要做三分流与去 marker。
func (t *UDPTransport) readLoop(conn *net.UDPConn, onNAT bool) {
	defer t.wg.Done()
	local := t.ikeAddr
	if onNAT {
		local = t.natAddr
	}
	buf := make([]byte, readBufLen)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			// Close 会让 ReadFrom 立刻返回 net.ErrClosed，这是正常退出路径。
			// 其余错误（如 ICMP 端口不可达导致的 ECONNREFUSED）在 UDP 上是瞬时的，
			// 不该让整条隧道下线——继续读。
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-t.done:
				return
			default:
			}
			continue
		}
		// ★双栈通配 socket 收到 IPv4 报文时，from 是 4-in-6 形态（::ffff:10.0.0.1）。
		// 不 Unmap 的后果：它与配置里写的 10.0.0.1 用 == 比不相等，
		// 于是「对端地址匹配」「SA 查找」「NAT 检测」会全线对不上，
		// 而每一处的表现都只是"收不到对端的包"，没有任何一处会说出真正的原因。
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())

		d, ok := classify(buf[:n], onNAT, t)
		if !ok {
			continue
		}
		d.Local = local
		d.Remote = from
		// 报文必须拷贝出来：buf 下一轮就会被覆盖。
		d.Payload = append([]byte(nil), d.Payload...)

		select {
		case t.in <- d:
		case <-t.done:
			return
		}
	}
}

// classify 做 4500 上的三分流（onNAT=false 时 500 上只可能是裸 IKE）。
// 返回 ok=false 表示这包该被静默丢弃。
func classify(b []byte, onNAT bool, t *UDPTransport) (Datagram, bool) {
	if !onNAT {
		// 500 端口上不存在 marker（RFC 3948 只在 4500 上定义它）。
		if len(b) < ikeHeaderLen {
			t.dropShort.Add(1)
			return Datagram{}, false
		}
		return Datagram{Kind: KindIKE, Payload: b}, true
	}

	switch {
	case len(b) == 1 && b[0] == 0xFF:
		// NAT keepalive：内容无意义，作用只是刷新 NAT 映射的老化计时器。
		t.keepalives.Add(1)
		return Datagram{Kind: KindKeepalive, Payload: nil}, true

	case len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0:
		// non-ESP marker：其后必须是一个完整的 IKE 头。
		// ★marker 在这里被剥掉，上层永远看不到它（见类型注释里 AUTH 签名那段）。
		if len(b)-4 < ikeHeaderLen {
			t.dropMarker.Add(1)
			return Datagram{}, false
		}
		return Datagram{Kind: KindIKE, Payload: b[4:]}, true

	case len(b) >= espHeaderLen:
		return Datagram{Kind: KindESP, Payload: b}, true

	default:
		t.dropShort.Add(1)
		return Datagram{}, false
	}
}
