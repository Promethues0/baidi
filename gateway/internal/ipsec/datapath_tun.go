package ipsec

import (
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// DefaultTunnelMTU 隧道内层默认 MTU。
//
// 算法：1500(以太网) − 20(外层 IPv4) − 8(外层 UDP) − 8(ESP SPI+Seq)
// − 16(最大 IV) − 16(ICV) − 2(PadLen+NextHeader) − 补齐余量 ≈ 1430，取 1400 留裕度。
//
// ★MTU 配大了的症状极具迷惑性：小包（ping、DNS、TCP 握手）全通，
// 一旦发满载数据段就静默丢弃，表现为「能 ping 通、SSH 能连上、HTTP 一传大文件就卡死」。
// 本实现**不做 PMTUD**（写进诚实边界），超 MTU 的内层包由 esp 层丢弃并计数，
// 绝不静默截断——截断出来的半个 IP 包会被对端正常解密后交给协议栈，
// 那时的现象离根因就更远了。
//
// 精确值应由 site.TunnelMTU() 按实际协商出的套件反推；这个常量只是没有协商结果时的兜底。
const DefaultTunnelMTU = 1400

// tunOffset TUN 读写在包前预留的字节数。
//
// macOS 的 utun 在每个包前有 4 字节地址族头；Linux/Windows 不需要，但 wireguard/tun
// 的批量接口在所有平台都接受一个 offset，统一用 4 可以让三平台走同一条代码路径
// （与 internal/dataplane 的既有约定保持一致，别在这里另创一套）。
const tunOffset = 4

// tunMaxSegment 单次读的最大包长。
//
// ★不能按 MTU 取。Linux 上开了 GRO/USO 时，一次 Read 返回的可能是**合并后的超大段**
// （远超 MTU），缓冲按 MTU 分配会直接越界 panic。internal/dataplane 踩过这个坑，
// 这里沿用同样的 65535。
const tunMaxSegment = 65535

// TUNDatapath 生产用数据面：一张 TUN 网卡，出向读、入向写。**需要 root**。
//
// 站点组网的姿态与客户端 utun 不同：这里的 TUN 只承载"要进隧道的受保护网段"，
// 路由由 routes 逐条写进去。routes 必须**由控制面下发**，不能让管理员手填——
// CLAUDE.md 记着的那个事故形态（业务地址散落在多个网段，只接管一条，
// 隧道建起来了、点开应用却直连不走隧道，无报错、UI 显示已接入）就出在这里。
type TUNDatapath struct {
	dev  tun.Device
	name string
	mtu  int

	// 批量读的暂存。wireguard/tun 一次 Read 可能吐出多个包，而 Datapath 契约
	// 是一次一个包，所以要在这里缓存并逐个交出去。
	mu    sync.Mutex
	bufs  [][]byte
	sizes []int
	have  int // 本轮读到的包数
	next  int // 下一个要交出去的下标

	closeOnce sync.Once
}

// NewTUNDatapath 建一张 TUN 网卡并把 routes 全部路由进去（需 root）。
//
// 接口不配地址（unnumbered）。Linux/Windows 支持这种用法；★macOS 的 utun 必须有
// 点对点地址才能 up，因此在 macOS 上本函数会直接报错并指路到 NewTUNDatapathWithAddr——
// 报错好过建出一张 up 不起来、路由却已写进去的半吊子接口。
func NewTUNDatapath(name string, mtu int, routes []netip.Prefix) (Datapath, error) {
	return NewTUNDatapathWithAddr(name, mtu, netip.Addr{}, routes)
}

// NewTUNDatapathWithAddr 同上，并给接口配一个本端地址 addr（点对点形态）。
func NewTUNDatapathWithAddr(name string, mtu int, addr netip.Addr, routes []netip.Prefix) (*TUNDatapath, error) {
	if mtu <= 0 {
		mtu = DefaultTunnelMTU
	}
	if runtime.GOOS == "darwin" && !addr.IsValid() {
		return nil, fmt.Errorf(
			"macOS 的 utun 必须配点对点地址才能 up：请改用 NewTUNDatapathWithAddr 指定本端隧道地址" +
				"（通常取本端受保护网段里的网关地址）。不配地址时 ifconfig 会失败，" +
				"而路由已经写进去了，结果是一张看着存在、实际不通的接口")
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN 设备 %q 失败：%w（需要 root/CAP_NET_ADMIN；macOS 上设备名必须是 utun 或 utun<N>）", name, err)
	}
	real, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("读取 TUN 设备名失败：%w", err)
	}
	if err := tunUp(real, addr, mtu, routes); err != nil {
		_ = dev.Close()
		return nil, err
	}

	bs := dev.BatchSize()
	if bs <= 0 {
		bs = 1
	}
	d := &TUNDatapath{
		dev:   dev,
		name:  real,
		mtu:   mtu,
		bufs:  make([][]byte, bs),
		sizes: make([]int, bs),
	}
	for i := range d.bufs {
		d.bufs[i] = make([]byte, tunOffset+tunMaxSegment)
	}
	return d, nil
}

// Name 实际的接口名（macOS 上内核会分配 utunN，与请求的名字未必一致）。
func (d *TUNDatapath) Name() string { return d.name }

// ReadOutbound 读一个待保护的出向 IP 包。
func (d *TUNDatapath) ReadOutbound(buf []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		// 先把上一轮批量读剩下的交完，再去读新的。
		for d.next < d.have {
			i := d.next
			d.next++
			n := d.sizes[i]
			if n == 0 {
				continue
			}
			pkt := d.bufs[i][tunOffset : tunOffset+n]
			if n > len(buf) {
				// ★宁可报错也不截断：半个 IP 包会被正常加密、被对端正常解密、
				// 再交给协议栈，然后表现为"连接莫名挂住"，离根因十万八千里。
				return 0, fmt.Errorf("ipsec: TUN %s 读到 %d 字节的包，装不进 %d 字节缓冲（隧道 MTU=%d，缓冲请按 %d 分配）",
					d.name, n, len(buf), d.mtu, tunMaxSegment)
			}
			return copy(buf, pkt), nil
		}
		n, err := d.dev.Read(d.bufs, d.sizes, tunOffset)
		if err != nil {
			return 0, err
		}
		d.have, d.next = n, 0
	}
}

// WriteInbound 把解封出来的入向 IP 包写回 TUN。
func (d *TUNDatapath) WriteInbound(ipPkt []byte) error {
	// wireguard/tun 要求包前留 offset 字节的空档，所以必须拷进一块带前缀的缓冲。
	out := make([]byte, tunOffset+len(ipPkt))
	copy(out[tunOffset:], ipPkt)
	_, err := d.dev.Write([][]byte{out}, tunOffset)
	if err != nil {
		return fmt.Errorf("ipsec: 写 TUN %s 失败：%w", d.name, err)
	}
	return nil
}

// MTU 隧道内层 MTU。
func (d *TUNDatapath) MTU() int { return d.mtu }

// Close 关闭设备（会唤醒阻塞中的 ReadOutbound）。可重复调用。
func (d *TUNDatapath) Close() error {
	var err error
	d.closeOnce.Do(func() { err = d.dev.Close() })
	return err
}

// tunUp 给接口配地址、设 MTU、写路由。
//
// 三平台的命令写法照抄 cmd/baidi-tun/ifup_*.go 的既有约定（那套是实跑验证过的），
// 只是这里放在同一个文件里用 runtime.GOOS 分支——本数据面不需要按平台分文件，
// 分文件反而会让"三平台行为是否一致"变得难以一眼看清。
//
// ★路由逐条加，任一条失败立刻返回并带上是哪一条。
// 「部分网段生效」是最难排查的中间态：隧道显示正常，只有一部分业务不通。
func tunUp(dev string, addr netip.Addr, mtu int, routes []netip.Prefix) error {
	switch runtime.GOOS {
	case "darwin":
		// utun 是点对点接口，ifconfig 需要 <本端> <对端> 两个地址；
		// 站点组网里没有"对端隧道地址"的概念，故两处都填本端（与 baidi-tun 同姿态）。
		a := addr.String()
		if err := sh("ifconfig", dev, "inet", a, a, "mtu", strconv.Itoa(mtu), "up"); err != nil {
			return err
		}
		for _, r := range routes {
			if err := sh("route", "-q", "-n", "add", "-net", r.String(), "-interface", dev); err != nil {
				return fmt.Errorf("添加路由 %s → %s 失败：%w", r, dev, err)
			}
		}
	case "linux":
		if err := sh("ip", "link", "set", "dev", dev, "mtu", strconv.Itoa(mtu), "up"); err != nil {
			return err
		}
		if addr.IsValid() {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			if err := sh("ip", "addr", "add", addr.String()+"/"+strconv.Itoa(bits), "dev", dev); err != nil {
				return err
			}
		}
		for _, r := range routes {
			if err := sh("ip", "route", "add", r.String(), "dev", dev); err != nil {
				return fmt.Errorf("添加路由 %s → %s 失败：%w", r, dev, err)
			}
		}
	case "windows":
		if addr.IsValid() {
			if err := sh("netsh", "interface", "ip", "set", "address",
				"name="+dev, "static", addr.String(), maskOf(addr)); err != nil {
				return err
			}
		}
		for _, r := range routes {
			if err := sh("netsh", "interface", "ip", "add", "route",
				r.String(), "interface="+dev); err != nil {
				return fmt.Errorf("添加路由 %s → %s 失败：%w", r, dev, err)
			}
		}
	default:
		return fmt.Errorf("ipsec: 平台 %s 尚未适配 TUN 接口配置（可用的生产平台是 linux）", runtime.GOOS)
	}
	return nil
}

// maskOf 给 Windows 的 netsh 用的点分掩码（单机 /32）。
func maskOf(addr netip.Addr) string {
	if addr.Is4() {
		return "255.255.255.255"
	}
	return "128"
}

func sh(name string, args ...string) error {
	// 带上完整命令行与输出：接口配置失败时，管理员需要的是"哪条命令、报了什么"，
	// 而不是一句 "exit status 1"。
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v 执行失败：%v：%s", name, args, err, out)
	}
	return nil
}
