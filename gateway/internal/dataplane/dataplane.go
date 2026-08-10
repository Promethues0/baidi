// Package dataplane 是白帝客户端数据面的平台无关引擎：
//
//	TUN 设备 → gVisor 用户态网络栈终止 TCP → 每条流 SPA 敲门 + 拨网关隧道(TLS/国密TLCP) → 后端业务
//
// 桌面 CLI(baidi-tun) 自建 utun 后调 Run；移动端(baidimobile, gomobile)用平台 VPN 扩展给的 TUN fd
// 包成 tun.Device 后调 Run。两者共享同一引擎，只是 TUN 的来源与接口配置不同。
package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
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
	Resmap     map[string]string // "host:port" → 资源 id（控制面剖面下发；VIP 与真实后端都登记）
	DefaultRes string            // 默认资源 id
	Reknock    time.Duration     // 保活间隔（Control 模式）
	MTU        int               // 链路 MTU（默认 1420）
	// TunnelPin 网关隧道证书的 SHA-256 指纹（小写 hex），由控制面经接入剖面下发。
	// 非空则对通用 TLS 隧道做证书钉扎：网关证书是自签的，没有公共 CA 可依赖，
	// 不钉扎就只能 InsecureSkipVerify——隧道加密但**不认证**，任何能抢到 TCP 连接的
	// 中间人都可冒充网关，把明文业务流量原样读走。空=退回不校验（并在日志显式告警）。
	TunnelPin string

	// DNSListen 隧道内 DNS 解析器监听的 VIP（如 "10.99.0.53"），空=不启用。
	//
	// ★这个 VIP 自己也必须在客户端接管的 routes 里，否则查询包压根不会进 utun，
	// 解析器永远收不到东西——症状是"域名解析超时"而不是"解析到错误地址"，
	// 排查时很容易怀疑到解析器实现上去，其实是路由少了一条。路由由控制面剖面下发。
	DNSListen string
	// DNSRecords FQDN（小写、不带尾点）→ IPv4。由控制面剖面下发，客户端只负责照答。
	DNSRecords map[string]string

	// Device 终端硬件指纹，随每次取敲门令牌上报给控制面（授信终端准入闸的判据）。
	// ★必须与 posture 上报用的是**同一个值**（桌面客户端的 collectPosture().device）：
	// 两处不一致的话，管理员在设备台账里批准的那台机器与敲门时自报的那台对不上，
	// 严格模式下表现为"批了也连不上"，而两边日志都完全正常。
	// 空 = 不上报指纹：观察模式照常放行并留痕，严格模式拒（fail-closed）。
	Device string
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

	// 解析器 VIP 先解析出来：配错了要在起栈之前就失败，而不是起来之后静默没有 DNS。
	// "配了 -dns-listen 却没生效"和"没配"在日志里看起来一模一样，必须早失败。
	resolver, dnsAddr, err := buildResolver(cfg)
	if err != nil {
		return err
	}

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		// UDP 协议在这里注册**只为隧道内 DNS**服务，见下方 udp handler 的说明。
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
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
		conn := gonet.NewTCPConn(&wq, ep)
		// ★发往解析器 VIP:53 的 TCP 必须在这里短路，不能掉进 tunnel()。
		// 解析器 VIP 随 routes 一并被 utun 接管，若不短路，这条连接会被当成一次普通
		// 业务访问去 CONNECT 一个根本不存在的资源 id——症状是「dig +tcp 挂住不返回」
		// 而 UDP 查询一切正常。这种「只有某一种查询方式卡死」的故障极难归因。
		if resolver != nil && id.LocalPort == dnsPort && id.LocalAddress.Equal(dnsAddr) {
			go resolver.serveTCPSession(conn)
			return
		}
		go t.tunnel(conn, dst)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	// ── UDP：只服务隧道内 DNS，其余一律不接管 ──
	//
	// ★不要把这理解成"UDP 通了"。隧道协议（`CONNECT <资源id>` + TLS 字节流）本身只承载
	// TCP 语义，网关侧也没有 UDP 转发路径。这里注册 UDP 协议**仅仅**是为了让发往
	// 解析器 VIP:53 的查询能被终结在本机 netstack 里。任何其它 UDP 目的地都不接管——
	// 顺手做"UDP 转发到网关"是另一个特性（要动隧道协议、网关、审计三处），不是这一处能加的。
	//
	// 不接管的包**返回 false 交回协议栈**，而不是自己吞掉：netstack 会回一个 ICMP
	// 端口不可达，应用立刻知道走不通。若黑洞丢弃，QUIC（UDP/443）这类会先卡满重试超时
	// 才降级到 TCP，用户看到的是"接入隧道后网页奇慢"——比直接失败难查得多。
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, e := r.CreateEndpoint(&wq)
		if e != nil {
			slog.Warn("DNS 会话建立失败", "src", id.RemoteAddress.String(), "err", e.String())
			return
		}
		go resolver.serveSession(gonet.NewUDPConn(&wq, ep))
	})
	udpDropped := &atomic.Uint64{}
	lastDropLog := &atomic.Int64{}
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if resolver != nil && id.LocalPort == dnsPort && id.LocalAddress.Equal(dnsAddr) {
			return udpFwd.HandlePacket(id, pkt)
		}
		// 丢弃要**可见**：静默丢包是本项目反复吃亏的失败形态。按 30s 节流打日志，
		// 既能在排查时看到"确实有 UDP 被丢"，又不会被一个 UDP 洪流刷爆日志。
		n := udpDropped.Add(1)
		now := time.Now().Unix()
		if prev := lastDropLog.Load(); now-prev >= 30 && lastDropLog.CompareAndSwap(prev, now) {
			slog.Info("UDP 不经隧道转发，已丢弃（隧道只承载 TCP；DNS 除外）",
				"dst", net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort))),
				"dropped_total", n)
		}
		return false // 交回协议栈 → ICMP 端口不可达，让应用快速失败而不是干等
	})

	slog.Info("数据面就绪：TUN→netstack→隧道", "proxy", cfg.ProxyAddr, "gm", cfg.Gm)
	if resolver != nil {
		slog.Info("隧道内 DNS 就绪（只作答不转发，未知域名回 REFUSED）",
			"listen", net.JoinHostPort(cfg.DNSListen, strconv.Itoa(dnsPort)), "records", len(resolver.records))
	} else {
		// 没有解析器 = 域名类应用只能靠系统 DNS + 默认出口直连，即"配了却不走隧道"。
		// 这条日志是该现象的唯一线索，别删。
		slog.Info("隧道内 DNS 未启用：域名后端将不经隧道（如需接管请由控制面下发 dns 段）")
	}

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
	tok, err := knock.FetchToken(t.cfg.Control, t.cfg.Token, t.cfg.Device)
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
		remote, err = tls.DialWithDialer(d, "tcp", c.ProxyAddr, tlsClientConfig(c.TunnelPin))
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

// buildResolver 按配置装配隧道内 DNS 解析器，返回解析器与它监听的地址。
// 未配置 DNSListen 时返回 (nil, 空地址, nil)——不启用是合法姿态（纯 IP 场景不需要）。
//
// 配了但地址非法则**直接报错停机**：这类笔误若只打个警告继续跑，现象是"域名解析全挂
// 但隧道显示正常"，而日志里那行警告早就被刷走了。宁可起不来，也不要半残地跑着。
func buildResolver(cfg *Config) (*dnsResponder, tcpip.Address, error) {
	var zero tcpip.Address
	listen := strings.TrimSpace(cfg.DNSListen)
	if listen == "" {
		return nil, zero, nil
	}
	ip := net.ParseIP(listen)
	if ip == nil || ip.To4() == nil {
		// 只支持 IPv4：VIP 段本身就是 IPv4（见控制面 clientprofile 的 VIP 分配）。
		return nil, zero, fmt.Errorf("隧道内 DNS 监听地址非法（需 IPv4 字面量）：%q", cfg.DNSListen)
	}
	return newDNSResponder(cfg.DNSRecords), tcpip.AddrFrom4Slice(ip.To4()), nil
}

// tlsClientConfig 构造通用 TLS 隧道的客户端配置。
//
// 网关隧道证书是启动期自签的，链校验必然失败，因此这里始终 InsecureSkipVerify=true
// 关掉**链**校验，转而在 VerifyPeerCertificate 里做**指纹钉扎**——信任根不是证书链，
// 而是控制面（客户端已用 mTLS/JWT 与控制面互认，指纹经接入剖面下发）。
// 这不是把校验放松，恰恰相反：钉扎比链校验更严，只认那一张证书。
//
// pin 为空时退化为「加密不认证」，此时打 WARN——这种降级必须在日志里看得见，
// 否则运维会误以为隧道自带身份保证。
func tlsClientConfig(pin string) *tls.Config {
	if pin == "" {
		slog.Warn("隧道未启用证书钉扎（控制面未下发网关证书指纹）：链路加密但不认证网关身份")
		return &tls.Config{InsecureSkipVerify: true}
	}
	want := strings.ToLower(strings.TrimSpace(pin))
	return &tls.Config{
		// 自签证书过不了链校验，故关闭内建校验，改由下面的回调做钉扎——
		// 回调返回 error 即中止握手，安全性由钉扎承担。
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("网关未出示证书")
			}
			// 与网关 certFingerprint 同口径：对叶子证书 DER 原文取 SHA-256。
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			// 定长比较用 subtle.ConstantTimeCompare：指纹比对虽非高价值侧信道目标，
			// 但常数时间比较无额外成本，不给计时侧信道留口子。
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				return fmt.Errorf("网关证书指纹不匹配（疑似中间人）：期望 %s，实得 %s", want, got)
			}
			return nil
		},
	}
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
