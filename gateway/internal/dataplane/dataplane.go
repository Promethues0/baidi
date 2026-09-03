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
	"github.com/emmansun/gmsm/smx509"
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
	// Endpoints 网关落点清单，**顺序即优先级**，由控制面接入剖面下发（见 failover.go）。
	// 空 = 退回下面的单落点三件套（SpaAddr/ProxyAddr/TunnelPin），移动端绑定与手工
	// 起的 baidi-tun 走这条路；非空时三件套不再被读取。
	Endpoints  []Endpoint
	SpaAddr    string            // 网关 SPA 敲门 host:port（单落点入口）
	ProxyAddr  string            // 网关隧道代理 host:port（单落点入口）
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

	// ControlTLS 调控制面（取敲门令牌）用的 TLS 配置，由**调用方预构建**（同 TLCPConfig 的范式）。
	//
	// ★nil = 用系统信任库，**不是跳过校验**。参考部署给控制面签的是自签证书，
	// 而系统信任库当然不认它——2026-09-03 安卓真机上这一跳报的正是
	// `x509: certificate signed by unknown authority`，隧道引擎起着而门永远敲不开。
	// 客户端持部署期分发的信任锚来认控制面（移动端经 baidimobile.Config.ControlCaPEM 下发，
	// 构建成「系统池 ∪ 那一张锚」），与网关用 -mtls-ca 认控制面同构。
	// 本包不提供、也永远不要提供 InsecureSkipVerify 的入口：那是给零信任的第一跳开一个
	// 默认关不掉的口子，且一旦加上就再也拆不掉。
	ControlTLS *tls.Config

	// Device 终端硬件指纹，随每次取敲门令牌上报给控制面（授信终端准入闸的判据）。
	// ★必须与 posture 上报用的是**同一个值**（桌面客户端的 collectPosture().device）：
	// 两处不一致的话，管理员在设备台账里批准的那台机器与敲门时自报的那台对不上，
	// 严格模式下表现为"批了也连不上"，而两边日志都完全正常。
	// 空 = 不上报指纹：观察模式照常放行并留痕，严格模式拒（fail-closed）。
	Device string

	// Health 健康状态载体（见 health.go）。**nil = 引擎自建**，调用方行为逐字不变。
	//
	// ★它存在的唯一理由：调用方要在 Run 之外读到「敲门有没有成功过、最近一次失败是什么」。
	// 桌面端从日志行里捞（Rust 壳读 stdout 尾巴），移动端是同进程调用、根本没有那条管道，
	// 于是此前只能靠"Start 返回了没有"判接入——2026-09-03 安卓真机上正是这样：
	// 引擎起来了、门没敲开（控制面 HTTPS 证书不受信任），界面却显示「已接入」。
	// 传进来的这份状态在 Run 结束后仍可读（终态原因不会随引擎一起消失）。
	Health *HealthState
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
	eps := cfg.endpoints()
	if err := validateEndpoints(eps); err != nil {
		return err
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

	t := newTunneler(cfg)
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

	_, first := t.pick.current()
	slog.Info("数据面就绪：TUN→netstack→隧道", "proxy", first.ProxyAddr, "gm", cfg.Gm)
	t.pick.logCurrent("网关落点已选定", false)
	if len(eps) == 1 {
		// 单落点 = 没有容灾余量。这台网关一挂就是整机断网，说清楚好过让人以为
		// "客户端支持多活"这件事在这次接入里也生效了。
		slog.Info("只有一个网关落点：无故障转移余量（控制面只下发了这一个落点）")
	}
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
	pick     *picker    // 网关落点选择器（多活 + 故障转移，见 failover.go）
	deny     chan error // control 定性拒绝（403：强制下线/账号禁用）单次上报，供 Run 停机
	denyOnce sync.Once
	fetch    *knock.Fetcher // 取敲门令牌（携带 cfg.ControlTLS 的信任材料；nil 配置=系统信任库）

	// ── 真实健康状态（供客户端展示与移动端绑定层读取）──
	// 状态本体搬去 health.go 的 HealthState（那里有完整的来龙去脉）。这里用**内嵌指针**，
	// 于是 t.markKnock() / t.knockOK 这些既有写法一字不改地继续可用；而同一份状态又能
	// 由调用方经 Config.Health 先建好、Run 之外读到（移动端接入态判据的唯一来源）。
	*HealthState
}

// newTunneler 是构造 tunneler 的**唯一**入口：落点选择器必须随之建好。
// 直接用结构体字面量构造的话，漏掉 pick 会在第一次敲门/拨号时空指针崩溃，
// 而那是运行期才出现的路径（编译期一点提示都没有）。
func newTunneler(cfg *Config) *tunneler {
	// ★cfg.Health 为 nil 时自建：baidi-tun 与既有调用方一个字都不用改，行为逐字不变
	// （它们本来就只从日志行读健康态）。只有需要在 Run 之外读状态的调用方（移动端绑定层）
	// 才自己 NewHealthState 再塞进来——那份指针必须**先于 Run 存在**，否则又回到
	// 「引擎起来了但外面拿不到真实健康态」的老形态。
	h := cfg.Health
	if h == nil {
		h = NewHealthState()
	}
	// 取令牌客户端在这里建一次（而不是每轮 knock 现建）：它内部有连接池，
	// 每次新建会让保活敲门每 15s 重做一次 TLS 完全握手。cfg.ControlTLS 为 nil 即系统信任库。
	return &tunneler{cfg: cfg, pick: newPicker(cfg.endpoints()), deny: make(chan error, 1),
		HealthState: h, fetch: knock.NewFetcher(cfg.ControlTLS)}
}

// knock 向**全部**落点各发一次 SPA 敲门：逐个向 control 换取短时效一次性令牌
// （use=knock），换不到就不敲那一个。
//
// ★为什么每轮都敲全部落点，而不是只敲当前那个：网关对未敲门者是隐身的，一个没被敲过
// 的落点在故障转移那一刻只会给出一次拨号超时——"有备用落点"就退化成"多等 5 秒再失败"。
// 保活成本是每轮 N 次取令牌 + N 个 UDP 包（N = 落点数，通常 2~3），换来的是切换即通。
//
// ★为什么逐落点各取一张令牌，而不是取一张发给所有网关：jti 去重是**每台网关各自**做的，
// 同一个封包发两处等于让它在第二台那里仍然可用一次——链路上截获它的人就能拿去
// 给**自己的源 IP** 开一扇窗。一次性语义只有在"一张令牌只出现在一条链路上"时才成立。
//
// ★绝不回退会话令牌：网关 strict 模式只认 control 签发的敲门令牌，回退包必被丢弃，
// 只会制造"日志显示已敲门、实际窗口到期即断"的假象。控制面不可达时窗口自然过期
// 是 fail-closed 的正确姿态——零信任下失去策略源就该收窗，而不是拿长效令牌硬撑。
// 遇 control 定性拒绝（ErrDenied）向 deny 通道上报一次，让 Run 停机并带出原因：
// 那是**账号级**判定（强制下线/账号禁用/终端不合规），与落点无关，换一台也一样被拒。
// ★逐落点**并发**敲：取令牌的 HTTP 超时是 5s，串行的话 N 个落点最坏要 N×5s，
// 而整轮保活必须显著小于网关的放行窗口（默认 30s）——否则一次 control 慢响应就会
// 让所有落点的窗口一起过期，症状是"隧道每隔一会儿断一下"，且落点越多越容易复现。
// 定性拒绝经 denyOnce 上报，并发安全。
func (t *tunneler) knock() {
	var wg sync.WaitGroup
	for _, ep := range t.pick.all() {
		wg.Add(1)
		go func(ep Endpoint) {
			defer wg.Done()
			t.knockOne(ep)
		}(ep)
	}
	wg.Wait()
}

// knockOne 敲一个落点。返回 true 表示遇到了控制面的定性拒绝（**账号级**判定，与落点无关）。
func (t *tunneler) knockOne(ep Endpoint) (denied bool) {
	tok, err := t.fetch.Fetch(t.cfg.Control, t.cfg.Token, t.cfg.Device)
	switch {
	case err == nil:
	case errors.Is(err, knock.ErrDenied):
		t.denyOnce.Do(func() { t.deny <- err })
		return true
	default:
		// 瞬时错误：本轮不敲门，等下一次 reknock 重试（间隔须显著小于网关 SPA 放行 TTL，
		// 否则 control 抖动会直接关窗——这是 fail-closed 的代价，须靠 reknock 频度补偿）。
		slog.Warn("取短时效敲门令牌失败，本轮放弃敲门（等待下轮 reknock 重试）",
			"gateway", ep.Label(), "err", err.Error())
		t.markKnockFail("取敲门令牌失败：" + err.Error())
		return false
	}
	uc, err := net.Dial("udp", ep.SPAAddr)
	if err != nil {
		slog.Warn("SPA 拨号失败", "gateway", ep.Label(), "err", err.Error())
		t.markKnockFail("SPA 拨号失败：" + err.Error())
		return false
	}
	defer uc.Close()
	if sealed, e := knock.Seal(tok); e == nil {
		if _, werr := uc.Write(sealed); werr == nil {
			t.markKnock() // 真的发出去了才算——此前界面只看"保活 ticker 起来了没有"
		}
	}
	return false
}

// tunnel 把一条被 TUN 捕获的 TCP 流，经 SPA 敲门后拨入网关隧道并双向拷贝。
func (t *tunneler) tunnel(local net.Conn, dst string) {
	defer local.Close()
	c := t.cfg

	remote, ep, err := t.dialTunnel(dst)
	if err != nil {
		slog.Warn("隧道拨号失败（未敲门成功/网关隐身?）", "dst", dst, "err", err.Error())
		// ★这条失败此前**到不了界面**：tunnel.ts 的 error 判据是 `!s.running && …`，
		//   运行中恒为空串。于是「全部落点拨不通」「gm 开关与网关不一致」
		//   「指纹钉扎失败（疑似中间人）」三类故障，界面一律显示绿色「已接入」。
		t.markTunnelFail(err.Error())
		return
	}
	defer remote.Close()
	t.markTunnel()
	rid := c.Resmap[dst]
	if rid == "" {
		rid = c.DefaultRes
	}
	if rid == "" {
		// ★不再"静默不发前导"。那样做的后果是这条连接落进网关的无前导回退分支——
		//   资源 ACL / DenyUsers / JIT 授予一个都不查（见 resource.Registry.AllowNoPreamble），
		//   而参考部署里那个默认后端正是控制面自身。也就是说：**剖面缺一条映射，
		//   合法客户端自己就把流量送上了一条不鉴权的路**，两侧都不报错。
		//   现在明确断开并说清原因——路由把包引进来了、却不知道它属于哪个资源，
		//   这本身就是配置缺口（剖面过期 / 资源被删 / route 与 resmap 不同步）。
		slog.Warn("引流已捕获但无法归属资源，拒绝经隧道转发（剖面缺少该目的地址的映射）",
			"captured_dst", dst,
			"提示", "该地址在受保护网段内却不在 resmap 里：请刷新接入剖面；若资源已下架，应同时收回路由")
		return
	}
	if _, err := remote.Write([]byte("CONNECT " + rid + "\n")); err != nil {
		slog.Warn("发送 CONNECT 前导失败", "captured_dst", dst, "resource", rid, "err", err.Error())
		return
	}
	slog.Info("引流 · 经隧道转发", "captured_dst", dst, "resource", rid, "via", ep.ProxyAddr, "gm", c.Gm)
	go func() { _, _ = io.Copy(remote, local) }()
	_, _ = io.Copy(local, remote)
}

// dialTunnel 从当前落点开始按序拨号，第一个拨通的即为新的当前落点。
//
// ★顺序不重排、只轮转起点：清单顺序是控制面算好的优先级，终端手里没有任何能推翻它的
// 材料。轮转起点则让"这台已经死了"这个事实在后续每条流上直接生效——每条流都从头撞一遍
// 死网关的话，5s 拨号超时会把体验拖成"接入后什么都打不开"，而日志里只有零星几条超时。
//
// 全部落点都拨不通时返回**首选落点**那次的错误：那是用户最该看到的原因
// （后面几台多半只是"没敲上门"的次生现象）。
func (t *tunneler) dialTunnel(dst string) (net.Conn, Endpoint, error) {
	start, _ := t.pick.current()
	eps := t.pick.all()
	var firstErr error
	for off := 0; off < len(eps); off++ {
		i := (start + off) % len(eps)
		ep := eps[i]
		conn, err := t.dialEndpoint(ep)
		if err == nil {
			if t.pick.promote(i, fmt.Sprintf("上一落点 %s 拨号失败：%v", eps[start].Label(), firstErr)) {
				// 切换必须让用户知道——桌面客户端接入页从这条日志解析出
				// 「当前用的是第几落点、为什么切」。静默切换 = "我明明连着但很慢"无从排查。
				t.pick.logCurrent("网关落点切换", true)
			}
			return conn, ep, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if len(eps) > 1 {
			slog.Warn("网关落点拨号失败，尝试下一个",
				"gateway", ep.Label(), "addr", ep.ProxyAddr, "dst", dst, "err", err.Error())
		}
	}
	return nil, Endpoint{}, firstErr
}

// dialEndpoint 按落点自己的信任材料拨一条隧道。
// ★钉扎指纹取 ep.Pin 而不是 cfg.TunnelPin：指纹是逐网关的，取错的后果是
// 故障转移后握手必然失败，且症状看起来像"第二台网关也坏了"。
func (t *tunneler) dialEndpoint(ep Endpoint) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if t.cfg.Gm {
		// ★国密路径同样做指纹钉扎（此前这里完全不认证服务端，见 PinVerifier 的说明）。
		// 钉扎与 CA 链校验不互斥：链校验（RootCAs）在有 CA 时照常生效，钉扎是**额外**
		// 那一层"只认这一张证书"；没有 CA、且客户端带 -insecure 时，钉扎就是唯一的
		// 服务端身份保证——而那正是参考部署的形态（网关证书自签，客户端手里没有国密 CA）。
		cfg := t.cfg.TLCPConfig
		if ep.Pin != "" {
			c := cfg.Clone()
			c.VerifyPeerCertificate = PinVerifierTLCP(ep.Pin)
			cfg = c
		} else {
			slog.Warn("国密隧道未启用证书钉扎（控制面未下发该落点的证书指纹）：若同时带 -insecure 则不认证网关身份",
				"gateway", ep.Label())
		}
		return tlcp.DialWithDialer(d, "tcp", ep.ProxyAddr, cfg)
	}
	return tls.DialWithDialer(d, "tcp", ep.ProxyAddr, tlsClientConfig(ep.Pin))
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
	return &tls.Config{
		// 自签证书过不了链校验，故关闭内建校验，改由下面的回调做钉扎——
		// 回调返回 error 即中止握手，安全性由钉扎承担。
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: PinVerifier(pin),
	}
}

// PinVerifier 生成一个「只认这一张证书」的对端校验回调。
//
// ★抽出来是为了让**国密 TLCP 路径也能用同一份判据**（tlcp.Config 的
// VerifyPeerCertificate 与 crypto/tls 同签名，且 gotlcp 明确写明
// 「InsecureSkipVerify 与 ClientAuth 不影响该函数运行」）。
//
// 此前 TLCP 那条路上没有任何服务端认证：
//   - 网关侧**专门**算了 TLCP 签名证书的指纹上报（cmd/baidi-gateway/main.go，
//     注释写着"钉扎必须钉签名证书，否则客户端永远比对不上"）；
//   - 控制面经接入剖面把它下发到客户端；
//   - 而 dialEndpoint 的 gm 分支不读 ep.Pin（注释说"走 CA 链校验"），
//     桌面客户端又在 gm 时无条件附加 -insecure（把那条链校验也关掉）。
//
// 三处注释各自看着都合理，合起来是「谁都没在做校验」——而 gm 是**默认开**的，
// 也就是参考部署下隧道服务端身份零校验，中间人可直接冒充网关。
// ★判据只写一遍，两条路径各自套一层签名适配：crypto/tls 与 gotlcp 的
// VerifyPeerCertificate 第二个参数类型不同（x509 / smx509），但**钉扎根本不看它**
// ——只认 rawCerts[0]。让两边共用同一个 matchPin，杜绝"改了一处、另一处还在放行"。
func matchPin(want string, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("网关未出示证书")
	}
	// 与网关 certFingerprint 同口径：对叶子证书 DER 原文取 SHA-256。
	// TLCP 双证书握手中 rawCerts[0] 是**签名证书**，与网关上报的那份一致。
	sum := sha256.Sum256(rawCerts[0])
	got := hex.EncodeToString(sum[:])
	// 定长比较用 subtle.ConstantTimeCompare：指纹比对虽非高价值侧信道目标，
	// 但常数时间比较无额外成本，不给计时侧信道留口子。
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("网关证书指纹不匹配（疑似中间人）：期望 %s，实得 %s", want, got)
	}
	return nil
}

// PinVerifier 通用 TLS 路径的钉扎回调。
func PinVerifier(pin string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	want := strings.ToLower(strings.TrimSpace(pin))
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error { return matchPin(want, rawCerts) }
}

// PinVerifierTLCP 国密 TLCP 路径的钉扎回调（判据与 PinVerifier 同源）。
func PinVerifierTLCP(pin string) func(rawCerts [][]byte, verifiedChains [][]*smx509.Certificate) error {
	want := strings.ToLower(strings.TrimSpace(pin))
	return func(rawCerts [][]byte, _ [][]*smx509.Certificate) error { return matchPin(want, rawCerts) }
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
