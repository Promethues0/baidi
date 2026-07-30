// Command baidi-ipsec 是白帝的 IPSec 站点组网守护进程（东西向数据面）：
// 纯 Go 用户态 IKEv2 + ESP，站点配置由控制面下发，运行态实测回报。
//
// # 为什么是独立进程而不是并进 baidi-gateway
//
//  1. **权限模型冲突**。baidi-gateway 是非 root、NoNewPrivileges=true 的进程——
//     SPA 敲门与 TLS 隧道代理只要两个高位端口。IPSec 要绑 UDP 500 并建 TUN 卡
//     （CAP_NET_BIND_SERVICE + CAP_NET_ADMIN）。合进去等于给一个**直接暴露在公网、
//     处理未认证 UDP 敲门包**的进程授予建网络接口的能力。
//  2. **失效域隔离**。网关挂 = 远程接入中断；本进程挂 = 站点组网中断。自研协议栈
//     早期版本的 panic 概率不低，不该让 IKE 解析器的一个 panic 顺带打掉远程接入。
//  3. 两者唯一的共享物是 mTLS 客户端证书与控制面地址，而它们已经是文件形式，复用零成本。
//
// # 进程内的装配关系
//
//	         ┌──────────── UDPTransport（500 + 4500，两者共用一条 socket 是 NAT 穿越的硬要求）
//	         │
//	  site.GoBackend ──demux──┬── IKE 支路 → ike.Engine（协商 → 装载 Child SA）
//	         │                └── ESP 支路 → 入向泵 → esp.Engine 解封 → Datapath
//	         │
//	         └── 出向泵 ← Datapath（TUN）
//
//	sync.go：15s 拉站点 → 按 pskVersion 单取密钥 → Backend.Apply 全量对账 → 回报实测状态
//
// # 端口与权限
//
//	-ike-port / -natt-port 可配**不是为测试开的后门**：IKE 端口可配是 NAT 环境的常规需求
//	（对端在做端口映射时必须能改），同时让自检能用高位端口在**无 root** 下跑完整协商。
//	生产默认 500/4500，需要 CAP_NET_BIND_SERVICE；TUN 数据面需要 CAP_NET_ADMIN。
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"baidi.dev/gateway/internal/cplane"
	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/esp"
	"baidi.dev/gateway/internal/ipsec/ike"
	"baidi.dev/gateway/internal/ipsec/site"
)

func main() {
	control := flag.String("control", env("BAIDI_IPSEC_CONTROL", ""),
		"baidi-control 的 mTLS 地址（形如 https://127.0.0.1:8443）。站点配置的唯一权威来源")
	gwid := flag.String("gwid", env("BAIDI_IPSEC_GW_ID", ""),
		"本网关 id，必须与 mTLS 客户端证书的 CN 完全一致，且以 ipsec- 开头；留空则自动取证书 CN")
	mtlsCert := flag.String("mtls-cert", env("BAIDI_IPSEC_MTLS_CERT", ""), "控制面签发的客户端证书 PEM（机器身份）")
	mtlsKey := flag.String("mtls-key", env("BAIDI_IPSEC_MTLS_KEY", ""), "客户端私钥 PEM")
	mtlsCA := flag.String("mtls-ca", env("BAIDI_IPSEC_MTLS_CA", ""), "控制面内部 CA 公证书 PEM（校验服务端）")

	listen := flag.String("listen", env("BAIDI_IPSEC_LISTEN", ""),
		"本端 IKE/ESP 绑定地址（留空=通配）。生产建议绑具体地址：通配绑定下无从得知报文从哪个本机地址收到，NAT 检测只能退而用配置值")
	ikePort := flag.Int("ike-port", envInt("BAIDI_IPSEC_IKE_PORT", 500),
		"IKE 端口（NAT 环境常需改；高位端口可在无 root 下跑完整协商）")
	nattPort := flag.Int("natt-port", envInt("BAIDI_IPSEC_NATT_PORT", 4500),
		"NAT-T / UDP-ESP 端口。★ESP 必须与 IKE 共用同一条 socket：NAT 映射按五元组建立，ESP 另开端口在 NAT 后必然收不到")
	poll := flag.Duration("poll", envDuration("BAIDI_IPSEC_POLL", 15*time.Second), "控制面同步间隔")

	datapath := flag.String("datapath", env("BAIDI_IPSEC_DATAPATH", "tun"),
		"数据面：tun（生产，需 CAP_NET_ADMIN）| netstack（无 root 自检，只跑协商与回报，不承载任何真实业务流量）")
	tunName := flag.String("tun", env("BAIDI_IPSEC_TUN", defaultTunName()), "TUN 设备名（-datapath=tun 时生效）")
	tunIP := flag.String("tun-ip", env("BAIDI_IPSEC_TUN_IP", ""),
		"本端隧道地址。tun 模式：macOS 必填（utun 不配点对点地址起不来），Linux 可留空；netstack 模式：必填且须带前缀长度（如 10.20.0.1/16）")
	mtu := flag.Int("mtu", envInt("BAIDI_IPSEC_MTU", ipsec.DefaultTunnelMTU), "隧道内层 MTU（宁小勿大，见下方说明）")
	logLevel := flag.String("log-level", env("BAIDI_IPSEC_LOG_LEVEL", "info"), "日志级别：debug|info|warn|error")
	flag.Parse()

	var lv slog.Level
	if err := lv.UnmarshalText([]byte(strings.TrimSpace(*logLevel))); err != nil {
		log.Fatalf("拒绝启动：-log-level=%q 无法识别（可用 debug|info|warn|error）", *logLevel)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
	slog.SetDefault(logger)

	// ── 启动期的硬校验：宁可起不来，也不要起来了却静默不工作 ──

	// 站点配置没有本地文件这条路：网关不推导、不猜测、不从别处补齐。
	// 没有控制面就没有任何站点可跑，起来只会是个空转的进程占着 500 端口。
	if strings.TrimSpace(*control) == "" {
		log.Fatal("拒绝启动：必须配置 -control。站点配置的唯一权威来源是控制面，" +
			"本进程不从本地文件读站点（网关不推导策略，与客户端接入剖面同一姿态）")
	}
	// 机器身份只有 mTLS 客户端证书一条路：数据面在代码层已无签发能力（阶段 4 删了 auth.Sign）。
	// 照抄 baidi-gateway 的 fail-closed 姿态——早失败好过起来后每 15 秒静默 403 一次。
	if *mtlsCert == "" || *mtlsKey == "" || *mtlsCA == "" {
		log.Fatal("拒绝启动：配了 -control 就必须同时配 -mtls-cert/-mtls-key/-mtls-ca。" +
			"用 admin 调 POST /api/v1/pki/gateway-certs 取证（gatewayId 须以 ipsec- 开头，响应含 certPem/keyPem/caPem）")
	}

	cn, err := certCN(*mtlsCert)
	if err != nil {
		log.Fatalf("读取客户端证书 CN 失败: %v", err)
	}
	id, err := resolveGatewayID(*gwid, cn)
	if err != nil {
		log.Fatalf("拒绝启动：%v", err)
	}

	cp, err := cplane.NewMTLS(*control, id, "", "", *mtlsCert, *mtlsKey, *mtlsCA)
	if err != nil {
		log.Fatalf("mTLS 控制面客户端初始化失败: %v", err)
	}
	// ★这里刻意不调 cp.Register：控制面的 accessCNet 明确拒绝 ipsec-* 证书调用
	// /api/v1/gateways/register，一张只负责站点组网的证书不该出现在接入网关名册里。
	// 代价是本进程不出现在监控中心的网关列表——它的存在感来自 ipsec_sa_state 里
	// 那几行带 gateway_id 的实测运行态，那比一条心跳更能说明问题。

	// ── 装配（端口在这里绑：端口冲突要第一时间炸出来，别等到跑起来才发现）──
	n, err := assemble(nodeOptions{
		GatewayID: id, Listen: *listen,
		IKEPort: *ikePort, NATTPort: *nattPort,
		Datapath: *datapath, TUNName: *tunName, TUNAddr: *tunIP, MTU: *mtu,
		Control: cp, Log: logger,
	})
	if err != nil {
		log.Fatalf("拒绝启动：%v", err)
	}
	engine, sy := n.engine, n.sy

	slog.Info("baidi-ipsec 启动",
		"gwid", id, "control", *control, "数据面", *datapath,
		"ike", n.udp.LocalIKE().String(), "nat-t", n.udp.LocalNAT().String(),
		"同步间隔", poll.String(), "隧道 MTU", n.dp.MTU())

	// ── 运行 ──
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(1)
	ikeDone := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(ikeDone)
		// Run 在 ctx 结束时会先向所有对端发 D(IKE) 再返回（见 ike.Engine.shutdown）。
		// ★这一步不能省：不发 Delete，对端会留一条"幽灵 SA"，直到 DPD 判死（默认 30s
		// 探测 + 最长 182s 重传）才清理，期间它仍会往一条已经没人接收的隧道里发业务流量。
		if err := engine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("IKE 事件循环退出", "err", err.Error())
		}
	}()

	wg.Add(1)
	syncDone := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(syncDone)
		sy.run(ctx, *poll)
	}()

	<-ctx.Done()
	stop() // 恢复默认信号行为：第二次 Ctrl-C 能直接杀掉进程，不至于卡在清理里出不来
	slog.Info("收到退出信号，正在拆除隧道（向对端发 Delete）…")

	// 停机三步，顺序不能换：
	//
	//  1. 等同步循环收工。★否则最后那次"站点已下线"的回报可能被一次**在途的**
	//     常规回报覆盖掉（两次全量覆写谁后到谁说了算），库里又留下一行 up 的残影。
	//  2. 等状态机把 Delete 发完——先关 socket 的话 Delete 根本发不出去，
	//     而日志上看起来一切正常（destroySA 对发送失败是"尽力而为"）。
	//  3. 回报下线，再关闭自己创建的零件。
	select {
	case <-syncDone:
	case <-time.After(3 * time.Second):
		slog.Warn("等待同步循环收工超时：最后一次状态回报可能被在途的常规回报覆盖")
	}
	select {
	case <-ikeDone:
	case <-time.After(3 * time.Second):
		slog.Warn("等待 IKE 事件循环退出超时，继续停机（对端可能残留幽灵 SA，将由 DPD 清理）")
	}

	// 最后一次回报：不报的话，库里那行 state=up 会永久留着，控制台上就是一条
	// "已建立"却早已不存在的隧道。给它一个短超时，回报不该拖住停机。
	rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	sy.shutdownReport(rctx, "收到停止信号")
	cancel()

	n.close()
	wg.Wait()
	slog.Info("baidi-ipsec 已退出")
}

// ── 装配 ──

// nodeOptions 一个 baidi-ipsec 实例的全部装配参数（= main 里那几个 flag 的值）。
type nodeOptions struct {
	GatewayID string
	Listen    string // 本端绑定地址，空=通配
	IKEPort   int
	NATTPort  int
	Datapath  string // tun | netstack
	TUNName   string
	TUNAddr   string
	MTU       int
	Control   controlClient
	Log       *slog.Logger
}

// node 装配完成的一整套零件。持有它们是为了能按正确的顺序关掉：
// ★所有权原则贯穿这几层——site.GoBackend 不关它没创建的 Transport/Datapath
// （越权关闭造成的 "use of closed network connection" 极难追溯到是谁关的），
// 于是"谁创建谁关闭"的责任就落在这里。
type node struct {
	udp     *ipsec.UDPTransport
	dp      ipsec.Datapath
	prot    *esp.Engine
	engine  *ike.Engine
	backend *site.GoBackend
	sy      *syncer
}

// assemble 把 Transport / Datapath / ESP / IKE / 编排层装成一个可运行的实例。
//
// ★装配顺序不是随意的，三处的先后关系错了都会得到"看起来在跑、实际不通"的结果：
//
//  1. **Protector 只能有一个实例**，同时给 IKE 状态机与 Backend。状态机协商完往里
//     Install，两条泵从里面 Protect/Unprotect；两个实例的后果是"握手全绿、
//     一个包都不通"，而两边日志都正常。
//  2. **状态机必须收 Backend 分出来的 IKE 支路**，不能收原始 Transport——否则它会
//     和入向泵抢同一个接收队列，两边各吞掉对方一部分报文，表现为「握手偶尔卡住、
//     流量偶尔丢包」，比例随负载变化，低负载下几乎不复现（见 lateTransport）。
//  3. **Extra 钩子要在 Apply 之前接上**。不接的话，管理员在界面上选了 IKEv1、
//     打开了 PQ 混合，网关会照常按 IKEv2 无 PQ 跑起来并显示 up——界面与实际彻底脱节。
//
// 抽成函数是为了让上面这三条能被 main_test.go 用两个真实实例对拨验证：
// 装配错误只在"两端真的要通信"时才现形，任何单元测试都替代不了。
func assemble(o nodeOptions) (*node, error) {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}

	var bind netip.Addr
	if v := strings.TrimSpace(o.Listen); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("-listen=%q 不是合法 IP：%w", v, err)
		}
		bind = a
	}
	if o.IKEPort < 0 || o.IKEPort > 65535 || o.NATTPort < 0 || o.NATTPort > 65535 {
		return nil, fmt.Errorf("端口越界（-ike-port=%d -natt-port=%d）", o.IKEPort, o.NATTPort)
	}
	// 端口同号只有在两个都是 0（内核各分配一个）时才无害。
	// ★否则 non-ESP marker 的加减规则会自相矛盾（500 上不加、4500 上加），
	// 表现为对端时而解不开 IKE 报文，且只在其中一条路径上出现。
	if o.IKEPort == o.NATTPort && o.IKEPort != 0 {
		return nil, fmt.Errorf("-ike-port 与 -natt-port 不能相同（都是 %d）："+
			"两个端口上的 non-ESP marker 规则不同，合并会让对端间歇性解不开 IKE 报文", o.IKEPort)
	}

	tr, err := ipsec.NewUDPTransport(bind, uint16(o.IKEPort), uint16(o.NATTPort))
	if err != nil {
		return nil, fmt.Errorf("绑定 IKE/NAT-T 端口失败：%w", err)
	}
	udp, ok := tr.(*ipsec.UDPTransport)
	if !ok {
		_ = tr.Close()
		return nil, fmt.Errorf("内部错误：NewUDPTransport 返回了非 *UDPTransport（%T），无从得知实际绑定的落点", tr)
	}

	dp, routes, err := buildDatapath(o.Datapath, o.TUNName, o.TUNAddr, o.MTU, log)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("初始化数据面失败：%w", err)
	}

	prot := esp.New(log, time.Now)
	late := &lateTransport{ready: make(chan struct{}), done: make(chan struct{})}
	engine := ike.NewEngine(ike.EngineOptions{
		Transport: late,
		Protector: prot,
		LocalIKE:  udp.LocalIKE(),
		LocalNAT:  udp.LocalNAT(),
		Log:       log,
	})

	sy := newSyncer(o.Control, o.GatewayID, nil, log, routes)
	backend, err := site.NewBackend(site.BackendOptions{
		GatewayID: o.GatewayID,
		Transport: tr,
		Datapath:  dp,
		IKE:       engine,
		Protector: prot,
		Log:       log,
		Extra:     sy.extraOf,
	})
	if err != nil {
		_ = dp.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("组装 IPSec 后端失败：%w", err)
	}
	late.set(backend.IKETransport())
	sy.back = backend

	return &node{udp: udp, dp: dp, prot: prot, engine: engine, backend: backend, sy: sy}, nil
}

// close 按"编排 → 数据面 → socket"的顺序关掉自己创建的东西。
//
// ★调用前必须先让 ike.Engine.Run 退出（它会在退出前发 D(IKE)）：
// 先关 socket 的话 Delete 根本发不出去，而日志上看起来一切正常
// （destroySA 对发送失败是"尽力而为"），对端会留一条幽灵 SA 直到 DPD 判死。
func (n *node) close() {
	_ = n.backend.Close()
	_ = n.dp.Close()
	_ = n.udp.Close()
}

// resolveGatewayID 定下本机 id，并守住两条硬约束。
//
// ★两条都必须是**启动期拒绝**，因为违反后的表现都是"静默不工作"：
//
//   - id 与证书 CN 不一致：控制面按 CN 过滤下发站点，本地 Backend 按 -gwid 过滤归属，
//     两边对不上时控制面下发的每一条站点都会被本地整条忽略——控制台上站点一直
//     connecting，网关日志里一条错误也没有。
//   - CN 不以 ipsec- 开头：三个 ipsec 端点全部 403（见 control 的 ipsecCNOnly），
//     每 15 秒失败一次，而失败原因藏在轮询日志里。
func resolveGatewayID(flagID, cn string) (string, error) {
	id := strings.TrimSpace(flagID)
	if id == "" {
		id = cn // 不填就取证书 CN：这消灭了"两处各写一遍、写岔了"这一整类故障
	}
	if id != cn {
		return "", fmt.Errorf("-gwid=%q 与 mTLS 客户端证书的 CN=%q 不一致：\n"+
			"    控制面按证书 CN 下发站点，本地按 -gwid 判断站点归属，两边对不上时"+
			"每一条下发的站点都会被本地整条忽略——现象是控制台上站点永远 connecting 而网关一条错误日志都没有。\n"+
			"    留空 -gwid 即自动取证书 CN。", flagID, cn)
	}
	if !strings.HasPrefix(id, "ipsec-") {
		return "", fmt.Errorf("网关 id / 证书 CN 是 %q，必须以 ipsec- 开头：\n"+
			"    控制面只允许 CN 以 ipsec- 开头的证书调用站点组网接口（一张只负责组网的证书"+
			"不该能读走全量资源授权策略）。\n"+
			"    重新签一张证书：POST /api/v1/pki/gateway-certs {\"gatewayId\":\"ipsec-%s\"}", id, id)
	}
	return id, nil
}

// certCN 读客户端证书 PEM 的第一张证书的 CN。
func certCN(certFile string) (string, error) {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("%s 里的证书解析失败：%w", certFile, err)
		}
		return c.Subject.CommonName, nil
	}
	return "", fmt.Errorf("%s 里没有 CERTIFICATE 块（是不是把私钥文件填到 -mtls-cert 上了？）", certFile)
}

// buildDatapath 建数据面，并返回一个"把该进隧道的网段写进路由表"的钩子（netstack 模式为 nil）。
func buildDatapath(kind, name, addr string, mtu int, log *slog.Logger) (ipsec.Datapath, func([]netip.Prefix), error) {
	// ★MTU 宁小勿大。配大了的症状极具迷惑性：小包（ping、DNS、TCP 握手）全通，
	// 一旦发满载数据段就被丢弃，表现为「能 ping 通、SSH 能登录、HTTP 一传大文件就卡死」，
	// 而隧道状态自始至终是 up。本实现不做 PMTUD，算错了没有任何自愈机制。
	//
	// 这里用保守常量而不是 site.TunnelMTU()：后者要按**实际协商定型**的套件反推，
	// 而网卡必须在协商之前就建好。小一点只损失几十字节吞吐，大一点是静默丢包。
	if mtu <= 0 {
		mtu = ipsec.DefaultTunnelMTU
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "tun":
		var local netip.Addr
		if v := strings.TrimSpace(addr); v != "" {
			a, err := parseTunAddr(v)
			if err != nil {
				return nil, nil, err
			}
			local = a
		}
		// 建卡时**不写任何路由**：站点还没拉到，此刻根本不知道该路由哪些网段。
		// 路由全部交给 routeAdder 在每轮同步后按控制面下发的 remoteSubnet 补齐。
		d, err := ipsec.NewTUNDatapathWithAddr(name, mtu, local, nil)
		if err != nil {
			return nil, nil, err
		}
		ra := &routeAdder{dev: d.Name(), log: log, done: map[netip.Prefix]bool{}}
		log.Info("数据面：TUN（生产）", "接口", d.Name(), "本端地址", addr, "MTU", mtu)
		return d, ra.ensure, nil

	case "netstack":
		// ★自检数据面：协商、密钥派生、ESP 加解密、状态回报**全都是真的**，
		// 但它背后是一个进程内的用户态协议栈，没有任何真实业务流量能从外面进出这条隧道。
		// 存在的唯一理由是让 ipsec-e2e.sh 能在无 root、无 Docker 的机器上跑完整协商链路。
		p, err := netip.ParsePrefix(strings.TrimSpace(addr))
		if err != nil {
			return nil, nil, fmt.Errorf("-datapath=netstack 需要 -tun-ip 写成带前缀长度的形式"+
				"（如 10.20.0.1/16，前缀长度决定哪些地址算同网段直连）：%w", err)
		}
		d, err := ipsec.NewNetstackDatapath(p, mtu)
		if err != nil {
			return nil, nil, err
		}
		log.Warn("⚠ 数据面：netstack 自检模式——协商与状态回报都是真的，" +
			"但这条隧道**不承载任何真实业务流量**（数据面在进程内）。生产必须用 -datapath=tun")
		return d, nil, nil

	default:
		return nil, nil, fmt.Errorf("-datapath=%q 无法识别：只支持 tun（生产）与 netstack（无 root 自检）", kind)
	}
}

// parseTunAddr 允许 -tun-ip 写成 10.20.0.1 或 10.20.0.1/16 两种形态（tun 模式只取地址部分）。
func parseTunAddr(v string) (netip.Addr, error) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Addr(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("-tun-ip=%q 不是合法地址：%w", v, err)
	}
	return a, nil
}

// routeAdder 把"该进隧道的网段"写进系统路由表。
//
// # 为什么路由是增量加、且**永不删**
//
// 路由缺一条与多一条的后果完全不对称：
//
//   - 缺：发往该网段的业务流量根本不会进 TUN，而是从物理网卡**明文直连出去**。
//     隧道状态一切正常、日志一行没有——这正是 CLAUDE.md 里 `baidi-tun -route` 那条
//     「隧道建起来了、点开应用却直连不走隧道」的事故形态。
//   - 多：流量进了 TUN 但没有匹配的 SA，被 esp 层以 ErrNoPolicy **丢弃并计数**
//     （出向泵绝不把它明文放行），管理员在日志与计数里看得见。
//
// 一边是静默泄漏，一边是可见的丢弃。所以停用/删除站点时刻意不撤路由。
//
// ★命令写法与 internal/ipsec/datapath_tun.go 的 tunUp 同源（那套是实跑验证过的），
// 两处必须保持一致；改一处就要改另一处。
type routeAdder struct {
	dev  string
	log  *slog.Logger
	mu   sync.Mutex
	done map[netip.Prefix]bool
}

func (r *routeAdder) ensure(ps []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range ps {
		if r.done[p] {
			continue
		}
		if err := addRoute(r.dev, p); err != nil {
			if isRouteExists(err) {
				// 上一次运行留下的路由（或系统里本来就有）：目标已达成，登记为已完成。
				r.done[p] = true
				r.log.Info("路由已存在，跳过", "网段", p.String(), "接口", r.dev)
				continue
			}
			// 不致命但很严重：这个网段的流量此刻正从物理网卡明文出去。
			// 每轮都会重试，也每轮都要吵——它值得被吵醒。
			r.log.Error("写入隧道路由失败：该网段的流量不会进入隧道，正在以明文从物理网卡直连",
				"网段", p.String(), "接口", r.dev, "err", err.Error())
			continue
		}
		r.done[p] = true
		r.log.Info("隧道路由已写入", "网段", p.String(), "接口", r.dev)
	}
}

func addRoute(dev string, p netip.Prefix) error {
	switch runtime.GOOS {
	case "darwin":
		return sh("route", "-q", "-n", "add", "-net", p.String(), "-interface", dev)
	case "linux":
		return sh("ip", "route", "add", p.String(), "dev", dev)
	case "windows":
		return sh("netsh", "interface", "ip", "add", "route", p.String(), "interface="+dev)
	default:
		return fmt.Errorf("平台 %s 尚未适配隧道路由写入（可用的生产平台是 linux）", runtime.GOOS)
	}
}

// isRouteExists 判断"这条路由本来就在"。三平台的措辞各不相同，全都收在这里。
func isRouteExists(err error) bool {
	s := strings.ToLower(err.Error())
	for _, k := range []string{"file exists", "already exists", "route already in table", "已存在", "对象已存在"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func sh(name string, args ...string) error {
	// 带上完整命令行与输出：路由写入失败时，管理员需要的是"哪条命令、报了什么"，
	// 而不是一句 "exit status 1"。
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v 执行失败：%v：%s", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// lateTransport 解一个组装顺序上的死结。
//
// ike.Engine 在构造时就要一条 Transport，而它**必须**用 site.GoBackend 分流出来的
// IKE 支路——收原始 Transport 的话，状态机会和入向泵抢同一个接收队列，两边各吞掉
// 对方一部分报文，表现为「握手偶尔卡住、流量偶尔丢包」，比例随负载变化，
// 低负载下几乎不复现。可那条支路只有在 NewBackend 之后才存在，而 NewBackend 又要
// 先拿到 Engine。
//
// 于是这里放一层薄壳：Engine 先拿到它，Backend 建好后再把真正的支路塞进来。
// set 之前的任何调用都会阻塞等待（实际上不会发生：Engine.Run 在 set 之后才启动），
// 而不是静默丢包——「组装顺序错了」必须表现为卡住而不是随机丢报文。
type lateTransport struct {
	ready chan struct{} // set 时关闭；close 建立 happens-before，inner 的读写因此无需加锁
	done  chan struct{}
	once  sync.Once
	inner ipsec.Transport
}

func (t *lateTransport) set(inner ipsec.Transport) {
	t.inner = inner
	close(t.ready)
}

func (t *lateTransport) get() (ipsec.Transport, error) {
	select {
	case <-t.ready:
		return t.inner, nil
	case <-t.done:
		return nil, ipsec.ErrClosed
	}
}

func (t *lateTransport) Send(d ipsec.Datagram) error {
	tr, err := t.get()
	if err != nil {
		return err
	}
	return tr.Send(d)
}

func (t *lateTransport) Recv() (ipsec.Datagram, error) {
	tr, err := t.get()
	if err != nil {
		return ipsec.Datagram{}, err
	}
	return tr.Recv()
}

func (t *lateTransport) Close() error {
	t.once.Do(func() { close(t.done) })
	select {
	case <-t.ready:
		return t.inner.Close()
	default:
		return nil
	}
}

// defaultTunName 各平台的缺省接口名。
// ★macOS 的设备名必须是 utun 或 utun<N>，别的名字会在建卡时直接失败。
func defaultTunName() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return "baidi-ipsec0"
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
		// 不静默回退到默认值：环境变量写错了却按默认端口起来，是"以为改了其实没改"的经典形态。
		log.Fatalf("拒绝启动：环境变量 %s=%q 不是整数", k, v)
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			log.Fatalf("拒绝启动：环境变量 %s=%q 不是合法时长（形如 15s / 1m）", k, v)
		}
		return d
	}
	return def
}
