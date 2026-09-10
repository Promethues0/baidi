package store

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ── DNAT 自伤闸（wave11 行动 13-①，PRD FR-NAT-12/13 + FR-SEC-SPA-05）──
//
// 背景：NATWarnSPA 是一条**常量字符串**，只要有任何一条启用中的策略就无条件挂出来，
// 它并不知道这条 DNAT 到底做了什么。而 DNAT 有两种**自伤**形态，两种都是
// 「入口 200 OK、数据面照灌 prerouting、控制台全绿」，链路上一处报错都没有：
//
//	甲 转换后目的 = 网关自己的监听口 —— 等于用地址转换给零信任接入面再开一扇门，
//	  而控制面对这扇门一无所知（剖面落点、七层入口主机名、网关页登记的对外接入地址、
//	  隐身回执里的"规则集保护端口"，全部按网关**自报的监听地址**算）。
//	乙 对外发布端 = 网关自己的监听口 —— prerouting 的目的地址转换排在路由决策**之前**，
//	  命中的报文整条改道走掉，本机服务再也收不到；而网关到控制面的心跳是**出向**的，
//	  照常在线。症状是全员拨号超时，页面上却什么都看不出来。
//
// 形态选**入口拒绝**而不是加一条告警：照 baidi-ipsec 的 parsePeer 拒收 FQDN 的先例
// （站点 peer 填 FQDN 时入口曾放行、400 文案还推荐 FQDN，管理员拿 200 OK 之后
// 站点安静地永远 down）。告警在这里不够——NATWarnSPA 那条早就挂着，而它挡不住任何人。
//
// ★判据来源是**网关自报的监听端口**（注册心跳里的 proxy/spa/web 三栏），不是写死的
// 18201/18443/18444。写死的话，管理员用 -proxy 换了端口这道闸保护的就是别人：
// 它既放过真正把隧道口发布出去的那条 DNAT，又把一条正常发布 18443 业务的规则拦下来，
// 两个方向同时错。取不到上报时**保守**判（退守出厂默认端口）并在拒绝文案里说清这一点。

// ErrNATSelfPublish 这条 DNAT 把网关自己的接入口卷进来了（自伤）。
var ErrNATSelfPublish = errors.New("nat dnat touches the gateway's own listening port")

// NATListen 一台网关**自报**的监听地址快照（注册心跳里的 proxy/spa/web 三栏原样）。
//
// 它不落库：网关的监听地址是运行态，随进程参数变化，控制面只在内存里持有最近一次心跳。
// 因此 Reported 三态里的 false 是真会出现的（控制面刚重启、下一个心跳还没到）。
type NATListen struct {
	// Reported 该网关有没有报过心跳。
	// ★false = 控制面此刻**不知道**它监听在哪，**不是**「它没有监听口」。
	// 两者塌成一个的话，重启后的 15s 窗口里这道闸会整个失效。
	Reported bool
	Proxy    string // -proxy 零信任隧道监听（TCP），形如 ":18443" / "10.0.0.1:18443"
	SPA      string // -spa SPA 敲门监听（UDP）
	Web      string // -web 七层 Web 代理监听（TCP）；空 = 该网关没开七层
}

// 判不出网关监听端口时退守的出厂默认值（与 gateway/firewall/baidi-nft.sh 的
// PROXY_PORT/SPA_PORT、CLAUDE.md 端口表同款）。
//
// ★它们只是「不可判定时的保守兜底」，**不是判据本身**。命中兜底时拒绝文案必须
// 当面写出这一条，否则一个换过端口的部署会收到一句方向完全错误的拒绝，
// 而管理员没有任何线索知道该等一次心跳再试。
const (
	NATDefaultTunnelPort = 18443
	NATDefaultSPAPort    = 18201
	NATDefaultWebPort    = 18444
)

// natOwnPort 网关自己占着的一个监听口。
type natOwnPort struct {
	Port  int
	Proto string // tcp | udp
	Label string // 渲染给管理员看的中文名（拒绝文案要点名"这是干什么的"）
}

// natOwnPorts 折算出「这台网关自己占着哪些端口」。
//
// 第二个返回值 assumed=true 表示这是**猜的**（网关没上报，或上报里连隧道口/敲门口
// 都解析不出来）——调用方必须把它照实写进拒绝文案。
func natOwnPorts(l NATListen) (ports []natOwnPort, assumed bool) {
	if l.Reported {
		tun, spa := natPortOf(l.Proxy), natPortOf(l.SPA)
		// 隧道口与敲门口是网关**必有**的两个监听。任一解析不出来，说明这份快照
		// 本身不可信（不是"这台网关没有隧道口"），整份退守默认值。
		if tun > 0 && spa > 0 {
			ports = append(ports,
				natOwnPort{tun, NATProtoTCP, "零信任隧道口（-proxy）"},
				natOwnPort{spa, NATProtoUDP, "SPA 敲门口（-spa）"})
			// ★Web 为空时**不补默认值**：网关已经明确说了它没开七层（`-web` 默认关），
			// 硬塞一个 18444 进来会把一条正常发布 18444 业务的 DNAT 拦下来，
			// 而拒绝理由指向一个这台机器上根本不存在的监听口。
			if web := natPortOf(l.Web); web > 0 {
				ports = append(ports, natOwnPort{web, NATProtoTCP, "七层 Web 代理口（-web）"})
			}
			return ports, false
		}
	}
	return []natOwnPort{
		{NATDefaultTunnelPort, NATProtoTCP, "零信任隧道口（-proxy）"},
		{NATDefaultSPAPort, NATProtoUDP, "SPA 敲门口（-spa）"},
		{NATDefaultWebPort, NATProtoTCP, "七层 Web 代理口（-web）"},
	}, true
}

// natPortOf 从监听地址里取端口。取不到回 0（= 不可判定，绝不回一个默认端口——
// 那会让"解析失败"与"它真的监听在 18443"在上层完全同形）。
func natPortOf(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// natHostOf 从监听地址里取显式 host；通配（空 / 0.0.0.0 / ::）回空串。
func natHostOf(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return ""
	}
	return host
}

// natIsGatewaySelf 判断一个 IPv4 地址是不是**这台网关自己**。
//
// 判据两条，都取自网关实测上报：回环，或该网关心跳报过的网卡地址 / 监听地址里的显式 host。
// ★刻意**不含**「同网段即算」这类推断：把整个 LAN 段当成网关自己，会把一条正常发布
// 内网业务的 DNAT 拦下来，而这道闸的价值恰恰建立在"它只拦真自伤"上——
// 一道会误伤的闸最后一定被人整个关掉。
func natIsGatewaySelf(ip, gwID string, l NATListen, ifaces []GatewayIface) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	for _, f := range ifaces {
		if f.GatewayID != gwID {
			continue
		}
		for _, a := range f.Addrs {
			if natAddrEq(a, addr) {
				return true
			}
		}
	}
	for _, listen := range []string{l.Proxy, l.SPA, l.Web} {
		if h := natHostOf(listen); h != "" && natAddrEq(h, addr) {
			return true
		}
	}
	return false
}

// natAddrEq 比对一条上报地址（可能带掩码，如 "10.0.0.1/24"）与目标地址。
func natAddrEq(reported string, want netip.Addr) bool {
	reported = strings.TrimSpace(reported)
	if reported == "" {
		return false
	}
	if pfx, err := netip.ParsePrefix(reported); err == nil {
		return pfx.Addr() == want
	}
	a, err := netip.ParseAddr(reported)
	return err == nil && a == want
}

// natPortTouch 这条策略的某一端会不会落在网关自己的某个监听口上。
//
// 协议语义与 natfw 生成的规则一致：tcp/udp 各管各的；`all` 在 nft 里展开成
// `meta l4proto { tcp, udp } th dport N`，两种都命中；`icmp` 没有端口概念。
func natPortTouch(proto string, port int, own natOwnPort) bool {
	if proto == NATProtoICMP || port <= 0 {
		return false
	}
	if proto != NATProtoAll && proto != own.Proto {
		return false
	}
	return port == own.Port
}

// natSelfPublish 检查一条**已归一**的 DNAT 是不是自伤。归一之后才能查是关键：
// TranslatedPort 留空时 normNATPolicy 会把它补成 DstPort，在归一之前查等于放过
// 「发布端口 = 隧道口、转换端口留空」这条最省事的写法。
func natSelfPublish(p NATPolicy, l NATListen, ifaces []GatewayIface) error {
	if p.Type != NATDnat {
		// SNAT 那一侧的自伤（源地址被改写导致隧道回包丢失，FR-NAT-13）由数据面的
		// natfw.Exempt 排除规则兜住，判据同样是网关自己知道的端口，不在这里重复。
		return nil
	}
	own, assumed := natOwnPorts(l)
	note := ""
	if assumed {
		note = natAssumedNote(p.GatewayID, own)
	}
	for _, o := range own {
		if natIsGatewaySelf(p.TranslatedAddr, p.GatewayID, l, ifaces) &&
			natPortTouch(p.Protocol, p.TranslatedPort, o) {
			return fmt.Errorf("%w: 这条 DNAT 的转换后目的 %s:%d 正是本网关自己的%s。"+
				"它等于用地址转换给零信任接入面**再开一扇门**（%s:%d/%s），而控制面对这扇门一无所知——"+
				"剖面下发给终端的落点、七层 Web 入口主机名、网关页登记的「对外接入地址」、"+
				"隐身回执里的「规则集保护端口」，全部按网关自报的监听地址算。"+
				"七层 Web 代理口本就不受 SPA 隐身保护，从这里发布出去等于把 B/S 入口摆到公网；"+
				"未启用内核态隐身的部署（默认即是）还会因此多一个可被扫描器判定为 open 的端点。"+
				"要把接入面对外发布，请让网关直接监听在对外地址上、并在网关页登记「对外接入地址」，别绕道 NAT。%s",
				ErrNATSelfPublish, p.TranslatedAddr, p.TranslatedPort, o.Label,
				p.DstAddr, p.DstPort, p.Protocol, note)
		}
		if natIsGatewaySelf(p.DstAddr, p.GatewayID, l, ifaces) &&
			natPortTouch(p.Protocol, p.DstPort, o) {
			return fmt.Errorf("%w: 这条 DNAT 的对外发布端 %s:%d 正是本网关自己的%s。"+
				"prerouting 的目的地址转换排在**路由决策之前**：命中的报文会被整条改道到 %s:%d，"+
				"本机服务再也收不到，从这个地址上敲门口/隧道口/七层入口会整体消失。"+
				"而网关到控制面的心跳是**出向**的、照常在线——控制台全绿、隐身回执正常、"+
				"客户端只是拨号超时，链路上没有任何一处报错。"+
				"请换一个不与网关自身监听口冲突的对外端口。%s",
				ErrNATSelfPublish, p.DstAddr, p.DstPort, o.Label,
				p.TranslatedAddr, p.TranslatedPort, note)
		}
	}
	return nil
}

// natAssumedNote 兜底判定时必须当面说清的那句话。
//
// 少了它，一个把 -proxy 换到别的端口的部署会收到一句方向完全错误的拒绝
// （"这是隧道口"——而它根本不是），且没有任何线索指向「等一次心跳再试」。
func natAssumedNote(gwID string, own []natOwnPort) string {
	parts := make([]string, 0, len(own))
	for _, o := range own {
		parts = append(parts, fmt.Sprintf("%d/%s", o.Port, o.Proto))
	}
	return fmt.Sprintf("（注：网关「%s」尚未上报过自己的监听地址（从未心跳，或控制面刚重启），"+
		"此处按出厂默认端口 %s **保守判定**。若它实际监听在别的端口上，"+
		"请等它心跳上报一次后重试——这道闸的判据取自网关自报，不写死。）",
		gwID, strings.Join(parts, "、"))
}
