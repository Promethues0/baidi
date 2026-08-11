package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// 地址转换（NAT）领域模型 —— PRD 第 18 章。
//
// ★定位先说清楚，免得被当成零信任能力：NAT 是把网关**复用**成传统出口/发布路由设备
// 的三层转发能力，与 SPA 隐身、隧道代理不是一回事，而且**天然冲突**（见 NATWarnSPA）。
// 判定权仍在控制面：策略在这里建模与校验，网关只把算好的规则灌进内核 nft/pf。

// 转换类型。
const (
	NATSnat = "snat" // 源地址转换：内网出站统一出口（代理上网）
	NATDnat = "dnat" // 目的地址转换：公网 IP:端口 → 内网真实 IP:端口（资源发布）
)

// 协议取值。ICMP 无端口概念，DNAT 选它时端口字段必须留空。
const (
	NATProtoTCP  = "tcp"
	NATProtoUDP  = "udp"
	NATProtoICMP = "icmp"
	NATProtoAll  = "all"
)

// 网卡类型。NAT 要求方向不能选反，故接口必须先被管理员定性。
const (
	IfaceLAN  = "lan"
	IfaceWAN  = "wan"
	IfaceNone = "" // 未定性：不能出现在任何 NAT 策略里
)

// NATPolicy 一条地址转换策略（PRD 18.4 实体一）。
type NATPolicy struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`      // snat | dnat
	GatewayID string `json:"gatewayId"` // 规则下发到哪台网关（NAT 是设备本地能力，必须绑定具体网关）

	SrcIface string `json:"srcIface"` // SNAT=LAN 口；DNAT=WAN 口
	SrcAddr  string `json:"srcAddr"`  // CIDR。SNAT=需代理上网的内网网段；DNAT=允许访问的公网源（默认 0.0.0.0/0）
	DstIface string `json:"dstIface"` // SNAT=WAN 口；DNAT=LAN 口
	DstAddr  string `json:"dstAddr"`  // SNAT=出口网段(CIDR)；DNAT=对外发布的公网 IP（单地址）

	Protocol string `json:"protocol"` // DNAT 必填；SNAT 固定 all（手册未要求按协议分流）

	// 仅 DNAT：转换后数据。
	DstPort        int    `json:"dstPort"`        // 对外发布端口
	TranslatedAddr string `json:"translatedAddr"` // 业务系统真实内网 IP
	TranslatedPort int    `json:"translatedPort"` // 业务系统真实端口

	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// GatewayIface 网关上报的一张网卡 + 管理员定性的类型（PRD 18.4 实体二）。
//
// ★网卡清单是网关**实测枚举**上报的（net.Interfaces），不是管理员手填：
// 手填的话，选错网卡名的症状是规则灌进内核后悄无声息地不匹配任何流量。
// 类型（LAN/WAN）没有可靠的自动判据，由管理员指定，落在控制面。
type GatewayIface struct {
	GatewayID string   `json:"gatewayId"`
	Name      string   `json:"name"`  // eth0 / en0 …
	Type      string   `json:"type"`  // lan | wan | ""（未定性）
	Addrs     []string `json:"addrs"` // 实测 IP/掩码，供管理员核对方向
	Up        bool     `json:"up"`
	UpdatedAt string   `json:"updatedAt"`
}

// NATBundle 地址转换页一次取全：策略 + 可选网卡 + 互斥告警。
type NATBundle struct {
	Policies []NATPolicy    `json:"policies"`
	Ifaces   []GatewayIface `json:"ifaces"`
	// Warnings 配置侧必须当面给出的风险提示（FR-NAT-12/16）。
	Warnings []string `json:"warnings"`
}

var (
	ErrNATNotFound      = errors.New("nat policy not found")
	ErrNATIfaceUnknown  = errors.New("interface not reported by gateway")
	ErrNATIfaceUntyped  = errors.New("interface has no lan/wan type")
	ErrNATIfaceWrongDir = errors.New("interface type does not match direction")
)

// NATWarnSPA 是 FR-NAT-12 要求「在配置侧体现」的那条互斥。
//
// ★为什么必须当面说：NAT 规则在内核 nat 表，SPA 隐身靠 filter 表的默认 DROP。
// 一旦 DNAT 把某个端口映射进内网，那条流量在 filter 之前就被改写并放行了——
// 隐身对它失效，而管理台上 SPA 仍显示「已启用」。两个功能各自都「正常」，
// 合起来是一个不设防的洞，且没有任何报错。
const NATWarnSPA = "已启用地址转换：命中 NAT 规则的流量优先走转换并绕过 SPA 服务隐身——" +
	"被 DNAT 发布出去的端口在公网上是可探测的。请确认这些端口本就打算公开。"

// NATWarnBandwidth FR-NAT-16。
const NATWarnBandwidth = "网关同时承担零信任隧道与地址转换转发，请确认链路带宽足以支撑两类业务并存。"

// NATWarnRoute FR-NAT-11：NAT 只是半条链路，回程路由不配就永远不通。
const NATWarnRoute = "启用 NAT 后网关以路由设备形态工作：内网 PC 需把网关 LAN 口设为网关地址，" +
	"被发布的业务系统需把回程路由指向网关 LAN 口，否则转换成功但回包丢失（表现为连接超时且网关侧无报错）。"

// normNATPolicy 归一化并校验一条策略。ifaces 是该网关**实测上报**的网卡清单。
//
// 校验必须在控制面做完：网关侧只负责把规则灌进内核，灌之前它没有「这条策略合不合理」
// 的判断依据；等到内核拒绝再报错，管理员看到的是一串 nft 语法错误。
func normNATPolicy(p NATPolicy, ifaces []GatewayIface) (NATPolicy, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return p, errors.New("策略名称不能为空")
	}
	if len([]rune(p.Name)) > 64 {
		return p, errors.New("策略名称最长 64 字")
	}
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	if p.Type != NATSnat && p.Type != NATDnat {
		return p, fmt.Errorf("转换类型只能是 %s 或 %s", NATSnat, NATDnat)
	}
	p.GatewayID = strings.TrimSpace(p.GatewayID)
	if p.GatewayID == "" {
		return p, errors.New("必须指定这条策略下发到哪台网关")
	}

	// 方向定性：SNAT 是 LAN→WAN，DNAT 是 WAN→LAN。选反了流量一条都不会命中。
	wantSrc, wantDst := IfaceWAN, IfaceLAN
	if p.Type == NATSnat {
		wantSrc, wantDst = IfaceLAN, IfaceWAN
	}
	var err error
	if p.SrcIface, err = checkIface(p.SrcIface, wantSrc, "源接口", p.GatewayID, ifaces); err != nil {
		return p, err
	}
	if p.DstIface, err = checkIface(p.DstIface, wantDst, "目的接口", p.GatewayID, ifaces); err != nil {
		return p, err
	}
	// ★这里刻意**没有**「源接口 ≠ 目的接口」这道检查：上面两次 checkIface 已要求
	// 一个是 LAN、一个是 WAN，同一张卡不可能同时是两种类型，那道检查永远不会触发。
	// 写了它会显得多了一层防护，实则是死代码——本项目最初的版本里就有一条，
	// 是被单测（源目填同一张卡时报的是方向错误而非同卡错误）逼出来才发现的。

	if p.SrcAddr, err = normCIDR(p.SrcAddr, "源地址"); err != nil {
		return p, err
	}

	if p.Type == NATSnat {
		if p.DstAddr, err = normCIDR(p.DstAddr, "目的地址"); err != nil {
			return p, err
		}
		// SNAT 不做协议分流（手册未要求），显式归一成 all 而不是留空——
		// 留空会让下发给网关的规则少一个字段，网关侧再补默认值就是第二处口径。
		p.Protocol = NATProtoAll
		// 转换后数据是 DNAT 专属：SNAT 带着它落库，页面上会显示一组永不生效的值。
		p.DstPort, p.TranslatedAddr, p.TranslatedPort = 0, "", 0
		return p, nil
	}

	// ── DNAT ──
	if p.DstAddr, err = normHostIP(p.DstAddr, "对外发布地址"); err != nil {
		return p, err
	}
	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	switch p.Protocol {
	case NATProtoTCP, NATProtoUDP, NATProtoICMP, NATProtoAll:
	default:
		return p, errors.New("协议只能是 tcp / udp / icmp / all")
	}
	if p.TranslatedAddr, err = normHostIP(p.TranslatedAddr, "转换后目的地址"); err != nil {
		return p, err
	}
	if p.Protocol == NATProtoICMP {
		// ICMP 没有端口。带上端口的话，生成的 nft 规则会因「icmp 协议匹配 dport」直接语法错误。
		if p.DstPort != 0 || p.TranslatedPort != 0 {
			return p, errors.New("协议为 ICMP 时不能配置端口（ICMP 没有端口概念）")
		}
		return p, nil
	}
	if err := checkPort(p.DstPort, "对外发布端口"); err != nil {
		return p, err
	}
	if p.TranslatedPort == 0 {
		p.TranslatedPort = p.DstPort // 不改端口是常见用法，缺省即同端口
	}
	if err := checkPort(p.TranslatedPort, "转换后端口"); err != nil {
		return p, err
	}
	return p, nil
}

func checkIface(name, want, label, gwID string, ifaces []GatewayIface) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%s不能为空", label)
	}
	for _, f := range ifaces {
		if f.GatewayID != gwID || f.Name != name {
			continue
		}
		if f.Type == IfaceNone {
			return "", fmt.Errorf("%w: %s「%s」尚未指定 LAN/WAN 类型", ErrNATIfaceUntyped, label, name)
		}
		if f.Type != want {
			return "", fmt.Errorf("%w: %s「%s」是 %s 口，此处需要 %s 口（方向选反会让规则一条流量都匹配不上）",
				ErrNATIfaceWrongDir, label, name, strings.ToUpper(f.Type), strings.ToUpper(want))
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: 网关 %s 没有上报过网卡「%s」", ErrNATIfaceUnknown, gwID, name)
}

func normCIDR(s, label string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%s不能为空", label)
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("%s「%s」不是合法网段（形如 10.0.0.0/16）", label, s)
	}
	if !pfx.Addr().Is4() {
		return "", fmt.Errorf("%s暂只支持 IPv4", label)
	}
	// Masked 归一：10.1.2.3/16 落库成 10.1.0.0/16。不归一的话同一个网段会有多种写法，
	// 去重与「规则是否变化」的比较都会失准。
	return pfx.Masked().String(), nil
}

func normHostIP(s, label string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%s不能为空", label)
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("%s「%s」不是合法 IPv4 地址", label, s)
	}
	return ip.To4().String(), nil
}

func checkPort(p int, label string) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("%s「%s」不在 1-65535 范围内", label, strconv.Itoa(p))
	}
	return nil
}

// NATWarnings 组装配置侧必须当面给出的提示。空策略集不给提示——
// 没启用 NAT 的系统弹一条「NAT 会让 SPA 失效」只会让人麻木。
func NATWarnings(policies []NATPolicy) []string {
	var anyEnabled bool
	for _, p := range policies {
		if p.Enabled {
			anyEnabled = true
			break
		}
	}
	if !anyEnabled {
		return nil
	}
	return []string{NATWarnSPA, NATWarnRoute, NATWarnBandwidth}
}

// NATForGateway 过滤出某台网关**启用中**的策略，供策略下发。
// 停用的策略不下发（而不是下发一个 enabled=false 让网关自己判断）：
// 判定权在控制面，数据面只执行给它的那份。
func NATForGateway(policies []NATPolicy, gwID string) []NATPolicy {
	out := make([]NATPolicy, 0, len(policies))
	for _, p := range policies {
		if p.Enabled && p.GatewayID == gwID {
			out = append(out, p)
		}
	}
	return out
}

// NATStore 地址转换的读写口（独立接口，不进 Store —— 与 AuthSourceStore 同款，
// 避免给 coverage_guard 的种子豁免逻辑增加无谓的表面积）。
type NATStore interface {
	NATPolicies(ctx context.Context) ([]NATPolicy, error)
	SaveNATPolicy(ctx context.Context, p NATPolicy) (NATPolicy, error)
	DeleteNATPolicy(ctx context.Context, id string) error
	GatewayIfaces(ctx context.Context) ([]GatewayIface, error)
	ReplaceGatewayIfaces(ctx context.Context, gwID string, ifaces []GatewayIface) error
	SetGatewayIfaceType(ctx context.Context, gwID, name, ifType string) error
}
