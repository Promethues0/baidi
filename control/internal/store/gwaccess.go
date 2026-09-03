package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ── 网关对外接入地址（PRD FR-SCEN-08/17，wave8 行动 4）──
//
// 此前**根本没有这个配置面**：客户端剖面里的落点主机名是从网关自报的**监听地址**
// 反推出来的（`profileGateways` 拿 `g.SPA` 拆 host），而网关默认监听 `:18201`——
// 不带 host。于是 `splitHostPortLoose` 得到空串，落进那条全局兜底
// `envOr("BAIDI_CLIENT_GW_HOST", "127.0.0.1")`，而 deploy 全程不设这个环境变量。
//
// 两个后果都完全静默：
//
//	① 按 install-remote.sh 装一台 WITH_GATEWAY=1 的网关，剖面下发给桌面客户端的
//	   host 是 127.0.0.1，客户端拨号超时；而控制台网关页显示在线、剖面 warnings
//	   一条不报（那两条只管指纹和在线数）。这正是 CLAUDE.md 记的
//	   「隧道建起来了、点开应用却不通、无报错」同族。
//	② 多数据中心下每台网关都默认 bind `:18201`，于是 N 个落点填**同一个** Host。
//	   客户端 dataplane.picker 忠实地「切到落点 2/3」并打出日志，实际拨的还是
//	   同一台机器——**故障转移在页面上可见、在网络上不存在**。
//
// 地址由管理员登记而不是网关自报：网关无从知道自己在 NAT/负载均衡后面对外是什么地址
// （这与网卡 LAN/WAN 定性由管理员定是同一条理由，见 gateway_ifaces 的注释）。

// GatewayAccess 一台网关的对外接入地址。两栏都可留空。
type GatewayAccess struct {
	GatewayID string `json:"gatewayId"`
	// LANHost 局域网访问地址（内网接入）。PRD FR-SCEN-17 明确要求与互联网地址分开填。
	LANHost string `json:"lanHost"`
	// WANHost 互联网访问地址（公网接入）。
	WANHost   string `json:"wanHost"`
	UpdatedAt string `json:"updatedAt"`
}

// Configured 报告这台网关是否登记过至少一个对外地址。
func (a GatewayAccess) Configured() bool {
	return strings.TrimSpace(a.LANHost) != "" || strings.TrimSpace(a.WANHost) != ""
}

var ErrBadAccessHost = errors.New("接入地址不合法")

// ── 主机地址字面量的可达性分类（登记接入地址 / 网关自报监听地址 / 七层入口共用）──
//
// ★这三处此前**各判各的**，同一个值能得到三种结论：
//
//	NormalizeAccessHost  只拿 net.ParseIP 判回环 → `localhost` 当合法主机名收下；
//	endpointWarnings     同上 → 登记成 localhost 的落点一条告警都不报；
//	api.webHostUnroutable 额外判了 `localhost` → 七层这边判它不可达、不签票。
//
// 于是管理员在网关页填 `localhost` 会 200 OK、剖面照发、客户端拨自己、控制台零报错，
// 而七层入口那边说"入口地址无法确定"——两条接入路对同一份配置给出相反的结论。
// 判据收敛到 ClassifyHost 一处，三个消费方共用。
//
// ★`net.ParseIP` 挡不住的三种写法（都能真监听/真解析到回环）：
//
//	127.1        inet_aton 短写（C 库与浏览器会展开成 127.0.0.1，Go 的 ParseIP 不认）
//	2130706433   同上的整数写法
//	::1%lo0      带 zone 的 IPv6 回环（net.ParseIP 不吃 zone，netip.ParseAddr 吃）
//	localhost.   带根点的 FQDN 写法
//
// 前两种归入 HostMalformed 而不是硬解 inet_aton：把 inet_aton 的十进制/八进制/十六进制
// 混合规则再实现一遍，等于给这条判据引入一个只有极少数人能复核的分支，而**判不出来就
// 当面说判不出来**在这里是完全够用的处置（这些写法没有一个是正常配置该出现的）。
type HostKind int

const (
	// HostRoutable 一个**可能**对外可达的地址：公网/内网 IP，或一个主机名。
	// 它只排除"必然不通"，不保证通——控制面无从知道浏览器/终端在网络的哪一侧。
	HostRoutable HostKind = iota
	// HostLoopback 回环：只有本机连得上。
	HostLoopback
	// HostWildcard 空 / 0.0.0.0 / ::——"所有接口都听"，不是一个能连的地址。
	HostWildcard
	// HostMalformed 形似 IP 字面量、却不是标准写法（inet_aton 短写/整数写法等）。
	// **不可判定**：它多半会被别的解析器展开成另一个地址，而控制面判不出是哪个。
	HostMalformed
)

// ClassifyHost 判一个 host 字面量属于哪一类。传入的必须是**已经去掉端口**的主机部分。
func ClassifyHost(h string) HostKind {
	s := strings.TrimSpace(h)
	s = strings.Trim(s, "[]")        // URL / 监听地址里的 IPv6 方括号
	s = strings.TrimRight(s, ".")    // 根点：localhost. 与 localhost 是同一个名字
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i] // IPv6 zone：::1%lo0 与 ::1 是同一个地址
	}
	if s == "" {
		return HostWildcard
	}
	if strings.EqualFold(s, "localhost") {
		return HostLoopback
	}
	if a, err := netip.ParseAddr(s); err == nil {
		switch {
		case a.IsLoopback():
			return HostLoopback
		case a.IsUnspecified():
			return HostWildcard
		}
		return HostRoutable
	}
	if looksLikeIPLiteral(s) {
		return HostMalformed
	}
	return HostRoutable
}

// IsUnroutableHost 报告这个 host **必然**到不了（或判不出来）：回环 / 通配 / 空 / 非标准写法。
// 只用于"能不能把它交给浏览器或终端去连"这一个问题。
func IsUnroutableHost(h string) bool { return ClassifyHost(h) != HostRoutable }

// IsLoopbackHost 报告这个 host 是回环（含 localhost 与短写/带 zone 的形态）。
func IsLoopbackHost(h string) bool { return ClassifyHost(h) == HostLoopback }

// looksLikeIPLiteral 每一段都是纯数字或 0x 十六进制 —— 没有任何一个合法主机名长这样，
// 而 inet_aton 会把它们当地址解析。
func looksLikeIPLiteral(s string) bool {
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return false
		}
		if strings.HasPrefix(label, "0x") || strings.HasPrefix(label, "0X") {
			if !allHex(label[2:]) {
				return false
			}
			continue
		}
		if !allDigits(label) {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func allHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// NormalizeAccessHost 校验并归一一个接入地址。
//
// 只收**主机名或 IP**，不收端口、协议、路径：端口由网关自报的监听地址决定
// （剖面里 spaPort/proxyPort 各有出处），在这里再收一份就会出现两个真相来源，
// 而它们不一致时症状是「敲门发到 A 口、隧道拨到 B 口」，两边日志都正常。
func NormalizeAccessHost(v string) (string, error) {
	h := strings.TrimSpace(v)
	if h == "" {
		return "", nil // 空 = 不登记该栏
	}
	if len(h) > 253 {
		return "", fmt.Errorf("%w：过长（≤253 字符）", ErrBadAccessHost)
	}
	if strings.ContainsAny(h, " /\\?#") || strings.Contains(h, "://") {
		return "", fmt.Errorf("%w：只填主机名或 IP，不要带协议、路径或空格（如 gw.example.com 或 203.0.113.9）", ErrBadAccessHost)
	}
	// 带端口的写法要当面拒绝而不是默默截断：端口的权威来源是网关自报的监听地址，
	// 这里再收一份就会有两个真相，而不一致时敲门与隧道会拨到不同的口。
	if _, _, err := net.SplitHostPort(h); err == nil {
		return "", fmt.Errorf("%w：不要带端口（端口取自网关自报的监听地址），只填 %s 这样的主机名或 IP",
			ErrBadAccessHost, strings.SplitN(h, ":", 2)[0])
	}
	// ★必然不通的三类当面拒（判据与剖面告警、七层入口共用 ClassifyHost）：
	// 回环只有网关本机连得上——它恰恰是此前那条全局兜底的默认值，不拦的话管理员会照旧行为抄一遍；
	// 通配是监听语义不是连接语义；形似 IP 的非标准写法控制面判不出它指向哪里，而浏览器与 C 库
	// 会按 inet_aton 展开（`127.1` 就是 127.0.0.1），收下等于放进一个自己看不懂的值。
	switch ClassifyHost(h) {
	case HostLoopback:
		return "", fmt.Errorf("%w：%s 是回环地址，只有网关本机连得上，客户端拨不到", ErrBadAccessHost, h)
	case HostWildcard:
		return "", fmt.Errorf("%w：%s 是通配监听地址，不是客户端能连的地址", ErrBadAccessHost, h)
	case HostMalformed:
		return "", fmt.Errorf("%w：%s 形似 IP 却不是标准写法（%s 这类短写会被浏览器与 C 库按 inet_aton "+
			"展开成另一个地址，控制面判不出它指向哪里）——请写成标准的点分四段 IP、IPv6 或主机名",
			ErrBadAccessHost, h, h)
	}
	if ip := net.ParseIP(h); ip != nil {
		return h, nil
	}
	// 主机名：只允许 [A-Za-z0-9.-]，且不以点/横线开头结尾。
	for _, r := range h {
		if !(r == '.' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return "", fmt.Errorf("%w：主机名含非法字符 %q", ErrBadAccessHost, string(r))
		}
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") ||
		strings.HasPrefix(h, "-") || strings.HasSuffix(h, "-") {
		return "", fmt.Errorf("%w：主机名不能以点或横线开头/结尾", ErrBadAccessHost)
	}
	return h, nil
}

// GatewayAccessStore 网关接入地址的持久化（SQLite 后端实现；纯内存栈不提供）。
type GatewayAccessStore interface {
	GatewayAccessList(ctx context.Context) ([]GatewayAccess, error)
	SetGatewayAccess(ctx context.Context, a GatewayAccess) (GatewayAccess, error)
}
