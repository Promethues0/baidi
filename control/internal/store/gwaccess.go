package store

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() {
			// 回环地址只有网关本机连得上。这不是「配错了格式」，是配了一个必然不通的值，
			// 而它恰恰是此前那条全局兜底的默认值——入口拒掉，免得管理员照着旧行为抄一遍。
			return "", fmt.Errorf("%w：%s 是回环地址，只有网关本机连得上，客户端拨不到", ErrBadAccessHost, h)
		}
		if ip.IsUnspecified() {
			return "", fmt.Errorf("%w：%s 是通配监听地址，不是客户端能连的地址", ErrBadAccessHost, h)
		}
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
