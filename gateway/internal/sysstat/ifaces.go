package sysstat

import (
	"net"
	"sort"
	"strings"
)

// Iface 一张网卡的实测信息，随心跳上报控制面供地址转换选源/目的接口。
//
// ★为什么必须实测上报而不是让管理员手填网卡名：手填打错的症状是
// NAT 规则灌进内核后一条流量都不匹配——没有报错、没有日志，
// 管理台上策略还是「已启用」。让控制面只能从真实存在的网卡里选，
// 这类错误在录入那一刻就不可能发生。
//
// 类型（LAN/WAN）不在这里判：网关没有可靠依据分辨哪张卡对公网
// （有默认路由 ≠ 对公网，多出口/策略路由下会判错），交给管理员在控制面指定。
// 猜一个再让管理员以为系统知道，比不猜更糟。
type Iface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"` // CIDR 形式，如 10.0.0.5/24
	Up    bool     `json:"up"`
}

// Ifaces 枚举本机网卡。
//
// 刻意排除环回与无地址的卡：它们不可能成为 NAT 的源/目的接口，
// 列出来只会让管理员在一堆 lo/utun/bridge 里挑。**但 down 的卡要保留**——
// 网线没插好时那张卡仍然是管理员想配的那张，藏起来会让他以为网卡名写错了。
func Ifaces() []Iface {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]Iface, 0, len(list))
	for _, in := range list {
		if in.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		var cidrs []string
		for _, a := range addrs {
			s := a.String()
			// 只留 IPv4：NAT 模型当前只支持 IPv4（store.normCIDR 会拒 v6），
			// 把 v6 地址列出来会让管理员选了之后在保存时才被拒。
			if ip, _, err := net.ParseCIDR(s); err == nil && ip.To4() != nil {
				cidrs = append(cidrs, s)
			}
		}
		if len(cidrs) == 0 {
			continue
		}
		sort.Strings(cidrs)
		out = append(out, Iface{
			Name:  strings.TrimSpace(in.Name),
			Addrs: cidrs,
			Up:    in.Flags&net.FlagUp != 0,
		})
	}
	// 稳定排序：心跳每 15s 一次，顺序抖动会让控制面每轮都重写一遍网卡表。
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
