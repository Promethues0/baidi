package api

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"baidi.dev/control/internal/store"
)

// ── DNAT 敞口：「攻击面 = 0」的第三个前提（wave11 行动 13-②）──
//
// 网关页那段正向安全断言此前只把七层 Web 口算进前提集。可**一条启用中的 DNAT
// 本身就是在网关的公网地址上开一个端口**——那正是 DNAT 的用途，而它同样不受
// SPA 隐身保护（隐身是 filter 表上按隧道口/敲门口写死的两条规则，与 nat 表无关；
// 被发布到内网主机的流量走的是 forward 链，那两条规则连碰都碰不到）。
// 于是一台规则集装好、又发布了三个内网业务的网关，页面会同时显示
// 「端口扫描全程超时，无任何端口可探测」与「攻击面 = 0」，而 nmap 一扫三个。
//
// ★判据是**已确认灌进内核**的那些，不是库里 enabled 的那些：网关没带 -nat 启动
// （参考部署的默认形态）时规则一条都不会进内核，把它算成敞口是另一个方向的假事实。
// 判不出来的（旧网关不上报 / 网关离线，回执是陈值）**单列**——不可判定既不能算敞口，
// 也不能拿去支撑「攻击面 = 0」这句正向断言。这条纪律与 stealthReceiptOf 的八态同源。

// natExposure 汇总 DNAT 在公网上开出来的端点。
//
// 返回 (已确认敞开的端点, 判不出来的网关说明, 策略表读到了吗)。
// 第三个返回值不可省：读失败与「一条 DNAT 都没有」必须分得开，
// 否则一次数据库抖动会让页面在什么都不知道的情况下给出最强的那句断言。
func (s *Server) natExposure(ctx context.Context) (exposed, unknown []string, known bool) {
	if s.nat == nil {
		// 纯内存演示栈根本存不了 NAT 策略：这是**确定的零**，不是不可判定。
		return nil, nil, true
	}
	ps, err := s.nat.NATPolicies(ctx)
	if err != nil {
		return nil, nil, false
	}
	var live []store.NATPolicy
	for _, p := range ps {
		if p.Enabled && p.Type == store.NATDnat {
			live = append(live, p)
		}
	}
	if len(live) == 0 {
		return nil, nil, true
	}
	rcpts := s.natReceipts(live)
	seenUnknown := map[string]bool{}
	for _, p := range live {
		r, ok := rcpts[strings.TrimSpace(p.GatewayID)]
		switch {
		case !ok || !r.Online:
			// 离线网关的回执是陈值：内核里此刻是什么样，控制面无从知道。
			if !seenUnknown[p.GatewayID] {
				seenUnknown[p.GatewayID] = true
				unknown = append(unknown, p.GatewayID+"（当前离线，地址转换回执是陈值）")
			}
		case r.Status == NATRcptUnreported:
			if !seenUnknown[p.GatewayID] {
				seenUnknown[p.GatewayID] = true
				unknown = append(unknown, p.GatewayID+"（未上报地址转换运行态，无从确认规则是否进了内核）")
			}
		case r.Status == NATRcptApplied:
			exposed = append(exposed, fmt.Sprintf("%s %s %s:%d → %s:%d",
				p.GatewayID, p.Protocol, p.DstAddr, p.DstPort, p.TranslatedAddr, p.TranslatedPort))
		default:
			// disabled / failed / dryrun：规则不在内核里，这条 DNAT 现在没开任何端口。
			// 它「配了却不生效」的问题由 natReceiptWarnings 在地址转换页说，不在这里重复。
		}
	}
	sort.Strings(exposed) // map 遍历序随机；告警条目每刷新一次就换个顺序会让人以为状态在变
	sort.Strings(unknown)
	return exposed, unknown, true
}

// natExposureWarning 把 DNAT 敞口翻成网关页顶部那条告警（文案由后端下发，前端不自己编）。
func natExposureWarning(exposed, unknown []string, known bool) string {
	if !known {
		return "读取地址转换策略失败：本页**无从判断**是否有 DNAT 在网关的公网地址上开着端口，" +
			"因此不对「攻击面 = 0」下结论。请先排除控制面数据库故障。"
	}
	switch {
	case len(exposed) > 0 && len(unknown) > 0:
		return fmt.Sprintf("有 %d 条地址转换（DNAT）规则已灌入内核，正在网关的公网地址上开着端口（%s）；"+
			"另有网关的运行态判不出来（%s）。**被 DNAT 发布出去的端口不受 SPA 隐身保护**——"+
			"隐身是 filter 表上按隧道口/敲门口写死的规则，与 nat 表无关，扫描器能直接看到这些端口。"+
			"因此本页的「攻击面 = 0」不适用于这套部署。",
			len(exposed), strings.Join(exposed, "、"), strings.Join(unknown, "、"))
	case len(exposed) > 0:
		return fmt.Sprintf("有 %d 条地址转换（DNAT）规则已灌入内核，正在网关的公网地址上开着端口（%s）。"+
			"**被 DNAT 发布出去的端口不受 SPA 隐身保护**——隐身是 filter 表上按隧道口/敲门口写死的规则，"+
			"与 nat 表无关，扫描器能直接看到这些端口。因此本页的「攻击面 = 0」不适用于这套部署；"+
			"这是「网关兼做发布路由设备」的固有取舍，不是配置错误。", len(exposed), strings.Join(exposed, "、"))
	case len(unknown) > 0:
		return fmt.Sprintf("有启用中的地址转换（DNAT）规则，但这些网关的运行态**判不出来**（%s）："+
			"控制面无从确认它们此刻有没有在公网地址上开着端口，因此不对「攻击面 = 0」下结论。",
			strings.Join(unknown, "、"))
	}
	return ""
}
