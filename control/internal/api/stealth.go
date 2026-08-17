package api

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"
)

// ── SPA 隐身真实态回执（wave8 行动 7，NFR-SEC-01 / NFR-OBS-01 / FR-OPS-10）──
//
// 隐身是白帝的第一卖点，NFR-SEC-01 的验收就是「外部扫描端口全闭」。此前控制面
// 对它**一个字都不知道**，却在两个地方替它打了包票：
//
//	① `Gateway.vue` 写死「端口扫描全程超时」「网关静默丢弃所有报文」「攻击面 = 0」；
//	② `/diag` 的 checkStealth 只要有一台网关在线就恒 pass。
//
// 而参考部署与在线演示站**都没启用**内核态隐身：`deploy/systemd/baidi-gateway.service`
// 明写默认不开 `-pf`，`install-remote.sh` 全程不执行 `baidi-nft.sh`。未开时未敲门的
// 连接走 `proxy.go` 的 accept-then-close——**TCP 三次握手已经完成**，nmap 判 open。
// 「握手后被断开」与页面断言的「等同于不存在」是两种安全等级。
//
// ★这是复发，不是新错：第七节记功删掉过 Security 页那个恒 true 的「已隐身」开关，
// 理由原文是「在替一台可能压根没配防火墙规则的网关打包票」——Gateway.vue 那四条断言
// 与 checkStealth 的恒 pass 正在做同一件事，只是换了个页面。
//
// 控制面确实无法从外部实测端口可见性（那要从公网侧扫描），但**网关自己完全知道**
// 规则集装没装、保护的是哪个端口——不上报等于把可判定的事硬做成不可判定。

// gwStealthState 网关随心跳上报的隐身实测态。字段语义见 darkfw.State / cplane.StealthState。
type gwStealthState struct {
	Wanted      bool   `json:"wanted"`
	Backend     string `json:"backend"`
	Root        bool   `json:"root"`
	Ruleset     *bool  `json:"ruleset"`     // nil = 探不到（非 root / 命令异常），不是「不在」
	GuardedPort *int   `json:"guardedPort"` // nil = 解析不出来，不是 0
	Detail      string `json:"detail"`
}

// gwStealthInfo 某台网关最近一次上报的隐身态 + 收到时刻。
type gwStealthInfo struct {
	State gwStealthState
	At    int64
}

// 隐身回执的状态取值。**每一个都是真实可区分的形态**，不是好看话。
const (
	// StealthUnreported 该网关从未上报过 stealth 字段（旧版本网关）——控制面对它一无所知。
	// ★与 "off" 必须分开：前者是"不知道"，后者是"确定没开"。
	StealthUnreported = "unreported"
	// StealthOff 网关明确说没带 -pf 启动：走用户态 accept-then-close，
	// 三次握手会完成，端口对扫描器表现为「open」。这是参考部署的默认形态。
	StealthOff = "off"
	// StealthNoRuleset -pf 开着但内核里没有白帝的规则集。**最危险的一种**：
	// 放行写不进去、默认 DROP 也不存在 → 端口对全世界敞开，而管理侧看着像"已配置"。
	StealthNoRuleset = "no-ruleset"
	// StealthOrphanRuleset 规则集装着，但网关**没带 -pf 启动**。
	//
	// ★这一态是写探测用例时才发现的，症状比"没有隐身"严重得多——是**全员连不上**：
	// 内核那条 `tcp dport <proxy> drop` 一直在生效（端口确实 filtered），
	// 但放行集合永远是空的（OnAllow 回调只在 `if *pf` 里挂），网关不会为任何一次
	// 成功敲门往里加 IP。于是敲门成功、令牌有效、网关日志正常、控制台显示在线，
	// 而每一个合法用户都只是拨号超时。多半是"跑过 setup 脚本、忘了给启动参数加 -pf"。
	StealthOrphanRuleset = "orphan-ruleset"
	// StealthNoDropRule 规则集（table/anchor）在，但里面**找不到那条默认 DROP 规则**。
	//
	// ★复核挖出来的一个新假绿：此前 GuardedPort==nil 会一路落进 default 判成 armed，
	// 摘要还写着「规则集实测在位，未授权源的报文在内核被丢弃」——而 GuardedPort==nil
	// 的语义恰恰是"没找到丢包那条规则"，也就是**没有任何东西在丢包**。
	// 真实成因：`baidi-nft.sh setup` 在 set -euo pipefail 下中途失败（表建好了、
	// drop 规则还没加）、排障时手工 flush 过链、或规则被写成 `dport { a, b } drop`
	// 这类正则匹配不上的形状。probe.go 里那句「绝不猜默认端口」的纪律，
	// 在消费端被 default 分支原样破坏了一遍。
	StealthNoDropRule = "no-drop-rule"
	// StealthUnknown 探不到（非 root / 命令异常）：不可判定，不等于生效。
	StealthUnknown = "unknown"
	// StealthPortMismatch 规则集在，但那条默认 DROP 保护的端口不是本网关的隧道口
	// （setup 脚本 PROXY_PORT 默认 18443，网关却可以 -proxy 换端口）。隧道口照样全世界可见。
	StealthPortMismatch = "port-mismatch"
	// StealthArmed 规则集实测在位且保护的正是本网关的隧道口：内核态 DROP 生效。
	StealthArmed = "armed"
)

// StealthReceipt 一台网关的隐身回执。
type StealthReceipt struct {
	GatewayID string `json:"gatewayId"`
	Status    string `json:"status"`
	// Wanted 管理意图（-pf 开关）。与 Status 分开呈现——与 NAT 回执同一条纪律：
	// 一列同时表达「想开」和「真的开着」正是 ipsec 那段注释批判过的形态。
	//
	// ★指针三态：nil = 该网关根本没上报（旧版本）。用 bool 的话零值会在页面上
	// 渲染成确定结论「-pf 未开启 · 非 root」，与同一张卡片上「控制面无从判断」
	// 的措辞直接打架——这正是本行动要消灭的那种"拿零值当事实"。
	Wanted  *bool  `json:"wanted,omitempty"`
	Backend string `json:"backend"`
	Root    *bool  `json:"root,omitempty"`
	// ProxyAddr 本网关自报的隧道监听地址；GuardedPort 规则集实际保护的端口（nil=解析不出）。
	ProxyAddr   string `json:"proxyAddr"`
	GuardedPort *int   `json:"guardedPort,omitempty"`
	// Summary 人话结论；Detail 网关侧的探测说明（原样透传）。
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
	// ScannerView **未敲门的攻击者从外部看到什么**。这一格是本功能的意义所在：
	// 它把「配置状态」翻译成「安全后果」，而后者才是 NFR-SEC-01 验收的东西。
	ScannerView string `json:"scannerView"`
	At          int64  `json:"at"`
}

// Armed 报告这台网关是否真的处在内核态隐身。**只有 armed 算**——
// unknown / unreported 一律不算：不可判定不是"生效了"。
func (r StealthReceipt) Armed() bool { return r.Status == StealthArmed }

// stealthReceipts 汇总全部**在线**网关的隐身回执（按网关 id 排序，稳定）。
//
// 只看在线网关：离线网关的隐身态是陈旧读数，且「这台离线了」已由网关在线那项覆盖。
func (s *Server) stealthReceipts() []StealthReceipt {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StealthReceipt, 0, len(s.gateways))
	for id, g := range s.gateways {
		if !gatewayFresh(g.LastSeen, now) {
			continue
		}
		info, ok := s.gwStealth[id]
		out = append(out, stealthReceiptOf(id, g.Proxy, info, ok))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GatewayID < out[j].GatewayID })
	return out
}

// stealthReceiptOf 把一台网关的上报折算成回执（纯函数，便于逐形态测试）。
//
// ★判定的骨架是「先分不可判定，再分确定结论」。任何一处拿"探不到"当"没问题"
// 或当"确定有问题"，都是本行动自己要消灭的形态换个方向再犯一次。
func stealthReceiptOf(id, proxyAddr string, info gwStealthInfo, reported bool) StealthReceipt {
	r := StealthReceipt{GatewayID: id, ProxyAddr: proxyAddr}
	if !reported {
		r.Status = StealthUnreported
		r.Summary = "该网关未上报隐身状态（旧版本网关）——控制面无从判断它是否真的隐身"
		r.ScannerView = "不可判定：升级该网关二进制后心跳会自动携带实测结果"
		// Wanted/Root 保持 nil：它没说过这两件事，别替它答（见字段注释）。
		return r
	}
	st := info.State
	w, rt := st.Wanted, st.Root
	r.Wanted, r.Root, r.Backend, r.GuardedPort = &w, &rt, st.Backend, st.GuardedPort
	r.Detail, r.At = st.Detail, info.At

	// ── 分支一：探不到规则集（几乎总是"非 root"）──
	// ★这一支必须在 Wanted 之前判。此前是先按 Wanted 分叉、`!Wanted` 那边只有
	// 「Ruleset==true 才是 orphan」，否则直接断言 off + 「端口 open」——于是在
	// **参考部署的真实形态**（非 root、无 -pf）下，Ruleset 恒为 nil，控制面会对
	// 一台可能装着规则集、实际全员连不上的网关，斩钉截铁地说"没启用隐身、端口开着"。
	// 方向和后果两句全反，运维会照着"去启用隐身"排查一个已经装好的规则集。
	if st.Ruleset == nil {
		r.Status = StealthUnknown
		if st.Wanted {
			r.Summary = "已开启 -pf，但网关探不到内核规则集，隐身是否生效不可判定"
			r.ScannerView = "不可判定——不等于生效。" + orElse(st.Detail, "网关未说明原因")
			return r
		}
		// 没开 -pf 且探不到：两种截然相反的真实状态都可能，必须都说出来。
		r.Summary = "未开启 -pf，且探不到内核规则集——实际状态不可判定"
		r.ScannerView = "两种相反的可能，控制面分不出：" +
			"① 机器上没有规则集 → 隧道口对扫描器是「open」（未敲门的 TCP 会先完成三次握手）；" +
			"② 机器上装着规则集 → 隧道口是「filtered」，但放行集合永远为空，" +
			"全部合法用户都连不上。在网关宿主机上跑 sudo nft list table inet baidi" +
			"（macOS：sudo pfctl -a baidi-gw -sr）即可确认；或让网关以 root 运行，它会自己探。"
		return r
	}

	// ── 分支二：探到了，且规则集不在 ──
	if !*st.Ruleset {
		if !st.Wanted {
			r.Status = StealthOff
			r.Summary = "未启用内核态隐身（网关未带 -pf 启动，机器上也没有规则集）——这是参考部署的默认形态"
			r.ScannerView = "端口对扫描器表现为「open」：未敲门的 TCP 连接会先完成三次握手，" +
				"再由用户态立即断开（proxy.go 的 accept-then-close）。" +
				"nmap 能确认这里有一个在监听的服务——与「在网络层不存在」是两种安全等级"
			return r
		}
		r.Status = StealthNoRuleset
		r.Summary = "已开启 -pf，但内核里没有白帝的规则集——隐身实际未生效"
		r.ScannerView = "端口对扫描器表现为「open」，且比未开 -pf 更坏：" +
			"放行写不进去（表不存在），默认 DROP 那条规则同样不存在，" +
			"于是退回用户态兜底，而管理侧看起来是「隐身已配置」。" +
			"先跑 sudo gateway/firewall/baidi-nft.sh setup（macOS 用 setup-pf.sh）再启动网关"
		return r
	}

	// ── 分支三：规则集在 ──
	if !st.Wanted {
		r.Status = StealthOrphanRuleset
		r.Summary = "内核规则集装着，但网关没带 -pf 启动——放行集合永远是空的，全部用户都连不上"
		r.ScannerView = "端口对扫描器确实是「filtered」，但合法用户同样进不来：" +
			"内核默认 DROP 在生效，而网关不会为任何一次成功敲门往放行集合里加 IP" +
			"（那个回调只在 -pf 模式下挂）。症状是敲门成功、令牌有效、控制台显示在线，" +
			"客户端却一律拨号超时。要么给启动参数加 -pf 并以 root 运行，" +
			"要么 sudo gateway/firewall/baidi-nft.sh teardown 卸掉规则集"
		return r
	}
	switch {
	case st.GuardedPort == nil:
		// ★规则集在、却找不到那条默认 DROP：没有任何东西在丢包（见 StealthNoDropRule）。
		r.Status = StealthNoDropRule
		r.Summary = "规则集在位，但里面找不到默认 DROP 规则——没有任何东西在丢包，隐身未生效"
		r.ScannerView = "端口对扫描器表现为「open」：table/anchor 建起来了，但那条 " +
			"`tcp dport <隧道口> drop` 不在（多半是 setup 脚本中途失败、或有人 flush 过这条链）。" +
			"用 sudo nft list table inet baidi（macOS：sudo pfctl -a baidi-gw -sr）看一眼，" +
			"确认后重跑 setup 脚本"
	case !stealthPortMatches(proxyAddr, *st.GuardedPort):
		r.Status = StealthPortMismatch
		r.Summary = fmt.Sprintf("规则集保护的是 %d 端口，而本网关的隧道口是 %s——隧道口未被保护",
			*st.GuardedPort, orElse(proxyAddr, "未上报"))
		r.ScannerView = fmt.Sprintf("隧道口 %s 对扫描器表现为「open」："+
			"规则集装得好好的，只是保护了另一个端口（setup 脚本的 PROXY_PORT 默认 18443）。"+
			"以 PROXY_PORT=%s 重跑 setup 脚本", orElse(proxyAddr, "（未上报）"), portOf(proxyAddr))
	default:
		r.Status = StealthArmed
		r.Summary = "内核态隐身已生效：规则集实测在位，未授权源的报文在内核被丢弃"
		r.ScannerView = "端口对未敲门的扫描器表现为「filtered」（无响应、无 RST）：" +
			"报文在内核被 DROP，TCP 三次握手不会完成。" +
			"★仍建议从外网侧实测一次——控制面转述的是网关自报的规则集状态，不是外部扫描结果"
	}
	return r
}

// stealthPortMatches 报告监听地址的端口是否等于规则集保护的端口。
// **解析不出端口时回 true**（不可判定不报警）：把解析失败渲染成「端口错配」，
// 会让运维去追一个不存在的错配——与 posture 的 unknown 同口径。
func stealthPortMatches(addr string, guarded int) bool {
	p := portOf(addr)
	if p == "" {
		return true
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return true
	}
	return n == guarded
}

// portOf 取监听地址里的端口（":18443" / "0.0.0.0:18443" → "18443"）；取不出回空串。
func portOf(addr string) string {
	if addr == "" {
		return ""
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return p
}

// stealthWarnings 需要顶到页面上的隐身告警（空 = 无事）。
//
// ★「未启用」也算一条：这正是参考部署的默认形态，而页面上此前写着「攻击面 = 0」。
// 沉默会让那句断言继续成立。
func stealthWarnings(rs []StealthReceipt) []string {
	var out []string
	for _, r := range rs {
		switch r.Status {
		case StealthNoRuleset:
			out = append(out, fmt.Sprintf(
				"网关「%s」已开启 -pf 但内核里没有规则集：隐身实际未生效，隧道口 %s 此刻对全世界可见。%s",
				r.GatewayID, orElse(r.ProxyAddr, "（未上报）"), r.Detail))
		case StealthPortMismatch:
			out = append(out, fmt.Sprintf(
				"网关「%s」的规则集保护的是 %d 端口，而它的隧道口是 %s——隧道口未被隐身保护。",
				r.GatewayID, deref(r.GuardedPort), orElse(r.ProxyAddr, "（未上报）")))
		case StealthNoDropRule:
			out = append(out, fmt.Sprintf(
				"网关「%s」的规则集在位，但里面没有默认 DROP 规则：没有任何东西在丢包，"+
					"隧道口 %s 此刻对全世界可见。", r.GatewayID, orElse(r.ProxyAddr, "（未上报）")))
		case StealthOrphanRuleset:
			out = append(out, fmt.Sprintf(
				"网关「%s」的内核规则集装着、但它没带 -pf 启动：放行集合永远为空，"+
					"全部合法用户都连不上（敲门会成功、控制台显示在线，客户端一律拨号超时）。", r.GatewayID))
		case StealthOff:
			out = append(out, fmt.Sprintf(
				"网关「%s」未启用内核态隐身：未敲门的 TCP 连接会先完成三次握手再被断开，"+
					"端口对扫描器表现为 open 而非 filtered。", r.GatewayID))
		case StealthUnknown:
			out = append(out, fmt.Sprintf(
				"网关「%s」开启了 -pf，但探不到内核规则集，隐身是否生效不可判定：%s",
				r.GatewayID, orElse(r.Detail, "网关未说明原因")))
		case StealthUnreported:
			out = append(out, fmt.Sprintf(
				"网关「%s」版本较旧，不上报隐身实测状态：控制面无从判断它是否真的隐身。", r.GatewayID))
		}
	}
	return out
}

// deref 取指针值；nil 回 0（仅用于已确知非 nil 的文案拼接）。
func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// checkStealth 检查 SPA 服务隐身。
//
// ★此前这项**只要有网关在线就恒 pass**，摘要写「未授权包默认丢弃」——
// 而那句话在参考部署（不开 -pf）下是错的。现在读的是网关实测回执：
// 只有全部在线网关都 armed 才 pass，其余逐台列出真实形态与攻击者视角的后果。
func (s *Server) checkStealth() DiagCheck {
	c := DiagCheck{Key: "spa", Category: "stealth", Name: "SPA 服务隐身"}
	rs := s.stealthReceipts()
	s.mu.Lock()
	total := len(s.gateways)
	s.mu.Unlock()

	if len(rs) == 0 {
		c.Status, c.Metric = "warn", fmt.Sprintf("在线 0 / 注册 %d", total)
		if total == 0 {
			c.Summary = "无网关经 mTLS 注册，隐身状态未知"
			c.Hint = "以 -control + mTLS 证书启动 baidi-gateway，注册后此处才有事实可报"
		} else {
			c.Summary = "已注册网关全部心跳超时，隐身状态未知"
			c.Hint = "检查网关进程与到控制面的网络连通"
		}
		return c
	}

	// ★三个桶而不是两个。此前只有 armed / bad，剩下的一律并进「未启用内核态隐身，
	// 端口表现为 open」——而那个差值里装着 unknown（探不到）与 unreported（旧网关），
	// 对这两态而言「未启用」「端口 open」都是控制面并不知道的事实。
	// 一台真正 armed 但以非 root 跑的网关，会被这句摘要当面说成"未启用隐身"。
	// 不可判定 ≠ 正常，也 ≠ 异常——反方向的违反同样是违反。
	armed, bad, undecided := 0, 0, 0
	for _, r := range rs {
		st := "warn"
		switch r.Status {
		case StealthArmed:
			st, armed = "pass", armed+1
		case StealthNoRuleset, StealthPortMismatch, StealthOrphanRuleset, StealthNoDropRule:
			st, bad = "fail", bad+1
		case StealthUnknown, StealthUnreported:
			undecided++
		}
		c.Items = append(c.Items, DiagItem{
			Label:  r.GatewayID,
			Value:  r.Summary + "（隧道口 " + orElse(r.ProxyAddr, "未上报") + "）",
			Status: st,
		})
	}
	c.Metric = fmt.Sprintf("内核态隐身生效 %d / 在线 %d（其中不可判定 %d）", armed, len(rs), undecided)
	switch {
	case bad > 0:
		c.Status = "fail"
		c.Summary = fmt.Sprintf("%d 台网关的隐身配置有实质问题（规则集缺失 / 保护了别的端口 / "+
			"规则集装着但网关没带 -pf 导致全员连不上）", bad)
		c.Hint = "先跑 sudo gateway/firewall/baidi-nft.sh setup（macOS 用 setup-pf.sh），" +
			"确认 PROXY_PORT 与网关 -proxy 一致，再以 root 带 -pf 启动"
	case armed == len(rs):
		c.Status = "pass"
		c.Summary = fmt.Sprintf("%d 台在线网关的内核规则集实测在位，未授权报文在内核被丢弃", armed)
		c.Hint = "控制面转述的是网关自报的规则集状态，不是外部扫描结果——建议从外网侧实测一次"
	default:
		c.Status = "warn"
		off := len(rs) - armed - undecided
		switch {
		case off > 0 && undecided > 0:
			c.Summary = fmt.Sprintf("%d 台在线网关确定未启用内核态隐身（未敲门的 TCP 会先完成三次握手，"+
				"端口表现为 open），另有 %d 台不可判定（探不到规则集 / 旧版本未上报）", off, undecided)
		case off > 0:
			c.Summary = fmt.Sprintf("%d / %d 台在线网关未启用内核态隐身："+
				"未敲门的 TCP 连接会先完成三次握手再被断开，端口对扫描器表现为 open", off, len(rs))
		default:
			// 全是不可判定：绝不替它们下「未启用」的结论。
			c.Summary = fmt.Sprintf("%d 台在线网关的隐身状态不可判定（网关非 root 探不到规则集，"+
				"或版本较旧不上报）——不可判定不等于未启用，也不等于已生效", undecided)
		}
		c.Hint = "内核态隐身需 root + 预置规则集（gateway/firewall/baidi-nft.sh setup）后带 -pf 启动；" +
			"参考部署 deploy/systemd/baidi-gateway.service 默认不开（该机 strongSwan-gm 也用 nft，需先评审 ruleset）"
	}
	return c
}
