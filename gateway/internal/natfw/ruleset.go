// Package natfw 把控制面下发的地址转换策略编译成内核规则集（nftables / pf）并灌进内核。
//
// 分层刻意做成「纯函数生成文本 + 薄薄一层 exec」：
//   - Build* 不碰内核、不需要 root，在任何主机上都能编译 + 单测，Linux 的 nft 语法在 mac 上
//     照样被逐字断言。只活在 #[cfg]/if runtime.GOOS 里的分支是验不到的（posture 采集器
//     踩过这个坑，那次是三平台里只有 macOS 真写了）。
//   - Apply 只做「原子换掉整张表」这一件事。
//
// 判定权仍在控制面：这里不做任何策略推导，网关不知道「哪个网段该上网」，
// 只把算好的规则翻译成内核语法。
package natfw

import (
	"fmt"
	"sort"
	"strings"
)

// Policy 控制面下发的一条地址转换策略（字段与 control 的 store.NATPolicy 同名同义）。
type Policy struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"` // snat | dnat
	SrcIface       string `json:"srcIface"`
	SrcAddr        string `json:"srcAddr"`
	DstIface       string `json:"dstIface"`
	DstAddr        string `json:"dstAddr"`
	Protocol       string `json:"protocol"` // tcp | udp | icmp | all
	DstPort        int    `json:"dstPort"`
	TranslatedAddr string `json:"translatedAddr"`
	TranslatedPort int    `json:"translatedPort"`
}

// Exempt 必须从 SNAT 中排除的本机端口（FR-NAT-13）。
//
// ★为什么是硬约束而不是「建议」：网关自己的隧道口（18443）与敲门口（18201）上的流量
// 若被 SNAT 改写源地址，回包就回不到发起方——隧道直接断，而管理员看到的是
// 「配完 NAT 之后零信任就不能用了」，两件事之间毫无线索。
// 这些端口由网关**自己**知道（不是控制面下发的），所以排除规则在数据面这一侧生成。
type Exempt struct {
	TunnelPort int // -proxy 监听端口（TCP）
	SPAPort    int // -spa 监听端口（UDP）
	WebPorts   []int
}

// Table/chain 名固定带 baidi 前缀，与 darkfw 的 inet baidi 表分开：
// 那张表在 filter，这张在 nat，混在一起会让 flush 互相误伤。
const (
	NftTable    = "baidi_nat"
	PfAnchor    = "baidi_nat"
	chainPrefix = "baidi"
)

// BuildNft 生成一份完整的 nftables 规则集（Linux）。
//
// 用 `table ... { }` 整体定义 + nft -f 原子替换，而不是逐条 add：
// 逐条 add 在中途失败时会留下半套规则——半套 NAT 比没有 NAT 危险得多
// （比如 DNAT 生效了但源地址限制那条没进去，等于对全网公开）。
func BuildNft(policies []Policy, ex Exempt) string {
	var b strings.Builder
	b.WriteString("# 白帝地址转换规则集（由控制面策略编译，勿手工编辑）\n")
	b.WriteString("table ip " + NftTable + "\n")        // 幂等：确保存在
	b.WriteString("delete table ip " + NftTable + "\n") // 再整体删掉旧的
	b.WriteString("table ip " + NftTable + " {\n")

	// ── prerouting：DNAT ──
	b.WriteString("  chain " + chainPrefix + "_prerouting {\n")
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, p := range sortedByID(policies) {
		if p.Type != "dnat" {
			continue
		}
		b.WriteString("    " + nftDnatRule(p) + "\n")
	}
	b.WriteString("  }\n")

	// ── postrouting：SNAT（先写排除，再写转换）──
	b.WriteString("  chain " + chainPrefix + "_postrouting {\n")
	b.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n")
	for _, line := range nftExemptRules(ex) {
		b.WriteString("    " + line + "\n")
	}
	for _, p := range sortedByID(policies) {
		if p.Type != "snat" {
			continue
		}
		b.WriteString("    " + nftSnatRule(p) + "\n")
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

// nftExemptRules 排除零信任隧道与 WEB 代理流量（FR-NAT-13）。
// return 让这些流量在 srcnat 链上**提前返回**，不落到后面的 snat 规则。
func nftExemptRules(ex Exempt) []string {
	var out []string
	out = append(out, "# 零信任隧道 / 敲门 / WEB 代理流量一律不做源地址转换（FR-NAT-13）：")
	out = append(out, "# 改写源地址会让回包找不到发起方，症状是「配了 NAT 之后隧道就断了」。")
	if ex.TunnelPort > 0 {
		out = append(out, fmt.Sprintf("tcp sport %d return", ex.TunnelPort))
		out = append(out, fmt.Sprintf("tcp dport %d return", ex.TunnelPort))
	}
	if ex.SPAPort > 0 {
		out = append(out, fmt.Sprintf("udp sport %d return", ex.SPAPort))
		out = append(out, fmt.Sprintf("udp dport %d return", ex.SPAPort))
	}
	for _, p := range ex.WebPorts {
		if p > 0 {
			out = append(out, fmt.Sprintf("tcp sport %d return", p))
			out = append(out, fmt.Sprintf("tcp dport %d return", p))
		}
	}
	return out
}

func nftSnatRule(p Policy) string {
	// counter 放在动作前：FR-NAT-17 的命中统计靠它，nft -j list 能读出来。
	return fmt.Sprintf("iifname %q oifname %q ip saddr %s ip daddr %s counter masquerade comment %q",
		p.SrcIface, p.DstIface, p.SrcAddr, p.DstAddr, natComment(p))
}

func nftDnatRule(p Policy) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("iifname %q", p.SrcIface))
	if p.SrcAddr != "" && p.SrcAddr != "0.0.0.0/0" {
		// 0.0.0.0/0 不写出来：nft 里它恒真，写了只是噪音；但**非**全放行时必须写，
		// 漏掉这一句就是把「只允许某公网段访问」悄悄变成对全网公开。
		parts = append(parts, "ip saddr "+p.SrcAddr)
	}
	parts = append(parts, "ip daddr "+p.DstAddr)
	switch p.Protocol {
	case "tcp", "udp":
		parts = append(parts, fmt.Sprintf("%s dport %d counter dnat to %s:%d",
			p.Protocol, p.DstPort, p.TranslatedAddr, p.TranslatedPort))
	case "icmp":
		parts = append(parts, "ip protocol icmp counter dnat to "+p.TranslatedAddr)
	default: // all
		if p.DstPort > 0 {
			// 「所有协议」但指定了端口：只有 tcp/udp 有端口，逐个展开而不是丢掉端口条件。
			return fmt.Sprintf("iifname %q %s ip daddr %s meta l4proto { tcp, udp } th dport %d counter dnat to %s:%d comment %q",
				p.SrcIface, saddrClause(p), p.DstAddr, p.DstPort, p.TranslatedAddr, p.TranslatedPort, natComment(p))
		}
		parts = append(parts, "counter dnat to "+p.TranslatedAddr)
	}
	parts = append(parts, fmt.Sprintf("comment %q", natComment(p)))
	return strings.Join(parts, " ")
}

func saddrClause(p Policy) string {
	if p.SrcAddr == "" || p.SrcAddr == "0.0.0.0/0" {
		return ""
	}
	return "ip saddr " + p.SrcAddr + " "
}

// natComment 规则注释里带策略 id：读回命中计数时靠它把 counter 对回策略。
func natComment(p Policy) string { return "baidi:" + p.ID }

// BuildPf 生成 pf 锚点内容（macOS）。
//
// pf 的 nat/rdr 规则**必须排在 filter 规则之前**且各自成组，与 nft 的链模型不同；
// 这里只产出锚点内容，由 setup 脚本 anchor 进主配置。
func BuildPf(policies []Policy, ex Exempt) string {
	var b strings.Builder
	b.WriteString("# 白帝地址转换锚点（由控制面策略编译，勿手工编辑）\n")
	// pf 的 no nat / no rdr 必须写在同类规则最前面才优先生效。
	b.WriteString("# 零信任隧道 / 敲门 / WEB 代理流量不做源地址转换（FR-NAT-13）\n")
	for _, port := range exemptPorts(ex) {
		b.WriteString(fmt.Sprintf("no nat on any proto %s from any to any port %d\n", port.proto, port.n))
		b.WriteString(fmt.Sprintf("no nat on any proto %s from any port %d to any\n", port.proto, port.n))
	}
	for _, p := range sortedByID(policies) {
		if p.Type != "snat" {
			continue
		}
		b.WriteString(fmt.Sprintf("nat on %s from %s to %s -> (%s)   # %s\n",
			p.DstIface, p.SrcAddr, p.DstAddr, p.DstIface, natComment(p)))
	}
	for _, p := range sortedByID(policies) {
		if p.Type != "dnat" {
			continue
		}
		b.WriteString(pfRdrRule(p) + "\n")
	}
	return b.String()
}

type portProto struct {
	n     int
	proto string
}

func exemptPorts(ex Exempt) []portProto {
	var out []portProto
	if ex.TunnelPort > 0 {
		out = append(out, portProto{ex.TunnelPort, "tcp"})
	}
	if ex.SPAPort > 0 {
		out = append(out, portProto{ex.SPAPort, "udp"})
	}
	for _, p := range ex.WebPorts {
		if p > 0 {
			out = append(out, portProto{p, "tcp"})
		}
	}
	return out
}

func pfRdrRule(p Policy) string {
	from := "any"
	if p.SrcAddr != "" && p.SrcAddr != "0.0.0.0/0" {
		from = p.SrcAddr
	}
	switch p.Protocol {
	case "tcp", "udp":
		return fmt.Sprintf("rdr on %s proto %s from %s to %s port %d -> %s port %d   # %s",
			p.SrcIface, p.Protocol, from, p.DstAddr, p.DstPort, p.TranslatedAddr, p.TranslatedPort, natComment(p))
	case "icmp":
		return fmt.Sprintf("rdr on %s proto icmp from %s to %s -> %s   # %s",
			p.SrcIface, from, p.DstAddr, p.TranslatedAddr, natComment(p))
	default:
		if p.DstPort > 0 {
			return fmt.Sprintf("rdr on %s proto { tcp udp } from %s to %s port %d -> %s port %d   # %s",
				p.SrcIface, from, p.DstAddr, p.DstPort, p.TranslatedAddr, p.TranslatedPort, natComment(p))
		}
		return fmt.Sprintf("rdr on %s from %s to %s -> %s   # %s",
			p.SrcIface, from, p.DstAddr, p.TranslatedAddr, natComment(p))
	}
}

// sortedByID 让同一批策略每次生成的文本逐字相同——规则集是拿来做「有没有变化」
// 比较的（变了才重灌内核），顺序抖动会导致每轮都误判成有变化并重灌。
func sortedByID(in []Policy) []Policy {
	out := append([]Policy(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
