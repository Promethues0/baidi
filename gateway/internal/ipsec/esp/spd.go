package esp

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// 本文件是「哪些流量该进哪条隧道」的全部判定，也是本包安全性上最吃重的一块：
//
//	出向：目的地址必须落在某条 SA 的 RemoteTS 内，源地址必须落在同一条 SA 的 LocalTS 内。
//	      匹配不到 → ErrNoPolicy → **丢弃并计数**。
//	入向：解密后必须再查一遍内层 IP 的源/目的是否落在协商好的 TS 里。
//	      匹配不到 → ErrTSMismatch → 丢弃并计数。
//
// ★入向那一遍不是冗余检查。ICV 只证明「这个包确实来自持有密钥的对端」，
// 完全不限制对端在内层写什么地址。不校验 = 对端可以借这条隧道往**本端任意内网地址**
// 注包（源地址还能伪造成任意值），一条站点隧道就此变成一张通往内网的白纸。
// 站点组网的对端往往是分支机构的设备，「已认证」离「可信」还差得远。
//
// ★出向那一遍则守着本项目历史上最迷惑人的失败形态：隧道建起来了、界面显示已接入、
// 流量却因为没匹配上策略而从旁路直连出去，**全程零报错**（CLAUDE.md 里
// `baidi-tun -route` 只接管单网段那次事故就是这个形状）。因此这里绝不允许
// 「匹配不到就原样放行」，必须返回 ipsec.ErrNoPolicy 让上层丢弃并计数。

// innerAddrs 从内层 IP 包里取源/目的地址，并返回它对应的 ESP Next Header 值。
//
// 只解析定位地址所必需的字段。特别地**不**校验 Total Length 与实际长度相等：
// 从 TUN 读上来的包在开启 GSO/TSO 的内核上可能带着 0 长度字段，
// 因这条把包丢掉会得到一个只在特定内核配置下复现的诡异故障。
func innerAddrs(pkt []byte) (src, dst netip.Addr, nextHeader uint8, err error) {
	if len(pkt) == 0 {
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("esp: 内层包为空")
	}
	switch v := pkt[0] >> 4; v {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("esp: IPv4 包仅 %d 字节，不足 20 字节固定头", len(pkt))
		}
		if ihl := int(pkt[0]&0x0F) * 4; ihl < 20 || ihl > len(pkt) {
			return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("esp: IPv4 头长字段 %d 字节非法（须 20..%d）", ihl, len(pkt))
		}
		return netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20])), protoIPv4, nil
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("esp: IPv6 包仅 %d 字节，不足 40 字节固定头", len(pkt))
		}
		return netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40])), protoIPv6, nil
	default:
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("esp: 内层包首字节高 4 位为 %d，既不是 IPv4(4) 也不是 IPv6(6)——"+
			"这一层拿到的必须是**完整 IP 包**（隧道模式），若上游给的是以太帧或裸载荷，接线就错了", v)
	}
}

// noPolicyError 出向无匹配策略。
//
// ★消息刻意推迟到 Error() 里才拼。这条错误在「隧道断了、TUN 却还在出包」时会以
// **线速**产生，而它的文案里带着整张策略表——每个包都 Sprintf 一遍，等于在系统
// 已经出问题的时刻又给自己加了一个内存压力源。现在每包只多一个小结构体，
// 真正拼字符串只发生在有人打印它的时候（Debug 日志默认关闭）。
//
// 其余几类丢弃（重放 / TS 越界 / 未知 SPI）的文案只含几个标量，直接 fmt.Errorf 即可；
// 哪天它们出现在 profile 里，照这个模式改就行。
type noPolicyError struct {
	src, dst netip.Addr
	site     string       // 非空表示「目的匹配、源不匹配」这一种更具体的形态
	localTS  netip.Prefix //
	remoteTS netip.Prefix //
	desc     string       // 策略摘要，由引擎在 SA 表变化时预先算好（不是每包算）
}

func (e *noPolicyError) Error() string {
	if e.site != "" {
		return fmt.Sprintf("esp: 出向包 %s → %s 无法进入隧道：目的地址匹配站点 %s 的 RemoteTS %s，"+
			"但源地址不在本端 LocalTS %s 内（多半是 TUN 网卡地址与控制面配的本端网段对不上）",
			e.src, e.dst, e.site, e.remoteTS, e.localTS)
	}
	return fmt.Sprintf("esp: 出向包 %s → %s 没有匹配的 IPSec 策略，已丢弃（%s）", e.src, e.dst, e.desc)
}

// Unwrap 让 errors.Is(err, ipsec.ErrNoPolicy) 成立——上层的丢弃判定依赖它。
func (e *noPolicyError) Unwrap() error { return ipsec.ErrNoPolicy }

// selectOutbound 按 SPD 为一个出向包挑一条 SA。
//
// 选择规则：源 ∈ LocalTS 且 目的 ∈ RemoteTS，且未过硬生存期。
// 多条命中时取 **CreatedAt 最新**的那条——rekey 期间新旧两条 SA 会同时命中同一对 TS，
// 出向必须尽快切到新的（旧的即将被对端删掉）。
//
// ★CreatedAt 相同则按 InSPI 取大者，这个看似多余的兜底是必要的：
// 没有确定性兜底时，选择结果取决于 map 的遍历顺序，同一条流会在两条 SA 之间逐包抖动。
// 那样其实也"能通"，但 tcpdump 里 SPI 交替出现、两条 SA 的反重放窗口各填一半，
// 排查任何别的问题时都会被这个现象带偏。
//
// desc 是调用方预先算好的策略摘要，只在无匹配时被塞进错误里（见 noPolicyError）。
func selectOutbound(table map[uint32]*sa, desc string, src, dst netip.Addr, now time.Time) (*sa, error) {
	var best *sa
	var dstOnly *sa // 目的匹配、源不匹配：单独记下来，因为它的错误提示完全不同
	for _, s := range table {
		if !s.remoteTS.Contains(dst) {
			continue
		}
		if !s.localTS.Contains(src) {
			if dstOnly == nil {
				dstOnly = s
			}
			continue
		}
		if s.expired(now) {
			continue
		}
		if best == nil || s.createdAt.After(best.createdAt) ||
			(s.createdAt.Equal(best.createdAt) && s.inSPI > best.inSPI) {
			best = s
		}
	}
	if best != nil {
		return best, nil
	}
	e := &noPolicyError{src: src, dst: dst, desc: desc}
	if dstOnly != nil {
		e.site, e.localTS, e.remoteTS = dstOnly.siteID, dstOnly.localTS, dstOnly.remoteTS
	}
	return nil, e
}

// describeTable 把当前装载的策略摊开成一句话。
//
// ★这句话是本文件里最实用的一行代码。「无匹配策略」单独出现时，运维只能猜；
// 把「你的包是 10.60.0.5 → 8.8.8.8，而当前策略只有 10.60.0.0/24 → 10.70.0.0/24」
// 摆在一起，问题在读到日志的那一秒就结束了。
func describeTable(table map[uint32]*sa) string {
	if len(table) == 0 {
		return "当前没有装载任何 Child SA——隧道尚未建立或已被拆除"
	}
	seen := make(map[string]struct{}, len(table))
	items := make([]string, 0, len(table))
	for _, s := range table {
		item := fmt.Sprintf("%s: %s → %s", s.siteID, s.localTS, s.remoteTS)
		if _, ok := seen[item]; ok {
			continue // rekey 期间同一站点有新旧两条 SA，TS 一样，没必要重复打印
		}
		seen[item] = struct{}{}
		items = append(items, item)
	}
	sort.Strings(items) // 稳定输出，便于把两次日志直接 diff
	if len(items) > 4 {
		items = append(items[:4], fmt.Sprintf("…另有 %d 条", len(items)-4))
	}
	return "当前已装载策略 " + strings.Join(items, "；")
}

// checkInnerTS 校验解封出来的内层 IP 包地址是否落在协商好的流量选择器内。
//
// 两个方向都要查，且措辞要指明**对端在试图做什么**——这类日志出现时基本可以确定
// 不是配置问题而是对端行为异常，值得被当成安全事件看待。
func checkInnerTS(s *sa, src, dst netip.Addr) error {
	if !s.remoteTS.Contains(src) {
		return fmt.Errorf("esp: 站点 %s 入向报文的内层源地址 %s 不在对端受保护网段 %s 内"+
			"（对端在借隧道伪造源地址；ICV 只证明报文来自持密钥方，不约束它往里写什么）: %w",
			s.siteID, src, s.remoteTS, ipsec.ErrTSMismatch)
	}
	if !s.localTS.Contains(dst) {
		return fmt.Errorf("esp: 站点 %s 入向报文的内层目的地址 %s 不在本端受保护网段 %s 内"+
			"（对端在借隧道往本端任意内网地址注包）: %w",
			s.siteID, dst, s.localTS, ipsec.ErrTSMismatch)
	}
	return nil
}

// checkVersion 校验 ESP 的 Next Header 与内层 IP 头自称的版本一致。
//
// 不一致意味着有一方在撒谎。放过去不会立刻出事（后续按内层实际版本解析即可），
// 但它是「对端实现有 bug 或有人在构造畸形包」的明确信号，早报早收敛。
func checkVersion(declared, actual uint8) error {
	if declared == actual {
		return nil
	}
	return fmt.Errorf("esp: ESP 头声明 NextHeader=%d，内层 IP 包实际是 %s（NextHeader 应为 %d）",
		declared, versionName(actual), actual)
}

func versionName(nh uint8) string {
	switch nh {
	case protoIPv4:
		return "IPv4"
	case protoIPv6:
		return "IPv6"
	}
	return fmt.Sprintf("协议号 %d", nh)
}
