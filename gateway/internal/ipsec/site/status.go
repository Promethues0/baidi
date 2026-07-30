package site

import (
	"errors"
	"fmt"
	"net/netip"

	"baidi.dev/gateway/internal/ipsec"
)

// 本文件只做一件事：**把协议码点翻译成管理员能据以行动的中文**。
//
// 为什么值得单独一个文件：IKEv2 对失败的表达能力极其有限——大量根因完全不同的
// 问题，最终都收敛成同一个通知码点。最典型的是 AUTHENTICATION_FAILED：
// PSK 不一致、ID 写成了 IP 形态、AUTH 计算里少算了 3 个保留字节、
// 报文被重新序列化过……对端看到的全是那一个码点。
//
// ★所以「把 NO_PROPOSAL_CHOSEN 原样甩给用户」等于没说。
// 每条翻译都必须回答两个问题：**这意味着什么** 和 **接下来该查什么**。
// 这不是文案美化，是这套东西能不能被别人排障的分水岭。

// IKEv2 通知码点（RFC 7296 §3.10.1）。
//
// 参数与常量都用裸 uint16，而不是 ike.NotifyType：本函数最常见的调用场景是
// 「手上只有一个数字」——从日志里抠出来的码点、控制面回传的字段、e2e 脚本里的断言。
// 要求先转成协议包的类型只会让这些地方多一次无意义的类型转换。
// 码点由 IANA 固定，权威来源是 RFC 7296 而不是任何一个包的常量表，
// 因此这里重复一遍数字不存在"两处不同步"的风险。
const (
	notifyUnsupportedCriticalPayload = 1
	notifyInvalidIKESPI              = 4
	notifyInvalidMajorVersion        = 5
	notifyInvalidSyntax              = 7
	notifyInvalidMessageID           = 9
	notifyNoProposalChosen           = 14
	notifyInvalidKEPayload           = 17
	notifyAuthenticationFailed       = 24
	notifySinglePairRequired         = 34
	notifyNoAdditionalSAs            = 35
	notifyTSUnacceptable             = 38
	notifyTemporaryFailure           = 43
	notifyChildSANotFound            = 44

	notifyInitialContact            = 16384
	notifyNATDetectionSourceIP      = 16388
	notifyNATDetectionDestinationIP = 16389
	notifyCookie                    = 16390
	notifyRekeySA                   = 16393

	// notifyErrorCeiling 错误类与状态类的分界线：小于它是错误（交换失败），
	// 大于等于它是状态（不认识的必须静默忽略）。这条分界线是互通的生命线——
	// strongSwan 默认会发好几个状态类通知，把它们当错误处理会导致完全无法建连。
	notifyErrorCeiling = 16384
)

// ExplainNotify 把 IKEv2 通知码点翻成中文，并附上排障方向。
//
// 状态类通知（≥16384）一般不该出现在错误路径上，这里也给了译文，
// 因为它们会出现在调试日志里，而"NOTIFY(16430)"这种字样只会让人去翻 RFC。
func ExplainNotify(n uint16) string {
	switch n {
	case notifyNoProposalChosen:
		return "对端不接受本端提出的任何加密套件（NO_PROPOSAL_CHOSEN）：" +
			"两端的 phase1/phase2 算法配置必须有交集，重点核对加密算法、DH 群与密钥长度；" +
			"若一端配了 suite=gm（白帝私有码点），另一端也必须是白帝且同样配 gm"
	case notifyInvalidKEPayload:
		return "对端要求换一个 DH 群（INVALID_KE_PAYLOAD）：本端首选的群不在对端支持列表里，" +
			"通常意味着两端 phase1.dh 配得不一样"
	case notifyAuthenticationFailed:
		return "认证失败（AUTHENTICATION_FAILED）：这个码点掩盖了好几种根因，按可能性依次排查——" +
			"① 两端 PSK 不一致（含控制面刚改过 PSK 但一端还没同步到）；" +
			"② localId/remoteId 与对端的配置不是镜像关系（本端的 localId 必须等于对端的 remoteId）；" +
			"③ ID 用了 IP 地址形态且链路上有 NAT（对端看到的是 NAT 后地址，必然匹配不上）"
	case notifyTSUnacceptable:
		return "对端不接受本端声明的受保护网段（TS_UNACCEPTABLE）：" +
			"本实现不做 narrowing，两端的网段必须严格镜像——" +
			"本端 localSubnet == 对端 remoteSubnet，本端 remoteSubnet == 对端 localSubnet"
	case notifyInvalidSyntax:
		return "对端认为本端的报文结构非法（INVALID_SYNTAX）：多半是版本/实现不对版，" +
			"若对端不是白帝网关，请注意本实现未与第三方设备做过互通验证"
	case notifyInvalidIKESPI:
		return "对端不认识本端使用的 IKE SPI（INVALID_IKE_SPI）：对端可能重启过，" +
			"本端持有的是一条已经不存在的 SA，等待重协商即可"
	case notifyInvalidMessageID:
		return "消息序号不同步（INVALID_MESSAGE_ID）：通常出现在一端重启后，本端会重建 SA"
	case notifyInvalidMajorVersion:
		return "对端不支持 IKEv2（INVALID_MAJOR_VERSION）：本实现只有 IKEv2，无法与 IKEv1 对端互通"
	case notifyTemporaryFailure:
		return "对端暂时无法处理（TEMPORARY_FAILURE）：双方几乎同时发起了重协商，" +
			"这是 RFC 7296 规定的收敛机制，会自动重试，无需处理"
	case notifyChildSANotFound:
		return "对端找不到要重协商的 Child SA（CHILD_SA_NOT_FOUND）：对端可能已单方面拆除该 SA，" +
			"本端会重新建立"
	case notifyNoAdditionalSAs:
		return "对端拒绝再建立新的 SA（NO_ADDITIONAL_SAS）：通常是对端达到了资源上限"
	case notifySinglePairRequired:
		return "对端只接受单一流量选择器对（SINGLE_PAIR_REQUIRED）：本实现本来就只发一对，" +
			"出现它说明对端实现与预期不符"
	case notifyUnsupportedCriticalPayload:
		return "对端遇到不认识且被标为关键的载荷（UNSUPPORTED_CRITICAL_PAYLOAD）：实现不对版"
	case notifyCookie:
		return "对端要求携带 cookie 重发（COOKIE）：对端正处于 half-open 洪泛防护状态，本端会自动重试"
	case notifyInitialContact:
		return "对端声明这是首次连接（INITIAL_CONTACT）：本端会清理与它之间的旧 SA"
	case notifyNATDetectionSourceIP, notifyNATDetectionDestinationIP:
		return "NAT 检测通知：链路上存在 NAT，后续报文将改走 UDP 4500 并加 non-ESP marker"
	case notifyRekeySA:
		return "重协商通知（REKEY_SA）：对端正在替换一条既有 SA"
	}
	if n < notifyErrorCeiling {
		return fmt.Sprintf("对端返回了本实现未识别的错误通知（码点 %d）：交换已中止。"+
			"若对端不是白帝网关，请注意本实现未与第三方设备做过互通验证", n)
	}
	return fmt.Sprintf("收到未识别的状态类通知（码点 %d），按 RFC 7296 已忽略", n)
}

// Explain 把本层可能冒出来的错误翻成中文。
//
// 与 ExplainNotify 分开是因为来源不同：那边是**对端**说的，这边是**本端**发现的。
// 管理员看到的最终字符串应当能区分"是我配错了"还是"对端拒绝了我"。
func Explain(err error) string {
	if err == nil {
		return ""
	}
	// 装载期拒绝：ConfigError 自带站点/字段/原因，已经是可读中文，原样用。
	var ce *ipsec.ConfigError
	if errors.As(err, &ce) {
		return ce.Error()
	}
	switch {
	case errors.Is(err, ipsec.ErrNoPolicy):
		return "出向流量没有匹配的 IPSec 策略：目的地址不在任何站点的 remoteSubnet 内，" +
			"或该站点尚未建立 Child SA。这些包已被丢弃（不会明文放行）"
	case errors.Is(err, ipsec.ErrNoSA):
		return "收到未知 SPI 的 ESP 报文：对端可能仍在用一条已被本端拆除的 SA，" +
			"也可能是无关流量或扫描"
	case errors.Is(err, ipsec.ErrAuth):
		return "ESP 完整性校验失败：密钥不一致或报文在途中被改动。" +
			"若持续出现且计数快速增长，优先怀疑两端密钥材料不同步"
	case errors.Is(err, ipsec.ErrReplay):
		return "ESP 反重放：序号重复或落在窗口之外。偶发通常是网络乱序，持续出现要怀疑重放攻击"
	case errors.Is(err, ipsec.ErrTSMismatch):
		return "解封后的内层地址越出协商好的流量选择器：对端在往隧道里塞不该塞的地址（越权），已丢弃"
	case errors.Is(err, ipsec.ErrClosed):
		return "通道已关闭（正常停机路径）"
	}
	return err.Error()
}

// DescribeConfig 一句话概括一条站点配置，用于日志与状态回显。
//
// ★刻意**不包含 PSK**，且这是唯一被允许用来打印配置的函数。
// SiteConfig 里带着密钥原文，任何"把整个结构体打进日志"的调试代码都是一次永久泄漏
// （日志会被归档、被转发、被贴进工单）。
func DescribeConfig(c ipsec.SiteConfig) string {
	return fmt.Sprintf("站点 %s（%s）：对端 %s，本端网段 %s ↔ 对端网段 %s，认证 %s，套件 %s，PFS %v，PSK 版本 %d",
		c.ID, c.Name, c.Peer, c.LocalSubnet, c.RemoteSubnet, c.Auth, c.Suite, c.PFS, c.PSKVersion)
}

// DescribeState 一句话概括一条站点的运行态，用于 e2e 断言失败时打印现场。
func DescribeState(st ipsec.SiteState) string {
	s := fmt.Sprintf("%s=%s", st.SiteID, st.State)
	if st.IKESPIi != "" || st.IKESPIr != "" {
		s += fmt.Sprintf(" ike_spi=%s/%s", st.IKESPIi, st.IKESPIr)
	}
	if st.ChildSPIIn != 0 || st.ChildSPIOut != 0 {
		s += fmt.Sprintf(" child_spi=in:%08x/out:%08x", st.ChildSPIIn, st.ChildSPIOut)
	}
	if st.NegotiatedProposal != "" {
		s += " 协商结果=" + st.NegotiatedProposal
	}
	s += fmt.Sprintf(" rx=%dB/%d包 tx=%dB/%d包", st.RxBytes, st.PacketsIn, st.TxBytes, st.PacketsOut)
	if st.LastError != "" {
		s += " 最后错误=" + st.LastError
	}
	return s
}

// SubnetSummary 汇总一批站点声明的对端网段，供数据面配路由用。
//
// ★存在的理由就是 CLAUDE.md 里 `baidi-tun -route` 那条事故：业务地址散落在多个网段，
// 只接管其中一条，结果是「隧道建起来了、点开应用却直连不走隧道」，无报错、界面显示正常。
// 网段清单必须由控制面下发的站点配置推导，绝不能让管理员手填。
//
// 只收 Enabled 且归本机的站点：给一条停用站点配路由，会把流量吸进一个没有 SA 的黑洞
// （表现为该网段整段不通，而站点状态是 down，两件事看起来毫不相干）。
func SubnetSummary(gatewayID string, sites []ipsec.SiteConfig) []netip.Prefix {
	seen := make(map[netip.Prefix]bool)
	var out []netip.Prefix
	for _, c := range sites {
		if !c.Enabled {
			continue
		}
		if c.GatewayID != "" && c.GatewayID != gatewayID {
			continue
		}
		p := c.RemoteSubnet
		if !p.IsValid() || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
