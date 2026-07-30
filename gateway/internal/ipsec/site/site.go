// Package site 是 IPSec 站点组网的**编排层**：把 IKEv2 控制面（ike）、
// ESP 数据面（esp）与数据面管道（ipsec.Datapath / ipsec.Transport）绑成
// 一个可以被控制面声明式驱动的整体。
//
// # 一条站点从"控制面下发"到"业务流量真的走隧道"要经过什么
//
//	控制面 GET /gateways/ipsec ──► Backend.Apply（全量对账）
//	                                 │
//	                                 ├─ SiteConfig.Validate  装载期拒绝 → SiteState{failed, 中文原因}
//	                                 └─ IKE.AddSite          → IKE_SA_INIT/IKE_AUTH → Protector.Install
//
//	出向：Datapath.ReadOutbound ─► Protector.Protect ─► Transport.Send(KindESP)
//	入向：Transport.Recv(KindESP) ─► Protector.Unprotect ─► Datapath.WriteInbound
//
// # 三条贯穿本包的原则
//
//  1. **全量声明式对账**：Apply 收到的是"当前应该有哪些站点"的完整快照，
//     本包负责收敛过去。增量 add/del 在网络抖动、重启、乱序下会积累出无人知晓的
//     残留状态；全量对账天然幂等（与 resource.Replace 同一姿态）。
//  2. **拒绝要看得见**：任何一条站点跑不起来，都必须变成那条站点的
//     SiteState{State: failed, LastError: 中文原因} 回到控制台，
//     而不是"网关默默跳过、界面永远 connecting"。
//  3. **绝不明文放行**：出向包一旦没有匹配的 SA，只能丢弃并计数。
//     ★「隧道显示已建立、流量却从旁路直连出去了、全程零报错」是本项目历史上
//     最迷惑人的失败形态（CLAUDE.md 里 `baidi-tun -route` 那条），
//     pump.go 里对应的分支写了同样的告诫。
package site

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/esp"
)

// IKE 是本包对 IKEv2 控制面的**全部**需求。
//
// # 为什么这里是接口而不是直接用 *ike.Engine
//
//  1. **并行施工**：ike 状态机与本包是两个工作包同时动工的。用接口意味着本包能
//     独立编译、独立单测，不必等状态机落地——而"等它落地再开始"通常意味着两边的
//     假设分叉到发现时已经很贵。
//  2. **可测**：backend_test.go 里注入一个假引擎，就能把"对账逻辑"与"协议实现"
//     分开验证。否则每测一次 Apply 都要跑一遍真握手，慢且掩盖问题。
//
// 方法签名逐字取自 PLAN §1.5，*ike.Engine 结构化满足本接口，无需显式声明实现。
// ★若状态机那边改了签名，编译会在组装点（cmd/baidi-ipsec）当场炸开——
// 这是刻意选择的响亮失败，好过在这里写个适配层把差异抹平。
type IKE interface {
	// AddSite 装载一条站点（内部会做算法名→码点映射，失败返回 *ipsec.ConfigError）。
	AddSite(cfg ipsec.SiteConfig) error
	// RemoveSite 拆除一条站点（先发 Delete 再拆本地状态）。
	RemoveSite(id string) error
	// States 导出各站点的实测运行态。
	States() []ipsec.SiteState
	// Run 事件循环：收 IKE 报文 + 跑重传/DPD/rekey 定时器。阻塞到 ctx 结束。
	Run(ctx context.Context) error
	// Touch 收到该入向 SPI 的 ESP 报文时回调，用于刷新 DPD 计时
	// （有数据在流就不必再探活，省掉一轮无谓的 INFORMATIONAL）。
	Touch(inSPI uint32)
}

// siteRemover 是 Protector 的可选能力：按站点批量拆 SA。
//
// ★为什么非要有它：`enabled=false` 必须**真的**让流量停掉。
// 只调 IKE.RemoveSite 而不清 ESP 侧的 SA，会留下一条"控制面已停用、
// 数据面仍在收发"的隧道——界面显示 down、流量照常通过，是最坏的一种不一致。
// esp.Engine 实现了它；换后端时若没实现，Apply 会退化为只拆 IKE 侧，
// 因此这里做类型断言而不是塞进 ipsec.Protector 接口（那会绑死所有后端）。
type siteRemover interface {
	RemoveSite(siteID string) int
}

// espStats 是 Protector 的可选能力：读实测计数。
//
// SiteState 里的流量数字**只允许**来自这里（types.go 的 Counters 注释写死了这条）：
// 回显配置正是旧实现"toggle 一下界面就显示 up"的根源。
type espStats interface {
	Drops() esp.Drops
	SiteDrops(siteID string) esp.Drops
	SiteCounters(siteID string) ipsec.Counters
}

// ── 隧道 MTU ──

// 外层封装的固定开销：IPv4 头 20 + UDP 头 8。
// IPv6 外层是 40 字节，本实现的对端落点目前只有 IPv4 形态，故按 20 算；
// 真要跑 IPv6 外层时这里必须改，否则会得到一个偏大 20 字节的 MTU
// （症状见下面 TunnelMTU 的注释）。
const outerIPv4UDPOverhead = 20 + 8

// TunnelMTU 由物理链路 MTU 反推隧道内层 MTU。
//
// ★这里必须用**最坏情况**开销（esp.Overhead 的口径就是最坏情况：含最大补齐）。
// 按平均值算出来的 MTU 会得到一种极具迷惑性的故障：小包（ping、DNS、TCP 握手）
// 全通，一旦发满载数据段就有一部分超限被丢——现象是「能 ping 通、SSH 能登录、
// HTTP 一传大文件就卡死」，而隧道状态自始至终是 up。
//
// 本实现不做 PMTUD（写进诚实边界），所以这个值算错了没有任何自愈机制。
func TunnelMTU(outerMTU int, encrID uint16, keyBits int, integID uint16) (int, error) {
	ov, err := esp.Overhead(encrID, keyBits, integID)
	if err != nil {
		return 0, fmt.Errorf("推算隧道 MTU 失败：%w", err)
	}
	mtu := outerMTU - outerIPv4UDPOverhead - ov
	if mtu < 576 {
		// 576 是 IPv4 要求所有主机都必须能接收的最小报文长度。低于它基本可以断定
		// 是外层 MTU 填错了（比如把隧道 MTU 又填了一遍），继续跑只会得到一条
		// 什么都传不动的隧道。
		return 0, fmt.Errorf("推算出的隧道 MTU 为 %d，低于 IPv4 最小值 576：外层 MTU=%d、ESP 最坏开销=%d，请检查外层 MTU 是否填错",
			mtu, outerMTU, ov)
	}
	return mtu, nil
}

// ── 站点条目 ──

// entry 一条站点在本层的全部状态。
//
// 注意它**不含**任何协议状态（SPI、密钥、生存期都在 ike/esp 里）：
// 本层只关心"这条站点该不该跑、跑起来没有、为什么没跑起来"。
type entry struct {
	cfg ipsec.SiteConfig
	// fp 配置指纹，用来判断"这一轮下发的配置跟上一轮是不是同一份"。
	// 相同就**什么都不做**——每 15 秒重建一次 SA 会让隧道永远处于握手中。
	fp [32]byte
	// rejectErr 装载期拒绝原因。非 nil 表示这条站点从未被交给 IKE 引擎，
	// 状态固定为 failed，LastError 就是它。
	rejectErr error
	// inEngine 是否已经交给 IKE 引擎。
	inEngine bool
	// addedAt 交给引擎的时刻（用于"还没开始协商"与"协商很久没成功"的区分）。
	addedAt time.Time
}

// fingerprint 计算配置指纹。
//
// ★必须**包含 PSK**：管理员改了 PSK 却不重建 SA，隧道会一直用旧密钥跑下去，
// 直到下一次 rekey 才突然认证失败——那时距离改密钥可能已经过去几个小时，
// 没有人会把两件事联系起来。
//
// 用 SHA-256 而不是直接比结构体，是因为指纹可以安全地写进日志（单向），
// 而 SiteConfig 里有 PSK，任何"打印整个配置"的调试代码都是一次永久泄漏。
func fingerprint(c ipsec.SiteConfig) [32]byte {
	h := sha256.New()
	w := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0}) // 分隔符：防 "ab"+"c" 与 "a"+"bc" 撞同一个指纹
		}
	}
	w(c.ID, c.Name, c.GatewayID, strconv.FormatBool(c.Enabled))
	w(c.Peer.String(), c.LocalSubnet.String(), c.RemoteSubnet.String())
	w(c.LocalID, c.RemoteID, c.Auth, c.Suite)
	w(c.Phase1.Enc, c.Phase1.Hash, c.Phase1.DH)
	w(c.Phase2.Enc, c.Phase2.Hash, c.Phase2.DH)
	// PeerNATPort 决定 ESP 的落点端口，改它必须重建 SA——漏算等于该字段永远改不动。
	w(strconv.FormatBool(c.PFS), strconv.Itoa(int(c.PeerNATPort)))
	w(c.IKELifetime.String(), c.ESPLifetime.String(), c.DPDDelay.String(), c.RetryInitial.String())
	w(strconv.Itoa(c.PSKVersion))
	h.Write(c.PSK) // 见上：PSK 变了必须重建
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// shortFP 指纹的可读前缀，只用于日志（"配置从 a1b2c3d4 变成 e5f6a7b8"这种句子
// 比"配置变了"有用得多，且不泄露任何密钥材料）。
func shortFP(fp [32]byte) string {
	const hexd = "0123456789abcdef"
	var sb strings.Builder
	for _, b := range fp[:4] {
		sb.WriteByte(hexd[b>>4])
		sb.WriteByte(hexd[b&0x0f])
	}
	return sb.String()
}
