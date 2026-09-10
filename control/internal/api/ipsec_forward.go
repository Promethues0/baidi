package api

import (
	"strings"

	"baidi.dev/control/internal/store"
)

// ── 内核 IP 转发回执（FR-IPSEC-06/07，wave11 行动 10-①）──
//
// 网关只报**事实**（那个开关是 0 还是 1、探不探得到），一句人话都不组。
// 折算与措辞收在本文件一处，理由与 api.stealthReceiptOf 完全相同：
// 同一份事实会同时出现在站点列表、详情抽屉与将来的 /diag 上，
// 措辞散在三处必然分家，而分家的表现是「同一条隧道在两个页面上结论相反」。
//
// ★这一格**不参与任何判定**。转发关着的隧道确实建起来了（IKE 协商不经转发），
// 把它折进 state 会让「协商失败」与「协商成功但没人能用」混成一格——
// 那正是本项目当初拆出五态时反对的形态。

// IpsecForward 一条站点的内核转发回执（下发给控制台）。
type IpsecForward struct {
	// Status 五态：on / off / unknown / n-a / unreported。
	// ★unreported 是**控制面折算出来的**，网关报不出它（网关一旦说话就至少是 unknown）。
	Status string `json:"status"`
	// Summary 一句结论。
	Summary string `json:"summary"`
	// Impact 这个结论意味着什么、下一步该做什么。空 = 一切正常，无需动作。
	Impact string `json:"impact,omitempty"`
	// Detail 网关原样报上来的探测说明（读哪个文件失败之类），供排障。
	Detail string `json:"detail,omitempty"`
}

// 回执状态（对外 JSON 值）。前四个与 store 的取值一致，第五个是控制面独有。
const (
	ipsecFwdUnreported = "unreported"
)

// ipsecForwardReceipt 把一条站点的回报折算成回执。sa 为 nil = 从未被任何网关回报过。
//
// ★只吃回报、不吃站点配置：这一格的每个字都必须能追到网关实测的那次探测上。
// 传进来一个 site 就迟早会有人拿 `site.Enabled` 之类去改结论——那就又成了
// 「配置回显冒充实测」，正是 ipsec_sa_state 当初从 ipsec_sites 里拆出来要消灭的东西。
//
// ★站点未启用时也照常折算而不是直接跳过：管理员点「启用」之前就看得见
// 「这台机器的转发是关着的」，比启用之后对着一条 up 却零流量的隧道查半天强。
func ipsecForwardReceipt(sa *store.IpsecSAState) *IpsecForward {
	if sa == nil {
		// 没有任何回报：这条站点还没被网关承载过。转发状态无从谈起，
		// 而站点行上已经有「未回报 / 无网关承载」的更强提示，这里不再画蛇添足。
		return nil
	}
	status := normalizeIpsecForward(sa.KernelForward)
	if status == "" {
		// 列是空的 = 这台网关从没报过这一项（旧版本二进制）。
		// ★这个折算只在**读侧**做，绝不在入站时写进库：写进去的话库里存的就不再是
		// 「网关说了什么」而是「控制面推断了什么」，而下一次读它会被 normalize
		// 认成一个不认识的值再折成 unknown——「没报过」就此变成「探不到」，
		// 两者的下一步动作完全不同（升级网关 vs 去机器上看一眼）。
		status = ipsecFwdUnreported
	}
	r := &IpsecForward{Status: status, Detail: sa.KernelForwardDetail}
	switch r.Status {
	case store.IpsecForwardOn:
		r.Summary = "内核 IP 转发已开启（承载网关实测）"
	case store.IpsecForwardOff:
		r.Summary = "内核 IP 转发处于关闭状态（承载网关实测）"
		r.Impact = "隧道本身可以建起来、SA 也会正常续期，但**经本网关转发**的分支主机流量" +
			"会在内核路由那一层被丢弃：现象是流量计数恒为 0、分支 PC 一个包都过不去，" +
			"而这里没有任何错误可看（包根本没走到 ESP 层，连丢弃计数都不会动）。" +
			"请在承载网关 " + orElse(sa.GatewayID, "（未知）") + " 上打开转发" +
			"（Linux：sysctl -w net.ipv4.ip_forward=1 并写进 /etc/sysctl.d/ 持久化；" +
			"macOS：sysctl -w net.inet.ip.forwarding=1）。" +
			"★白帝**不替你改这个开关**——它是宿主机的全局网络行为，那台机器上可能还跑着别的东西。" +
			"若本站点只需要网关自身访问对端网段（不为局域网主机做中转），这一项可以忽略。"
	case store.IpsecForwardNA:
		r.Summary = "内核 IP 转发对这条站点不适用"
		r.Impact = "承载它的网关用的是 netstack 自检数据面（进程内用户态协议栈，无 root）：" +
			"协商、加解密与状态回报都是真的，但这条隧道**不承载任何真实业务流量**，" +
			"内核转发开关与它无关。生产部署请用 -datapath=tun。"
	case ipsecFwdUnreported:
		r.Summary = "承载网关未上报内核转发状态（旧版本网关）"
		r.Impact = "控制面无从判断这台机器的 IP 转发开没开——" +
			"关着的话隧道会显示「已建立」而分支主机一个包都过不去，且全程零报错。" +
			"升级该网关的 baidi-ipsec 二进制后，回报会自动带上这一项；" +
			"在那之前可在网关上执行 sysctl net.ipv4.ip_forward 自行确认。"
	default: // unknown
		r.Status = store.IpsecForwardUnknown
		r.Summary = "内核 IP 转发状态不可判定（网关探测未能得出结论）"
		r.Impact = "**不可判定不等于没问题**：转发若实际关着，隧道会显示「已建立」" +
			"而分支主机一个包都过不去。请在承载网关上执行 sysctl net.ipv4.ip_forward" +
			"（macOS：sysctl net.inet.ip.forwarding）自行确认。"
	}
	return r
}

// normalizeIpsecForward 把网关报上来的值收敛到已知取值。**入站与读侧共用这一个。**
//
// ★认不出来一律折成 unknown，**绝不折成 on**——与 normalizeIpsecState 折成 failed
// 同一条纪律：把不认识的值折成好值，等于让一个字段拼写错误变成一句「一切正常」。
//
// ★空串**原样保留空串**，不在这里折成 unreported。这一列存的必须是
// 「网关说了什么」；把控制面的推断写进去，会让下一次读时 normalize 认不出
// "unreported" 而折成 unknown——「没报过」静默变成「探不到」。
// 空串→unreported 的折算只在 ipsecForwardReceipt（读侧）做一次。
func normalizeIpsecForward(v string) string {
	switch strings.TrimSpace(v) {
	case "":
		return ""
	case store.IpsecForwardOn:
		return store.IpsecForwardOn
	case store.IpsecForwardOff:
		return store.IpsecForwardOff
	// 数据面那侧的常量是 "n/a"（见 gateway/internal/ipsec.KernelForwardNA）。
	// 斜杠要进 CSS class 与查询串，故落库与下发一律用 "n-a"，转换只在这一处。
	case "n/a", store.IpsecForwardNA:
		return store.IpsecForwardNA
	}
	return store.IpsecForwardUnknown
}
