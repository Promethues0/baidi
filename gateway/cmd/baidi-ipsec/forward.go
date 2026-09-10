package main

import (
	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/kernelfwd"
)

// ── 内核 IP 转发回执（FR-IPSEC-06/07）──
//
// # 这一格补的是哪个洞
//
// 站点组网**从不设置也从不检查**内核 IP 转发，而分支 PC 的流量要进隧道，必须先被
// 内核从局域网口**转发**到 baidi-ipsec 的 TUN 上。转发关着时：
//
//	IKE 全绿（协商是本机 UDP 收发，不经转发）→ 站点显示「已建立」
//	→ SA 剩余寿命正常倒数 → rx/tx 字节数恒为 0 → 分支 PC 一个包都过不去
//
// 而且连**丢弃计数**都是 0：包在内核路由那一层就没了，ESP 引擎从头到尾没见过它，
// `dropHint` 那七个计数器一个都不会动。整条链路上没有任何一处会报错。
//
// # 为什么是回执，不是断言、更不是自动修
//
//   - **不自动修**：`sysctl -w net.ipv4.ip_forward=1` 改的是**宿主机的全局网络行为**，
//     那台机器上可能还跑着别的东西。这个决定必须由管理员做，白帝只负责让它可见。
//     （natfw 那边的 EnableForwarding 是 NAT 功能显式承诺的一部分，语义不同，别照抄。）
//   - **不当判定**：站点该 up 还是 up。转发关着不代表隧道没建起来——它确实建起来了，
//     只是没有流量能走到它上面。把它折进 state 会让「协商失败」与「协商成功但没人能用」
//     混成一格，那正是本项目拆出五态时反对的形态。
//   - **不塌成 false**：探不到就报 unknown（见 kernelfwd 包注释）。
type forwardReceipt struct {
	// kernelDP 数据面是否真的经过内核。
	//
	// ★`-datapath=netstack`（无 root 自检模式）下整条数据面是进程内的用户态协议栈，
	// 内核转发开关与它**毫无关系**。此时必须报 n/a 而不是 off——报 off 会让
	// ipsec-e2e.sh 每次跑完都在控制台上挂两条假告警，而假告警多了这一格就没人看了。
	kernelDP bool
	// probe 注入的探针（测试替换）。生产是 kernelfwd.Probe。
	probe func() kernelfwd.State
}

// forSites 探一次内核状态，并按**每条站点自己的地址族**给出回执。
//
// 只探一次：v4/v6 两格对本进程的全部站点都是同一份事实，逐站点探是白白多做 N 次 IO。
//
// isV4 的键是站点 id；**键不存在 = 本层不知道这条站点的网段**（典型是状态机里
// 拆除未完成的残留行）。那时报 unknown 并说明理由——猜一个地址族去查开关，
// 有一半概率给出方向完全相反的结论。
func (f forwardReceipt) forSites(states []ipsec.SiteState, isV4 map[string]bool) {
	if !f.kernelDP {
		for i := range states {
			states[i].KernelForward = ipsec.KernelForwardNA
			states[i].KernelForwardDetail = "本网关的数据面是 netstack（进程内用户态协议栈，无 root 自检模式）：" +
				"受保护流量不经内核路由，内核 IP 转发开关对这条站点不适用"
		}
		return
	}
	st := f.probe()
	for i := range states {
		v4, known := isV4[states[i].SiteID]
		if !known {
			states[i].KernelForward = ipsec.KernelForwardUnknown
			states[i].KernelForwardDetail = "本网关已不持有该站点的网段配置（多半是拆除未完成的残留），" +
				"无从判断该查 IPv4 还是 IPv6 的转发开关"
			continue
		}
		on, fam := st.V4, "IPv4"
		if !v4 {
			on, fam = st.V6, "IPv6"
		}
		switch {
		case on == nil:
			states[i].KernelForward = ipsec.KernelForwardUnknown
			states[i].KernelForwardDetail = "读不到本机的 " + fam + " 转发开关：" +
				orElseStr(st.Detail, "探测未给出原因")
		case *on:
			states[i].KernelForward = ipsec.KernelForwardOn
			states[i].KernelForwardDetail = "实测本机 " + fam + " 转发已开启"
		default:
			states[i].KernelForward = ipsec.KernelForwardOff
			states[i].KernelForwardDetail = "实测本机 " + fam + " 转发处于关闭状态"
		}
	}
}

func orElseStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
