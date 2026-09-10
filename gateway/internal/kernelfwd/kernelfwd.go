// Package kernelfwd 只做一件事：**实测**内核 IP 转发开关，并如实回答三态。
//
// # 为什么值得单独一个包
//
// 「网关以路由设备形态工作」是 NAT 与 IPSec 站点组网**共同的**硬前提，而内核转发关着
// 时两者的症状完全一样、且都零报错：
//
//   - IPSec：IKE 协商全绿、隧道显示「已建立」、SA 倒计时正常跳动，
//     只有 rx/tx 字节数恒为 0——因为分支 PC 的包从网卡进来后，内核发现目的地址
//     不是本机、转发又关着，直接丢弃，**根本走不到 TUN 上**，ESP 层连一个包都没见过。
//   - NAT：规则全部正确、计数器恒零。
//
// 这两种形态是白帝反复吃亏的那一类「配置齐全却静默不生效」。此前 baidi-gateway 的
// NAT 路径已经会读它，而 **baidi-ipsec 从头到尾既不设置也不检查**——本包把那一半补上。
//
// # 三条纪律
//
//  1. **探不到就是探不到**。指针三态：nil ≠ false。读失败（无 /proc、容器里被屏蔽、
//     非 Linux/darwin）一律留 nil 并在 Detail 里说明原因。塌成 false 是虚警
//     （会让运维去开一个本来就开着的开关），塌成 true 是替一台可能什么都不通的
//     机器背书——两种错法在页面上都看不出来。
//  2. **只读不写**。本包没有任何写内核的函数。给站点组网偷偷 `sysctl -w` 是在改
//     宿主机的**全局**网络行为（那台机器上可能还跑着别的东西），这个决定必须由
//     管理员做。natfw 那边的 EnableForwarding 是 NAT 功能的显式一部分，语义不同。
//  3. **解析与 IO 分开**。parseProcFlag / parseSysctlFlag 不带 build tag，
//     于是 Linux 的 /proc 格式与 darwin 的 sysctl 输出在任意主机上都能编译 + 单测。
//     只活在 #cgo/#build 分支里的解析代码，在 mac 上连语法都验不到。
//
// # 为什么 v4 / v6 分开报
//
// 两个开关在内核里是**独立**的（Linux 是两个文件，darwin 是两个 sysctl 名）。
// 一条 IPv6 网段的站点在「v4 开着、v6 关着」的机器上一个包都过不去，
// 而只探 v4 会给出一个绿色的、方向完全错误的回执。调用方按站点的地址族取对应那一格。
package kernelfwd

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// State 一次实测的结果。**每一格都可能是「不可判定」，绝不用好值顶包。**
type State struct {
	// Platform 探测时的 GOOS，供控制面在「不可判定」时说清是哪种不可判定。
	Platform string `json:"platform,omitempty"`
	// V4 / V6 内核转发开关的实测值。
	// ★指针三态：nil = 探不到，不是「关着」。理由见包注释纪律 1。
	V4 *bool `json:"v4,omitempty"`
	V6 *bool `json:"v6,omitempty"`
	// Detail 探不到时的原因（读哪个文件失败、命令报什么错），供控制面原样呈现。
	// 「不可判定」不带原因等于没说——运维下一步该查什么全靠这句话。
	Detail string `json:"detail,omitempty"`
}

// linux 内核转发开关的两个 procfs 路径。
//
// ★v6 是 `conf/all/forwarding` 而不是 `ip_forward`：IPv6 没有全局 ip_forward，
// 写错路径的表现是「文件不存在 → 探不到」，比报错更隐蔽。
const (
	procV4 = "/proc/sys/net/ipv4/ip_forward"
	procV6 = "/proc/sys/net/ipv6/conf/all/forwarding"
)

// darwin 的两个 sysctl 名。
const (
	sysctlV4 = "net.inet.ip.forwarding"
	sysctlV6 = "net.inet6.ip6.forwarding"
)

// Probe 实测一次内核转发状态。**只读，不修改任何内核参数。**
//
// 成本：Linux 两次 procfs 读（微秒级，且 procfs 世界可读——**不需要 root**，
// 这与 darkfw.Probe 需要 root 才看得到规则集不同，所以这里的「不可判定」应当很罕见）；
// darwin 两次 sysctl exec（毫秒级）。随 15s 同步循环调用完全无压力。
func Probe() State {
	st := State{Platform: runtime.GOOS}
	switch runtime.GOOS {
	case "linux":
		v4, d4 := probeProc(procV4)
		v6, d6 := probeProc(procV6)
		st.V4, st.V6 = v4, v6
		st.Detail = joinDetail(d4, d6)
	case "darwin":
		v4, d4 := probeSysctl(sysctlV4)
		v6, d6 := probeSysctl(sysctlV6)
		st.V4, st.V6 = v4, v6
		st.Detail = joinDetail(d4, d6)
	default:
		// Windows 等平台：本项目的站点组网数据面本来就只在 Linux/macOS 上跑，
		// 但**说「不支持」比留一个 false 好**——false 会让控制台报一条永远无法消除的告警。
		st.Detail = "本平台（" + runtime.GOOS + "）没有可读的内核转发开关，转发状态不可判定"
	}
	return st
}

// probeProc 读一个 procfs 布尔文件。返回 (值, 失败说明)。
func probeProc(path string) (*bool, string) {
	b, err := os.ReadFile(path)
	if err != nil {
		// 最常见的两种：容器里 /proc/sys 被只读挂载且屏蔽、内核没编 IPv6。
		// 原样带上 err 才指得到根因。
		return nil, "读 " + path + " 失败：" + err.Error()
	}
	v, ok := parseProcFlag(string(b))
	if !ok {
		return nil, path + " 的内容不是 0/1（实际 " + shorten(string(b)) + "），转发状态不可判定"
	}
	return &v, ""
}

// probeSysctl 读一个 darwin sysctl 布尔值。返回 (值, 失败说明)。
func probeSysctl(name string) (*bool, string) {
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		return nil, "执行 sysctl -n " + name + " 失败：" + err.Error()
	}
	v, ok := parseSysctlFlag(string(out))
	if !ok {
		return nil, "sysctl -n " + name + " 的输出不是 0/1（实际 " + shorten(string(out)) + "），转发状态不可判定"
	}
	return &v, ""
}

// parseProcFlag 解析 procfs 的布尔文件内容。第二个返回值 false = 认不出来。
//
// ★认不出来必须回 (false,false) 让调用方留 nil，而不是「不是 1 就当 0」。
// procfs 在被屏蔽/挂了个空文件时会读到空串，把空串当 0 就是凭空断言「转发关着」。
func parseProcFlag(s string) (bool, bool) { return parseFlag(s) }

// parseSysctlFlag 解析 `sysctl -n <name>` 的输出。
//
// darwin 的 `sysctl -n` 只吐值本身（"0\n" / "1\n"）。若某天换成带名字的格式
// （"net.inet.ip.forwarding: 1"），这里会认不出来并如实报「不可判定」，
// 而不是解析出一个错的布尔——那正是 parseFlag 拒绝做模糊匹配的理由。
func parseSysctlFlag(s string) (bool, bool) { return parseFlag(s) }

func parseFlag(s string) (bool, bool) {
	switch strings.TrimSpace(s) {
	case "1":
		return true, true
	case "0":
		return false, true
	}
	return false, false
}

func joinDetail(parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, "；")
}

// shorten 把异常内容截短后放进错误文案。
// 直接把整个文件内容拼进日志/回报，遇到一个被挂成大文件的路径就是一次自伤。
func shorten(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 32 {
		return s[:32] + "…"
	}
	if s == "" {
		return "空"
	}
	return s
}
