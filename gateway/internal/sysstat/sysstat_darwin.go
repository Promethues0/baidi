//go:build darwin

package sysstat

// darwin 取数：走 sysctl(3) 与路由套接字，全部经标准库 syscall，无 cgo、无第三方。

import "syscall"

// readCPUTimes 在 darwin 上恒为不可判定。
//
// macOS 没有 kern.cp_time 这个 sysctl（那是 BSD 的），CPU 时间片的权威来源是 mach 的
// host_statistics(HOST_CPU_LOAD_INFO)，取它必须 cgo。
// ★这里**如实报不可判定**而不是拿负载凑一个数：负载是运行队列长度，8 核机器上
// load=4 可能是 50% 也可能是 100%，用它冒充 CPU 使用率就是在编造一个可被告警消费的假值。
// 生产网关跑 Linux，这一项在生产路径上是有值的；darwin 是开发/自检机器。
func readCPUTimes() (cpuTimes, bool) { return cpuTimes{}, false }

// readMemUsedPct 由页计数算内存使用率：vm.pages（总页数）、vm.page_free_count（空闲页）、
// vm.page_pageable_external_count（文件页，可回收）。口径与 Linux 的 MemAvailable 对齐。
func readMemUsedPct() (float64, bool) {
	total, ok1 := sysctlUint64("vm.pages")
	free, ok2 := sysctlUint64("vm.page_free_count")
	if !ok1 || !ok2 {
		return 0, false
	}
	// 文件页取不到时按 0 算（只会让使用率偏高，不会把一台吃满内存的机器显示成空闲）
	external, _ := sysctlUint64("vm.page_pageable_external_count")
	return memPctFromPages(total, free, external)
}

func readLoad1() (float64, bool) {
	s, err := syscall.Sysctl("vm.loadavg")
	if err != nil {
		return 0, false
	}
	return parseSysctlLoadavg([]byte(s))
}

// readNetCounters 经路由套接字取接口计数（NET_RT_IFLIST），累加非回环的 UP 接口。
//
// syscall.RouteRIB / ParseRoutingMessage 已标记 Deprecated（官方推荐 golang.org/x/net/route），
// 这里仍用标准库版本：功能实测可用，而为一个观测指标把 x/net 提成直接依赖不划算。
// ★darwin 的 IfData 计数器是 32 位的，4 GiB 就回绕一次；回绕由 Collector 的
// 「计数器回退 → 本轮不可判定」统一兜住，不会变成一个假尖峰。
func readNetCounters() (netCounters, bool) {
	buf, err := syscall.RouteRIB(syscall.NET_RT_IFLIST, 0)
	if err != nil {
		return netCounters{}, false
	}
	msgs, err := syscall.ParseRoutingMessage(buf)
	if err != nil {
		return netCounters{}, false
	}
	var nc netCounters
	seen := false
	for _, m := range msgs {
		ifm, ok := m.(*syscall.InterfaceMessage)
		if !ok {
			continue
		}
		flags := ifm.Header.Flags
		if flags&syscall.IFF_LOOPBACK != 0 || flags&syscall.IFF_UP == 0 {
			continue
		}
		nc.rx += uint64(ifm.Header.Data.Ibytes)
		nc.tx += uint64(ifm.Header.Data.Obytes)
		seen = true
	}
	return nc, seen
}

// sysctlUint64 读一个整数型 sysctl。syscall.Sysctl 返回原始字节（并剥掉结尾的一个 NUL），
// 故统一走 leUint64 补齐再解——直接用 SysctlUint32 会在 64 位项上返回 ENOMEM。
func sysctlUint64(name string) (uint64, bool) {
	s, err := syscall.Sysctl(name)
	if err != nil {
		return 0, false
	}
	b := []byte(s)
	if len(b) <= 4 {
		v, ok := leUint32(b)
		return uint64(v), ok
	}
	return leUint64(b)
}
