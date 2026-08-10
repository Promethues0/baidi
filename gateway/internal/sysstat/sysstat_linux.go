//go:build linux

package sysstat

// Linux（含 android，构建约束 linux 在 android 上同样成立）取数：只做「读文件」，
// 解析全在 parse.go 的无 tag 函数里，好让它们在 mac 上也能编译 + 单测。

import "os"

func readCPUTimes() (cpuTimes, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	return parseProcStat(string(b))
}

func readMemUsedPct() (float64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	return parseMeminfo(string(b))
}

func readLoad1() (float64, bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	return parseLoadavgProc(string(b))
}

func readNetCounters() (netCounters, bool) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return netCounters{}, false
	}
	return parseProcNetDev(string(b))
}
