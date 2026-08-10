package sysstat

// 各平台原始文本 / 二进制的**纯解析函数**。
//
// ★刻意不带任何 build tag：只活在 //go:build linux 里的解析分支，在 mac 上连语法都
// 验不到，更谈不上单测——这与 posture 采集器把三平台解析抽到 Env trait 后面是同一个
// 理由（见 CLAUDE.md「采集三态」）。读文件/调 sysctl 那一步留在带 tag 的文件里，
// 解析这一步在任意主机上都编译 + 单测。

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// parseProcStat 解析 Linux /proc/stat 的首行聚合 cpu 行：
//
//	cpu  user nice system idle iowait irq softirq steal guest guest_nice
//
// total = 全部字段之和，busy = total - idle - iowait。
// ★guest / guest_nice 已经被计进 user / nice（内核文档明说），再加一遍会让
// total 偏大、使用率系统性偏低，故只累加前 8 个字段。
func parseProcStat(text string) (cpuTimes, bool) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var total, idle float64
		n := len(fields) - 1
		if n > 8 {
			n = 8
		}
		for i := 1; i <= n; i++ {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				return cpuTimes{}, false
			}
			total += v
			// 第 4 列 idle、第 5 列 iowait 都是「没在干活」
			if i == 4 || i == 5 {
				idle += v
			}
		}
		if total <= 0 {
			return cpuTimes{}, false
		}
		return cpuTimes{busy: total - idle, total: total}, true
	}
	return cpuTimes{}, false
}

// parseMeminfo 解析 Linux /proc/meminfo，返回内存使用率百分比。
//
// 口径是 MemTotal 与 MemAvailable 的差，而不是 MemTotal-MemFree：后者会把
// page cache 全算成「已用」，一台正常跑着的机器常年显示 95%+，于是这个指标
// 对告警彻底失去分辨力。MemAvailable 是内核自己算的「不触发换页能拿到多少」，
// 正是运维想看的那个数。老内核（<3.14）没有这一项，退回 MemFree+Buffers+Cached。
func parseMeminfo(text string) (float64, bool) {
	vals := map[string]float64{}
	for _, line := range strings.Split(text, "\n") {
		k, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		vals[k] = v // 单位统一是 kB，只做比值，无需换算
	}
	total := vals["MemTotal"]
	if total <= 0 {
		return 0, false
	}
	avail, ok := vals["MemAvailable"]
	if !ok {
		f, hasFree := vals["MemFree"]
		if !hasFree {
			return 0, false
		}
		avail = f + vals["Buffers"] + vals["Cached"]
	}
	return (total - avail) / total * 100, true
}

// parseLoadavgProc 解析 Linux /proc/loadavg 的第一列（1 分钟平均负载）。
func parseLoadavgProc(text string) (float64, bool) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseProcNetDev 解析 Linux /proc/net/dev，累加**非回环**接口的收发字节。
//
//	Inter-|   Receive                            |  Transmit
//	 face |bytes packets errs drop fifo frame compressed multicast|bytes ...
//
// 排除 lo：回环上的流量与「这台网关对外收发了多少」无关，隧道自环还会把它算两遍。
// 一个接口都没数到时返回 false（不可判定）而不是 0——0 B/s 会被读成「链路很闲」。
func parseProcNetDev(text string) (netCounters, bool) {
	var nc netCounters
	seen := false
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // 前两行表头没有冒号
		}
		name = strings.TrimSpace(name)
		if name == "" || name == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		nc.rx += rx
		nc.tx += tx
		seen = true
	}
	return nc, seen
}

// parseSysctlLoadavg 解析 darwin `sysctl vm.loadavg` 返回的原始结构体：
//
//	struct loadavg { fixpt_t ldavg[3]; long fscale; };
//
// 布局（64 位 darwin）：3×uint32 = 12 字节，long 需 8 字节对齐 → 12..16 是填充，
// fscale 落在 16..24。负载 = ldavg[0] / fscale。
//
// ★syscall.Sysctl 会剥掉**一个**结尾的 NUL 字节，所以拿到手常是 23 而非 24 字节；
// 判据写成 len >= 20（够读到 fscale 的低 4 字节）而不是 == 24，否则在真机上永远不通过。
// fscale 为 0 时报不可判定——除零得到 +Inf，那个值会一路污染到时序库里。
func parseSysctlLoadavg(b []byte) (float64, bool) {
	if len(b) < 20 {
		return 0, false
	}
	ldavg0 := binary.LittleEndian.Uint32(b[0:4])
	// fscale 是 long（8 字节），实测恒为 2048，取低 4 字节足够且免去尾部截断的麻烦
	fscale := binary.LittleEndian.Uint32(b[16:20])
	if fscale == 0 {
		return 0, false
	}
	return float64(ldavg0) / float64(fscale), true
}

// leUint64 把 sysctl 返回的定长整数（可能被剥掉结尾 NUL）补齐后按小端解出来。
// hw.memsize 是 8 字节，值恰好以 0x00 结尾时 syscall.Sysctl 会还给你 7 字节。
func leUint64(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var buf [8]byte
	copy(buf[:], b)
	return binary.LittleEndian.Uint64(buf[:]), true
}

// leUint32 同上，用于 4 字节的 sysctl 整数。
func leUint32(b []byte) (uint32, bool) {
	if len(b) == 0 || len(b) > 4 {
		return 0, false
	}
	var buf [4]byte
	copy(buf[:], b)
	return binary.LittleEndian.Uint32(buf[:]), true
}

// memPctFromPages 由页计数算内存使用率：可回收的部分（空闲页 + 文件页）不算已用。
// 与 parseMeminfo 的 MemAvailable 口径对齐——两个平台的数字得能横向比较，
// 否则同一条「内存 >85% 告警」在 Linux 和 macOS 上意味着完全不同的事。
func memPctFromPages(total, free, external uint64) (float64, bool) {
	if total == 0 {
		return 0, false
	}
	avail := free + external
	if avail > total {
		avail = total // 三个计数取自三次独立的 sysctl，彼此不是同一瞬间的快照
	}
	return float64(total-avail) / float64(total) * 100, true
}
