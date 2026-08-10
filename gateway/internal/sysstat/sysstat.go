// Package sysstat 采集网关宿主机的设备状态指标（CPU 使用率 / 内存使用率 / 磁盘使用率 /
// 系统负载 / 网络收发字节速率），随 mTLS 心跳上报控制面（PRD ch5 FR-MON-01/02）。
//
// 两条纪律贯穿本包：
//
//  1. **纯标准库**。Linux 读 /proc，darwin 读 sysctl，其余平台一律「不可判定」。
//     刻意不引 gopsutil 之类的第三方——这里要的东西加起来不到两百行，而那类库会
//     往数据面二进制里拖进一串间接依赖；网关是被保护方，依赖面越小越好。
//
//  2. **三态而非补零**。采不到的指标报「不可判定」（nil），绝不用 0 冒充。
//     报 0 的后果很具体：控制台上「CPU 0%」看起来像一台空闲的机器，而实际是这台机器
//     根本没采到过 CPU；「CPU>80% 告警」也会因此对一台失明的网关永远保持沉默——
//     一个静默失效，两处都无报错。这与终端 posture 采集器的 unknown 语义是同一条
//     纪律（见 clients/desktop/src-tauri/src/posture.rs 与 CLAUDE.md「采集三态」）。
//
// 平台可采性一览（不可判定的项在控制台上显示为「—」并注明原因，不参与告警判定）：
//
//	           CPU   内存   磁盘   负载   吞吐
//	linux       ✓     ✓     ✓     ✓     ✓     /proc/{stat,meminfo,loadavg,net/dev} + statfs
//	darwin      ✗     ✓     ✓     ✓     ✓     sysctl + statfs；CPU 时间片只在 mach
//	                                          host_statistics() 里，取它要 cgo，故如实报不可判定
//	其他        ✗     ✗     ✗     ✗     ✗
package sysstat

import (
	"sync"
	"time"
)

// Sample 一次采样。每个字段都是可空的：
// 非 nil = 本次真采到的实测值；nil = 不可判定（本平台采不到，或差分所需的前一个采样点还不存在）。
//
// JSON 上用 omitempty：不可判定的指标**在报文里根本不出现**，而不是出现一个 0。
// 控制面对缺字段容忍（解到 nil → 落库 NULL），旧控制面则整个忽略 metrics 字段。
type Sample struct {
	CPU   *float64 `json:"cpu,omitempty"`   // CPU 使用率，0-100
	Mem   *float64 `json:"mem,omitempty"`   // 内存使用率，0-100
	Disk  *float64 `json:"disk,omitempty"`  // 磁盘使用率（Collector 指定的挂载点），0-100
	Load1 *float64 `json:"load,omitempty"`  // 1 分钟平均负载（**不是**百分比，可 >1）
	RxBps *float64 `json:"rxBps,omitempty"` // 网络收字节速率，B/s
	TxBps *float64 `json:"txBps,omitempty"` // 网络发字节速率，B/s
}

// cpuTimes 累计 CPU 时间片。单位无所谓（jiffies / ticks 都行），
// 但两次采样必须同源——使用率是它们的差分比值。
type cpuTimes struct{ busy, total float64 }

// netCounters 全机累计收发字节（跳过回环与 down 掉的接口）。
type netCounters struct{ rx, tx uint64 }

// Collector 有状态的采集器：CPU 使用率与网络速率都是**差分**指标，
// 必须记住上一次的累计值才算得出来。并发安全（Sample 可从任意 goroutine 调）。
type Collector struct {
	mu       sync.Mutex
	diskPath string           // 量哪个挂载点的磁盘水位（通常是 "/"）
	now      func() time.Time // 注入点：速率的分母是两次采样的真实间隔，测试要能控它

	prevCPU     cpuTimes
	havePrevCPU bool
	prevNet     netCounters
	prevNetAt   time.Time
	havePrevNet bool
}

// New 构造采集器。diskPath 为空时默认量根文件系统。
func New(diskPath string) *Collector {
	if diskPath == "" {
		diskPath = "/"
	}
	return &Collector{diskPath: diskPath, now: time.Now}
}

// Sample 采一次。
//
// ★首次调用必然报不出 CPU 与吞吐（差分要两个点）——这时报的是**不可判定**而不是 0。
// 「刚启动还没有第二个采样点」与「这台机器很闲」是两回事，塌缩成 0 就再也分不开了。
func (c *Collector) Sample() Sample {
	c.mu.Lock()
	defer c.mu.Unlock()

	var s Sample

	// ── CPU：累计时间片差分 ──
	if cur, ok := readCPUTimes(); ok {
		if c.havePrevCPU {
			dTotal := cur.total - c.prevCPU.total
			dBusy := cur.busy - c.prevCPU.busy
			// 计数器回退或不自洽（宿主机重启、容器换了 cgroup 视图）→ 本轮不可判定，
			// 只把基线换成新值。硬算会得到负数或几千的百分比，比缺一个点糟得多。
			if dTotal > 0 && dBusy >= 0 && dBusy <= dTotal {
				s.CPU = pctPtr(dBusy / dTotal * 100)
			}
		}
		c.prevCPU, c.havePrevCPU = cur, true
	}

	// ── 内存 / 磁盘 / 负载：瞬时值，一次采样即可 ──
	if v, ok := readMemUsedPct(); ok {
		s.Mem = pctPtr(v)
	}
	if v, ok := readDiskUsedPct(c.diskPath); ok {
		s.Disk = pctPtr(v)
	}
	if v, ok := readLoad1(); ok && v >= 0 {
		load := v
		s.Load1 = &load
	}

	// ── 网络吞吐：累计字节差分 / 真实间隔 ──
	if cur, ok := readNetCounters(); ok {
		now := c.now()
		if c.havePrevNet {
			dt := now.Sub(c.prevNetAt).Seconds()
			// 计数器回退按不可判定处理。darwin 的接口计数器是 32 位的，跑满 4 GiB
			// 就会回绕一次；硬减会得到一个 4 GB/s 的假尖峰，那种尖峰在趋势图上比
			// 缺一个点更容易把人引到错误的方向（"这里被打流量了"）。
			if dt > 0 && cur.rx >= c.prevNet.rx && cur.tx >= c.prevNet.tx {
				rx := float64(cur.rx-c.prevNet.rx) / dt
				tx := float64(cur.tx-c.prevNet.tx) / dt
				s.RxBps, s.TxBps = &rx, &tx
			}
		}
		c.prevNet, c.prevNetAt, c.havePrevNet = cur, now, true
	}

	return s
}

// pctPtr 把百分比夹到 [0,100] 并取地址。
// 夹取而不是丢弃：算出 100.3% 通常只是时间片取整误差，丢掉反而制造缺口。
func pctPtr(v float64) *float64 {
	switch {
	case v < 0:
		v = 0
	case v > 100:
		v = 100
	}
	return &v
}
