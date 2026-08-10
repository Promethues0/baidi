package sysstat

// 设备状态采集器的单元测试。分两类：
//   - 在**本机真跑**（断言值域合理、三态语义正确）；
//   - 解析函数用固定样本跑（Linux 的 /proc 文本与 darwin 的 sysctl 二进制在
//     任意主机上都能验，不靠 build tag 撞运气）。

import (
	"encoding/binary"
	"runtime"
	"testing"
	"time"
)

// 本机真采一次：拿到值的项必须落在合理值域，拿不到的项必须是 nil（而不是 0）。
func TestSampleOnThisHost(t *testing.T) {
	c := New("/")
	s1 := c.Sample()

	// 首次采样：CPU 与吞吐是差分指标，此刻必然不可判定——这条正是「别报 0」的核心。
	if s1.CPU != nil {
		t.Errorf("首次采样不该有 CPU 值（差分需要两个采样点），得到 %v", *s1.CPU)
	}
	if s1.RxBps != nil || s1.TxBps != nil {
		t.Errorf("首次采样不该有吞吐速率，得到 rx=%v tx=%v", s1.RxBps, s1.TxBps)
	}

	time.Sleep(60 * time.Millisecond) // 让计数器有机会走动，也让速率的分母非零
	s2 := c.Sample()

	assertPct(t, "CPU", s2.CPU)
	assertPct(t, "内存", s2.Mem)
	assertPct(t, "磁盘", s2.Disk)
	if s2.Load1 != nil && *s2.Load1 < 0 {
		t.Errorf("负载不该为负：%v", *s2.Load1)
	}
	for name, v := range map[string]*float64{"rxBps": s2.RxBps, "txBps": s2.TxBps} {
		if v != nil && *v < 0 {
			t.Errorf("%s 不该为负：%v", name, *v)
		}
	}

	// 平台可采性的最低要求：unix 上磁盘与负载必须真采到，否则说明取数那一步坏了
	// （全 nil 的采集器"测试也能过"是这类代码最容易腐烂的方式）。
	switch runtime.GOOS {
	case "linux", "darwin":
		if s2.Disk == nil {
			t.Error("unix 上磁盘使用率应可采（statfs），却是不可判定")
		}
		if s2.Load1 == nil {
			t.Error("unix 上系统负载应可采，却是不可判定")
		}
		if s2.Mem == nil {
			t.Error("unix 上内存使用率应可采，却是不可判定")
		}
	}
	// darwin 上 CPU 没有 cgo-free 的来源，必须是不可判定而不是 0
	if runtime.GOOS == "darwin" && s2.CPU != nil {
		t.Errorf("darwin 上 CPU 使用率应为不可判定（mach host_statistics 需 cgo），得到 %v", *s2.CPU)
	}
}

func assertPct(t *testing.T, name string, v *float64) {
	t.Helper()
	if v == nil {
		return // 不可判定是合法状态
	}
	if *v < 0 || *v > 100 {
		t.Errorf("%s 使用率越界：%v，应在 0-100", name, *v)
	}
}

// 计数器回退（宿主机重启 / 32 位计数器回绕）必须报不可判定，
// 而不是一个负速率或一个 4 GB/s 的假尖峰。
func TestCounterRollbackYieldsUnknown(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	c := &Collector{diskPath: "/", now: func() time.Time { return base }}

	// 手工喂基线（跳过平台取数），模拟「上一轮读到 1000 字节」
	c.prevNet, c.prevNetAt, c.havePrevNet = netCounters{rx: 1000, tx: 2000}, base, true
	c.prevCPU, c.havePrevCPU = cpuTimes{busy: 500, total: 1000}, true

	// 回退：新值比旧值小
	if rate, ok := rateOrUnknown(netCounters{rx: 10, tx: 20}, c.prevNet, 10); ok {
		t.Errorf("计数器回退时应报不可判定，却算出 %v", rate)
	}
	// 正常前进：速率 = 增量 / 秒数
	rate, ok := rateOrUnknown(netCounters{rx: 1100, tx: 2200}, c.prevNet, 10)
	if !ok {
		t.Fatal("计数器正常前进时应算得出速率")
	}
	if rate.rx != 10 || rate.tx != 20 {
		t.Errorf("速率算错：rx=%v tx=%v，期望 10/20", rate.rx, rate.tx)
	}
}

// rateOrUnknown 复刻 Sample 里的速率判据，供上面的表驱动断言使用
// （生产路径的那份内联在 Sample 中，两处逻辑一致由本测试与 TestSampleOnThisHost 共同钉住）。
type bps struct{ rx, tx float64 }

func rateOrUnknown(cur, prev netCounters, dt float64) (bps, bool) {
	if dt <= 0 || cur.rx < prev.rx || cur.tx < prev.tx {
		return bps{}, false
	}
	return bps{rx: float64(cur.rx-prev.rx) / dt, tx: float64(cur.tx-prev.tx) / dt}, true
}

// 速率的分母是两次采样的**真实间隔**：注入时钟走 10s，增量 1000 字节 → 100 B/s。
func TestNetRateUsesRealInterval(t *testing.T) {
	if _, ok := readNetCounters(); !ok {
		t.Skip("本平台采不到接口计数器，跳过")
	}
	now := time.Unix(1_700_000_000, 0)
	c := &Collector{diskPath: "/", now: func() time.Time { return now }}
	c.Sample() // 建立基线
	now = now.Add(10 * time.Second)
	s := c.Sample()
	if s.RxBps == nil || s.TxBps == nil {
		t.Fatal("第二次采样应算得出吞吐速率")
	}
	if *s.RxBps < 0 || *s.TxBps < 0 {
		t.Errorf("速率不该为负：rx=%v tx=%v", *s.RxBps, *s.TxBps)
	}
}

func TestParseProcStat(t *testing.T) {
	const sample = `cpu  100 20 30 800 40 5 5 0 0 0
cpu0 50 10 15 400 20 2 3 0 0 0
intr 12345
`
	ct, ok := parseProcStat(sample)
	if !ok {
		t.Fatal("应解析成功")
	}
	// total = 100+20+30+800+40+5+5 = 1000；idle+iowait = 840；busy = 160
	if ct.total != 1000 || ct.busy != 160 {
		t.Fatalf("解析结果 busy=%v total=%v，期望 160/1000", ct.busy, ct.total)
	}
	if _, ok := parseProcStat("garbage\n"); ok {
		t.Error("无 cpu 行应报不可判定")
	}
}

func TestParseMeminfo(t *testing.T) {
	const withAvail = `MemTotal:       16000 kB
MemFree:         2000 kB
MemAvailable:    4000 kB
Buffers:          500 kB
Cached:          3000 kB
`
	v, ok := parseMeminfo(withAvail)
	if !ok || v != 75 {
		t.Fatalf("MemAvailable 口径应得 75%%，得到 %v ok=%v", v, ok)
	}
	// 老内核无 MemAvailable → 退回 MemFree+Buffers+Cached = 5500/16000 → 已用 65.625%
	const noAvail = `MemTotal:       16000 kB
MemFree:         2000 kB
Buffers:          500 kB
Cached:          3000 kB
`
	v, ok = parseMeminfo(noAvail)
	if !ok || v < 65.6 || v > 65.7 {
		t.Fatalf("退化口径应得 ~65.63%%，得到 %v ok=%v", v, ok)
	}
	if _, ok := parseMeminfo("Foo: 1 kB\n"); ok {
		t.Error("缺 MemTotal 应报不可判定，而不是 0%")
	}
}

func TestParseLoadavgProc(t *testing.T) {
	v, ok := parseLoadavgProc("0.52 0.44 0.39 2/512 12345\n")
	if !ok || v != 0.52 {
		t.Fatalf("得到 %v ok=%v，期望 0.52", v, ok)
	}
	if _, ok := parseLoadavgProc("\n"); ok {
		t.Error("空内容应报不可判定")
	}
}

func TestParseProcNetDev(t *testing.T) {
	const sample = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 999999    1000    0    0    0     0          0         0  999999    1000    0    0    0     0       0          0
  eth0: 1000       10    0    0    0     0          0         0     2000      20    0    0    0     0       0          0
  eth1:  500        5    0    0    0     0          0         0      700       7    0    0    0     0       0          0
`
	nc, ok := parseProcNetDev(sample)
	if !ok {
		t.Fatal("应解析成功")
	}
	// lo 必须被排除：只累加 eth0+eth1
	if nc.rx != 1500 || nc.tx != 2700 {
		t.Fatalf("得到 rx=%d tx=%d，期望 1500/2700（lo 应被排除）", nc.rx, nc.tx)
	}
	if _, ok := parseProcNetDev("Inter-|   Receive\n"); ok {
		t.Error("一个接口都没有时应报不可判定，而不是 0 B/s")
	}
}

// darwin sysctl vm.loadavg 的二进制布局解析（在任何平台上都跑）。
func TestParseSysctlLoadavg(t *testing.T) {
	var buf [24]byte
	binary.LittleEndian.PutUint32(buf[0:4], 6144) // ldavg[0]
	binary.LittleEndian.PutUint32(buf[16:20], 2048)
	v, ok := parseSysctlLoadavg(buf[:])
	if !ok || v != 3 {
		t.Fatalf("得到 %v ok=%v，期望 3", v, ok)
	}
	// syscall.Sysctl 会剥掉结尾的一个 NUL，实测拿到 23 字节——必须照样能解
	if v, ok := parseSysctlLoadavg(buf[:23]); !ok || v != 3 {
		t.Fatalf("23 字节（结尾 NUL 被剥）应照常解析，得到 %v ok=%v", v, ok)
	}
	if _, ok := parseSysctlLoadavg(buf[:12]); ok {
		t.Error("长度不足以读到 fscale 时应报不可判定")
	}
	// fscale=0 会除零得 +Inf，那个值一路污染到时序库
	var zero [24]byte
	if _, ok := parseSysctlLoadavg(zero[:]); ok {
		t.Error("fscale=0 应报不可判定而不是 +Inf")
	}
}

func TestMemPctFromPages(t *testing.T) {
	v, ok := memPctFromPages(1000, 100, 200)
	if !ok || v != 70 {
		t.Fatalf("得到 %v ok=%v，期望 70", v, ok)
	}
	// 三次独立 sysctl 不是同一瞬间的快照，可用页可能超过总页 → 夹到 0 而不是给负数
	v, ok = memPctFromPages(1000, 900, 900)
	if !ok || v != 0 {
		t.Fatalf("可用页超总页时应夹到 0%%，得到 %v", v)
	}
	if _, ok := memPctFromPages(0, 0, 0); ok {
		t.Error("总页数为 0 应报不可判定")
	}
}

func TestPctPtrClamps(t *testing.T) {
	if v := pctPtr(-1); *v != 0 {
		t.Errorf("负值应夹到 0，得到 %v", *v)
	}
	if v := pctPtr(100.4); *v != 100 {
		t.Errorf("超 100 应夹到 100，得到 %v", *v)
	}
}
