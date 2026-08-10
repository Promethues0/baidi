//go:build !linux && !darwin

package sysstat

// 未适配平台（windows / *bsd …）：四项一律不可判定。
//
// ★这里返回 false 而不是 0，是本包最要紧的一处：Windows 版网关如果报回一串 0，
// 控制台上会画出一条漂亮的、完全虚构的平线，而「CPU 恒 0%」既不会触发任何告警，
// 也不会让任何人起疑。缺数据就显示缺数据。

func readCPUTimes() (cpuTimes, bool)       { return cpuTimes{}, false }
func readMemUsedPct() (float64, bool)      { return 0, false }
func readLoad1() (float64, bool)           { return 0, false }
func readNetCounters() (netCounters, bool) { return netCounters{}, false }
