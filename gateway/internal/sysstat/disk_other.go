//go:build !unix

package sysstat

// 非 unix（windows）：磁盘水位不可判定。取它要走 GetDiskFreeSpaceEx，
// 而 syscall 里没有现成封装，为一个观测指标手搓 LazyDLL 不划算——如实报「—」。
func readDiskUsedPct(string) (float64, bool) { return 0, false }
