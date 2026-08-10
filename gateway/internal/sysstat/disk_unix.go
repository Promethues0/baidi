//go:build unix

package sysstat

import "syscall"

// readDiskUsedPct 实测挂载点所在文件系统的使用率（0-100）。
//
// 口径与 df 一致：已用 = Blocks-Bfree，容量 = 已用 + 可用(Bavail)。
// 不用 (Blocks-Bavail)/Blocks 是因为那会把 root 预留块算成「已用」，
// 与运维在机器上 df 看到的数字对不上——对不上的监控数字没人会信第二次。
//
// Bsize 在 darwin 是 uint32、在 linux 是 int64，统一折成 uint64 后两平台都能编译
// （与 control/internal/store/diskusage_unix.go 同一处理）。
func readDiskUsedPct(path string) (float64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	used := st.Blocks - st.Bfree
	capacity := used + st.Bavail
	if capacity == 0 {
		return 0, false
	}
	return float64(used) / float64(capacity) * 100, true
}
