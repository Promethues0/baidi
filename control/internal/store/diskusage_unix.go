//go:build !windows

package store

import "syscall"

// fsUsage 实测 path 所在文件系统的总容量与可用余量（字节）。
// darwin 的 Bsize 是 uint32、linux 是 int64，统一经 uint64 折算后两个平台都能编译。
func fsUsage(path string) (total, free uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	return uint64(st.Bsize) * st.Blocks, uint64(st.Bsize) * st.Bavail, true
}
