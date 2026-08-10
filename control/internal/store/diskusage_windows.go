//go:build windows

package store

// fsUsage Windows 兜底：控制面部署面不含 Windows，不做容量探测，
// 如实返回"不支持"让上层示弱，而不是编一个占用率出来。
func fsUsage(string) (total, free uint64, ok bool) {
	return 0, 0, false
}
