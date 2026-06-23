//go:build windows

package gmcert

// Windows 上网关/gmca 不部署（数据面 baidi-tun 仅调 LoadCAPool 不调 EnsureGateway），
// 故此处文件锁为 no-op，仅保证跨平台编译通过。
func lockDir(dir string) (func(), error) {
	return func() {}, nil
}
