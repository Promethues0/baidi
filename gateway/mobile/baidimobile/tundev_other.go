//go:build !android

package baidimobile

import (
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// newTunDevice 非安卓侧（iOS/darwin，以及本机跑单测的 linux/macOS）把平台给的 fd
// 变成 tun.Device，走 wireguard 的常规入口。
//
// iOS 这一侧刻意**不**跟着安卓改用 Unmonitored：NEPacketTunnelProvider 没有安卓那条
// SELinux 限制，darwin 的实现本就与 linux 不同路（utun + AF_ROUTE），
// 换一条没在 iOS 上跑过的路径只会让一个从未验证过的平台再多一个变量。
// 两侧的差异收敛在这两个 build tag 文件里，别改回运行时 if 判断——
// 那样另一平台的分支在本平台连编译都验不到，正是本项目在采集器上吃过亏的形态。
func newTunDevice(fd int, mtu int) (tun.Device, error) {
	file := os.NewFile(uintptr(fd), "baidi-tun")
	return tun.CreateTUNFromFile(file, mtu)
}
