//go:build android

package baidimobile

import (
	"golang.zx2c4.com/wireguard/tun"
)

// newTunDevice 安卓侧把 VpnService 给的 fd 变成 tun.Device。
//
// ★这里**必须**用 CreateUnmonitoredTUNFromFD，不能用 CreateTUNFromFile。
// 后者内部顺序是 Name → initFromFlags → getIFIndex → createNetlinkSocket → setMTU，
// 而 Android 10 起禁止 untrusted_app 绑 netlink 路由套接字，于是它在 netlink 那步就返回，
// 连 setMTU 都到不了。2026-09-03 在 OPPO PKU110 / Android 16 真机上确认过，
// UI 报「数据面引擎启动失败：permission denied」，内核 SELinux 审计原文是：
//
//	avc: denied { bind } for scontext=u:r:untrusted_app:s0
//	     tclass=netlink_route_socket permissive=0 bug=b/155595000 app=dev.baidi.mobile
//
// 这是 AOSP 既定策略而非厂商定制，任何 10+ 设备同此，所以这不是「换台机器试试」的问题。
// wireguard-android 官方走的也是 Unmonitored 这条。
//
// 代价：拿不到链路事件（Events 通道不会有 MTU/上下线变化），也不由它设 MTU。
// 两者在本项目都没有消费方——dataplane 只用 Read/Write/Close/BatchSize；
// MTU 由 Kotlin 侧 VpnService.Builder.setMtu 定，netstack 那份走 dataplane.Config.MTU。
// 若将来有人要读 dev.Events()，先回来看这条注释：安卓上它恒为空。
//
// fd 所有权：Kotlin 侧调的是 pfd.detachFd()，所以 fd 已经交给 Go。成功时由返回的
// Device 持有（它内部自建 os.File）；失败时那个 os.File 会被 GC 的 finalizer 关掉，
// 这里**刻意不**再显式 close 一次——重复关闭一个可能已被复用的 fd 号比泄漏更危险。
func newTunDevice(fd int, mtu int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		return nil, err
	}
	return dev, nil
}
