package baidimobile

import (
	"os"
	"strings"
	"testing"
)

// TestAndroidTunEntryAvoidsNetlink 钉住「安卓侧不得用 CreateTUNFromFile」。
//
// ★为什么用源码文本断言而不是跑一次真的建卡：本机（macOS/Linux）跑不出安卓的 SELinux
// 策略，`//go:build android` 那份在这里连编译都不参与，任何运行期用例都覆盖不到它。
// 而这条约束一旦被改回去，症状是**安卓端数据面 100% 起不来**（UI 只报一句
// permission denied），却要等到有人把包装进真机才发现——2026-09-03 之前它就这么躺了很久。
// 同款做法见 console/scripts/check-dead-ui.mjs 与 elevate.rs 里的源码文本守卫。
func TestAndroidTunEntryAvoidsNetlink(t *testing.T) {
	const f = "tundev_android.go"
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("读不到 %s：%v（安卓建卡入口必须单独成文件，不能并回 baidimobile.go）", f, err)
	}
	src := string(b)

	if !strings.HasPrefix(src, "//go:build android\n") {
		t.Errorf("%s 必须以 //go:build android 开头，否则它会在别的平台也参与编译", f)
	}
	if !strings.Contains(src, "CreateUnmonitoredTUNFromFD") {
		t.Errorf("%s 必须用 tun.CreateUnmonitoredTUNFromFD：\n"+
			"  它不建 netlink 套接字，而 Android 10 起禁止 untrusted_app 绑 netlink_route_socket\n"+
			"  （AOSP 既定策略，非厂商定制；2026-09-03 在 Android 16 真机上有内核审计原文为证）", f)
	}
	if strings.Contains(src, "CreateTUNFromFile") && !strings.Contains(src, "不能用 CreateTUNFromFile") {
		t.Errorf("%s 出现了 CreateTUNFromFile：它内部 createNetlinkSocket 排在 setMTU 之前，\n"+
			"  在安卓上必然被 SELinux 拒在那一步，整条数据面起不来（报 permission denied）", f)
	}

	// 非安卓那一侧必须仍走常规入口：iOS 没有这条限制，且 darwin 实现本就不同路，
	// 把它一起改成 Unmonitored 等于给一个从未实机验证过的平台再加一个变量。
	o, err := os.ReadFile("tundev_other.go")
	if err != nil {
		t.Fatalf("读不到 tundev_other.go：%v", err)
	}
	if !strings.Contains(string(o), "CreateTUNFromFile") {
		t.Error("tundev_other.go 应保持 CreateTUNFromFile（iOS/darwin 无 netlink 限制）")
	}

	// 调用点只能有一个，且必须是分平台的 newTunDevice——否则分文件就白分了。
	m, err := os.ReadFile("baidimobile.go")
	if err != nil {
		t.Fatalf("读不到 baidimobile.go：%v", err)
	}
	if strings.Contains(string(m), "tun.CreateTUNFromFile") || strings.Contains(string(m), "tun.CreateUnmonitoredTUNFromFD") {
		t.Error("baidimobile.go 不应直接调建卡函数：建卡入口按平台收在 tundev_*.go 的 newTunDevice 里")
	}
	if !strings.Contains(string(m), "newTunDevice(") {
		t.Error("baidimobile.go 应经 newTunDevice 建卡")
	}
}
