package main

import (
	"context"
	"strings"
	"testing"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/kernelfwd"
)

func ptrBool(v bool) *bool { return &v }

func fixedProbe(st kernelfwd.State) func() kernelfwd.State {
	return func() kernelfwd.State { return st }
}

// TestForwardReceiptFollowsSiteFamily 钉住「按站点自己的地址族取那一格」。
//
// ★这条用例的存在理由：内核里 v4 与 v6 转发是**两个独立开关**。只读 v4 的实现
// 会给一条 IPv6 站点挂上一个绿色的、方向完全错误的回执——那台机器上 IPv6
// 一个包都过不去，而控制台说「转发已开启」。
//
// 变异验证：把 forSites 里 `if !v4 { on = st.V6 }` 那一支删掉（恒取 V4），
// 本用例的 site-v6 断言立刻变红。
func TestForwardReceiptFollowsSiteFamily(t *testing.T) {
	f := forwardReceipt{
		kernelDP: true,
		probe: fixedProbe(kernelfwd.State{
			Platform: "linux",
			V4:       ptrBool(true),  // v4 开着
			V6:       ptrBool(false), // v6 关着
		}),
	}
	states := []ipsec.SiteState{{SiteID: "site-v4"}, {SiteID: "site-v6"}}
	f.forSites(states, map[string]bool{"site-v4": true, "site-v6": false})

	if states[0].KernelForward != ipsec.KernelForwardOn {
		t.Fatalf("IPv4 站点应报 on，得到 %q", states[0].KernelForward)
	}
	if states[1].KernelForward != ipsec.KernelForwardOff {
		t.Fatalf("IPv6 站点应报 off（v6 开关是独立的），得到 %q", states[1].KernelForward)
	}
	if !strings.Contains(states[1].KernelForwardDetail, "IPv6") {
		t.Fatalf("回执必须点名是哪个地址族，否则运维会去看错的那个开关：%q", states[1].KernelForwardDetail)
	}
}

// TestForwardReceiptUnknownIsNotOff 探不到必须报 unknown。
//
// ★塌成 off 是虚警（运维去开一个本来就开着的开关），塌成 on 是替一台可能
// 什么都不通的机器背书。两种错法在页面上都看不出来，所以必须有第三种取值。
func TestForwardReceiptUnknownIsNotOff(t *testing.T) {
	f := forwardReceipt{
		kernelDP: true,
		probe: fixedProbe(kernelfwd.State{
			Platform: "windows",
			Detail:   "本平台（windows）没有可读的内核转发开关，转发状态不可判定",
		}),
	}
	states := []ipsec.SiteState{{SiteID: "s1"}}
	f.forSites(states, map[string]bool{"s1": true})

	if states[0].KernelForward != ipsec.KernelForwardUnknown {
		t.Fatalf("探不到必须报 unknown，得到 %q（塌成 off 是虚警、塌成 on 是背书）", states[0].KernelForward)
	}
	if !strings.Contains(states[0].KernelForwardDetail, "不可判定") {
		t.Fatalf("不可判定必须带上探测方给的原因，得到 %q", states[0].KernelForwardDetail)
	}
}

// TestForwardReceiptNetstackIsNotApplicable netstack 自检数据面报 n/a，不是 off。
//
// ★报 off 的后果：`ipsec-e2e.sh` 每跑一次就在控制台上挂两条假告警。
// 假告警多了这一格就没人看了，而它真正要抓的是生产上那条「显示已建立、实际不通」。
func TestForwardReceiptNetstackIsNotApplicable(t *testing.T) {
	probed := false
	f := forwardReceipt{
		kernelDP: false,
		probe: func() kernelfwd.State {
			probed = true
			return kernelfwd.State{V4: ptrBool(false)}
		},
	}
	states := []ipsec.SiteState{{SiteID: "s1"}}
	f.forSites(states, map[string]bool{"s1": true})

	if states[0].KernelForward != ipsec.KernelForwardNA {
		t.Fatalf("netstack 数据面应报 n/a，得到 %q", states[0].KernelForward)
	}
	if probed {
		t.Fatal("数据面不经内核时不该去读内核开关——读了也只是白白给出一个不相干的结论")
	}
}

// TestForwardReceiptUnknownFamilyIsNotGuessed 不知道地址族时不猜。
//
// 场景：状态机里还有一条已从控制面移除、拆除未完成的残留站点，本层没有它的网段。
// 此时按 v4 猜有一半概率给出方向相反的结论，故必须报不可判定。
func TestForwardReceiptUnknownFamilyIsNotGuessed(t *testing.T) {
	f := forwardReceipt{
		kernelDP: true,
		probe:    fixedProbe(kernelfwd.State{V4: ptrBool(true), V6: ptrBool(true)}),
	}
	states := []ipsec.SiteState{{SiteID: "leftover"}}
	f.forSites(states, map[string]bool{}) // 键缺席

	if states[0].KernelForward != ipsec.KernelForwardUnknown {
		t.Fatalf("地址族未知时不许拿 v4 顶包，得到 %q", states[0].KernelForward)
	}
}

// TestReportCarriesForwardReceipt 端到端：回执必须真的进到发给控制面的那份状态里。
//
// ★只测 forSites 是不够的——它是个纯函数，接不进 report() 的话照样全绿，
// 而现场是「网关升级了、控制台那一格永远显示未上报」。
func TestReportCarriesForwardReceipt(t *testing.T) {
	cp := newFakeControl()
	back := &fakeBackend{states: []ipsec.SiteState{{SiteID: "s1", State: ipsec.StateUp}}}
	s := testSyncer(cp, back)
	s.fwd.probe = fixedProbe(kernelfwd.State{Platform: "linux", V4: ptrBool(false), V6: ptrBool(false)})
	s.siteV4 = map[string]bool{"s1": true}

	s.report(context.Background())

	if len(cp.reported) == 0 {
		t.Fatal("没有任何回报")
	}
	got := cp.reported[len(cp.reported)-1]
	if got[0].KernelForward != ipsec.KernelForwardOff {
		t.Fatalf("回报里的内核转发回执应为 off，得到 %q——回执没接进 report() 就等于没做",
			got[0].KernelForward)
	}
	// 回执绝不能篡改五态：转发关着的隧道确实建起来了。
	if got[0].State != ipsec.StateUp {
		t.Fatalf("内核转发回执改写了站点状态（%q）：它是回执不是判定", got[0].State)
	}
}

// TestShutdownReportMarksForwardUnknown 停机那一轮不留空。
//
// 空串在控制面上的语义是「旧版本网关，从没报过」，会把一次正常停机
// 说成一台该升级的网关——两者的下一步动作完全不同。
func TestShutdownReportMarksForwardUnknown(t *testing.T) {
	cp := newFakeControl()
	back := &fakeBackend{states: []ipsec.SiteState{
		{SiteID: "s1", State: ipsec.StateUp, KernelForward: ipsec.KernelForwardOn},
	}}
	s := testSyncer(cp, back)

	s.shutdownReport(context.Background(), "收到停止信号")

	got := cp.reported[len(cp.reported)-1]
	if got[0].KernelForward != ipsec.KernelForwardUnknown {
		t.Fatalf("停机回报的转发回执应为 unknown，得到 %q", got[0].KernelForward)
	}
	if got[0].KernelForwardDetail == "" {
		t.Fatal("停机那轮的不可判定同样要说明原因")
	}
}
