package api

import (
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── 内核 IP 转发回执（wave11 行动 10-①）──
//
// 网关只报事实，控制面折算成人话。这一组用例守的是「不可判定不许塌成好值」
// 与「网关没报 ≠ 报了但探不到」两条。

// TestNormalizeIpsecForwardNeverInventsGood 认不出的值一律折成 unknown。
//
// ★这是 normalizeIpsecState「未知一律折成 failed」的同款纪律：把不认识的值折成
// 好值，等于让一个字段拼写错误变成一句「一切正常」。
//
// 变异验证：把 default 分支改成 return store.IpsecForwardOn，本用例立刻变红。
func TestNormalizeIpsecForwardNeverInventsGood(t *testing.T) {
	for in, want := range map[string]string{
		"on":      store.IpsecForwardOn,
		"off":     store.IpsecForwardOff,
		"unknown": store.IpsecForwardUnknown,
		// 数据面那侧的常量是 "n/a"，落库与下发统一成 "n-a"（斜杠要进 CSS class 与查询串）。
		"n/a": store.IpsecForwardNA,
		"n-a": store.IpsecForwardNA,
		// ★空串原样保留：这一列存的必须是「网关说了什么」。折成 unreported 写进库的话，
		// 下一次读时 normalize 认不出 "unreported"、折成 unknown——
		// 「没报过」就此静默变成「探不到」。空串→unreported 只在读侧折算一次。
		"": "",
		// 反过来也钉住：控制面自己那个值不该被当成网关能报的取值。
		"unreported": store.IpsecForwardUnknown,
		// 以下每一条都必须折成 unknown，不许折成 on。
		"ON":      store.IpsecForwardUnknown,
		"true":    store.IpsecForwardUnknown,
		"enabled": store.IpsecForwardUnknown,
		"1":       store.IpsecForwardUnknown,
	} {
		if got := normalizeIpsecForward(in); got != want {
			t.Fatalf("normalizeIpsecForward(%q)=%q，期望 %q", in, got, want)
		}
	}
}

// TestForwardReceiptSeparatesUnreportedFromUnknown 「没报过」与「探不到」必须分开。
//
// 前者要去升级网关，后者要去机器上看一眼——下一步动作不同，合成一个「未知」
// 就等于把那句话删掉。
func TestForwardReceiptSeparatesUnreportedFromUnknown(t *testing.T) {
	old := ipsecForwardReceipt(&store.IpsecSAState{SiteID: "s", GatewayID: "ipsec-1"})
	if old == nil || old.Status != ipsecFwdUnreported {
		t.Fatalf("字段缺席应折成 unreported，得到 %+v", old)
	}
	if !strings.Contains(old.Impact, "升级") {
		t.Fatalf("unreported 的下一步动作是升级网关，文案里必须有：%q", old.Impact)
	}

	unk := ipsecForwardReceipt(&store.IpsecSAState{
		SiteID: "s", GatewayID: "ipsec-1", KernelForward: store.IpsecForwardUnknown,
		KernelForwardDetail: "读 /proc/sys/net/ipv4/ip_forward 失败：permission denied",
	})
	if unk.Status != store.IpsecForwardUnknown {
		t.Fatalf("unknown 应原样保留，得到 %q", unk.Status)
	}
	if !strings.Contains(unk.Impact, "不可判定不等于没问题") {
		t.Fatalf("不可判定必须明说「不等于没问题」，否则会被读成绿灯：%q", unk.Impact)
	}
	if !strings.Contains(unk.Detail, "permission denied") {
		t.Fatal("网关给的探测说明必须原样带到前端，那是唯一能指路的信息")
	}
}

// TestForwardReceiptOffExplainsTheSilentFailure off 的影响说明必须点出那条静默失效。
//
// 光说「转发关着」是不够的：管理员看到隧道显示「已建立」，会先怀疑这条提示。
// 必须把「计数恒为 0、连丢弃计数都不动」说出来，那正是他此刻在页面上看到的现象。
func TestForwardReceiptOffExplainsTheSilentFailure(t *testing.T) {
	r := ipsecForwardReceipt(
		&store.IpsecSAState{SiteID: "s", GatewayID: "ipsec-7", KernelForward: store.IpsecForwardOff},
	)
	if r.Status != store.IpsecForwardOff {
		t.Fatalf("状态应为 off，得到 %q", r.Status)
	}
	for _, want := range []string{"ipsec-7", "计数恒为 0", "不替你改"} {
		if !strings.Contains(r.Summary+r.Impact, want) {
			t.Fatalf("影响说明缺少 %q：%s", want, r.Impact)
		}
	}
}

// TestForwardReceiptNilWhenNeverReported 从未被回报过的站点不画这一格。
//
// 站点行上已经有「未回报 / 无网关承载」这个更强的提示，
// 再挂一句「转发状态未知」只会让人以为是两个问题。
func TestForwardReceiptNilWhenNeverReported(t *testing.T) {
	if r := ipsecForwardReceipt(nil); r != nil {
		t.Fatalf("没有任何回报时不该造回执，得到 %+v", r)
	}
}

// TestGatewayReportsForwardEndToEnd 端到端：网关报 → 落库 → 清单里出现回执。
//
// ★这条用例覆盖的是「补了列却没接线」这一类：三处（DTO 字段 / 入站归一 / SQL 列）
// 任何一处漏掉，单元测试都还是绿的，而控制台上那一格永远显示「网关未上报」。
func TestGatewayReportsForwardEndToEnd(t *testing.T) {
	f := newIpsecFixture(t)

	// 网关经 mTLS 回报：站点 up，但内核转发关着。
	body := `{"states":[{"siteId":"site-sh","state":"up",` +
		`"kernelForward":"off","kernelForwardDetail":"实测本机 IPv4 转发处于关闭状态"}]}`
	if code, resp := f.callMTLS(t, http.MethodPost, "/api/v1/gateways/ipsec/status", "ipsec-1", body); code != http.StatusOK {
		t.Fatalf("回报失败：%d %v", code, resp)
	}

	code, resp := f.callAdmin(t, http.MethodGet, "/api/v1/ipsec", "", adminToken())
	if code != http.StatusOK {
		t.Fatalf("读清单失败：%d", code)
	}
	var fwd map[string]any
	var state string
	for _, raw := range resp["sites"].([]any) {
		m := raw.(map[string]any)
		if m["id"] != "site-sh" {
			continue
		}
		fwd, _ = m["forward"].(map[string]any)
		if sa, ok := m["sa"].(map[string]any); ok {
			state, _ = sa["state"].(string)
		}
	}
	if fwd == nil {
		t.Fatal("清单里没有 forward 回执——补了列没接线，控制台那一格会永远显示「网关未上报」")
	}
	if fwd["status"] != store.IpsecForwardOff {
		t.Fatalf("回执状态应为 off，得到 %v", fwd["status"])
	}
	if fwd["detail"] != "实测本机 IPv4 转发处于关闭状态" {
		t.Fatalf("网关的探测说明没被原样带出来：%v", fwd["detail"])
	}
	// ★回执绝不改写五态：转发关着的隧道确实建起来了，只是没有流量能走上去。
	if state != "up" {
		t.Fatalf("站点状态被回执改写成了 %q——它是回执不是判定", state)
	}
}

// TestGatewayForwardValueIsNormalizedBeforeStore 入站就归一，库里不留 "n/a"。
//
// 斜杠会进 CSS class 与查询串；归一散在读侧的话，「库里存什么」会随读路径而变。
func TestGatewayForwardValueIsNormalizedBeforeStore(t *testing.T) {
	f := newIpsecFixture(t)
	body := `{"states":[{"siteId":"site-sh","state":"up","kernelForward":"n/a"}]}`
	if code, _ := f.callMTLS(t, http.MethodPost, "/api/v1/gateways/ipsec/status", "ipsec-1", body); code != http.StatusOK {
		t.Fatalf("回报失败：%d", code)
	}
	states, err := f.st.IpsecSAStates(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].KernelForward != store.IpsecForwardNA {
		t.Fatalf("库里应存归一后的 %q，得到 %+v", store.IpsecForwardNA, states)
	}
}

// TestOldGatewayReportLeavesForwardUnreported 旧网关不带这两个字段时的兼容。
//
// 与设备指标那条「旧网关不带 metrics → 不落点、单列成未上报」同一条纪律：
// 缺席必须能与「报了个空值」区分开，且缺席不许被读成任何一种确定结论。
func TestOldGatewayReportLeavesForwardUnreported(t *testing.T) {
	f := newIpsecFixture(t)
	body := `{"states":[{"siteId":"site-sh","state":"up"}]}` // 旧网关：没有 kernelForward
	if code, _ := f.callMTLS(t, http.MethodPost, "/api/v1/gateways/ipsec/status", "ipsec-1", body); code != http.StatusOK {
		t.Fatalf("回报失败：%d", code)
	}
	states, err := f.st.IpsecSAStates(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].KernelForward != "" {
		t.Fatalf("旧网关的回报里这一列应为空串（=未上报），得到 %q", states[0].KernelForward)
	}
	r := ipsecForwardReceipt(&states[0])
	if r.Status != ipsecFwdUnreported {
		t.Fatalf("空串应折成 unreported，得到 %q", r.Status)
	}
}
