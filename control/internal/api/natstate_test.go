package api

import (
	"net/http"
	"strings"
	"testing"
)

// ── 地址转换回执（wave8 行动 3）──
//
// 守的是同一件事：**页面上那一栏说的，就是网关内核里此刻的实况**。
// 改造前 `enabled` 一个开关同时表达「管理员想让它开」与「它真的开着」，
// 于是两种失效与正常完全同形，而网关侧一行日志都不打：
//   ① 网关没带 -nat 启动（deploy 生成的 env 根本不含这一项）；
//   ② 有内核后端但规则灌入失败。
// 同一形态 IPSec 已经修过一遍（拆 ipsec_sa_state），NAT 这边原样重犯。

// natHeartbeat 一份带 nat 字段的网关心跳。nat 为 nil 时整个字段缺席（旧网关形态）。
func natHeartbeat(gwID string, nat map[string]any) map[string]any {
	hb := map[string]any{
		"id": gwID, "proxy": "127.0.0.1:18443", "spa": "127.0.0.1:18201",
		"clients": 0, "tunnels": 0, "uptime": 10, "version": "v0.5.0",
	}
	if nat != nil {
		hb["nat"] = nat
	}
	return hb
}

// natPolicyOn 落一条启用中的 SNAT 策略到指定网关（经真实端点，顺带过一遍入口校验）。
func natPolicyOn(t *testing.T, h http.Handler, gwID string) {
	t.Helper()
	// 先让网关把网卡报上来——NAT 策略的接口必须是实测枚举过的（ErrNATIfaceUnknown）。
	hb := natHeartbeat(gwID, nil)
	hb["ifaces"] = []map[string]any{
		{"name": "eth0", "up": true, "addrs": []string{"10.0.0.1/24"}},
		{"name": "eth1", "up": true, "addrs": []string{"203.0.113.9/24"}},
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), hb); code != http.StatusOK {
		t.Fatalf("网关心跳 http %d: %v", code, out)
	}
	for _, f := range []struct{ name, typ string }{{"eth0", "lan"}, {"eth1", "wan"}} {
		if code, out := doJSON(t, h, "PUT", "/api/v1/nat/ifaces/"+gwID+"/"+f.name, adminToken(),
			map[string]any{"type": f.typ}); code != http.StatusOK {
			t.Fatalf("定性网卡 %s http %d: %v", f.name, code, out)
		}
	}
	code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), map[string]any{
		"name": "内网代理上网", "type": "snat", "gatewayId": gwID,
		"srcIface": "eth0", "srcAddr": "10.0.0.0/24",
		"dstIface": "eth1", "dstAddr": "203.0.113.0/24",
		"protocol": "all", "enabled": true,
	})
	if code != http.StatusOK {
		t.Fatalf("保存 NAT 策略 http %d: %v", code, out)
	}
}

// natReceipt 读回页面看到的那份回执。
func natReceipt(t *testing.T, h http.Handler, gwID string) map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /nat http %d: %v", code, out)
	}
	rc, _ := out["receipts"].(map[string]any)
	r, _ := rc[gwID].(map[string]any)
	if r == nil {
		t.Fatalf("回执里没有网关 %s：%v", gwID, out["receipts"])
	}
	return r
}

func natWarnings(t *testing.T, h http.Handler) []string {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /nat http %d", code)
	}
	return strSlice(out["warnings"])
}

// ★核心用例①：网关**没带 -nat 启动**——最常见的那种失效。
// 改造前控制台上这条策略是绿的、网关侧一行日志都不打。
func TestNATReceipt_网关未开启NAT必须当面说(t *testing.T) {
	h := newTestServer(t)
	natPolicyOn(t, h, "gw-1")
	// 新网关如实上报「我没开」
	if code, out := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", map[string]any{"enabled": false, "backend": "未启用（本网关未带 -nat 启动）"})); code != http.StatusOK {
		t.Fatalf("心跳 http %d: %v", code, out)
	}
	r := natReceipt(t, h, "gw-1")
	if asStr(r["status"]) != NATRcptDisabled {
		t.Fatalf("应判 disabled，实得 %v（%v）", r["status"], r["say"])
	}
	if !strings.Contains(asStr(r["say"]), "-nat") {
		t.Fatalf("结论必须点名 -nat（管理员要知道去哪开），实得 %q", r["say"])
	}
	// 页面顶部还要有一条告警：光在表格里标红，管理员可能整屏都不会往右看
	ws := strings.Join(natWarnings(t, h), " | ")
	if !strings.Contains(ws, "gw-1") {
		t.Fatalf("顶部告警应点名该网关，实得 %q", ws)
	}
}

// ★核心用例②：规则灌入内核失败。
func TestNATReceipt_灌入失败必须当面说(t *testing.T) {
	h := newTestServer(t)
	natPolicyOn(t, h, "gw-1")
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", map[string]any{
			"enabled": true, "backend": "nftables(Linux)", "applied": 0,
			"lastError": "nft: Error: syntax error, unexpected string",
		})); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	r := natReceipt(t, h, "gw-1")
	if asStr(r["status"]) != NATRcptFailed {
		t.Fatalf("应判 failed，实得 %v", r["status"])
	}
	if !strings.Contains(asStr(r["say"]), "syntax error") {
		t.Fatalf("必须把内核报的原文带出来（否则管理员无从下手），实得 %q", r["say"])
	}
}

// ★核心用例③：规则灌进去了，但内核 IP 转发关着。
// 这种情况下规则**全部正确**，一个包也过不去，而且没有任何报错——
// 只看「已灌入内核」四个字会让人以为没问题。
func TestNATReceipt_转发关闭不能被已灌入盖住(t *testing.T) {
	h := newTestServer(t)
	natPolicyOn(t, h, "gw-1")
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", map[string]any{
			"enabled": true, "backend": "nftables(Linux)", "applied": 1,
			"forwarding": false,
		})); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	r := natReceipt(t, h, "gw-1")
	if asStr(r["status"]) != NATRcptApplied {
		t.Fatalf("规则确实灌进去了，状态应为 applied，实得 %v", r["status"])
	}
	if !strings.Contains(asStr(r["say"]), "转发") {
		t.Fatalf("必须把「转发关着」说出来，否则「已灌入内核」会盖住它：%q", r["say"])
	}
	ws := strings.Join(natWarnings(t, h), " | ")
	if !strings.Contains(ws, "转发") {
		t.Fatalf("顶部告警也要有（规则对但一个包不通），实得 %q", ws)
	}
}

// ★核心用例④：**旧网关（不上报 nat 字段）与「新网关说没开」必须分得开**。
// 这是本次改造最要紧的一条区分：前者是「我们不知道」，后者是「我们知道它没开」，
// 而只在开了 NAT 时才上报的话，两者在控制面看来完全一样。
func TestNATReceipt_旧网关未上报与明确说没开必须分得开(t *testing.T) {
	h := newTestServer(t)
	natPolicyOn(t, h, "gw-1")
	// 旧网关：心跳里根本没有 nat 字段
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", nil)); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	r := natReceipt(t, h, "gw-1")
	if asStr(r["status"]) != NATRcptUnreported {
		t.Fatalf("旧网关应判 unreported，实得 %v（%v）", r["status"], r["say"])
	}
	if strings.Contains(asStr(r["say"]), "未带 -nat 启动") {
		t.Fatalf("不能把「没上报」说成「没开」——控制面并不知道它开没开：%q", r["say"])
	}
	// 换成新网关明确说「我没开」，结论必须变
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", map[string]any{"enabled": false})); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	if got := asStr(natReceipt(t, h, "gw-1")["status"]); got != NATRcptDisabled {
		t.Fatalf("明确说没开应判 disabled，实得 %v", got)
	}
}

// 旧网关的心跳**不得覆盖**同 id 新网关刚报过的运行态：
// 它对 NAT 什么都没说，把它读成「清空」会把已知状态抹成未知。
// 与 reach / ifaces 同一条三态纪律。
func TestNATReceipt_旧网关心跳不覆盖已有运行态(t *testing.T) {
	h := newTestServer(t)
	natPolicyOn(t, h, "gw-1")
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", map[string]any{"enabled": true, "backend": "nftables(Linux)", "applied": 3})); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	if got := asStr(natReceipt(t, h, "gw-1")["status"]); got != NATRcptApplied {
		t.Fatalf("前置失败：应为 applied，实得 %v", got)
	}
	// 再来一次缺 nat 字段的心跳
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", nil)); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	if got := asStr(natReceipt(t, h, "gw-1")["status"]); got != NATRcptApplied {
		t.Fatalf("缺字段的心跳不该抹掉已知运行态，实得 %v", got)
	}
}

// 命中计数三态：网关报不出计数时页面必须显示「不可判定」而不是 0。
// 「规则没灌进去」与「灌进去了但没流量命中」排障方向完全相反。
func TestNATHits_读不到计数不能显示成零(t *testing.T) {
	h := newTestServer(t)
	natPolicyOn(t, h, "gw-1")
	// 不带 hits 字段（pf 拆不到规则粒度 / nft -j 失败）
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", map[string]any{"enabled": true, "backend": "pf(macOS)", "applied": 1})); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	code, out := doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /nat http %d", code)
	}
	if out["hitsKnown"] == true {
		t.Fatal("没有任何网关报得出计数时 hitsKnown 必须为 false，否则页面会把不可判定画成 0 包")
	}
	// 带上 hits 之后要能读到
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", map[string]any{
			"enabled": true, "backend": "nftables(Linux)", "applied": 1,
			"hits": []map[string]any{{"policyId": "p-x", "packets": 42, "bytes": 4096}},
		})); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	_, out = doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	if out["hitsKnown"] != true {
		t.Fatalf("网关报了计数就该 hitsKnown=true，实得 %v", out["hitsKnown"])
	}
	hits, _ := out["hits"].(map[string]any)
	hx, _ := hits["p-x"].(map[string]any)
	if hx == nil || hx["packets"] != float64(42) {
		t.Fatalf("计数没透传：%v", out["hits"])
	}
}

// 停用中的策略不产生「配了却不生效」的告警——管理员本来就没指望它生效。
func TestNATReceipt_停用策略不报未生效告警(t *testing.T) {
	h := newTestServer(t)
	natPolicyOn(t, h, "gw-1")
	// 把策略停掉
	code, out := doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /nat http %d", code)
	}
	ps, _ := out["policies"].([]any)
	if len(ps) == 0 {
		t.Fatal("前置失败：没有策略")
	}
	p, _ := ps[0].(map[string]any)
	p["enabled"] = false
	if code, o := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), p); code != http.StatusOK {
		t.Fatalf("停用策略 http %d: %v", code, o)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		natHeartbeat("gw-1", map[string]any{"enabled": false})); code != http.StatusOK {
		t.Fatal("心跳失败")
	}
	for _, w := range natWarnings(t, h) {
		if strings.Contains(w, "未带 -nat 启动") {
			t.Fatalf("策略已停用，不该报「网关没开 NAT」：%q", w)
		}
	}
}
