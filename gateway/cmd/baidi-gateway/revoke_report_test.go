package main

import "testing"

// ── wave8 行动 8 顺带修的：撤销回执每轮重复 ──
//
// 控制面对 disabled/locked 与 posture-blocked 账号是**滚动续期**下发的
// （until = now + kickBanTTL，每轮都是新值，见 api.handleGatewayPolicy）——那是对的，
// 账号一直禁用就该一直拒。但网关侧 applied 按 until 去重，于是每轮都判成「新窗口」，
// 重新执行 + **重新入队一条回执**：一个被禁账号每 15s 产出一条
// 「已撤销…撤销放行 0 个源IP、切断 0 条隧道」的审计 —— 记录的是什么都没发生。
// 一天约 5760 条；50 个离职账号就是每天 28 万条，真正该被看见的放行/拒绝被整段冲走。
//
// 本机实测（改前 62 秒新增 8 条 → 改后 0 条，而本机日志里闸照旧每轮执行 22 次）。

// TestRevokeReportFirstBanThenSilent 首次封禁报一条，之后无事发生就不再报。
func TestRevokeReportFirstBanThenSilent(t *testing.T) {
	s := revokeReportSet{}
	if !s.should("zhao.min", 0) {
		t.Fatal("首次封禁必须报——否则「这个人被封了」这件事在审计里根本不存在")
	}
	for i := 0; i < 10; i++ {
		if s.should("zhao.min", 0) {
			t.Fatalf("第 %d 轮什么都没切断，不该再报", i+2)
		}
	}
}

// TestRevokeReportEffectAlwaysReports 真切断了东西就必须报，不管报过没有。
// 「刚才这个人还有 3 条隧道，现在被切了」是一次真实处置，压掉它就是漏记。
func TestRevokeReportEffectAlwaysReports(t *testing.T) {
	s := revokeReportSet{}
	s.should("zhao.min", 0) // 首次
	for _, effect := range []int{1, 3, 2} {
		if !s.should("zhao.min", effect) {
			t.Fatalf("切断了 %d 条，必须报", effect)
		}
	}
}

// TestRevokeReportReBanReportsAgain 解禁后再被封，要能重新报一次。
//
// ★这是本组最容易漏的一条：少了 retain，一个账号「禁用 → 恢复 → 再禁用」的
// 第二次封禁在审计里完全不存在——而那恰恰是最该留痕的一次（有人把它放出来过）。
func TestRevokeReportReBanReportsAgain(t *testing.T) {
	s := revokeReportSet{}
	s.should("zhao.min", 0)
	s.retain(map[string]bool{"zhao.min": true}) // 仍在名单里
	if s.should("zhao.min", 0) {
		t.Fatal("还在名单里且无事发生，不该重复报")
	}
	s.retain(map[string]bool{}) // 解禁：从名单里消失
	if !s.should("zhao.min", 0) {
		t.Fatal("解禁后再被封必须重新报一次")
	}
}

// TestRevokeReportPerUser 去重按账号，互不影响。
func TestRevokeReportPerUser(t *testing.T) {
	s := revokeReportSet{}
	if !s.should("a", 0) || !s.should("b", 0) {
		t.Fatal("两个账号首次封禁都要报")
	}
	if s.should("a", 0) || s.should("b", 0) {
		t.Fatal("第二轮都不该报")
	}
	s.retain(map[string]bool{"b": true}) // a 解禁，b 还在
	if !s.should("a", 0) {
		t.Fatal("a 解禁后再被封要重新报")
	}
	if s.should("b", 0) {
		t.Fatal("b 一直在名单里，不该重复报")
	}
}
