package spa

import (
	"testing"
	"time"
)

// ── wave11 行动 3：放行表的键是 (源 IP, 账号) ──
//
// ★既有用例全是「单账号 + 一个 IP」，而缺陷只在同一源 IP 上有两个账号时显形：
// 原来 `map[源IP]entry` 且 `Allow()` 整条覆盖，于是同出口（企业 NAT / CGNAT /
// 公共 Wi-Fi）下后敲门者会把前一个人的身份、首次接入时刻、业务活跃时刻**全部刷掉**。
// 这一组把每一条被刷掉的东西各钉一遍。

func TestSharedIPKeepsAccountsApart(t *testing.T) {
	al := NewAllowlist()
	al.Allow("203.0.113.7", "alice", "user", time.Minute)
	al.Allow("203.0.113.7", "bob", "admin", time.Minute) // 同出口第二个人

	if !al.AllowedFor("203.0.113.7", "alice") || !al.AllowedFor("203.0.113.7", "bob") {
		t.Fatal("同一源 IP 上的两个账号应各自持窗")
	}
	if !al.Allowed("203.0.113.7") {
		t.Fatal("端口闸应开着")
	}
	// ★ActiveCount 此前数的是**源 IP 数**却被上报成「已授权客户端数」：
	// 同出口 20 个人在线，控制台显示 1。
	if n := al.ActiveCount(); n != 2 {
		t.Fatalf("已授权客户端数应为 2（两个账号），得 %d", n)
	}
	byUser := map[string]Session{}
	for _, s := range al.Sessions() {
		byUser[s.User] = s
	}
	if len(byUser) != 2 || byUser["alice"].Role != "user" || byUser["bob"].Role != "admin" {
		t.Fatalf("两条会话应各带各的角色，得 %+v", byUser)
	}
	// LiveOn 返回全部：逃生舱据此判"是不是恰好一个"，返回"最近那条"会把不可判定藏起来。
	if got := al.LiveOn("203.0.113.7"); len(got) != 2 {
		t.Fatalf("LiveOn 应返回该 IP 上全部有效会话，得 %d 条", len(got))
	}
}

// TestTouchAndSinceArePerAccount 业务活跃时刻与首次接入时刻都不得被同出口的另一个人刷写。
func TestTouchAndSinceArePerAccount(t *testing.T) {
	al := NewAllowlist()
	al.Allow("203.0.113.7", "alice", "user", time.Minute)
	aliceSince := sessionFor(t, al, "alice").Since

	time.Sleep(2 * time.Millisecond)
	al.Allow("203.0.113.7", "bob", "user", time.Minute)
	// ★bob 首次敲门不得继承 alice 的 since：那样控制面看到的"bob 的在线时长"是别人的。
	if bs := sessionFor(t, al, "bob").Since; !bs.After(aliceSince) {
		t.Fatalf("bob 的首次接入时刻应是它自己的（%v），不该继承 alice 的 %v", bs, aliceSince)
	}

	// 只有 alice 有业务流量。
	al.Touch("203.0.113.7", "alice")
	if sessionFor(t, al, "alice").LastActive.IsZero() {
		t.Fatal("alice 打点后应有活跃时刻")
	}
	// ★bob 的活跃时刻必须仍是零值（= 从未有过业务连接，不可判定）。
	// 按 IP 打点的话，A 在用会把 B 的会话一路续命，「无业务流量超时注销」对 B 永不触发。
	if got := sessionFor(t, al, "bob").LastActive; !got.IsZero() {
		t.Fatalf("bob 没有过业务连接，活跃时刻必须是零值，得 %v", got)
	}
}

// TestRevokeUserOnlyRemovesThatAccount 撤销一个账号不得殃及同出口的另一个。
//
// ★这条是**变异逃逸补回来的**：把 RevokeUser 改回「整条 IP 删掉」时，本包用例
// 一条都不红（老用例全是「一个 IP 一个账号」，两种实现在那种数据上逐字等价），
// 只有 proxy 包的端到端用例抓住了它。判据留在这一层才对——RevokeUser 的语义
// 由本包定义，靠上层用例间接守着，下一次有人重构 proxy 就会连守卫一起失去。
func TestRevokeUserOnlyRemovesThatAccount(t *testing.T) {
	al := NewAllowlist()
	al.Allow("203.0.113.7", "alice", "user", time.Minute)
	al.Allow("203.0.113.7", "bob", "user", time.Minute)

	if ips := al.RevokeUser("alice"); len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Fatalf("撤销应报出受影响的源 IP，得 %v", ips)
	}
	if al.AllowedFor("203.0.113.7", "alice") {
		t.Fatal("alice 的窗口应已被撤销")
	}
	if !al.AllowedFor("203.0.113.7", "bob") {
		t.Fatal("★同出口的 bob 被误伤了：强制下线一个人把整条出口上的人全踢了")
	}
	if n := al.ActiveCount(); n != 1 {
		t.Fatalf("撤销后应剩 1 个已授权客户端，得 %d", n)
	}
	// 重复撤销为空——审计里不该出现一件没发生的事。
	if got := al.RevokeUser("alice"); len(got) != 0 {
		t.Fatalf("重复撤销应为空，得 %v", got)
	}
}

// TestReapExpiresPerAccount 过期回收只清过期的那个账号，同 IP 上另一个人不受影响。
func TestReapExpiresPerAccount(t *testing.T) {
	al := NewAllowlist()
	al.Allow("203.0.113.7", "alice", "user", 5*time.Millisecond)
	al.Allow("203.0.113.7", "bob", "user", time.Minute)
	time.Sleep(20 * time.Millisecond)

	ips := al.Reap()
	if len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Fatalf("回收应报出受影响的源 IP，得 %v", ips)
	}
	if al.AllowedFor("203.0.113.7", "alice") {
		t.Fatal("alice 的窗口已过期，应被回收")
	}
	if !al.AllowedFor("203.0.113.7", "bob") {
		t.Fatal("★bob 的窗口没过期，不该被同 IP 的回收误伤")
	}
	// -pf 回收前那道复核（main.go 里的 al.Allowed(ip)）必须仍为真：
	// 少了它，alice 一过期就会把内核放行规则删掉，而 bob 还连着——症状是"用着用着突然全断"。
	if !al.Allowed("203.0.113.7") {
		t.Fatal("该 IP 上还有人在用，端口闸不能关（否则 -pf 会误删内核放行规则）")
	}
}

func sessionFor(t *testing.T, al *Allowlist, user string) Session {
	t.Helper()
	for _, s := range al.Sessions() {
		if s.User == user {
			return s
		}
	}
	t.Fatalf("找不到 %s 的会话", user)
	return Session{}
}
