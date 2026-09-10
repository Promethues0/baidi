package webproxy

// 七层 Web 会话台账的用例（wave11 行动 14 ②③）。
//
// ★这些断言在改造前**结构上不可能存在**：会话完全在 Cookie 里，网关既数不出
// 有几条 B/S 会话，也没有单独终止其中一条的手段。四条各自钉一个曾经真实存在的洞。

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"baidi.dev/gateway/internal/resource"
)

// ① 会话必须进台账并随心跳可上报——「在线用户」页里 B/S 那一半的来源。
//
// 变异实测：把 handleEnter 里的 s.sessions.start(...) 注释掉 → 本条与 ②③ 同时红
// （Sessions() 空；且逐请求复核查不到台账，正常访问被 401）。
func TestWebSessionEnteredIntoLedger(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	ss := h.ws.Sessions()
	if len(ss) != 1 {
		t.Fatalf("★换票成功必须在台账里留一条会话（否则「在线用户」页数不到 B/S 接入），得 %d 条", len(ss))
	}
	if ss[0].User != "zhangsan" || ss[0].Res != "oa" {
		t.Fatalf("台账内容不对：%+v", ss[0])
	}
	if ss[0].Since == 0 || ss[0].LastActive == 0 || ss[0].Exp == 0 {
		t.Fatalf("★三个时刻都必须有真实值（建会话那一刻起算），得 %+v", ss[0])
	}
	// 正常访问一次，活跃时刻必须被刷新（超时注销的判据就是它）。
	before := ss[0].LastActive
	h.ws.sessions.touch(ss[0].ID, before-1) // 人为把它推回去一秒，再发一个真请求
	resp := h.get(t, "/app/oa/x", ck)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("正常访问应 200，得 %d", resp.StatusCode)
	}
	if got := h.ws.Sessions()[0].LastActive; got < before {
		t.Fatalf("★业务请求必须刷新活跃时刻，%d < %d", got, before)
	}
}

// ② 强制下线立刻对**普通请求**生效，且不靠账号封禁窗兜底。
//
// 这是本波补的真洞：此前 KillUser 只切 WebSocket，普通请求全靠 spa.Allowlist 的
// 5 分钟封禁窗挡，而 Cookie 活 15 分钟——封禁一过，被"下线"的人拿同一张 Cookie
// 接着访问，而管理台上写着「已下线」。这里**刻意不调 al.DenyUser**，
// 只调 KillUser：封禁窗不在场时它必须自己拦得住。
//
// 变异实测：把 KillUser 里的 s.sessions.endUser(user) 删掉 → 本条红（第二次仍 200）。
func TestKillUserEndsPlainRequestSession(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	ok := h.get(t, "/app/oa/x", ck)
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("下线前应能访问，得 %d", ok.StatusCode)
	}
	conns, sess := h.ws.KillUser("ZhangSan") // 大小写不敏感：与 spa/proxy 的封禁名单同口径
	if conns != 0 || sess != 1 {
		t.Fatalf("★应注销 1 条 Web 会话、切断 0 条长连接，得 conns=%d sessions=%d", conns, sess)
	}
	after := h.get(t, "/app/oa/x", ck)
	defer after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("★强制下线后同一张 Cookie 必须访问不了（不能只靠 5 分钟封禁窗），得 %d", after.StatusCode)
	}
	if len(h.ws.Sessions()) != 0 {
		t.Fatal("★被下线的会话必须从台账里消失，否则「在线用户」页仍显示他在线")
	}
}

// ③ 接入超时注销（FR-POLICY-30 在 B/S 这一侧的执行方）。
//
// 三条同时钉：阈值 0 时一律不注销（回落方向恒为"不生效"）；超过阈值即注销并要求重进；
// 有业务流量则不注销（判据是**上一次业务请求**而不是会话建立时刻）。
//
// 变异实测：
//   - 把 `if idle := s.IdleTimeout(); idle > 0` 改成 `idle >= 0` → 阈值 0 那段红；
//   - 把 touch 挪到逐请求鉴权**之前** → 「活跃即不注销」仍绿（touch 只是提前），
//     故另有 TestIdleTouchOnlyAfterAuthz 从被拒请求那一侧钉住顺序。
func TestWebIdleLogout(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	sid := h.ws.Sessions()[0].ID

	// 阈值 0（规则关着）：把活跃时刻推到一小时前也不该注销。
	h.ws.sessions.touch(sid, time.Now().Add(-time.Hour).Unix())
	r0 := h.get(t, "/app/oa/x", ck)
	r0.Body.Close()
	if r0.StatusCode != http.StatusOK {
		t.Fatalf("★阈值为 0 时绝不注销任何人（控制面没下发 = 规则不生效），得 %d", r0.StatusCode)
	}

	// 开启 5 分钟阈值：刚刚那次访问已经刷新过活跃时刻，故不该注销。
	h.ws.SetIdleTimeout(5 * time.Minute)
	r1 := h.get(t, "/app/oa/x", ck)
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("★有业务流量的会话不得被注销，得 %d", r1.StatusCode)
	}

	// 把活跃时刻推回 6 分钟前 → 超阈值，必须注销且台账清空。
	h.ws.sessions.touch(sid, time.Now().Add(-6*time.Minute).Unix())
	r2 := h.get(t, "/app/oa/x", ck)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("★超过阈值必须注销，得 %d", r2.StatusCode)
	}
	if len(h.ws.Sessions()) != 0 {
		t.Fatalf("★注销后台账必须清空（留着的话「在线用户」页仍显示他在线），得 %d 条",
			len(h.ws.Sessions()))
	}
	// 且这条会话**再也回不来**：同一张 Cookie 重放同样被拒（须回门户重进）。
	r3 := h.get(t, "/app/oa/x", ck)
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("★已注销的会话不得靠重放 Cookie 复活，得 %d", r3.StatusCode)
	}
}

// ④ 活跃时刻只在**全部复核通过之后**才刷新。
//
// 与 spa.Allowlist.Touch 同一条纪律：放在复核之前的话，往 L7 口打一个必然被拒的
// 请求（这里用跨应用路径）就能替别人续命，「无业务流量超时」于是可以被任何人
// 从外面免费关掉，而两侧日志里都只有一条正常的拒绝记录。
//
// ★判据必须取**最后一道闸**（逐请求 Authorize）的拒绝。第一版只用了最早那道
// （跨应用复用），于是"把 touch 挪到跨应用闸之后、Authorize 之前"的变异整条逃逸——
// 变异实测不变红才发现。两道都断言，最后那道是硬的。
//
// 变异实测：把 s.sessions.touch(...) 挪到 handleAny 里 Allow.UserDenied 之前 → (b) 段红。
func TestIdleTouchOnlyAfterAuthz(t *testing.T) {
	h := newHarness(t)
	ck := h.enter(t, "zhangsan", "user", "oa")
	sid := h.ws.Sessions()[0].ID
	stale := time.Now().Add(-time.Hour).Unix()

	// (a) 最早那道闸：Cookie 绑的是 oa，请求路径却是另一个应用（服务端复核绑定）。
	h.ws.sessions.touch(sid, stale)
	bad := h.get(t, "/app/"+otherRes+"/x", ck)
	bad.Body.Close()
	if bad.StatusCode != http.StatusForbidden {
		t.Fatalf("跨应用复用应被拒，得 %d", bad.StatusCode)
	}
	if got := h.ws.Sessions()[0].LastActive; got != stale {
		t.Fatalf("★被拒的请求不得刷新活跃时刻（否则谁都能替别人续命），%d != %d", got, stale)
	}

	// (b) 最后那道闸：控制面把该账号放进 DenyUsers（风险降权 / JIT 到期同一条路径）。
	bu, _ := url.Parse(h.backend.URL)
	h.reg.Replace([]resource.Resource{{ID: "oa", Backend: bu.Host,
		AllowRoles: []string{"user"}, DenyUsers: []string{"zhangsan"}}})
	h.ws.sessions.touch(sid, stale)
	denied := h.get(t, "/app/oa/x", ck)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("逐请求鉴权未通过应被拒，得 %d", denied.StatusCode)
	}
	if got := h.ws.Sessions()[0].LastActive; got != stale {
		t.Fatalf("★鉴权未通过的请求不得刷新活跃时刻，%d != %d", got, stale)
	}
}

// otherRes 脚手架里的第二个资源 id（用于跨应用断言）。
const otherRes = "git"

// ⑤ Cookie 过期的行必须从台账里消失——判据与 Open() 的过期判定同一条。
//
// 两处分叉的话，台账里会留下一批 Open 已认定过期、而心跳仍在上报的"幽灵在线会话"：
// 管理员在「在线用户」页看到一个早就关了浏览器的人，点「强制下线」还会真的
// 把他的账号封禁 5 分钟。
func TestExpiredSessionPrunedFromLedger(t *testing.T) {
	h := newHarness(t)
	h.enter(t, "zhangsan", "user", "oa")
	sid := h.ws.Sessions()[0].ID
	h.ws.sessions.mu.Lock()
	h.ws.sessions.m[sid].exp = time.Now().Add(-time.Second).Unix()
	h.ws.sessions.mu.Unlock()
	if n := len(h.ws.Sessions()); n != 0 {
		t.Fatalf("★已过期的会话不得再出现在台账快照里，得 %d 条", n)
	}
}
