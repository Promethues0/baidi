package api

import (
	"net/http"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// 会话令牌注销（wave11 行动 4，FR-SYSCFG-09 / FR-SYSCFG-11 / FR-MON-13）。
//
// ★改造前：auth.Middleware 只验签名与用途白名单、不查任何库；AdminRoleFor 的 SQL 只筛
// role='admin' **不筛 status**；requireUser 更是纯令牌判定。于是四条处置——禁用、锁定、
// 强制下线、闲置自动锁定——对已签发的 8h 令牌全部无效：数据面当场断了（entryGates 查
// accountBlocked、撤销通道下发到网关），而管理 API / 门户 / JIT 这一侧还开着。
//
// 管理员账号被盗后的标准处置就是点「禁用」；点完之后控制台显示已禁用、审计也记了一条，
// 而攻击者在最长八小时里仍是完整管理员。

// TestDisabledAdminTokenLosesControlPlaneAccess 禁用管理员后，他手里那张令牌立刻失效。
func TestDisabledAdminTokenLosesControlPlaneAccess(t *testing.T) {
	h := newTestServer(t)
	tok := makeAdmin(t, h, "sec.victim", "security")

	// 处置前：读写两侧都通（否则后面的"失效了"是空断言）。
	if code, out := doJSON(t, h, "GET", "/api/v1/users", tok, nil); code != http.StatusOK {
		t.Fatalf("前置条件不成立：处置前就读不到用户目录 %d %v", code, out)
	}

	// 找到他的 id 并禁用。
	id := userIDByAccount(t, h, "sec.victim")
	if code, out := doJSON(t, h, "POST", "/api/v1/users/"+id+"/status", adminToken(),
		map[string]any{"status": "disabled"}); code != http.StatusOK {
		t.Fatalf("禁用应成功：%d %v", code, out)
	}

	// 处置后：同一张令牌读写全断。
	for _, p := range []struct{ method, path string }{
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/online"},
		{"GET", "/api/v1/apps"},
	} {
		code, out := doJSON(t, h, p.method, p.path, tok, nil)
		if code != http.StatusForbidden {
			t.Fatalf("被禁用的管理员用旧令牌访问 %s %s 应 403，实得 %d %v——"+
				"「禁用」在控制面这一侧没有兑现，攻击者在最长 8h 内仍是完整管理员",
				p.method, p.path, code, out)
		}
	}
}

// TestKickSessionRevokesControlPlaneToken 强制下线要连控制面令牌一起注销。
//
// 改造前「强制下线」只做两件事：数据面撤窗断隧道 + 页面上打一个 offline 标记，
// 而那个人的 8h 令牌毫发无损——隧道断了，门户 / JIT 申请 / 客户端剖面全都还开着。
func TestKickSessionRevokesControlPlaneToken(t *testing.T) {
	h, srv := newTestServerWithSrv(t)

	// 造一条网关上报的真实会话（handleKickSession 只认真实会话）。
	// ★网关本身也要登记成「心跳新鲜」，否则 /online 会把离线网关的会话整段跳过，
	// 用例就退化成在验一个空列表。
	seedLiveSession(srv, "gw-1", "10.1.2.3", "zhang.wei", time.Now().Add(-time.Minute))

	utok := userToken("zhang.wei")
	if code, _ := doJSON(t, h, "GET", "/api/v1/client/profile", utok, nil); code != http.StatusOK {
		t.Fatalf("前置条件不成立：下线前剖面就拉不到")
	}

	code, out := doJSON(t, h, "POST", "/api/v1/online/gw-1:10.1.2.3/kick", adminToken(),
		map[string]any{"reason": "测试"})
	if code != http.StatusOK {
		t.Fatalf("强制下线应成功：%d %v", code, out)
	}
	if out["sessionRevoked"] != true {
		t.Fatalf("回执必须说清控制面令牌也注销了（只报数据面那一半会让管理员以为另一件也做了）：%v", out)
	}

	if code, out := doJSON(t, h, "GET", "/api/v1/client/profile", utok, nil); code != http.StatusForbidden {
		t.Fatalf("强制下线后旧令牌应 403，实得 %d %v——"+
			"「强制下线」在控制面这一侧没有兑现", code, out)
	}
}

// TestKickedFlagClearsOnReconnect 「已下线」覆盖层必须在人重连后自动让位。
//
// 会话 id 是 `网关id:源IP`，用户自动重连后网关用**同一个 id** 重新上报一条新会话，
// 而这张覆盖表此前只增不减：那个人明明已经回来了，页面上仍写着「已下线」，
// 「强制下线」按钮也因为状态是 offline 而点不到——管理员想再踢一次都没有入口。
func TestKickedFlagClearsOnReconnect(t *testing.T) {
	h, srv := newTestServerWithSrv(t)
	seedLiveSession(srv, "gw-1", "10.1.2.3", "zhang.wei", time.Now().Add(-time.Minute))

	if code, _ := doJSON(t, h, "POST", "/api/v1/online/gw-1:10.1.2.3/kick", adminToken(),
		map[string]any{"reason": "测试"}); code != http.StatusOK {
		t.Fatal("强制下线应成功")
	}
	if st := sessionStatus(t, h, "gw-1:10.1.2.3"); st != "offline" {
		t.Fatalf("刚下线时应显示 offline，实得 %q", st)
	}

	// 他重连了：网关用同一个 id 上报一条**建立时刻更新**的会话。
	seedLiveSession(srv, "gw-1", "10.1.2.3", "zhang.wei", time.Now().Add(2*time.Second))

	if st := sessionStatus(t, h, "gw-1:10.1.2.3"); st != "online" {
		t.Fatalf("重连后应回到 online，实得 %q——覆盖层永不清理会让这一行永远写着"+
			"「已下线」，而「强制下线」按钮因状态是 offline 点不到", st)
	}
}

// TestSessionGuardBackfillIsPermissive 补列回填必须是 0（不限），不能是「现在」。
//
// ★回填成 now 就是升级那一刻**全员掉线**，而现场表现为"升级把系统弄坏了"，
// 没人会想到是一条安全修复。这条用例从正面钉住「升级后既有令牌仍然可用」。
func TestSessionGuardBackfillIsPermissive(t *testing.T) {
	// 纯函数判定，不需要起服务。
	old := auth.Claims{Sub: "zhang.wei", Role: "user", Name: "张伟",
		Iat: time.Now().Add(-2 * time.Hour).Unix()}
	cred := store.Credential{Status: "active", TokensValidAfter: 0}
	if ok, why := checkSessionValid(old, cred); !ok {
		t.Fatalf("从未被处置过的账号，其旧令牌必须仍然有效（回填 0 = 不限），实得拒绝：%s", why)
	}
	// 一旦真的处置过，同一张旧令牌就该失效。
	cred.TokensValidAfter = time.Now().Unix()
	if ok, _ := checkSessionValid(old, cred); ok {
		t.Fatal("处置之后签发于处置前的令牌必须失效")
	}
}

// TestReactivateDoesNotResurrectOldTokens 恢复账号不得让旧令牌复活。
//
// 清掉 tokens_valid_after 等于让攻击者手里那张旧令牌在账号解禁的同一刻复活。
// 解除只有一次完整的重新登录（新令牌的 iat 自然更大）。
func TestReactivateDoesNotResurrectOldTokens(t *testing.T) {
	h := newTestServer(t)
	tok := makeAdmin(t, h, "sec.back", "security")
	id := userIDByAccount(t, h, "sec.back")

	if code, _ := doJSON(t, h, "POST", "/api/v1/users/"+id+"/status", adminToken(),
		map[string]any{"status": "disabled"}); code != http.StatusOK {
		t.Fatal("禁用应成功")
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/users/"+id+"/status", adminToken(),
		map[string]any{"status": "active"}); code != http.StatusOK {
		t.Fatal("恢复应成功")
	}
	if code, out := doJSON(t, h, "GET", "/api/v1/users", tok, nil); code != http.StatusForbidden {
		t.Fatalf("账号恢复后，被禁用期间那张旧令牌仍必须失效（否则攻击者手里的令牌"+
			"在解禁同一刻复活），实得 %d %v", code, out)
	}
}

// seedLiveSession 登记一台心跳新鲜的网关 + 它上报的一条会话。
// 两件事必须一起做：/online 会跳过离线网关的全部会话（离线网关的会话不计入在线）。
func seedLiveSession(srv *Server, gwID, ip, user string, since time.Time) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	gw := srv.gateways[gwID]
	gw.LastSeen = time.Now().Unix()
	srv.gateways[gwID] = gw
	srv.gwSess[gwID] = []GwSession{{IP: ip, User: user, Since: since.Unix()}}
}

func userIDByAccount(t *testing.T, h http.Handler, account string) string {
	t.Helper()
	_, out := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	items, _ := out["users"].([]any)
	for _, it := range items {
		m := mapOf(t, it)
		if m["account"] == account {
			if id, _ := m["id"].(string); id != "" {
				return id
			}
		}
	}
	t.Fatalf("目录里找不到账号 %s：%v", account, out)
	return ""
}

func sessionStatus(t *testing.T, h http.Handler, id string) string {
	t.Helper()
	_, out := doJSON(t, h, "GET", "/api/v1/online", adminToken(), nil)
	items, _ := out["sessions"].([]any)
	for _, it := range items {
		m := mapOf(t, it)
		if m["id"] == id {
			st, _ := m["status"].(string)
			return st
		}
	}
	t.Fatalf("在线列表里找不到会话 %s：%v", id, out)
	return ""
}
