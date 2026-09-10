package proxy

import (
	"net"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/secevent"
	"baidi.dev/gateway/internal/spa"
)

// ── wave11 行动 3：同一源 IP 上的两个账号必须各是各的 ──
//
// ★这一组用例存在的理由，是既有 proxy/spa 用例**在结构上分不出两种实现**：
// 它们全是「单账号 + 127.0.0.1」，而被修的缺陷恰恰只在"同一源 IP 上有两个账号"时显形。
// 按源 IP 定身份与按连接定身份，在单账号场景里逐字等价，测多少遍都是绿的。
//
// 被修的形态：spa.Allowlist 以源 IP 为唯一键、entry 直接携带 user，`Allow()` 整条覆盖；
// proxy.handle 每条 TCP 流现查 al.Allowed(ip) 取身份。于是同一出口（企业 NAT / CGNAT /
// 公共 Wi-Fi / 同公网 IP 的云主机）下，谁最后敲的门谁就是"这条连接的身份"——
// 另一台主机直连隧道口即继承其全部资源授权、JIT 与降权结论，而审计里记的是那个无辜者。

// tagBackend 起一个把 tag 回给客户端就关连接的后端，用于分辨流量真的落到了哪一个。
func tagBackend(t *testing.T, tag string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起后端失败：%v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(tag))
			_ = c.Close()
		}
	}()
	return ln
}

// runOne 走一条完整的隧道连接：写 preamble，读回后端的应答（读不到即空串）。
func runOne(t *testing.T, reg *resource.Registry, al *spa.Allowlist, rep *secevent.Reporter,
	id TunnelID, preamble string) string {
	t.Helper()
	cli, srv := tcpPair(t)
	done := make(chan struct{})
	go func() { handle(srv, reg, al, rep, id); close(done) }()
	_ = cli.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := cli.Write([]byte(preamble)); err != nil {
		t.Fatalf("写前导失败：%v", err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := cli.Read(buf)
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle 没有返回")
	}
	return string(buf[:n])
}

// sharedIPFixture 两个账号从**同一个源 IP** 交替敲门，各自只被授权一个资源。
type sharedIPFixture struct {
	reg  *resource.Registry
	al   *spa.Allowlist
	cap  *capture
	rep  *secevent.Reporter
	id   TunnelID
	sign signTunnel
	// rogueSign 用一把网关没装的密钥签票（"别处签的票"反例）。
	rogueSign signTunnel
}

func newSharedIPFixture(t *testing.T) *sharedIPFixture {
	t.Helper()
	beA := tagBackend(t, "BACKEND-A")
	beB := tagBackend(t, "BACKEND-B")
	reg := resource.New("")
	reg.Replace([]resource.Resource{
		{ID: "res-a", Backend: beA.Addr().String(), AllowUsers: []string{"alice"}},
		{ID: "res-b", Backend: beB.Addr().String(), AllowUsers: []string{"bob"}},
	})
	al := spa.NewAllowlist()
	// 交替敲门：真实形态是两台机器各自每 15s 敲一次，落在网关看来就是同一个源 IP。
	al.Allow("127.0.0.1", "alice", "user", time.Minute)
	al.Allow("127.0.0.1", "bob", "user", time.Minute)
	al.Allow("127.0.0.1", "alice", "user", time.Minute)
	al.Allow("127.0.0.1", "bob", "user", time.Minute) // ★bob 是**最后一个**敲门的
	cap := &capture{}
	id, sign, rogue := newTestTunnelIDWithSigner(t)
	return &sharedIPFixture{reg: reg, al: al, cap: cap, rep: secevent.New(cap.sink),
		id: id, sign: sign, rogueSign: rogue}
}

// TestSharedSourceIPIdentityIsPerConnection 同一源 IP 上，每条连接的身份由它自己的票据决定。
//
// ★核心断言是第二条：**alice 的票访问 bob 的资源必须被拒**。
// 按源 IP 定身份时，最后敲门的是 bob，于是这条连接会被当成 bob → 放行 → 拿到 BACKEND-B。
func TestSharedSourceIPIdentityIsPerConnection(t *testing.T) {
	f := newSharedIPFixture(t)

	if got := runOne(t, f.reg, f.al, f.rep, f.id,
		"CONNECT res-a "+f.sign("alice", "user")+"\n"); !strings.Contains(got, "BACKEND-A") {
		t.Fatalf("alice 持自己的票访问自己的资源应通，实得 %q", got)
	}
	if got := runOne(t, f.reg, f.al, f.rep, f.id,
		"CONNECT res-b "+f.sign("alice", "user")+"\n"); strings.Contains(got, "BACKEND-B") {
		t.Fatal("★alice 竟拿到了 bob 的资源：身份被按源 IP 反查（最后敲门的是 bob），" +
			"这正是同出口继承他人授权的那个缺陷")
	}
	if got := runOne(t, f.reg, f.al, f.rep, f.id,
		"CONNECT res-b "+f.sign("bob", "user")+"\n"); !strings.Contains(got, "BACKEND-B") {
		t.Fatalf("bob 持自己的票访问自己的资源应通，实得 %q", got)
	}

	// 审计必须各记各的：放行留痕上的账号是**票据自证的那个**，不是最后敲门的那个。
	allows := f.cap.allowRecs()
	var okA, okB bool
	for _, r := range allows {
		if strings.Contains(r, "alice") && strings.Contains(r, "res-a") {
			okA = true
		}
		if strings.Contains(r, "bob") && strings.Contains(r, "res-b") {
			okB = true
		}
		if strings.Contains(r, "bob") && strings.Contains(r, "res-a") {
			t.Errorf("放行留痕把 alice 的访问记到了 bob 头上：%s", r)
		}
	}
	if !okA || !okB {
		t.Errorf("两条放行留痕应各记各的账号与资源，实得 %v", allows)
	}
	// 越权那次要有一条点名 alice 的拒绝——记成 bob 的话，查审计的人会去问错的人。
	var denyNamedAlice bool
	for _, r := range f.cap.denyRecs() {
		if strings.HasPrefix(r, "proxy-authz|") && strings.Contains(r, "alice") {
			denyNamedAlice = true
		}
	}
	if !denyNamedAlice {
		t.Errorf("越权拒绝应点名发起者 alice，实得 %v", f.cap.denyRecs())
	}
}

// TestRevokeOneAccountLeavesTheOtherAlone 撤 A 不影响 B，且 A 真的进不来。
//
// ★两个方向都要断言：
//   - 漏撤（RevokeUser 按 entry.user 匹配，末次敲门者是 B 时整条不匹配）→ A 仍然进得来；
//   - 误伤（一旦匹配上就把整条 IP 记录删掉）→ B 一起被踢下线。
//
// 这两种错法此前**同时**存在，方向相反且都不报错。
func TestRevokeOneAccountLeavesTheOtherAlone(t *testing.T) {
	f := newSharedIPFixture(t)

	ips := f.al.RevokeUser("alice")
	if len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("撤销 alice 应命中它在 127.0.0.1 上的窗口，实得 %v", ips)
	}
	// A 真的进不来：票据还在手里且没过期，但窗口没了。
	if got := runOne(t, f.reg, f.al, f.rep, f.id,
		"CONNECT res-a "+f.sign("alice", "user")+"\n"); strings.Contains(got, "BACKEND-A") {
		t.Fatal("★alice 已被强制下线，却仍凭手里那张没过期的票连上了——" +
			"票据必须再过一道 (源IP,账号) 的窗口复核，否则撤窗对新连接无效")
	}
	var nowindow bool
	for _, r := range f.cap.denyRecs() {
		if strings.HasPrefix(r, "proxy-nowindow|") && strings.Contains(r, "alice") {
			nowindow = true
		}
	}
	if !nowindow {
		t.Errorf("撤窗后的拒绝要留痕并点名账号，实得 %v", f.cap.denyRecs())
	}
	// B 完全不受影响。
	if got := runOne(t, f.reg, f.al, f.rep, f.id,
		"CONNECT res-b "+f.sign("bob", "user")+"\n"); !strings.Contains(got, "BACKEND-B") {
		t.Fatalf("★撤销 alice 把同出口的 bob 一起踢了（误伤），实得 %q", got)
	}
	// 端口闸仍开着（bob 还在），但这**不该**让 alice 沾光——上面那条已经断言过了。
	if !f.al.Allowed("127.0.0.1") {
		t.Fatal("bob 的窗口还在，端口闸不该关")
	}
	if f.al.AllowedFor("127.0.0.1", "alice") {
		t.Fatal("alice 的窗口应已被撤销")
	}
}

// TestTunnelRejectsMissingAndForgedTickets 严格模式下：没票、票是别处签的、用途不对，一律拒。
func TestTunnelRejectsMissingAndForgedTickets(t *testing.T) {
	f := newSharedIPFixture(t)

	// ① 完全不带票据——尽管这个源 IP 上确实有两个人持窗（老实现正是靠这个放行的）。
	if got := runOne(t, f.reg, f.al, f.rep, f.id, "CONNECT res-a\n"); got != "" {
		t.Fatalf("★不带票据的连接必须被拒（源 IP 有窗口不等于这条连接有身份），实得 %q", got)
	}
	assertDeny(t, f.cap, "proxy-noticket")

	// ② 票是**另一把密钥**签的：网关只装了 tunnel 那把公钥，kid 查不到 → 连签名都验不过。
	//    这是密钥分离的价值——即便 use 语义闸被误改，别处签的票在这里仍然过不去。
	if got := runOne(t, f.reg, f.al, f.rep, f.id,
		"CONNECT res-a "+f.rogueSign("alice", "user")+"\n"); got != "" {
		t.Fatalf("★别处签的票必须验不过，实得 %q", got)
	}
	assertDeny(t, f.cap, "proxy-ticket")

	// ③ 票据自证的账号在放行表里根本没敲过门。
	if got := runOne(t, f.reg, f.al, f.rep, f.id,
		"CONNECT res-a "+f.sign("carol", "user")+"\n"); got != "" {
		t.Fatalf("★没敲过门的账号不该只凭一张票就进来，实得 %q", got)
	}
	assertDeny(t, f.cap, "proxy-nowindow")
}

// TestTunnelIDFallbackRefusesAmbiguity 逃生舱开着时，同源多账号仍必须拒——不可判定 ≠ 随便挑一个。
//
// ★这条是逃生舱的边界：关掉严格模式是为了让**还没升级**的老客户端能过渡，
// 而不是把"同出口继承他人授权"原样留着。恰好一个账号持窗时身份是确定的（放行 + 留痕），
// 两个及以上时身份不可判定，只能拒。
func TestTunnelIDFallbackRefusesAmbiguity(t *testing.T) {
	f := newSharedIPFixture(t)
	loose := f.id
	loose.Strict = false

	// 同一 IP 上 alice 与 bob 都持窗 → 不带票据 = 不可判定 → 拒。
	if got := runOne(t, f.reg, f.al, f.rep, loose, "CONNECT res-a\n"); got != "" {
		t.Fatalf("★同源多账号 + 无票据是不可判定，绝不能挑一个身份放行，实得 %q", got)
	}
	assertDeny(t, f.cap, "proxy-idambig")

	// 只剩 alice 一个人持窗时才回落，且**每次都留痕**（否则这个开关会永久隐形地开着）。
	f.al.RevokeUser("bob")
	if got := runOne(t, f.reg, f.al, f.rep, loose, "CONNECT res-a\n"); !strings.Contains(got, "BACKEND-A") {
		t.Fatalf("逃生舱 + 唯一持窗账号应放行（兼容老客户端），实得 %q", got)
	}
	var traced bool
	for _, r := range f.cap.allowRecs() {
		if strings.HasPrefix(r, "tunnel-idfallback|") && strings.Contains(r, "alice") {
			traced = true
		}
	}
	if !traced {
		t.Errorf("回落必须留痕（类别 tunnel-idfallback）：只写本机日志的话，"+
			"这个逃生舱会永久开着而中心侧查不到它还在用；实得 %v", f.cap.allowRecs())
	}
}

func assertDeny(t *testing.T, cap *capture, cat string) {
	t.Helper()
	for _, r := range cap.denyRecs() {
		if strings.HasPrefix(r, cat+"|") {
			return
		}
	}
	t.Errorf("应有一条 %s 拒绝留痕，实得 %v", cat, cap.denyRecs())
}
