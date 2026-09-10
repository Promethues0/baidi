package proxy

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/auth"
)

// newTestReader 与 handle 里那一行同款缓冲（大小一致才谈得上"行长受它封顶"）。
func newTestReader(c net.Conn) *bufio.Reader { return bufio.NewReaderSize(c, preambleBufSize) }

// ── 用途闸的隧道这一侧（wave11 行动 3）──
//
// ★四条入场路径各拒其余三种：敲门口拒 tunnel/web（spa.checkKnock）、L7 拒 knock/tunnel
// （webproxy.checkTicket）、隧道口拒 knock/web（这里）、控制面入站三种全拒
// （auth.Middleware 的默认拒绝分支）。少任何一向，一张票就能开两条闸，而两条闸的
// 前置判定完全不同（敲门那条有终端合规与设备准入，隧道这条没有）。
//
// 生产里还有一层密码学隔离（四条路径各装一把公钥），这里测的是语义闸本身：
// 即便有朝一日两把公钥被误装成同一把，它也必须拦住。
func TestCheckTunnelTicketRejectsOtherUses(t *testing.T) {
	now := time.Now()
	base := auth.Claims{Sub: "u", Role: "user", Name: "u",
		Iat: now.Unix(), Exp: now.Add(5 * time.Minute).Unix()}

	for _, tc := range []struct {
		name string
		use  string
	}{
		{"敲门令牌", auth.UseKnock},
		{"Web 访问票据", auth.UseWeb},
		{"会话令牌（use 为空）", ""},
	} {
		c := base
		c.Use = tc.use
		if err := checkTunnelTicket(c, 15*time.Minute); err == nil {
			t.Errorf("★%s 必须不能当隧道身份", tc.name)
		} else if !strings.Contains(err.Error(), "非隧道身份票据") {
			t.Errorf("%s 应因用途不符被拒，得: %v", tc.name, err)
		}
	}

	// 对照组：同样的信封、同样的寿命，只把 use 换成 tunnel 就该通过——
	// 证明上面那些拒绝确实来自用途闸，而不是别的字段不合格。
	ok := base
	ok.Use = auth.UseTunnel
	if err := checkTunnelTicket(ok, 15*time.Minute); err != nil {
		t.Fatalf("对照组隧道票据应通过: %v", err)
	}
}

// TestCheckTunnelTicketRoleAndTTL 角色白名单与寿命上界。
func TestCheckTunnelTicketRoleAndTTL(t *testing.T) {
	now := time.Now()
	// role=gateway（网关机器身份）与 role=mfa（二次认证半程票据）都不得成为隧道身份。
	for _, role := range []string{"gateway", "mfa", ""} {
		c := auth.Claims{Sub: "u", Role: role, Name: "u", Use: auth.UseTunnel,
			Iat: now.Unix(), Exp: now.Add(time.Minute).Unix()}
		if err := checkTunnelTicket(c, 15*time.Minute); err == nil {
			t.Errorf("★角色 %q 不得作为隧道身份", role)
		}
	}
	// 寿命超上界：纵深防御，控制面签得再长也不认。
	long := auth.Claims{Sub: "u", Role: "user", Name: "u", Use: auth.UseTunnel,
		Iat: now.Unix(), Exp: now.Add(2 * time.Hour).Unix()}
	if err := checkTunnelTicket(long, 15*time.Minute); err == nil {
		t.Fatal("超上界的票据应被拒")
	}
	// 上界没配（0）时回落到硬上界，而不是"不限"——一个没有上界的纵深不是纵深。
	if err := checkTunnelTicket(long, 0); err == nil {
		t.Fatal("上界为 0 时应回落到硬上界，2h 的票据仍应被拒")
	}
	// 缺 Iat 的票据算不出寿命 → 拒（fail-closed，不能当成"很短"）。
	noIat := auth.Claims{Sub: "u", Role: "user", Name: "u", Use: auth.UseTunnel,
		Exp: now.Add(time.Minute).Unix()}
	if err := checkTunnelTicket(noIat, 15*time.Minute); err == nil {
		t.Fatal("缺 iat 的票据算不出寿命，必须拒")
	}
}

// TestPreambleParsesTicketAndStaysBackwardCompatible 前导格式：两段（老客户端）与三段（新客户端）。
//
// ★向后兼容是解析层的事，收不收由 TunnelID.Strict 决定——两件事必须分开：
// 在解析层就把"没票据"判成错误的话，逃生舱那条过渡路径连存在的余地都没有。
func TestPreambleParsesTicketAndStaysBackwardCompatible(t *testing.T) {
	for _, tc := range []struct {
		name, line        string
		rid, ticket       string
		hasPreamble, good bool
	}{
		{name: "老客户端两段", line: "CONNECT res-git\n", rid: "res-git", ticket: "", hasPreamble: true, good: true},
		{name: "新客户端三段", line: "CONNECT res-git tok123\n", rid: "res-git", ticket: "tok123", hasPreamble: true, good: true},
		// ≥4 段是不认识的格式：可能是将来的协议版本，也可能是有人在试探解析器。
		// 「忽略多余字段继续放行」在这两种情况下都错，故 fail-closed。
		{name: "四段不认识", line: "CONNECT res-git tok123 extra\n", hasPreamble: false, good: false},
		{name: "空资源 id", line: "CONNECT \n", hasPreamble: false, good: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := tcpPair(t)
			go func() { _, _ = cli.Write([]byte(tc.line)); _ = cli.Close() }()
			br := newTestReader(srv)
			rid, ticket, has, good := readPreamble(srv, br)
			if rid != tc.rid || ticket != tc.ticket || has != tc.hasPreamble || good != tc.good {
				t.Fatalf("解析 %q 得 (rid=%q ticket=%q has=%v good=%v)，期望 (%q %q %v %v)",
					tc.line, rid, ticket, has, good, tc.rid, tc.ticket, tc.hasPreamble, tc.good)
			}
		})
	}
}
