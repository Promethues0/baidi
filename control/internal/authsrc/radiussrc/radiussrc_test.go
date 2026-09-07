package radiussrc

// 端到端用例：客户端是生产代码本身，服务端是进程内的真实 RADIUS 服务端（testsrv_test.go）。
// 每一条断言都对着 radiussrc.go 包注释里标了 ★ 的那些安全点。

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"layeh.com/radius"

	"baidi.dev/control/internal/authsrc"
)

const (
	srcID     = "src-radius-1"
	alicePass = "alice-pass"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func stdUsers() map[string]string {
	return map[string]string{"alice": alicePass, "bob": "bob-pass", "li.fang": "radius-pw"}
}

// newProv 用测试服务端地址建一个 Provider；短超时让失败用例不拖慢整包。
func newProv(t *testing.T, srv *testSrv, mutate func(*Config)) *Provider {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	var portN int
	for _, ch := range port {
		portN = portN*10 + int(ch-'0')
	}
	cfg := Config{
		SourceID: srcID, Host: host, Port: portN, Secret: "s3cret",
		Timeout: 150 * time.Millisecond, Retries: 1, Logger: discardLogger(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

// ── 认证 ──────────────────────────────────────────────────────────────────

func TestPAPAccept(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers()})
	p := newProv(t, srv, nil)
	id, err := p.Authenticate(ctx(t), " Alice ", alicePass)
	if err != nil {
		t.Fatalf("PAP 放行应成功：%v", err)
	}
	// Subject 跟着实际发给服务器的 User-Name 走：只 trim、不改大小写（" Alice " → "Alice"）。
	if id.Subject != "radius:"+srcID+":Alice" {
		t.Errorf("Subject 应为 radius:<源 id>:<发给服务器的 User-Name，只 trim>，得到 %q", id.Subject)
	}
	// Username 是展示/建号用的账号名，仍走 Identity.Normalized 的小写口径——与 Subject 刻意不同。
	if id.Username != "alice" {
		t.Errorf("Username 应规范化为 alice，得到 %q", id.Username)
	}
	if id.Email != "" || id.DisplayName != "" {
		t.Errorf("RADIUS 没有邮箱/显示名，不该编造：%+v", id)
	}
	if len(id.Groups) != 0 {
		t.Errorf("未配置组属性时不该映射出组：%v", id.Groups)
	}
	// ★请求必须带合法的 Message-Authenticator：服务端是严格姿态（没带就丢），
	// 能收到 Accept 本身已证明，这里再从服务端视角断一遍。
	srv.mu.Lock()
	valid := srv.lastReqMAValid
	srv.mu.Unlock()
	if !valid {
		t.Error("Access-Request 没带合法的 Message-Authenticator")
	}
}

func TestCHAPAccept(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers()})
	p := newProv(t, srv, func(c *Config) { c.Protocol = ProtocolCHAP })
	id, err := p.Authenticate(ctx(t), "alice", alicePass)
	if err != nil {
		t.Fatalf("CHAP 放行应成功：%v", err)
	}
	if id.Subject != "radius:"+srcID+":alice" {
		t.Errorf("CHAP 与 PAP 的 Subject 必须一致（换协议不该换身份），得到 %q", id.Subject)
	}
	// CHAP 下口令错也要被拒（服务端按同一份明文口令算 MD5）。
	if _, err := p.Authenticate(ctx(t), "alice", "wrong"); !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Errorf("CHAP 口令错应为 ErrInvalidCredentials，得到 %v", err)
	}
}

// TestRejectIsInvalidCredentials Access-Reject 是**唯一**映射到"凭据错"的结果。
func TestRejectIsInvalidCredentials(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers()})
	p := newProv(t, srv, nil)
	for _, tc := range []struct{ user, pw string }{{"alice", "wrong"}, {"nobody", "x"}} {
		_, err := p.Authenticate(ctx(t), tc.user, tc.pw)
		if !errors.Is(err, authsrc.ErrInvalidCredentials) {
			t.Errorf("%s/%s：Access-Reject 应为 ErrInvalidCredentials，得到 %v", tc.user, tc.pw, err)
		}
		if errors.Is(err, authsrc.ErrSourceUnavailable) {
			t.Errorf("%s/%s：凭据错不能同时是源不可用（两类必须分得开）：%v", tc.user, tc.pw, err)
		}
		// ★服务端的 Reply-Message（"bad credentials"）不许透给调用方——那是用户名枚举面。
		if strings.Contains(err.Error(), "bad credentials") {
			t.Errorf("Reply-Message 泄漏进错误文案：%v", err)
		}
	}
}

// TestTimeoutIsUnavailable 黑洞服务端：超时 = 源不可用，不是密码错；且真的重发过。
func TestTimeoutIsUnavailable(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), blackhole: true})
	p := newProv(t, srv, nil) // 150ms × (1+1) = 300ms 预算
	start := time.Now()
	_, err := p.Authenticate(ctx(t), "alice", alicePass)
	spent := time.Since(start)
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("超时应为 ErrSourceUnavailable，得到 %v", err)
	}
	if errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("超时绝不能被当成密码错误（会计入锁定、误导用户）：%v", err)
	}
	if !errors.Is(err, errNoResponse) {
		t.Errorf("超时错误链上应带 errNoResponse（Probe 回退逻辑靠它分辨）：%v", err)
	}
	if spent < 250*time.Millisecond || spent > 2*time.Second {
		t.Errorf("预算应约为 Timeout×(Retries+1)=300ms，实际 %v", spent)
	}
	if n := srv.count(radius.CodeAccessRequest); n < 2 {
		t.Errorf("Retries=1 应至少发两份请求，服务端只收到 %d", n)
	}
	// 文案要把"静默丢包"的两种成因说出来——真实 FreeRADIUS 对密钥不对/未登记客户端都是不回包。
	for _, want := range []string{"共享密钥", "NAS 客户端"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("超时文案应提到「%s」，得到：%v", want, err)
		}
	}
}

// TestWrongSecretIsUnavailable 共享密钥不匹配 → 应答校验失败 → 源不可用，**不是密码错**。
//
// 回错了的症状：共享密钥一换，全公司同时"密码错误"并被计入锁定，而每个人的密码都是对的。
func TestWrongSecretIsUnavailable(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), secret: "server-side-secret", noRequireReqMA: true})
	p := newProv(t, srv, nil) // 客户端仍用 s3cret
	start := time.Now()
	_, err := p.Authenticate(ctx(t), "alice", alicePass)
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("密钥不匹配应为 ErrSourceUnavailable，得到 %v", err)
	}
	if errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("密钥不匹配绝不能被当成密码错误：%v", err)
	}
	if !strings.Contains(err.Error(), "共享密钥") {
		t.Errorf("文案应点名共享密钥，得到：%v", err)
	}
	// 第一份校验不过的应答就该下结论，而不是拖到超时才报（两种故障会混成一种）。
	if spent := time.Since(start); spent > 250*time.Millisecond {
		t.Errorf("密钥不匹配应在首份应答到达时即报错，实际耗时 %v（像是等到了超时）", spent)
	}
}

func TestEmptyPasswordRejectedLocally(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), acceptAll: true})
	p := newProv(t, srv, nil)
	_, err := p.Authenticate(ctx(t), "alice", "")
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("空口令应在本地就拒，得到 %v", err)
	}
	if n := srv.total(); n != 0 {
		t.Errorf("空口令不该发到服务端（对面 acceptAll 会放行），却发了 %d 份", n)
	}
}

// TestChallengeIsUnavailableNotInvalid 多轮挑战本包不做：它不是凭据错（口令可能是对的）。
func TestChallengeIsUnavailableNotInvalid(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), challengeUsers: map[string]bool{"alice": true}})
	p := newProv(t, srv, nil)
	_, err := p.Authenticate(ctx(t), "alice", alicePass)
	if !errors.Is(err, authsrc.ErrSourceUnavailable) || errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("Access-Challenge 应归为源不可用且不是凭据错，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "Access-Challenge") {
		t.Errorf("文案应点名 Access-Challenge：%v", err)
	}
}

// TestReplyMessageAuthenticatorVerified 应答带 Message-Authenticator 时必须校验——
// Blast-RADIUS 伪造的正是只有 MD5 Response Authenticator 的应答。
func TestReplyMessageAuthenticatorVerified(t *testing.T) {
	good := startSrv(t, srvOpts{users: stdUsers()})
	if _, err := newProv(t, good, nil).Authenticate(ctx(t), "alice", alicePass); err != nil {
		t.Fatalf("合法 MA 的应答应通过：%v", err)
	}
	bad := startSrv(t, srvOpts{users: stdUsers(), badReplyMA: true})
	_, err := newProv(t, bad, nil).Authenticate(ctx(t), "alice", alicePass)
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("MA 校验失败的 Access-Accept 必须拒绝且归为源不可用，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "Message-Authenticator") {
		t.Errorf("文案应点名 Message-Authenticator：%v", err)
	}
}

// TestResponseWithoutMessageAuthenticatorRejected **缺席也要拒**：Blast-RADIUS（CVE-2024-3596）
// 的攻击者就在链路上，把伪造应答里的 Message-Authenticator 属性删掉就能让「带了才校验」那种
// 判据整个失效——要不要验成了攻击者的选择，只剩他已经攻破的 MD5 Response Authenticator。
//
// 夹具说明：真攻击者不知道共享密钥，靠 MD5 选择前缀碰撞造出一份 Response Authenticator 能过的
// 应答；进程内没法复现那步计算，所以用「知道密钥、但不回 MA 的服务端」等价模拟**攻击成功之后
// 那一刻的报文**（MD5 那层已经过了，只剩本包这道 HMAC 闸）。
func TestResponseWithoutMessageAuthenticatorRejected(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), noReplyMA: true})

	// ① 默认（逃生舱关）：一份**不带 MA 的 Access-Accept**必须判源不可用，绝不能认证通过。
	id, err := newProv(t, srv, nil).Authenticate(ctx(t), "alice", alicePass)
	if err == nil {
		t.Fatalf("不带 Message-Authenticator 的 Access-Accept 竟认证通过了：%+v", id)
	}
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("应判源不可用，得到 %v", err)
	}
	if errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("这不是凭据错（口令是对的），计入锁定会把链路故障算到用户头上：%v", err)
	}
	// 文案要同时说出两种可能与出路——只说"被剥离"会让老设备的管理员无路可走，
	// 只说"服务器不支持"会把一次真实的中间人说成配置问题。
	for _, want := range []string{"Message-Authenticator", "剥离", "CVE-2024-3596", "老设备", "allowMissingResponseMessageAuthenticator"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("拒绝文案应提到「%s」，得到：%v", want, err)
		}
	}

	// ② 显式打开逃生舱：同一份报文被接受——证明它真的是逃生舱，而不是一句注释。
	waived := newProv(t, srv, func(c *Config) { c.AllowMissingResponseMessageAuthenticator = true })
	id, err = waived.Authenticate(ctx(t), "alice", alicePass)
	if err != nil {
		t.Fatalf("打开逃生舱后同一份应答应被接受：%v", err)
	}
	if id.Subject != "radius:"+srcID+":alice" {
		t.Errorf("逃生舱只放宽 MA 这一条，身份计算不该变：%q", id.Subject)
	}

	// ③ 逃生舱**不放宽"带了但校验不过"**：那是确定的篡改或密钥不匹配，任何配置下都拒。
	bad := startSrv(t, srvOpts{users: stdUsers(), badReplyMA: true})
	if _, err := newProv(t, bad, func(c *Config) { c.AllowMissingResponseMessageAuthenticator = true }).
		Authenticate(ctx(t), "alice", alicePass); !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("MA 校验失败在逃生舱打开时也必须拒绝，得到 %v", err)
	}

	// ④ 零值即安全那一侧：不填这个字段（存量调用方、旧库里没有这个键）= 要求带 MA。
	var zero Config
	if zero.AllowMissingResponseMessageAuthenticator {
		t.Error("Config 零值必须是「要求应答带 Message-Authenticator」那一侧")
	}
}

// TestProbeSaysWaiverIsOn 逃生舱开着时，「测试连接」结论必须当面说明放弃了哪一层保护，
// 并分清「开着但其实用不上」与「开着且这次真用上了」——两种情况的下一步动作相反。
func TestProbeSaysWaiverIsOn(t *testing.T) {
	waive := func(c *Config) { c.AllowMissingResponseMessageAuthenticator = true }

	// 服务器其实回了 MA：结论要说"可以关掉"。
	withMA := startSrv(t, srvOpts{users: stdUsers(), statusServer: true})
	rep, err := newProv(t, withMA, waive).ProbeDetail(ctx(t))
	if err != nil {
		t.Fatalf("探测应成功：%v", err)
	}
	if !strings.Contains(rep.Detail, "允许应答不带 Message-Authenticator") || !strings.Contains(rep.Detail, "建议关掉") {
		t.Errorf("逃生舱开着且服务器其实带了 MA，结论应告警并建议关掉，得到：%s", rep.Detail)
	}

	// 服务器确实不回 MA：结论要说清关掉会让该源不可用。
	noMA := startSrv(t, srvOpts{users: stdUsers(), statusServer: true, noReplyMA: true})
	rep, err = newProv(t, noMA, waive).ProbeDetail(ctx(t))
	if err != nil {
		t.Fatalf("逃生舱开着时探测应成功：%v", err)
	}
	if !strings.Contains(rep.Detail, "确实没带") || !strings.Contains(rep.Detail, "关掉开关会让该源不可用") {
		t.Errorf("结论应说清这次真的用上了逃生舱，得到：%s", rep.Detail)
	}

	// 逃生舱关着时不加任何告警（免得一句常驻警告被人当背景噪声）。
	rep, err = newProv(t, withMA, nil).ProbeDetail(ctx(t))
	if err != nil {
		t.Fatalf("探测应成功：%v", err)
	}
	if strings.Contains(rep.Detail, "⚠") {
		t.Errorf("默认姿态不该有逃生舱告警，得到：%s", rep.Detail)
	}

	// 逃生舱关着 + 服务器不回 MA：探测必须失败（与登录同一道闸），而不是"连接正常"。
	if _, err := newProv(t, noMA, nil).ProbeDetail(ctx(t)); !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("默认姿态下不回 MA 的服务器应判不可用，得到 %v", err)
	}
}

// TestCtxBudgetCaps 调用方 ctx 的剩余预算比配置更紧时以 ctx 为准（对齐 8s 外部认证预算）。
func TestCtxBudgetCaps(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), blackhole: true})
	p := newProv(t, srv, func(c *Config) { c.Timeout = 5 * time.Second; c.Retries = 3 })
	c, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := p.Authenticate(c, "alice", alicePass)
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("应为源不可用：%v", err)
	}
	if spent := time.Since(start); spent > 1500*time.Millisecond {
		t.Errorf("ctx 只给 200ms，实际等了 %v——配置的 5s×4 盖过了调用方预算", spent)
	}
}

// ── 组映射 ─────────────────────────────────────────────────────────────────

func TestGroupAttrMapping(t *testing.T) {
	groups := map[string][]string{"alice": {"vpn-users", " ops ", "vpn-users"}}
	for _, attr := range []GroupAttr{GroupAttrClass, GroupAttrFilterID, GroupAttrReplyMessage} {
		t.Run(string(attr), func(t *testing.T) {
			srv := startSrv(t, srvOpts{users: stdUsers(), groups: groups, groupAttr: string(attr), binaryClass: attr == GroupAttrClass})
			p := newProv(t, srv, func(c *Config) { c.GroupAttr = attr })
			id, err := p.Authenticate(ctx(t), "alice", alicePass)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"vpn-users", "ops"} // 去空白、去重、保序；二进制 Class 被跳过
			if strings.Join(id.Groups, ",") != strings.Join(want, ",") {
				t.Errorf("组映射：want %v got %v", want, id.Groups)
			}
		})
	}
	// 配了属性但服务端没回 → 空组，不报错（准入的组白名单会据此 fail-closed，那是它的职责）。
	srv := startSrv(t, srvOpts{users: stdUsers(), groupAttr: "class"})
	id, err := newProv(t, srv, func(c *Config) { c.GroupAttr = GroupAttrClass }).Authenticate(ctx(t), "bob", "bob-pass")
	if err != nil || len(id.Groups) != 0 {
		t.Errorf("服务端未回组属性应得空组：groups=%v err=%v", id.Groups, err)
	}
}

// ── Subject ────────────────────────────────────────────────────────────────

// TestSubjectStableAndSourceIsolated Subject 在同源内稳定（同写法 → 同 Subject）、跨源隔离、
// **大小写敏感**（不同写法 → 不同 Subject）。前两条是对 SCOPE 里「没有稳定 Subject」那条
// 明拒理由的正面回答；第三条的理由：
//
// 绑定键必须等于被认证方真正认过的字符串。对大小写敏感的 RADIUS 后端（FreeRADIUS 接
// files/SQL 后端的默认姿态），"Alice" 与 "alice" 是**两个各有口令的账号**——此前 Subject
// 按小写归一，两个人会被白帝绑成同一个 Subject，后登者继承先登者的授权/JIT/封禁，审计里
// 是一次正常登录。反过来的代价（同一人换大小写登录建出两个账号）便宜且在用户目录页可见；
// 服务器侧不区分大小写的部署应在 RADIUS 侧规范化 User-Name，白帝不替它做。
func TestSubjectStableAndSourceIsolated(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers()})
	p := newProv(t, srv, nil)
	a1, err := p.Authenticate(ctx(t), "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	a1b, err := p.Authenticate(ctx(t), " alice ", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	if a1.Subject != a1b.Subject {
		t.Errorf("同一写法（首尾空白不算写法差异）两次登录 Subject 必须一致：%q vs %q", a1.Subject, a1b.Subject)
	}
	// 测试服务端对大小写不敏感（模拟 AD 后端），所以 "ALICE" 也能过；但白帝这边它是另一个 Subject——
	// 因为对大小写**敏感**的后端，它就是另一个账号，而白帝分不出对面是哪一种。
	a2, err := p.Authenticate(ctx(t), "ALICE", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	if a1.Subject == a2.Subject {
		t.Errorf("大小写不同的 User-Name 必须是不同 Subject（否则大小写敏感后端上的两个账号会被合并成一个）：%q", a1.Subject)
	}
	if a2.Subject != "radius:"+srcID+":ALICE" {
		t.Errorf("Subject 里的 User-Name 必须与发给服务器的逐字一致，得到 %q", a2.Subject)
	}
	// Username（建号用的账号名）仍小写归一：两个 Subject 会在 BindExternalUser 撞名分支各得一个账号，可见。
	if a1.Username != "alice" || a2.Username != "alice" {
		t.Errorf("Username 仍应走小写口径：%q / %q", a1.Username, a2.Username)
	}
	b, _ := p.Authenticate(ctx(t), "bob", "bob-pass")
	if b.Subject == a1.Subject {
		t.Error("不同用户的 Subject 撞了")
	}
	// 另一条源（同一台服务器也罢）里的 alice 是另一个身份。
	p2 := newProv(t, srv, func(c *Config) { c.SourceID = "src-radius-2" })
	a3, err := p2.Authenticate(ctx(t), "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	if a3.Subject == a1.Subject {
		t.Errorf("跨源 Subject 必须隔离（源 id 是那道墙），得到同一个 %q", a3.Subject)
	}
	if Subject("s", " Alice ") != "radius:s:Alice" {
		t.Errorf("Subject 只 trim 不改大小写：%q", Subject("s", " Alice "))
	}
}

// TestGroupValuesCapped 组属性值的入口上限：只考察前 32 个、单值 ≤128 字节，超出的整个丢弃。
//
// 把 Class 用作逐会话标识的服务器（Cisco ISE 的 CACS:<session>…）每次登录都回新值，
// 不设上限等于让对面决定我们这边的内存与表规模。
func TestGroupValuesCapped(t *testing.T) {
	many := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		many = append(many, "g"+strconv.Itoa(i))
	}
	long := strings.Repeat("x", maxGroupValueLen+1)
	exact := strings.Repeat("y", maxGroupValueLen)
	// 长值放在最前面：它占一个"考察名额"但被丢弃，后面 32 个里只剩 31 个进结果。
	groups := map[string][]string{
		"alice": append([]string{long, exact}, many...),
	}
	srv := startSrv(t, srvOpts{users: stdUsers(), groups: groups, groupAttr: "class"})
	p := newProv(t, srv, func(c *Config) { c.GroupAttr = GroupAttrClass })
	id, err := p.Authenticate(ctx(t), "alice", alicePass)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Groups) > maxGroupValues {
		t.Fatalf("组数应 ≤ %d，得到 %d", maxGroupValues, len(id.Groups))
	}
	joined := "," + strings.Join(id.Groups, ",") + ","
	if strings.Contains(joined, ","+long+",") {
		t.Errorf("超过 %d 字节的值应整个丢弃（不截断），却进了结果", maxGroupValueLen)
	}
	if !strings.Contains(joined, ","+exact+",") {
		t.Errorf("恰好 %d 字节的值是合法的，却被丢了", maxGroupValueLen)
	}
	// 前 32 个值 = long, exact, g0..g29；g30 起在名额之外。
	if !strings.Contains(joined, ",g29,") || strings.Contains(joined, ",g30,") {
		t.Errorf("应按报文顺序只考察前 %d 个值（g29 在、g30 不在），得到 %v", maxGroupValues, id.Groups)
	}
	if len(id.Groups) != maxGroupValues-1 {
		t.Errorf("32 个名额里 1 个是被丢弃的长值，结果应为 %d 个，得到 %d", maxGroupValues-1, len(id.Groups))
	}
}

// TestRetriesZeroSendsOnce 显式 Retries=0 = 只发一次不重发；<0 才是"取默认 1"。
// API 层的 radiusRetries 靠这条语义把「配置里缺席」与「管理员选了 0」分开。
func TestRetriesZeroSendsOnce(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), blackhole: true})
	p := newProv(t, srv, func(c *Config) { c.Retries = 0 })
	if p.cfg.Retries != 0 {
		t.Fatalf("显式 0 不该被归一成默认值，得到 %d", p.cfg.Retries)
	}
	start := time.Now()
	_, err := p.Authenticate(ctx(t), "alice", alicePass)
	spent := time.Since(start)
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("黑洞应为源不可用：%v", err)
	}
	if n := srv.count(radius.CodeAccessRequest); n != 1 {
		t.Errorf("Retries=0 应只发一份请求，服务端收到 %d", n)
	}
	// 预算 = 150ms × (0+1)：明显短于 Retries=1 的 300ms。
	if spent > 260*time.Millisecond {
		t.Errorf("Retries=0 的预算应约 150ms，实际 %v（像是按默认 1 算成了 300ms）", spent)
	}
	// 对照：<0 取默认 1 → 两份。
	p1 := newProv(t, srv, func(c *Config) { c.Retries = -1 })
	if p1.cfg.Retries != defaultRetries {
		t.Fatalf("负数应取默认 %d，得到 %d", defaultRetries, p1.cfg.Retries)
	}
}

// TestNewClientRetryTimer 「显式 retries=0 只发一份」的**确定性**守卫：直接断库客户端的重发计时器。
//
// ★为什么不能只靠上面那条数报文的用例：Retries=0 时预算恰好等于 Timeout×1，库里的重发计时器
// 与 ctx 截止**同时**触发，select 二选一随机——把 newClient 里 `client.Retry = 0` 那行删掉，
// 实测只有约一半的跑次会红（复审员 2/6、本次 3/6）；而本用例在同一变异下 10/10 红。
// 「显式 0 只发一次」被 CLAUDE.md、docs/ARCHITECTURE.md 第七节与本包注释
// 三处当成事实写着，守卫必须每次都红。报文计数那条保留作端到端补充（它证明这个字段真的管用）。
func TestNewClientRetryTimer(t *testing.T) {
	base := Config{SourceID: srcID, Host: "127.0.0.1", Secret: "x", Timeout: 150 * time.Millisecond, Logger: discardLogger()}
	for _, tc := range []struct {
		name    string
		retries int
		want    time.Duration
	}{
		{"显式0_关掉重发计时器", 0, 0},
		{"1_按单次超时周期重发", 1, 150 * time.Millisecond},
		{"3_同上", 3, 150 * time.Millisecond},
		{"负数_归一成默认1", -1, 150 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.Retries = tc.retries
			p, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.newClient().Retry; got != tc.want {
				t.Errorf("Retries=%d 时 radius.Client.Retry 应为 %v，得到 %v", tc.retries, tc.want, got)
			}
		})
	}
}

// ── 探测 ───────────────────────────────────────────────────────────────────

func TestProbeStatusServer(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), statusServer: true})
	rep, err := newProv(t, srv, nil).ProbeDetail(ctx(t))
	if err != nil {
		t.Fatalf("Status-Server 应答正常却报错：%v", err)
	}
	if rep.Method != ProbeMethodStatusServer {
		t.Errorf("方法应为 status-server，得到 %q", rep.Method)
	}
	if srv.count(radius.CodeAccessRequest) != 0 {
		t.Error("Status-Server 已应答，不该再打回退用的 Access-Request（那会在对面留一条失败登录）")
	}
}

// TestProbeFallbackRejectMeansReachable 老服务器不认 Status-Server：回退一次探测用
// Access-Request，Access-Reject 判成"可达"，且结论里说清是哪一种。
func TestProbeFallbackRejectMeansReachable(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers()}) // statusServer=false
	rep, err := newProv(t, srv, nil).ProbeDetail(ctx(t))
	if err != nil {
		t.Fatalf("回退路径收到 Access-Reject 应判可达，却报错：%v", err)
	}
	if rep.Method != ProbeMethodAccessRequest {
		t.Errorf("方法应为 access-request，得到 %q", rep.Method)
	}
	for _, want := range []string{"Access-Reject", "失败登录", "不支持 Status-Server"} {
		if !strings.Contains(rep.Detail, want) {
			t.Errorf("回退结论应提到「%s」，得到：%s", want, rep.Detail)
		}
	}
	if srv.count(radius.CodeStatusServer) == 0 || srv.count(radius.CodeAccessRequest) == 0 {
		t.Errorf("应先 Status-Server 再回退 Access-Request，实际计数 %v", srv.codes)
	}
}

func TestProbeTimeoutIsUnreachable(t *testing.T) {
	srv := startSrv(t, srvOpts{users: stdUsers(), blackhole: true})
	rep, err := newProv(t, srv, nil).ProbeDetail(ctx(t))
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("两种探测都超时应判不可达：%v", err)
	}
	if !strings.Contains(err.Error(), "均无应答") {
		t.Errorf("文案应写明两种探测都无应答：%v", err)
	}
	if rep.Method != ProbeMethodAccessRequest {
		t.Errorf("最后一次尝试的是回退路径，Method 应为 access-request，得到 %q", rep.Method)
	}
}

// TestProbeWrongSecret 共享密钥不匹配的两副面孔，两副都必须判成"不可用 + 点名共享密钥"：
//   - 宽松服务器（不校验请求 MA）：回一份用它的密钥签的应答 → 校验失败 → 结论已定，**不再回退**；
//   - 严格服务器（FreeRADIUS 姿态）：MA 校验不过就静默丢包 → 两种探测都超时 → 文案里
//     必须把"共享密钥不匹配"列为可能成因，否则管理员只会去查网络。
func TestProbeWrongSecret(t *testing.T) {
	t.Run("宽松服务器_应答校验失败_不回退", func(t *testing.T) {
		srv := startSrv(t, srvOpts{users: stdUsers(), statusServer: true, secret: "other", noRequireReqMA: true})
		_, err := newProv(t, srv, nil).ProbeDetail(ctx(t))
		if !errors.Is(err, authsrc.ErrSourceUnavailable) || !strings.Contains(err.Error(), "共享密钥") {
			t.Fatalf("密钥不匹配应判不可用并点名共享密钥：%v", err)
		}
		if errors.Is(err, errNoResponse) {
			t.Errorf("服务器有应答（只是校验不过），不该被报成无应答：%v", err)
		}
		if srv.count(radius.CodeAccessRequest) != 0 {
			t.Error("密钥不匹配已成结论，不该再打回退 Access-Request")
		}
	})
	t.Run("严格服务器_静默丢包_文案点名密钥", func(t *testing.T) {
		srv := startSrv(t, srvOpts{users: stdUsers(), statusServer: true, secret: "other"})
		_, err := newProv(t, srv, nil).ProbeDetail(ctx(t))
		if !errors.Is(err, authsrc.ErrSourceUnavailable) || !errors.Is(err, errNoResponse) {
			t.Fatalf("严格服务器对错密钥静默丢包，应表现为无应答：%v", err)
		}
		if !strings.Contains(err.Error(), "共享密钥") {
			t.Errorf("无应答的文案必须把共享密钥不匹配列为可能成因：%v", err)
		}
	})
}

// TestProbeAcceptAllIsNotGreen 随机探测账号竟被放行：那台服务器可能对任何人放行，
// 绿灯会替它背书，必须判失败并点名。
func TestProbeAcceptAllIsNotGreen(t *testing.T) {
	srv := startSrv(t, srvOpts{acceptAll: true})
	_, err := newProv(t, srv, nil).ProbeDetail(ctx(t))
	if err == nil || !strings.Contains(err.Error(), "放行") {
		t.Fatalf("随机账号被 Accept 应判失败并说明原因，得到 %v", err)
	}
	if errors.Is(err, authsrc.ErrInvalidCredentials) || errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Errorf("这不是凭据错也不是源不可用，是服务端策略问题，不该挂在两个哨兵上：%v", err)
	}
}

// ── 配置校验 ────────────────────────────────────────────────────────────────

func TestNewValidation(t *testing.T) {
	base := Config{SourceID: srcID, Host: "127.0.0.1", Secret: "x", Logger: discardLogger()}
	cases := map[string]func(*Config){
		"缺源 id":   func(c *Config) { c.SourceID = "" },
		"缺主机":     func(c *Config) { c.Host = "" },
		"缺共享密钥":   func(c *Config) { c.Secret = "" },
		"端口越界":    func(c *Config) { c.Port = 70000 },
		"协议未知":    func(c *Config) { c.Protocol = "eap" },
		"组属性未知":   func(c *Config) { c.GroupAttr = "vendor-x" },
		"重发次数超上限": func(c *Config) { c.Retries = 99 },
	}
	for name, mut := range cases {
		c := base
		mut(&c)
		if _, err := New(c); !errors.Is(err, authsrc.ErrNotConfigured) {
			t.Errorf("%s：应为 ErrNotConfigured，得到 %v", name, err)
		}
	}
	p, err := New(base)
	if err != nil {
		t.Fatalf("最小合法配置应通过：%v", err)
	}
	if p.cfg.Port != 1812 || p.cfg.Protocol != ProtocolPAP || p.cfg.NASIdentifier != defaultNASIdentifier {
		t.Errorf("默认值：port=%d protocol=%s nas=%s", p.cfg.Port, p.cfg.Protocol, p.cfg.NASIdentifier)
	}
}
