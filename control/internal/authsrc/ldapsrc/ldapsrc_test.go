package ldapsrc

// 端到端用例：客户端是生产代码本身，服务端是进程内的真实 LDAP 服务端（testdir_test.go）。
// 每一条断言都对着 ldapsrc.go 里标了 ★ 的那些安全点。

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/authsrc"
)

const (
	baseDN    = "ou=people,dc=corp,dc=example"
	svcDN     = "cn=svc,dc=corp,dc=example"
	svcPW     = "svc-pass"
	aliceDN   = "uid=alice,ou=people,dc=corp,dc=example"
	alicePass = "alice-pass"
)

func personAttrs(uid, cn, mail string) map[string][]string {
	return map[string][]string{
		"objectClass": {"person"},
		"uid":         {uid},
		"cn":          {cn},
		"mail":        {mail},
		"memberOf":    {"cn=eng,ou=groups,dc=corp,dc=example"},
	}
}

// baseEntry 让 Probe 的 scope=base 搜索能命中 Base DN 自身。
func baseEntry() dirEntry {
	return dirEntry{DN: baseDN, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"people"}}}
}

func stdDir(t *testing.T, mutate func(*dirOpts)) *testDir {
	t.Helper()
	o := dirOpts{
		baseDNs:   []string{baseDN},
		serviceDN: svcDN,
		servicePW: svcPW,
		entries: []dirEntry{
			baseEntry(),
			{DN: aliceDN, Attrs: personAttrs("alice", "Alice Zhang", "Alice@Corp.Example"), Pass: alicePass},
			{DN: "uid=bob,ou=people,dc=corp,dc=example", Attrs: personAttrs("bob", "Bob Li", "bob@corp.example"), Pass: "bob-pass"},
		},
	}
	if mutate != nil {
		mutate(&o)
	}
	return startDir(t, o)
}

// discardLogger 默认丢弃日志；需要断言日志内容的用例用 captureLogger。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func cfgFor(d *testDir) Config {
	return Config{
		Kind:           authsrc.KindLDAP,
		Host:           "127.0.0.1",
		Port:           d.port,
		TLS:            TLSModePlaintext, // 测试用明文；TLS 路径由专门的用例覆盖
		BindDN:         d.opts.serviceDN,
		BindPassword:   d.opts.servicePW,
		BaseDN:         baseDN,
		ConnectTimeout: 3 * time.Second,
		RequestTimeout: 3 * time.Second,
		Logger:         discardLogger(),
	}
}

func newProvider(t *testing.T, c Config) *Provider {
	t.Helper()
	p, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// ── 成功路径 ───────────────────────────────────────────────────────────────

func TestAuthenticate_成功(t *testing.T) {
	d := stdDir(t, nil)
	p := newProvider(t, cfgFor(d))

	id, err := p.Authenticate(ctx(t), "alice", alicePass)
	if err != nil {
		t.Fatalf("认证应当成功: %v", err)
	}
	// ★ Subject 必须是认证源侧的权威标识（entryDN），账号映射以它为准。
	if id.Subject != aliceDN {
		t.Fatalf("Subject = %q，期望 entryDN %q", id.Subject, aliceDN)
	}
	if id.Username != "alice" {
		t.Fatalf("Username = %q，期望 alice", id.Username)
	}
	// Identity.Normalized 会把邮箱转小写，目录里存的是 Alice@Corp.Example。
	if id.Email != "alice@corp.example" {
		t.Fatalf("Email = %q，期望规范化后的小写形式", id.Email)
	}
	if id.DisplayName != "Alice Zhang" {
		t.Fatalf("DisplayName = %q", id.DisplayName)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "cn=eng,ou=groups,dc=corp,dc=example" {
		t.Fatalf("Groups = %v", id.Groups)
	}

	// 用户 bind 必须真的发生过，且用的是目录返回的 DN（不是拼出来的）。
	ub := d.UserBinds()
	if len(ub) != 1 || ub[0].DN != aliceDN {
		t.Fatalf("用户 bind 记录 = %v，期望恰好一次且 DN=%s", ub, aliceDN)
	}
}

func TestAuthenticate_大小写与空白被规范化(t *testing.T) {
	d := stdDir(t, nil)
	p := newProvider(t, cfgFor(d))
	// 用户名两侧带空白应被 trim；目录里的 uid 匹配大小写不敏感（求值器按 EqualFold）。
	id, err := p.Authenticate(ctx(t), "  Alice  ", alicePass)
	if err != nil {
		t.Fatalf("认证应当成功: %v", err)
	}
	if id.Username != "alice" {
		t.Fatalf("Username = %q，期望 alice", id.Username)
	}
}

// ── 凭据类失败 ─────────────────────────────────────────────────────────────

func TestAuthenticate_口令错误(t *testing.T) {
	d := stdDir(t, nil)
	p := newProvider(t, cfgFor(d))

	_, err := p.Authenticate(ctx(t), "alice", "wrong")
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("err = %v，期望 ErrInvalidCredentials", err)
	}
	if errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatal("口令错误不能同时被判成「源不可用」，否则登录失败计数与告警都会错位")
	}
}

func TestAuthenticate_用户不存在(t *testing.T) {
	d := stdDir(t, nil)
	p := newProvider(t, cfgFor(d))

	_, err := p.Authenticate(ctx(t), "nobody", "whatever")
	// ★与"口令错误"刻意同一个错误：区分开就成了用户名枚举接口。
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("err = %v，期望 ErrInvalidCredentials", err)
	}
	if len(d.UserBinds()) != 0 {
		t.Fatalf("用户不存在时不应发生任何用户 bind，实际 = %v", d.UserBinds())
	}
}

// ── ★空口令必须被拒 ────────────────────────────────────────────────────────

func TestAuthenticate_空口令必须被拒(t *testing.T) {
	// 服务端故意实现成"有 DN + 空口令 = 匿名 bind，回 success"，
	// 也就是那个经典的认证绕过。生产代码若把空口令放过去，这个用例就会认证成功。
	d := stdDir(t, func(o *dirOpts) { o.anonymousOnEmptyPassword = true })

	lg, logs := captureLogger()
	c := cfgFor(d)
	c.Logger = lg
	p := newProvider(t, c)

	id, err := p.Authenticate(ctx(t), "alice", "")
	if err == nil {
		t.Fatalf("★认证绕过：空口令居然登录成功了，Identity=%+v", id)
	}
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("err = %v，期望 ErrInvalidCredentials", err)
	}
	// 更强的断言：连接都不该建立——空口令要在发出任何报文**之前**被拦下。
	if got := d.Binds(); len(got) != 0 {
		t.Fatalf("★空口令请求被送到了目录服务器上（bind 记录 %v），必须在客户端就拦下", got)
	}
	if got := d.Filters(); len(got) != 0 {
		t.Fatalf("空口令请求不该触发任何搜索，实际 = %v", got)
	}
	if !strings.Contains(logs.String(), "空口令") {
		t.Fatalf("空口令拒绝应当留下告警日志，实际日志：%s", logs.String())
	}
}

// ── ★LDAP 注入 ─────────────────────────────────────────────────────────────

func TestAuthenticate_用户名注入被转义(t *testing.T) {
	d := stdDir(t, nil)
	p := newProvider(t, cfgFor(d))

	// 这个载荷若不转义，拼出来是 (&(objectClass=person)(uid=*)(uid=*))，
	// 会命中目录里第一个 person（alice 或 bob），随后拿它的 DN 去 bind。
	_, err := p.Authenticate(ctx(t), "*)(uid=*", "whatever")
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("err = %v，期望 ErrInvalidCredentials（注入载荷不该匹配到任何人）", err)
	}

	fs := d.Filters()
	if len(fs) != 1 {
		t.Fatalf("期望恰好一次搜索，实际 %v", fs)
	}
	// 服务端收到的是**编解码之后**的过滤器：载荷已经是一个字面断言值，
	// 而不是被解析成 (uid=*)(uid=*) 那样的结构。这一条才是"协议层真的被转义了"的证据。
	want := `(&(objectClass=person)(uid=\2a\29\28uid=\2a))`
	if fs[0] != want {
		t.Fatalf("★服务端收到的过滤器 = %q，期望 %q", fs[0], want)
	}
	if ub := d.UserBinds(); len(ub) != 0 {
		t.Fatalf("★注入尝试导致了对真实用户 DN 的 bind：%v", ub)
	}
}

func TestAuthenticate_单个星号不能匹配任意用户(t *testing.T) {
	d := stdDir(t, nil)
	p := newProvider(t, cfgFor(d))

	_, err := p.Authenticate(ctx(t), "*", alicePass)
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("err = %v，期望 ErrInvalidCredentials（* 必须是字面量而不是通配符）", err)
	}
	if ub := d.UserBinds(); len(ub) != 0 {
		t.Fatalf("★用户名 \"*\" 触发了对真实用户的 bind：%v", ub)
	}
}

// ── ★命中多条必须拒 ────────────────────────────────────────────────────────

func dupDir(t *testing.T, n int, mutate func(*dirOpts)) *testDir {
	t.Helper()
	o := dirOpts{
		baseDNs:   []string{baseDN},
		serviceDN: svcDN,
		servicePW: svcPW,
		entries:   []dirEntry{baseEntry()},
	}
	for i := 0; i < n; i++ {
		dn := "uid=dup" + string(rune('a'+i)) + ",ou=people,dc=corp,dc=example"
		// 三条条目的 uid 属性都是 dup —— 过滤器写宽了的真实形态。
		o.entries = append(o.entries, dirEntry{
			DN:    dn,
			Attrs: personAttrs("dup", "Dup "+string(rune('A'+i)), "dup@corp.example"),
			Pass:  "dup-pass",
		})
	}
	if mutate != nil {
		mutate(&o)
	}
	return startDir(t, o)
}

func TestAuthenticate_命中多条必须拒(t *testing.T) {
	d := dupDir(t, 2, nil)
	lg, logs := captureLogger()
	c := cfgFor(d)
	c.Logger = lg
	p := newProvider(t, c)

	// 注意：口令是**对的**。也就是说"挑第一条去 bind"的实现会在这里认证成功，
	// 用户以为登录成了 dupa、实际可能是 dupb，两侧日志都看不出异常。
	_, err := p.Authenticate(ctx(t), "dup", "dup-pass")
	if err == nil {
		t.Fatal("★过滤器命中多条时认证居然成功了：用户会以为自己登录成了 A、实际认证的是 B")
	}
	if !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("err = %v，期望 ErrNotConfigured（这是过滤器/目录数据问题，不是用户口令问题）", err)
	}
	if errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatal("命中多条不能报成「密码错误」，那会把运维引去查用户而不是查过滤器")
	}
	if ub := d.UserBinds(); len(ub) != 0 {
		t.Fatalf("★命中多条时不该对任何条目发起 bind，实际 = %v", ub)
	}
	if !strings.Contains(logs.String(), "命中多个条目") {
		t.Fatalf("命中多条应当在服务端日志里留下可归因的记录，实际日志：%s", logs.String())
	}
}

func TestAuthenticate_服务端回SizeLimitExceeded也算命中多条(t *testing.T) {
	// 服务端守约按 sizeLimit=2 截断，并在 searchDone 里回 4 号码。
	// 结果被截断 = 至少还有我们没看到的条目 → 唯一性无法确认 → 必须拒。
	// 若把 4 号码当普通错误吞掉、或把截断后的第一条拿去 bind，就又回到"登成了 B"的老路。
	d := dupDir(t, 3, nil)
	p := newProvider(t, cfgFor(d))

	_, err := p.Authenticate(ctx(t), "dup", "dup-pass")
	if !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("err = %v，期望 ErrNotConfigured", err)
	}
	if ub := d.UserBinds(); len(ub) != 0 {
		t.Fatalf("★不该对任何条目发起 bind，实际 = %v", ub)
	}
}

func TestAuthenticate_服务端无视SizeLimit时客户端仍须拒(t *testing.T) {
	// sizeLimit 在协议里只是建议值，服务端可以合法地无视它。
	// 只指望服务端守约的话，"命中多条即拒"这道闸就形同虚设。
	d := dupDir(t, 3, func(o *dirOpts) { o.ignoreSizeLimit = true })
	p := newProvider(t, cfgFor(d))

	_, err := p.Authenticate(ctx(t), "dup", "dup-pass")
	if !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("err = %v，期望 ErrNotConfigured", err)
	}
	if ub := d.UserBinds(); len(ub) != 0 {
		t.Fatalf("★不该对任何条目发起 bind，实际 = %v", ub)
	}
}

// ── ★空 DN 条目 ────────────────────────────────────────────────────────────

func TestAuthenticate_空DN条目必须被拒(t *testing.T) {
	d := stdDir(t, func(o *dirOpts) {
		o.blankDN = true
		// 空 DN 去 bind 时，服务端若把它当匿名处理就会回成功——那就是任何口令登任何号。
		o.anonymousOnEmptyPassword = true
	})
	p := newProvider(t, cfgFor(d))

	_, err := p.Authenticate(ctx(t), "alice", alicePass)
	if err == nil {
		t.Fatal("★目录返回空 DN 时认证居然成功了：空 DN 的 bind 可能被服务端当作匿名并回成功")
	}
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("err = %v，期望 ErrSourceUnavailable（目录返回了非法条目，属源异常）", err)
	}
	if ub := d.UserBinds(); len(ub) != 0 {
		t.Fatalf("★空 DN 被送去 bind 了：%v", ub)
	}
}

// ── ★错误分类：源不可用 ────────────────────────────────────────────────────

func TestAuthenticate_服务端不可达(t *testing.T) {
	port := freePort(t) // 拿一个空闲端口但**不**在上面监听
	c := Config{
		Host: "127.0.0.1", Port: port, TLS: TLSModePlaintext,
		BindDN: svcDN, BindPassword: svcPW, BaseDN: baseDN,
		ConnectTimeout: time.Second, RequestTimeout: time.Second,
		Logger: discardLogger(),
	}
	p := newProvider(t, c)

	_, err := p.Authenticate(ctx(t), "alice", alicePass)
	// ★这里若回 ErrInvalidCredentials，症状就是"AD 挂了，全公司看到密码错误"。
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("err = %v，期望 ErrSourceUnavailable", err)
	}
	if errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatal("★目录不可达绝不能报成「用户名或密码错误」，那会让运维去查用户而不是查目录")
	}
	if err := p.Probe(ctx(t)); !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("Probe err = %v，期望 ErrSourceUnavailable", err)
	}
}

func TestAuthenticate_服务账号口令错是配置故障(t *testing.T) {
	d := stdDir(t, nil)
	lg, logs := captureLogger()
	c := cfgFor(d)
	c.BindPassword = "wrong-svc-pass"
	c.Logger = lg
	p := newProvider(t, c)

	_, err := p.Authenticate(ctx(t), "alice", alicePass)
	if errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatal("★服务账号口令错报成了「用户名或密码错误」：服务账号一到期全公司同时「密码错误」，而每个人的密码都是对的")
	}
	if !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("err = %v，期望 ErrNotConfigured", err)
	}
	if !strings.Contains(logs.String(), "服务账号") {
		t.Fatalf("服务账号 bind 失败应当在日志里明确指出，实际日志：%s", logs.String())
	}
}

// ── Probe ──────────────────────────────────────────────────────────────────

func TestProbe_成功(t *testing.T) {
	d := stdDir(t, nil)
	p := newProvider(t, cfgFor(d))
	if err := p.Probe(ctx(t)); err != nil {
		t.Fatalf("Probe 应当成功: %v", err)
	}
	// Probe 不校验任何用户凭据：只能出现服务账号那一次 bind。
	if ub := d.UserBinds(); len(ub) != 0 {
		t.Fatalf("Probe 不应对用户条目发起 bind，实际 = %v", ub)
	}
}

func TestProbe_BaseDN写错(t *testing.T) {
	d := stdDir(t, nil)
	c := cfgFor(d)
	c.BaseDN = "ou=nonexistent,dc=corp,dc=example"
	p := newProvider(t, c)

	err := p.Probe(ctx(t))
	// ★这正是"测试连接"最该抓住的问题：连得上、服务账号也 bind 成功，
	// 但 BaseDN 写错 → 之后每个用户都搜不到 → 表现为"所有人密码都不对"。
	if !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("Probe err = %v，期望 ErrNotConfigured（Base DN 不存在）", err)
	}
}

func TestProbe_服务账号口令错(t *testing.T) {
	d := stdDir(t, nil)
	c := cfgFor(d)
	c.BindPassword = "nope"
	p := newProvider(t, c)

	if err := p.Probe(ctx(t)); !errors.Is(err, authsrc.ErrNotConfigured) {
		t.Fatalf("Probe err = %v，期望 ErrNotConfigured", err)
	}
}

// ── TLS ────────────────────────────────────────────────────────────────────

func TestAuthenticate_LDAPS(t *testing.T) {
	serverTLS, caPEM := selfSignedTLS(t)
	d := stdDir(t, func(o *dirOpts) {
		o.tlsCfg = serverTLS
		o.ldaps = true
	})
	c := cfgFor(d)
	c.TLS = TLSModeLDAPS
	c.CACert = caPEM
	c.ServerName = "localhost" // 证书里签的是 localhost / 127.0.0.1
	p := newProvider(t, c)

	if _, err := p.Authenticate(ctx(t), "alice", alicePass); err != nil {
		t.Fatalf("LDAPS 认证应当成功: %v", err)
	}
}

func TestAuthenticate_StartTLS(t *testing.T) {
	serverTLS, caPEM := selfSignedTLS(t)
	d := stdDir(t, func(o *dirOpts) { o.tlsCfg = serverTLS })
	c := cfgFor(d)
	c.TLS = TLSModeStartTLS
	c.CACert = caPEM
	c.ServerName = "localhost"
	p := newProvider(t, c)

	if _, err := p.Authenticate(ctx(t), "alice", alicePass); err != nil {
		t.Fatalf("StartTLS 认证应当成功: %v", err)
	}
}

func TestAuthenticate_StartTLS协商失败不得降级明文(t *testing.T) {
	// 服务端不支持 StartTLS（没配 tlsCfg，扩展操作没有路由）。
	d := stdDir(t, nil)
	c := cfgFor(d)
	c.TLS = TLSModeStartTLS
	p := newProvider(t, c)

	_, err := p.Authenticate(ctx(t), "alice", alicePass)
	if err == nil {
		t.Fatal("★StartTLS 协商失败后仍然认证成功，说明降级成了明文——用户口令会被明文发出去")
	}
	if !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("err = %v，期望 ErrSourceUnavailable", err)
	}
	// 没有任何 bind 打出去 = 口令没上过网线。
	if got := d.Binds(); len(got) != 0 {
		t.Fatalf("★StartTLS 失败后仍发出了 bind（口令走了明文）：%v", got)
	}
}

func TestAuthenticate_证书不受信必须失败(t *testing.T) {
	serverTLS, _ := selfSignedTLS(t)
	_, otherCA := selfSignedTLS(t) // 另一把无关的 CA
	d := stdDir(t, func(o *dirOpts) {
		o.tlsCfg = serverTLS
		o.ldaps = true
	})
	c := cfgFor(d)
	c.TLS = TLSModeLDAPS
	c.CACert = otherCA
	c.ServerName = "localhost"
	p := newProvider(t, c)

	if _, err := p.Authenticate(ctx(t), "alice", alicePass); !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("err = %v，期望 ErrSourceUnavailable（证书链校验失败）", err)
	}

	// 开了逃生舱就能连上——这正是它"危险但存在"的意义，同时必须打 WARN。
	lg, logs := captureLogger()
	c.InsecureSkipVerify = true
	c.Logger = lg
	p2 := newProvider(t, c)
	if _, err := p2.Authenticate(ctx(t), "alice", alicePass); err != nil {
		t.Fatalf("开启 InsecureSkipVerify 后应当能连上: %v", err)
	}
	if !strings.Contains(logs.String(), "跳过了服务端证书校验") {
		t.Fatalf("★InsecureSkipVerify 必须打 WARN，实际日志：%s", logs.String())
	}
}

func TestNew_明文模式必须告警(t *testing.T) {
	lg, logs := captureLogger()
	c := Config{Host: "127.0.0.1", Port: 389, TLS: TLSModePlaintext, BaseDN: baseDN, Logger: lg}
	if _, err := New(c); err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.Contains(logs.String(), "明文连接") {
		t.Fatalf("★明文 LDAP 必须打 WARN（口令会明文上网线），实际日志：%s", logs.String())
	}
}

func TestNew_默认走TLS(t *testing.T) {
	// 不填 TLS 字段时必须落到 ldaps:636，而不是明文 389。
	// 默认值决定了"没人特意配置时"的安全水位。
	c := Config{Host: "ldap.corp.example", BaseDN: baseDN, Logger: discardLogger()}
	p, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.cfg.TLS != TLSModeLDAPS {
		t.Fatalf("默认 TLS 模式 = %q，期望 ldaps", p.cfg.TLS)
	}
	if p.cfg.Port != 636 {
		t.Fatalf("默认端口 = %d，期望 636", p.cfg.Port)
	}
}

// ── 配置校验 ───────────────────────────────────────────────────────────────

func TestNew_配置错误一律归为ErrNotConfigured(t *testing.T) {
	ok := Config{Host: "h", BaseDN: baseDN, Logger: discardLogger()}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"缺服务器地址", func(c *Config) { c.Host = "" }},
		{"缺 Base DN", func(c *Config) { c.BaseDN = "" }},
		{"传输方式非法", func(c *Config) { c.TLS = "tls" }},
		// ★服务账号有 DN 却没口令：多数目录会把它当匿名 bind 并回成功，
		// 于是我们以为在用服务账号搜索、实际是匿名身份（表现为"部分用户查不到"）。
		{"服务账号有 DN 但口令为空", func(c *Config) { c.BindDN = svcDN; c.BindPassword = "" }},
		{"过滤器缺占位符", func(c *Config) { c.UserFilter = "(uid=alice)" }},
		{"过滤器语法非法", func(c *Config) { c.UserFilter = "(&(uid=" + usernamePlaceholder + ")" }},
		{"CA 证书不是合法 PEM", func(c *Config) { c.CACert = "not a pem" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ok
			tc.mutate(&c)
			_, err := New(c)
			if !errors.Is(err, authsrc.ErrNotConfigured) {
				t.Fatalf("err = %v，期望 ErrNotConfigured", err)
			}
		})
	}

	if _, err := New(ok); err != nil {
		t.Fatalf("基准配置本身应当合法: %v", err)
	}
}

func TestNew_匿名搜索必须告警(t *testing.T) {
	lg, logs := captureLogger()
	c := Config{Host: "h", BaseDN: baseDN, Logger: lg}
	if _, err := New(c); err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.Contains(logs.String(), "匿名身份搜索") {
		t.Fatalf("未配服务账号应当告警，实际日志：%s", logs.String())
	}
}

func TestAuthenticate_超长用户名被拒且不落到目录上(t *testing.T) {
	d := stdDir(t, nil)
	p := newProvider(t, cfgFor(d))

	_, err := p.Authenticate(ctx(t), strings.Repeat("a", maxUsernameLen+1), "pw")
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("err = %v，期望 ErrInvalidCredentials", err)
	}
	if got := d.Filters(); len(got) != 0 {
		t.Fatalf("超长用户名不该触发搜索，实际 = %v", got)
	}
}

// ── AD 方言 ────────────────────────────────────────────────────────────────

const (
	adBase   = "ou=users,dc=corp,dc=example"
	carolDN  = "cn=carol,ou=users,dc=corp,dc=example"
	daveDN   = "cn=dave,ou=users,dc=corp,dc=example"
	adSvcDN  = "cn=svc,dc=corp,dc=example"
	adSvcPW  = "ad-svc"
	carolPW  = "carol-pass"
	adDiag99 = "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 533, v2580"
)

func adAttrs(sam, upn, cn string) map[string][]string {
	return map[string][]string{
		"objectClass":       {"user"},
		"sAMAccountName":    {sam},
		"userPrincipalName": {upn},
		"cn":                {cn},
		"mail":              {upn},
		"memberOf":          {"cn=Sales,ou=groups,dc=corp,dc=example"},
	}
}

func adDir(t *testing.T) *testDir {
	t.Helper()
	return startDir(t, dirOpts{
		baseDNs:   []string{adBase},
		serviceDN: adSvcDN,
		servicePW: adSvcPW,
		entries: []dirEntry{
			{DN: adBase, Attrs: map[string][]string{"objectClass": {"organizationalUnit"}}},
			{DN: carolDN, Attrs: adAttrs("carol", "carol@corp.example", "Carol Wang"), Pass: carolPW},
			// dave 的口令永远不对，且带上 AD 的 data 533（账号已禁用）诊断串。
			{DN: daveDN, Attrs: adAttrs("dave", "dave@corp.example", "Dave Sun"), BindDiag: adDiag99},
		},
	})
}

func adCfg(d *testDir) Config {
	return Config{
		Kind: authsrc.KindAD,
		Host: "127.0.0.1", Port: d.port, TLS: TLSModePlaintext,
		BindDN: adSvcDN, BindPassword: adSvcPW, BaseDN: adBase,
		ConnectTimeout: 3 * time.Second, RequestTimeout: 3 * time.Second,
		Logger: discardLogger(),
	}
}

func TestAD_默认属性用sAMAccountName(t *testing.T) {
	d := adDir(t)
	p := newProvider(t, adCfg(d))

	id, err := p.Authenticate(ctx(t), "carol", carolPW)
	if err != nil {
		// ★照通用 LDAP 抄 uid/posixAccount 的话，这里就是"连得上、服务账号也 bind 成功了，
		// 但所有人都查不到"——AD 默认 schema 里压根没有 uid。
		t.Fatalf("AD 认证应当成功: %v", err)
	}
	if id.Subject != carolDN {
		t.Fatalf("Subject = %q，期望 %q", id.Subject, carolDN)
	}
	if id.Username != "carol" {
		t.Fatalf("Username = %q，期望 sAMAccountName carol", id.Username)
	}
}

func TestAD_支持UPN形式登录(t *testing.T) {
	d := adDir(t)
	p := newProvider(t, adCfg(d))

	// AD 用户习惯输入 carol@corp.example 这种 UPN 形式。
	id, err := p.Authenticate(ctx(t), "carol@corp.example", carolPW)
	if err != nil {
		t.Fatalf("UPN 形式登录应当成功: %v", err)
	}
	// 回填的 Username 仍然是 sAMAccountName——本地账号映射口径要稳定。
	if id.Username != "carol" {
		t.Fatalf("Username = %q，期望 carol", id.Username)
	}
}

func TestAD_账号禁用对用户仍是凭据错但日志要解出data码(t *testing.T) {
	d := adDir(t)
	lg, logs := captureLogger()
	c := adCfg(d)
	c.Logger = lg
	p := newProvider(t, c)

	_, err := p.Authenticate(ctx(t), "dave", "any")
	// 对用户侧：仍然只回统一文案，不构成账号状态枚举。
	if !errors.Is(err, authsrc.ErrInvalidCredentials) {
		t.Fatalf("err = %v，期望 ErrInvalidCredentials", err)
	}
	// 对运维侧：★必须能从日志看出是"账号被禁用"，否则会顺着"用户忘了密码"查一整天。
	s := logs.String()
	if !strings.Contains(s, "533") {
		t.Fatalf("日志里应当出现 AD data 码 533，实际：%s", s)
	}
	if !strings.Contains(s, "账号已被禁用") {
		t.Fatalf("日志里应当把 533 解释成「账号已被禁用」，实际：%s", s)
	}
}

// ── 杂项：确保测试里用到的地址工具没有把端口算错 ──────────────────────────

func TestDialTimeout_ctx已过期时不会退化成永不超时(t *testing.T) {
	p := newProvider(t, Config{Host: "h", BaseDN: baseDN, Logger: discardLogger()})
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	// ★net.Dialer.Timeout == 0 的语义是"没有超时"。ctx 已过期时算出来正好是负数，
	// 直接塞进去就变成永不超时——本该毫秒级失败的拨号会挂死。
	if d := p.dialTimeout(expired); d <= 0 {
		t.Fatalf("dialTimeout = %v，必须为正值", d)
	}
}

func TestTimeLimitSeconds_不会向下取整到0(t *testing.T) {
	p := newProvider(t, Config{Host: "h", BaseDN: baseDN, RequestTimeout: 800 * time.Millisecond, Logger: discardLogger()})
	// LDAP 协议里 timeLimit=0 表示"不限时"，与 dialTimeout 那个坑同源。
	if got := p.timeLimitSeconds(); got < 1 {
		t.Fatalf("timeLimitSeconds = %d，必须 ≥ 1", got)
	}
}
