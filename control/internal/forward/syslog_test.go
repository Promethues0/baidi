package forward

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/control/internal/store"
)

// ── 进程内 syslog 接收端 ──
//
// ★这些用例刻意**不测格式化函数**，而是真的起一个 TCP 服务端、真的解帧、
// 真的把 RFC 5424 报文拆成字段来断言。只测 message() 的话，
// 「帧写错了导致收集端整段解析不出来」这类缺陷一条都发现不了——
// 而那正是审计外送最容易出的问题（它在发送方看来完全成功）。

// syslogSink 起一个接收端，返回监听地址与「取到目前为止收到的全部报文」。
// framing 决定它怎么切帧；切错帧就会拿到垃圾，正好也是一种断言。
func syslogSink(t *testing.T, framing Framing, tlsCfg *tls.Config) (string, func() []string) {
	t.Helper()
	var ln net.Listener
	var err error
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	var mu sync.Mutex
	var msgs []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				got, rerr := readFrames(conn, framing)
				if rerr != nil && rerr != io.EOF {
					return
				}
				mu.Lock()
				msgs = append(msgs, got...)
				mu.Unlock()
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, msgs...)
	}
}

// readFrames 按帧方式把一条连接上的字节流切成若干条 syslog 报文。
func readFrames(r io.Reader, framing Framing) ([]string, error) {
	br := bufio.NewReader(r)
	var out []string
	if framing == FramingLF {
		for {
			line, err := br.ReadString('\n')
			if line = strings.TrimSuffix(line, "\n"); line != "" {
				out = append(out, line)
			}
			if err != nil {
				return out, err
			}
		}
	}
	for {
		// RFC 6587 §3.4.1：十进制长度 + 空格 + 报文
		lenStr, err := br.ReadString(' ')
		if err != nil {
			return out, err
		}
		n, cerr := strconv.Atoi(strings.TrimSpace(lenStr))
		if cerr != nil || n <= 0 {
			return out, cerr
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return out, err
		}
		out = append(out, string(buf))
	}
}

// splitSyslog 把一条 RFC 5424 报文拆成 header 六格 + SD + MSG。
func splitSyslog(t *testing.T, msg string) (pri int, ts, host, app, procid, msgid, sd, body string) {
	t.Helper()
	if !strings.HasPrefix(msg, "<") {
		t.Fatalf("报文不是以 PRI 开头: %q", msg)
	}
	end := strings.Index(msg, ">")
	if end < 0 {
		t.Fatalf("PRI 没有闭合: %q", msg)
	}
	pri, err := strconv.Atoi(msg[1:end])
	if err != nil {
		t.Fatalf("PRI 不是数字: %q", msg)
	}
	rest := msg[end+1:]
	// VERSION 恒为 1
	if !strings.HasPrefix(rest, "1 ") {
		t.Fatalf("VERSION 应为 1: %q", msg)
	}
	rest = rest[2:]
	parts := strings.SplitN(rest, " ", 6)
	if len(parts) < 6 {
		t.Fatalf("HEADER 字段不足: %q", msg)
	}
	ts, host, app, procid, msgid = parts[0], parts[1], parts[2], parts[3], parts[4]
	tail := parts[5]
	if !strings.HasPrefix(tail, "[") {
		t.Fatalf("缺少 STRUCTURED-DATA: %q", msg)
	}
	// SD 以未转义的 ] 结束
	esc := false
	for i := 1; i < len(tail); i++ {
		if esc {
			esc = false
			continue
		}
		switch tail[i] {
		case '\\':
			esc = true
		case ']':
			return pri, ts, host, app, procid, msgid, tail[:i+1], strings.TrimPrefix(tail[i+1:], " ")
		}
	}
	t.Fatalf("STRUCTURED-DATA 没有闭合: %q", msg)
	return
}

func testRecords() []Record {
	return []Record{
		{Time: "2026-08-11 09:15:04", Category: "admin", User: "安全管理员", SrcIP: "10.0.0.9",
			Event: "保存受控资源「oa」", Verdict: "ok", Seq: 41, MAC: "aa11bb22"},
		{Time: "2026-08-11 09:15:07", Category: "security", User: "ext.zhou", SrcIP: "203.0.113.7",
			Event: "拒发敲门令牌：终端环境不合规", Verdict: "deny", Seq: 42, MAC: "cc33dd44"},
	}
}

// 真实往返：起 TCP 接收端 → 发两条 → 按 RFC 5424 拆字段逐格断言。
func TestSyslogTCPRoundTrip(t *testing.T) {
	addr, frames := syslogSink(t, FramingOctet, nil)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	f, err := NewSyslog(SyslogConfig{Host: host, Port: port, Hostname: "ctl-1", AppName: "baidi-control"})
	if err != nil {
		t.Fatalf("构造 syslog 出口: %v", err)
	}
	if err := f.Send(context.Background(), testRecords()); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	got := waitFrames(t, frames, 2)

	pri, ts, hostname, app, procid, msgid, sd, body := splitSyslog(t, got[0])
	// local0(16)*8 + info(6) = 134
	if pri != 134 {
		t.Errorf("verdict=ok 应为 info，PRI 期望 134，实得 %d", pri)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000Z07:00", ts); err != nil {
		t.Errorf("TIMESTAMP 不是 RFC3339: %q (%v)", ts, err)
	}
	if hostname != "ctl-1" || app != "baidi-control" {
		t.Errorf("HOSTNAME/APP-NAME 不对: %q / %q", hostname, app)
	}
	if _, err := strconv.Atoi(procid); err != nil {
		t.Errorf("PROCID 应为 pid: %q", procid)
	}
	if msgid != "admin" {
		t.Errorf("MSGID 应为审计类别 admin，实得 %q", msgid)
	}
	// ★这是整个功能的价值所在：链的 seq/mac 必须真的出现在报文里。
	for _, want := range []string{`seq="41"`, `mac="aa11bb22"`, `actor="安全管理员"`, `srcIp="10.0.0.9"`, `verdict="ok"`} {
		if !strings.Contains(sd, want) {
			t.Errorf("STRUCTURED-DATA 缺少 %s：%s", want, sd)
		}
	}
	if !strings.HasPrefix(sd, "[baidi@32473 ") {
		t.Errorf("SD-ID 应为 baidi@32473（RFC 5612 文档企业号），实得 %s", sd)
	}
	if !strings.HasPrefix(body, "\xEF\xBB\xBF") {
		t.Errorf("MSG 应带 UTF-8 BOM，实得 %q", body)
	}
	if !strings.Contains(body, "保存受控资源") {
		t.Errorf("MSG 应含事件原文，实得 %q", body)
	}

	// 第二条：deny 抬成 warning。
	pri2, _, _, _, _, msgid2, sd2, _ := splitSyslog(t, got[1])
	if pri2 != 16*8+sevWarning {
		t.Errorf("verdict=deny 应为 warning，PRI 期望 %d，实得 %d", 16*8+sevWarning, pri2)
	}
	if msgid2 != "security" {
		t.Errorf("第二条 MSGID 应为 security，实得 %q", msgid2)
	}
	if !strings.Contains(sd2, `seq="42"`) {
		t.Errorf("第二条缺少 seq=42：%s", sd2)
	}
}

// LF 帧：报文后跟一个换行，且报文内部不得再出现裸换行（否则收集端会切出半条）。
func TestSyslogLFFraming(t *testing.T) {
	addr, frames := syslogSink(t, FramingLF, nil)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	f, err := NewSyslog(SyslogConfig{Host: host, Port: port, Framing: FramingLF, Hostname: "ctl-1"})
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	recs := testRecords()
	// 事件文本里塞一个换行：真实世界里它来自对端错误信息，混进审计文案是可能的。
	recs[0].Event = "第一行\n第二行"
	if err := f.Send(context.Background(), recs); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	got := waitFrames(t, frames, 2)
	if len(got) != 2 {
		t.Fatalf("LF 帧应切出 2 条，实得 %d：%q", len(got), got)
	}
	if strings.Contains(got[0], "\n") {
		t.Errorf("报文内不得残留裸换行：%q", got[0])
	}
	if !strings.Contains(got[0], "第一行 第二行") {
		t.Errorf("换行应被压成空格而不是丢字：%q", got[0])
	}
}

// SD 参数转义：事件文本里的 ] " \ 必须转义，否则会提前闭合 SD 元素，
// 后半截内容被收集端当成 MSG——一条被悄悄截断的审计。
func TestSyslogEscapesStructuredData(t *testing.T) {
	addr, frames := syslogSink(t, FramingOctet, nil)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	f, _ := NewSyslog(SyslogConfig{Host: host, Port: port, Hostname: "ctl-1"})
	if err := f.Send(context.Background(), []Record{{
		Time: "2026-08-11 09:15:04", Category: "auth", Verdict: "fail",
		User: `ev]il" \x`, SrcIP: "1.2.3.4", Event: "登录失败", Seq: 7, MAC: "ff",
	}}); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	got := waitFrames(t, frames, 1)
	_, _, _, _, _, _, sd, body := splitSyslog(t, got[0])
	if !strings.Contains(sd, `actor="ev\]il\" \\x"`) {
		t.Errorf("SD 参数未按 RFC 5424 §6.3.3 转义：%s", sd)
	}
	if !strings.Contains(body, "登录失败") {
		t.Errorf("MSG 被 SD 的提前闭合吃掉了：%q", body)
	}
}

// SD 参数截断不得留下悬空反斜杠。
//
// ★这是一条**免认证可触发**的回归：门户登录失败时 actor 就是请求体里那个用户名，
// 攻击者可以自己填。先转义后截断的写法会在截断点落进 `\"` 中间时输出以单个 `\` 收尾，
// 把随后拼上的闭合引号转义掉 —— actor 这个 SD-PARAM 永远不闭合，srcIp/verdict 与
// 整段 MSG 全被吞进它的值里，SIEM 侧丢掉 seq/mac 两格结构化字段。
func TestSyslogSDParamTruncationKeepsElementClosed(t *testing.T) {
	// 逐个长度扫一遍，保证截断点落在转义序列中间的那些长度都不会漏。
	for n := 1; n <= 600; n++ {
		v := "A" + strings.Repeat(`"`, n)
		esc := sdEscape(v)
		if len([]rune(esc)) > sdParamMaxRunes {
			t.Fatalf("n=%d：转义后 %d 字符，超过上界 %d", n, len([]rune(esc)), sdParamMaxRunes)
		}
		// 结尾的反斜杠必须成对（成对 = 一个被转义的字面反斜杠；落单 = 会吃掉闭合引号）。
		trailing := 0
		for i := len(esc) - 1; i >= 0 && esc[i] == '\\'; i-- {
			trailing++
		}
		if trailing%2 != 0 {
			t.Fatalf("n=%d：转义结果以 %d 个反斜杠收尾（奇数即悬空）：…%q", n, trailing, tailOf(esc, 8))
		}
	}

	// 端到端：拿那个构造出来的用户名真发一条，SD 必须仍能被逐字段解析出来。
	addr, frames := syslogSink(t, FramingOctet, nil)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	f, _ := NewSyslog(SyslogConfig{Host: host, Port: port, Hostname: "ctl-1"})
	if err := f.Send(context.Background(), []Record{{
		Time: "2026-08-11 09:15:04", Category: "auth", Verdict: "fail",
		User: "A" + strings.Repeat(`"`, 256), SrcIP: "203.0.113.7",
		Event: "门户登录失败：用户名或密码错误", Seq: 9, MAC: "beef",
	}}); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	got := waitFrames(t, frames, 1)
	_, _, _, _, _, _, sd, body := splitSyslog(t, got[0])
	for _, key := range []string{`seq="9"`, `mac="beef"`, `srcIp="203.0.113.7"`, `verdict="fail"`} {
		if !strings.Contains(sd, key) {
			t.Errorf("actor 未闭合，把后面的字段吞掉了：缺 %s\nSD=%q", key, sd)
		}
	}
	if !strings.Contains(body, "门户登录失败") {
		t.Errorf("MSG 被未闭合的 SD 吃掉了：%q", body)
	}
}

// tailOf 取字符串末尾若干字节（错误信息用）。
func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// TLS 路径：CA 对上就能发；CA 对不上必须失败。
//
// ★后半段才是重点。本实现**没有**跳过证书校验的开关，这条用例就是它的守卫：
// 哪天有人加回一个 InsecureSkipVerify 并默认打开，这里会立刻变红。
func TestSyslogTLSVerifiesServerCert(t *testing.T) {
	certPEM, keyPEM := selfSignedCert(t, "127.0.0.1")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("装载证书: %v", err)
	}
	addr, frames := syslogSink(t, FramingOctet, &tls.Config{Certificates: []tls.Certificate{cert}})
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ok, err := NewSyslog(SyslogConfig{Host: host, Port: port, TLS: true, CACert: string(certPEM), Hostname: "ctl-1"})
	if err != nil {
		t.Fatalf("构造（信任正确 CA）: %v", err)
	}
	if err := ok.Send(context.Background(), testRecords()[:1]); err != nil {
		t.Fatalf("TLS 发送应成功: %v", err)
	}
	got := waitFrames(t, frames, 1)
	if !strings.Contains(got[0], `seq="41"`) {
		t.Errorf("TLS 路径收到的报文不含 seq：%q", got[0])
	}

	// 对照组：换一把无关的 CA，必须连不上（而不是"加密但不认证"地成功）。
	otherPEM, _ := selfSignedCert(t, "127.0.0.1")
	bad, err := NewSyslog(SyslogConfig{Host: host, Port: port, TLS: true, CACert: string(otherPEM), Hostname: "ctl-1"})
	if err != nil {
		t.Fatalf("构造（错误 CA）: %v", err)
	}
	if err := bad.Send(context.Background(), testRecords()[:1]); err == nil {
		t.Fatal("CA 不匹配时必须失败——证书校验被关掉了，中间人可以无声接管整条审计流")
	}
}

// 对端不可达 / 拒绝时必须报错（而不是静默成功）：队列据此留队重试。
func TestSyslogSendFailsWhenSinkDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close() // 端口立刻释放，拨号应被拒绝
	f, _ := NewSyslog(SyslogConfig{Host: host, Port: port, Timeout: 2 * time.Second, Hostname: "ctl-1"})
	if err := f.Send(context.Background(), testRecords()); err == nil {
		t.Fatal("对端不可达时必须返回错误，否则队列会把这一批当成已送达而删掉")
	}
}

// 配置校验：坏取值在装载期就要被拒，而不是存下来在真出审计时静默失败。
func TestSyslogConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  SyslogConfig
	}{
		{"缺主机", SyslogConfig{}},
		{"端口越界", SyslogConfig{Host: "a", Port: 70000}},
		{"facility 越界", SyslogConfig{Host: "a", Facility: 99}},
		{"未知帧方式", SyslogConfig{Host: "a", Framing: "raw"}},
		{"企业号含非法字符", SyslogConfig{Host: "a", EnterpriseID: "32473]evil"}},
		{"CA 不是 PEM", SyslogConfig{Host: "a", TLS: true, CACert: "not-a-pem"}},
	}
	for _, c := range cases {
		if _, err := NewSyslog(c.cfg); err == nil {
			t.Errorf("%s：应当被拒绝", c.name)
		}
	}
	// 默认值：TLS 走 6514、明文走 514、帧默认 octet。
	f, err := NewSyslog(SyslogConfig{Host: "a", TLS: true})
	if err != nil {
		t.Fatalf("合法配置被拒: %v", err)
	}
	if !strings.HasSuffix(f.Target(), ":6514") || !strings.HasPrefix(f.Target(), "tls://") {
		t.Errorf("TLS 默认端口应为 6514，实得 %s", f.Target())
	}
}

// 时间戳解析不了时回 NILVALUE "-"，不许拿 time.Now() 顶替。
func TestSyslogUnparsableTimeIsNilValue(t *testing.T) {
	if got := syslogTime("不是时间"); got != "-" {
		t.Fatalf("解析不了的时间应回 NILVALUE（拿「现在」冒充会让 SIEM 看到一批时间全等于外送时刻的记录），实得 %q", got)
	}
}

// Record 必须就是 store.AuditEntry：三个出口同源的编译期保证。
func TestRecordIsAuditEntry(t *testing.T) {
	var r Record = store.AuditEntry{Seq: 1}
	if r.Seq != 1 {
		t.Fatal("Record 应当是 store.AuditEntry 的类型别名")
	}
}

// 退避阶梯：单调不减且封顶，不会退到几小时一次。
func TestBackoffMonotonicAndCapped(t *testing.T) {
	prev := time.Duration(0)
	for i := 1; i <= 10; i++ {
		d := Backoff(i)
		if d < prev {
			t.Fatalf("退避不应回退：第 %d 次 %v < 上一次 %v", i, d, prev)
		}
		if d > 15*time.Minute {
			t.Fatalf("退避封顶应为 15min，第 %d 次实得 %v", i, d)
		}
		prev = d
	}
	if Backoff(0) != Backoff(1) {
		t.Fatal("attempts<1 应按第一档处理")
	}
}

// waitFrames 等到收到至少 n 条（接收端在另一个 goroutine 里落盘）。
func waitFrames(t *testing.T, frames func() []string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := frames(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待 %d 条报文超时，实得 %d 条", n, len(frames()))
	return nil
}

// selfSignedCert 生成一张自签证书（同时充当 CA：测试里 leaf 自签自验）。
func selfSignedCert(t *testing.T, host string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP(host)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("序列化密钥: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
