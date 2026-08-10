package notify

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testsmtpd_test.go 一个**进程内的最小 SMTP 服务端**，用来跑真实协议往返。
//
// 为什么自己写而不是 mock 掉 net/smtp：这一层要证明的恰恰是协议行为——
// STARTTLS 没通告时是不是真的不发 MAIL、AUTH 是不是真的只在 TLS 之后发、
// 中文主题是不是真按 RFC 2047 编码出去的。把 smtp.Client 换成打桩对象，
// 这几件事一件都验不到（照 authsrc/ldapsrc 用 gldap 起真目录的同一思路）。

type smtpdOpts struct {
	advertiseSTARTTLS bool // EHLO 是否通告 STARTTLS（不通告 = 对照组）
	implicitTLS       bool // 监听端口即 TLS（465 形态）
	advertiseAuth     bool // EHLO 是否通告 AUTH PLAIN LOGIN
	wantUser          string
	wantPass          string
}

// receivedMail 服务端实际收到的一封信。
type receivedMail struct {
	From string
	Rcpt []string
	Data string
	// OverTLS 记录 DATA 落地时这条连接是否已加密。
	// ★这是"绝不降级"那条断言的判据：不看它的话，一个降级成明文却仍然把信发出去的
	// 实现会让"发送成功"的测试照样绿。
	OverTLS bool
}

type fakeSMTPD struct {
	t      *testing.T
	ln     net.Listener
	opts   smtpdOpts
	tlsCfg *tls.Config
	caPEM  string

	mu    sync.Mutex
	verbs []string // 收到的命令动词（大写），按序
	mails []receivedMail
	auths []string // 成功完成的认证机制
}

func newFakeSMTPD(t *testing.T, opts smtpdOpts) *fakeSMTPD {
	t.Helper()
	cfg, caPEM := selfSignedTLS(t)
	d := &fakeSMTPD{t: t, opts: opts, tlsCfg: cfg, caPEM: caPEM}
	var err error
	if opts.implicitTLS {
		d.ln, err = tls.Listen("tcp", "127.0.0.1:0", cfg)
	} else {
		d.ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	go d.serve()
	t.Cleanup(func() { _ = d.ln.Close() })
	return d
}

func (d *fakeSMTPD) addr() (host string, port int) {
	a := d.ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

func (d *fakeSMTPD) snapshot() ([]string, []receivedMail, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string{}, d.verbs...), append([]receivedMail{}, d.mails...), append([]string{}, d.auths...)
}

// sawVerb 报告服务端是否收到过某个命令动词。
func (d *fakeSMTPD) sawVerb(v string) bool {
	verbs, _, _ := d.snapshot()
	for _, got := range verbs {
		if got == v {
			return true
		}
	}
	return false
}

func (d *fakeSMTPD) serve() {
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		go d.handle(c)
	}
}

func (d *fakeSMTPD) note(verb string) {
	d.mu.Lock()
	d.verbs = append(d.verbs, verb)
	d.mu.Unlock()
}

func (d *fakeSMTPD) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	tlsOn := d.opts.implicitTLS
	br := bufio.NewReader(c)
	w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	w("220 fake.baidi.test ESMTP")

	var from string
	var rcpt []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.Fields(line + " ")[0])
		d.note(verb)
		switch verb {
		case "EHLO", "HELO":
			// ★首行必须是问候行、扩展从第二行起：net/smtp 的 ehlo() 解析时
			// 会**丢掉多行应答的第一行**（那是域名问候）。把 STARTTLS 放在首行，
			// 客户端就永远看不到它——服务端"通告了"而客户端"没看见"，
			// 表现为莫名其妙的不降级报错。
			lines := []string{"fake.baidi.test"}
			if d.opts.advertiseSTARTTLS && !tlsOn {
				lines = append(lines, "STARTTLS")
			}
			if d.opts.advertiseAuth {
				lines = append(lines, "AUTH PLAIN LOGIN")
			}
			for i, l := range lines {
				if i == len(lines)-1 {
					w("250 " + l)
				} else {
					w("250-" + l)
				}
			}
		case "STARTTLS":
			if !d.opts.advertiseSTARTTLS {
				w("500 5.5.1 Unrecognized command")
				continue
			}
			w("220 2.0.0 Ready to start TLS")
			tc := tls.Server(c, d.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, br, tlsOn = tc, bufio.NewReader(tc), true
			w = func(s string) { _, _ = tc.Write([]byte(s + "\r\n")) }
		case "AUTH":
			mech, cred := parseAuth(line)
			ok := false
			switch mech {
			case "PLAIN":
				if cred == "" {
					w("334 ")
					cred, _ = br.ReadString('\n')
					cred = strings.TrimSpace(cred)
				}
				raw, _ := base64.StdEncoding.DecodeString(cred)
				parts := strings.Split(string(raw), "\x00")
				ok = len(parts) == 3 && parts[1] == d.opts.wantUser && parts[2] == d.opts.wantPass
			case "LOGIN":
				w("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, _ := br.ReadString('\n')
				w("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, _ := br.ReadString('\n')
				ub, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
				pb, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
				ok = string(ub) == d.opts.wantUser && string(pb) == d.opts.wantPass
			}
			if !ok {
				w("535 5.7.8 Authentication credentials invalid")
				continue
			}
			d.mu.Lock()
			d.auths = append(d.auths, mech)
			d.mu.Unlock()
			w("235 2.7.0 Authentication successful")
		case "MAIL":
			from = angleAddr(line)
			rcpt = nil
			w("250 2.1.0 Ok")
		case "RCPT":
			rcpt = append(rcpt, angleAddr(line))
			w("250 2.1.5 Ok")
		case "DATA":
			w("354 End data with <CR><LF>.<CR><LF>")
			var sb strings.Builder
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" || l == ".\n" {
					break
				}
				sb.WriteString(l)
			}
			d.mu.Lock()
			d.mails = append(d.mails, receivedMail{From: from, Rcpt: rcpt, Data: sb.String(), OverTLS: tlsOn})
			d.mu.Unlock()
			w("250 2.0.0 Ok: queued")
		case "QUIT":
			w("221 2.0.0 Bye")
			return
		case "RSET", "NOOP":
			w("250 2.0.0 Ok")
		default:
			w("502 5.5.2 Command not implemented")
		}
	}
}

func parseAuth(line string) (mech, cred string) {
	f := strings.Fields(line)
	if len(f) >= 2 {
		mech = strings.ToUpper(f[1])
	}
	if len(f) >= 3 {
		cred = f[2]
	}
	return mech, cred
}

func angleAddr(line string) string {
	i, j := strings.Index(line, "<"), strings.LastIndex(line, ">")
	if i < 0 || j <= i {
		return strings.TrimSpace(line)
	}
	return line[i+1 : j]
}

// selfSignedTLS 生成一张给 localhost / 127.0.0.1 用的自签证书，
// 返回服务端 tls.Config 与可作为客户端 CACert 的 PEM。
//
// 客户端用 CACert（而不是 InsecureSkipVerify）连它：这样连"只信这一把 CA"
// 那条代码路径也一并跑到了——逃生舱开着的话，证书校验那段等于没测。
func selfSignedTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签证书失败: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
	return cfg, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
