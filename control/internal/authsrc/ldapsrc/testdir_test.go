package ldapsrc

// 测试用的**进程内真实 LDAP 服务端**。
//
// ★为什么非要真跑协议：本仓库在 IPSec 那边已经吃过一次"没跟真实对端跑过就是没跑过"的亏
// （suite=gm 至今没和 strongSwan 实机互通验证过，只能诚实标注）。认证这条链路更不能重蹈：
// 只 mock 掉 PasswordAuthenticator 接口，等于测了一遍我们自己写的 if/else，
// 而真正要证明的东西——"转义后的用户名在 BER 编码里确实是一个字面量而不是过滤器结构"、
// "空口令没有被送到线上去"——只有让报文真的走一遍编解码才能证明。
//
// 服务端用 github.com/jimlambrt/gldap（仅测试依赖），客户端就是生产代码本身。
// 下面还带了一个**最小但语义真实**的过滤器求值器：它按 RFC 4515 先按未转义的 `*` 切分、
// 再对每段做 \XX 反转义（顺序反了的话 `\2a` 会被当成通配符，注入用例就会因为错误的
// 原因通过——那比没有这个用例更危险）。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"
)

// ── 目录数据 ───────────────────────────────────────────────────────────────

type dirEntry struct {
	DN    string
	Attrs map[string][]string
	// Pass 该条目 bind 时接受的口令。空串表示"任何口令都拒"。
	// ★注意这不是"空口令即通过"：真实目录的空口令行为（当作匿名 bind 回成功）
	// 由 dirOpts.anonymousOnEmptyPassword 单独模拟，见那里的说明。
	Pass string
	// BindDiag bind 失败时附带的诊断串，用来模拟 AD 的 `data 533` 这类子状态码。
	BindDiag string
}

type dirOpts struct {
	entries   []dirEntry
	baseDNs   []string // 认得的 Base DN；不在其中的搜索回 noSuchObject
	serviceDN string
	servicePW string

	// tlsCfg 非 nil 时支持 StartTLS；再配合 ldaps=true 则整条连接直接 TLS。
	tlsCfg *tls.Config
	ldaps  bool

	// ignoreSizeLimit 模拟"服务端无视客户端 sizeLimit"的目录（协议里 sizeLimit
	// 只是建议值，这种实现是合法的）。用来验证我们客户端侧也强制了上限。
	ignoreSizeLimit bool

	// blankDN 模拟"目录回了一条 DN 为空的条目"这种异常实现。
	// 拿空 DN 去 bind 有可能被服务端当作匿名/未认证 bind 并回成功，
	// 所以生产代码必须在 bind 之前就拒掉它。
	blankDN bool

	// anonymousOnEmptyPassword 模拟 RFC 4513 §5.1.1 的经典行为：
	// 「有 DN + 零长度口令」被当作匿名 bind 并**返回成功**。
	// 生产代码必须在发出请求之前就把空口令拦下，所以这个开关打开后
	// 依然不能有任何一次空口令 bind 打到服务端上。
	anonymousOnEmptyPassword bool
}

type bindRec struct {
	DN   string
	Pass string
}

type testDir struct {
	t    *testing.T
	opts dirOpts
	addr string
	port int
	srv  *gldap.Server

	mu      sync.Mutex
	filters []string
	binds   []bindRec
}

func (d *testDir) recordFilter(f string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.filters = append(d.filters, f)
}

func (d *testDir) recordBind(dn, pass string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.binds = append(d.binds, bindRec{DN: dn, Pass: pass})
}

// Filters 返回服务端收到的全部搜索过滤器（原样，未做归一化以外的加工）。
func (d *testDir) Filters() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.filters...)
}

// Binds 返回服务端收到的全部 bind 尝试。
func (d *testDir) Binds() []bindRec {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]bindRec(nil), d.binds...)
}

// UserBinds 过滤掉服务账号那一次，只留下"拿用户 DN 去 bind"的尝试。
func (d *testDir) UserBinds() []bindRec {
	var out []bindRec
	for _, b := range d.Binds() {
		if d.opts.serviceDN != "" && strings.EqualFold(b.DN, d.opts.serviceDN) {
			continue
		}
		out = append(out, b)
	}
	return out
}

// startDir 起一个进程内 LDAP 服务端，测试结束自动关闭。
func startDir(t *testing.T, o dirOpts) *testDir {
	t.Helper()
	port := freePort(t)
	d := &testDir{t: t, opts: o, port: port, addr: net.JoinHostPort("127.0.0.1", fmt.Sprint(port))}

	srv, err := gldap.NewServer()
	if err != nil {
		t.Fatalf("gldap.NewServer: %v", err)
	}
	mux, err := gldap.NewMux()
	if err != nil {
		t.Fatalf("gldap.NewMux: %v", err)
	}
	must(t, mux.Bind(d.handleBind))
	must(t, mux.Search(d.handleSearch))
	must(t, mux.Unbind(func(*gldap.ResponseWriter, *gldap.Request) {}))
	if o.tlsCfg != nil {
		must(t, mux.ExtendedOperation(d.handleStartTLS, gldap.ExtendedOperationStartTLS))
	}
	must(t, srv.Router(mux))
	d.srv = srv

	go func() {
		var runOpts []gldap.Option
		if o.ldaps {
			runOpts = append(runOpts, gldap.WithTLSConfig(o.tlsCfg))
		}
		_ = srv.Run(d.addr, runOpts...)
	}()
	t.Cleanup(func() { _ = srv.Stop() })
	waitListening(t, d.addr)
	return d
}

func (d *testDir) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		return
	}
	dn, pw := m.UserName, string(m.Password)
	d.recordBind(dn, pw)

	if pw == "" && d.opts.anonymousOnEmptyPassword {
		// ★这就是那个认证绕过：服务端把它当匿名 bind，回 success。
		resp.SetResultCode(gldap.ResultSuccess)
		return
	}
	if d.opts.serviceDN != "" && dn == d.opts.serviceDN {
		if pw == d.opts.servicePW {
			resp.SetResultCode(gldap.ResultSuccess)
		}
		return
	}
	for _, e := range d.opts.entries {
		if !strings.EqualFold(e.DN, dn) {
			continue
		}
		if e.Pass != "" && e.Pass == pw {
			resp.SetResultCode(gldap.ResultSuccess)
			return
		}
		if e.BindDiag != "" {
			resp.SetDiagnosticMessage(e.BindDiag)
		}
		return
	}
}

func (d *testDir) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetSearchMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultOperationsError)
		return
	}
	d.recordFilter(m.Filter)

	if !d.knownBase(m.BaseDN) {
		resp.SetResultCode(gldap.ResultNoSuchObject)
		return
	}
	expr, err := parseTestFilter(m.Filter)
	if err != nil {
		resp.SetResultCode(gldap.ResultOperationsError)
		return
	}

	var matched []dirEntry
	for _, e := range d.opts.entries {
		switch m.Scope {
		case gldap.BaseObject:
			if !strings.EqualFold(e.DN, m.BaseDN) {
				continue
			}
		default: // WholeSubtree / SingleLevel 一律按子树处理，测试用不到更细的语义
			if !dnUnder(e.DN, m.BaseDN) {
				continue
			}
		}
		if expr.eval(e.Attrs) {
			matched = append(matched, e)
		}
	}

	truncated := false
	if !d.opts.ignoreSizeLimit && m.SizeLimit > 0 && int64(len(matched)) > m.SizeLimit {
		matched = matched[:m.SizeLimit]
		truncated = true
	}
	for _, e := range matched {
		dn := e.DN
		if d.opts.blankDN {
			dn = ""
		}
		_ = w.Write(r.NewSearchResponseEntry(dn, gldap.WithAttributes(e.Attrs)))
	}
	if truncated {
		resp.SetResultCode(gldap.ResultSizeLimitExceeded)
	}
}

func (d *testDir) handleStartTLS(w *gldap.ResponseWriter, r *gldap.Request) {
	res := r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	res.SetResponseName(gldap.ExtendedOperationStartTLS)
	if err := w.Write(res); err != nil {
		return
	}
	_ = r.StartTLS(d.opts.tlsCfg)
}

func (d *testDir) knownBase(dn string) bool {
	for _, b := range d.opts.baseDNs {
		if strings.EqualFold(strings.TrimSpace(b), strings.TrimSpace(dn)) {
			return true
		}
	}
	return false
}

// dnUnder 判断 dn 是否落在 base 子树内（含 base 自身）。测试够用的粗略实现。
func dnUnder(dn, base string) bool {
	dn, base = strings.ToLower(strings.TrimSpace(dn)), strings.ToLower(strings.TrimSpace(base))
	return dn == base || strings.HasSuffix(dn, ","+base)
}

// ── 最小过滤器求值器 ───────────────────────────────────────────────────────

type testFilter struct {
	op   byte // '&' '|' '!'；0 表示叶子断言
	kids []testFilter
	attr string
	pat  string // **仍带转义**的断言值，通配符 * 以未转义形态存在
}

func parseTestFilter(s string) (testFilter, error) {
	f, n, err := parseTestFilterAt(s, 0)
	if err != nil {
		return testFilter{}, err
	}
	if n != len(s) {
		return testFilter{}, fmt.Errorf("过滤器尾部有多余内容: %q", s[n:])
	}
	return f, nil
}

func parseTestFilterAt(s string, i int) (testFilter, int, error) {
	if i >= len(s) || s[i] != '(' {
		return testFilter{}, i, fmt.Errorf("位置 %d 期望 '('", i)
	}
	i++
	if i < len(s) && (s[i] == '&' || s[i] == '|' || s[i] == '!') {
		node := testFilter{op: s[i]}
		i++
		for i < len(s) && s[i] == '(' {
			kid, ni, err := parseTestFilterAt(s, i)
			if err != nil {
				return testFilter{}, i, err
			}
			node.kids = append(node.kids, kid)
			i = ni
		}
		if i >= len(s) || s[i] != ')' {
			return testFilter{}, i, fmt.Errorf("位置 %d 期望 ')'", i)
		}
		return node, i + 1, nil
	}
	eq := strings.IndexByte(s[i:], '=')
	if eq < 0 {
		return testFilter{}, i, fmt.Errorf("位置 %d 起的断言缺少 '='", i)
	}
	attr := s[i : i+eq]
	i += eq + 1
	// ★这里按**原始的** ')' 断句是刻意的：合法过滤器里断言值内的右括号一定是 \29，
	// 所以能读到裸 ')' 就说明它是结构。注入之所以能改写语义，正是因为这一点——
	// 求值器必须忠实还原这个行为，否则测出来的"安全"是假的。
	end := strings.IndexByte(s[i:], ')')
	if end < 0 {
		return testFilter{}, i, fmt.Errorf("位置 %d 起的断言缺少 ')'", i)
	}
	pat := s[i : i+end]
	return testFilter{attr: attr, pat: pat}, i + end + 1, nil
}

func (f testFilter) eval(attrs map[string][]string) bool {
	switch f.op {
	case '&':
		for _, k := range f.kids {
			if !k.eval(attrs) {
				return false
			}
		}
		return true
	case '|':
		for _, k := range f.kids {
			if k.eval(attrs) {
				return true
			}
		}
		return false
	case '!':
		return len(f.kids) == 1 && !f.kids[0].eval(attrs)
	}
	var vals []string
	for k, v := range attrs {
		if strings.EqualFold(k, f.attr) {
			vals = v
			break
		}
	}
	for _, v := range vals {
		if matchAssertion(f.pat, v) {
			return true
		}
	}
	return false
}

// matchAssertion 按 RFC 4515 语义比对断言值。
//
// ★顺序至关重要：**先**按未转义的 '*' 切分，**再**对每段做 \XX 反转义。
// 反过来先反转义的话，`\2a`（一个字面 '*'）会变成真的通配符，
// 于是"被正确转义的注入串"照样能匹配一切——注入用例就会以完全错误的理由通过。
func matchAssertion(pat, value string) bool {
	segs := strings.Split(pat, "*")
	for i := range segs {
		segs[i] = unescapeFilterValue(segs[i])
	}
	value = strings.ToLower(value)
	for i := range segs {
		segs[i] = strings.ToLower(segs[i])
	}
	if len(segs) == 1 {
		return segs[0] == value
	}
	if !strings.HasPrefix(value, segs[0]) {
		return false
	}
	rest := value[len(segs[0]):]
	last := segs[len(segs)-1]
	for _, mid := range segs[1 : len(segs)-1] {
		idx := strings.Index(rest, mid)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(mid):]
	}
	return strings.HasSuffix(rest, last)
}

func unescapeFilterValue(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+2 < len(s) {
			if v, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				b.Write(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// ── 杂项 ───────────────────────────────────────────────────────────────────

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("测试 LDAP 服务端 %s 未在超时内就绪", addr)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("测试目录初始化失败: %v", err)
	}
}

// selfSignedTLS 生成一张自签证书（同时充当自己的 CA），返回服务端 TLS 配置与 CA PEM。
func selfSignedTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "baidi-test-ldap"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发自签证书失败: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}, string(certPEM)
}
