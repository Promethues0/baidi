package knock

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestControlTLSEmptyMeansSystemStore 钉住「空 = 系统信任库，不是跳过校验」。
func TestControlTLSEmptyMeansSystemStore(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\t "} {
		cfg, err := ControlTLSFromPEM(in)
		if err != nil {
			t.Fatalf("空锚不该报错：%v", err)
		}
		if cfg != nil {
			t.Fatalf("空锚必须回 nil（由 dataplane 走系统信任库），得到 %#v", cfg)
		}
	}
}

// TestControlTLSNeverSkipsVerification 反例：任何输入都不得产出一个跳过校验的配置。
func TestControlTLSNeverSkipsVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	cfg, err := ControlTLSFromPEM(certPEMOf(t, srv.Certificate().Raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("控制面这一跳永远不许跳过校验：这是零信任链路的第一跳，开了口子就再也拆不掉")
	}
	if cfg.RootCAs == nil {
		t.Fatal("非空锚必须装进 RootCAs")
	}
}

// TestControlTLSBadPEMIsAnError 坏锚必须报错，不得静默回落成"系统信任库"。
// ★静默回落的后果是「配了却不生效」，而现场与"根本没配"完全同形。
func TestControlTLSBadPEMIsAnError(t *testing.T) {
	for _, bad := range []string{
		"not a pem at all",
		"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----", // 发错材料：私钥不是证书
	} {
		if _, err := ControlTLSFromPEM(bad); err == nil {
			t.Errorf("坏锚必须报错而不是当空处理：%.40q", bad)
		}
	}
}

// TestControlTLSUnionsWithSystemPool 钉住「并集而不是替换」——**本文件最重要的一条**。
//
// ★变异：把 x509.SystemCertPool() 换成 x509.NewCertPool()（从零起池），本条必须红。
// 那个变异的真实后果是：部署方哪天把控制面换成受信证书，所有带锚的终端在同一刻集体连不上，
// 而换证书的人完全预料不到，现场是「换了张更好的证书、客户端反而全挂了」。
//
// ★**双模，且一定说出自己跑的是哪一模**：macOS 的 x509.SystemCertPool() 返回的是一个
// 非 nil 但 Subjects() 为空的池（Go 不枚举钥匙串，链校验交给系统做）。于是"数张数"这种写法
// 在本机恒有 base=0、got=1 == base+1 —— 把「从零起池」这个变异照样判成通过。所以能数的时候
// 数（Linux / CI），数不了的时候退到源码断言，绝不静默跳过——一道检查不出错误的检查比没有更坏。
func TestControlTLSUnionsWithSystemPool(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	cfg, err := ControlTLSFromPEM(certPEMOf(t, srv.Certificate().Raw))
	if err != nil {
		t.Fatal(err)
	}

	sys, serr := x509.SystemCertPool()
	base := 0
	if serr == nil && sys != nil {
		base = len(sys.Subjects()) //nolint:staticcheck // 只用来数张数，不做证书匹配
	}
	if base > 0 {
		t.Logf("模式：计数（系统池 %d 张）", base)
		if got := len(cfg.RootCAs.Subjects()); got != base+1 { //nolint:staticcheck // 同上
			t.Fatalf("锚必须**并进**系统池：系统 %d 张 + 锚 1 张应得 %d，实得 %d"+
				"（从零起池会让换受信证书那天全员掉线）", base, base+1, got)
		}
		return
	}

	// 本机数不出来（macOS）→ 退到源码断言，把"基座必须是系统池"这件事钉在实现上。
	t.Log("模式：源码断言（本机系统池 Subjects() 为空，计数判不出来）")
	body := trustFuncBody(t, "controltrust.go", "func ControlTLSFromPEM(")
	if !strings.Contains(body, "x509.SystemCertPool()") {
		t.Error("信任池的基座必须是 x509.SystemCertPool()：从零起池会让部署方换成受信证书那天，" +
			"所有带锚的终端在同一刻集体连不上，而换证书的人完全预料不到")
	}
	// NewCertPool 只允许出现在"系统池取不到"的兜底里，不许当基座
	i, j := strings.Index(body, "x509.NewCertPool()"), strings.Index(body, "x509.SystemCertPool()")
	if i >= 0 && (j < 0 || i < j) {
		t.Error("x509.NewCertPool() 出现在 SystemCertPool() 之前 —— 基座被换成了空池")
	}
}

// TestControlTLSMakesSelfSignedControlReachable 端到端：拿这份配置真去取一次敲门令牌。
// 不装锚必须失败（x509），装了锚必须握手成功（服务端回 401 = TLS 这一跳过了）。
func TestControlTLSMakesSelfSignedControlReachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	if _, err := NewFetcher(nil).Fetch(srv.URL, "tok", "dev"); err == nil ||
		!strings.Contains(err.Error(), "不信任") {
		t.Fatalf("不装锚应当栽在证书上（且已翻成中文），得到：%v", err)
	}
	cfg, err := ControlTLSFromPEM(certPEMOf(t, srv.Certificate().Raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewFetcher(cfg).Fetch(srv.URL, "tok", "dev"); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Fatalf("装了锚应当握手成功、栽在 401（业务层）而不是证书，得到：%v", err)
	}
}

// TestControlTLSFromFile 文件入口的四种输入。**除了"路径为空"，其余异常一律报错**：
// 路径打错/文件是空的时候静默走系统信任库，自签部署下表现为"门永远敲不开"，
// 而管理员手里明明配着一条 -control-ca，会一路怀疑到证书本身去。
func TestControlTLSFromFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	dir := t.TempDir()
	good := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(good, []byte(certPEMOf(t, srv.Certificate().Raw)), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	if cfg, err := ControlTLSFromFile(""); err != nil || cfg != nil {
		t.Fatalf("空路径 = 系统信任库（nil, nil），得到 %#v / %v", cfg, err)
	}
	cfg, err := ControlTLSFromFile(good)
	if err != nil || cfg == nil || cfg.RootCAs == nil || cfg.InsecureSkipVerify {
		t.Fatalf("好锚应当装载成功且不跳过校验，得到 %#v / %v", cfg, err)
	}
	for _, tc := range []struct{ name, path string }{
		{"文件不存在", filepath.Join(dir, "缺席.pem")},
		{"空文件", empty},
		{"坏 PEM", bad},
	} {
		if _, err := ControlTLSFromFile(tc.path); err == nil {
			t.Errorf("%s 必须报错（fail-closed），不得静默回落成系统信任库", tc.name)
		}
	}
}

// TestControlTLSMobileTrackStaysInSync 跨轨守卫：移动端那份 controlTLSConfig 必须与本包同源。
//
// ★为什么需要它：本仓最高频的缺陷模式是「纪律只做了一半」——一端改对了、另一端零感知。
// 桌面与移动端这两跳的现场症状毫无共同点（一个是 Go 的 x509 报错、一个是 WebView 的
// ERR_CERT_AUTHORITY_INVALID），分家之后会被当成两个不相干的 bug 各修一次。
//
// 理想形态是移动端直接 `return knock.ControlTLSFromPEM(pem)`（本包已被它 import），
// 收口那一步需要改 gateway/mobile/baidimobile/，不在本轨的改动范围内；在收口之前，
// 本条至少保证那份拷贝不会悄悄丢掉三条判据中的任何一条。
func TestControlTLSMobileTrackStaysInSync(t *testing.T) {
	const path = "../../mobile/baidimobile/controltrust.go"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("读不到移动端那份（%v）——本条只在同仓内有意义", err)
	}
	body := trustFuncBody(t, path, "func controlTLSConfig(")
	if strings.Contains(body, "ControlTLSFromPEM(") {
		return // 已收口成 delegate，判据只剩本包这一份
	}
	for _, must := range []struct{ frag, why string }{
		{"x509.SystemCertPool()", "基座必须是系统池：从零起池会让部署方换成受信证书那天全员掉线"},
		{"AppendCertsFromPEM", "锚必须真的并进池子"},
		{"return nil, nil", "空锚 = 系统信任库（不是跳过校验，也不是报错）"},
	} {
		if !strings.Contains(body, must.frag) {
			t.Errorf("移动端 controlTLSConfig 与 knock.ControlTLSFromPEM 已分家（缺 %s）：%s",
				must.frag, must.why)
		}
	}
	if strings.Contains(body, "InsecureSkipVerify") {
		t.Error("移动端那份出现了 InsecureSkipVerify：控制面这一跳永远不许跳过校验")
	}
}

func certPEMOf(t *testing.T, der []byte) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	const w = 64
	enc := base64.StdEncoding.EncodeToString(der)
	for i := 0; i < len(enc); i += w {
		j := i + w
		if j > len(enc) {
			j = len(enc)
		}
		b.WriteString(enc[i:j] + "\n")
	}
	b.WriteString("-----END CERTIFICATE-----\n")
	return b.String()
}

// trustFuncBody 取出 name 开头那个函数的函数体，并**剥掉注释**：源码断言必须只看代码，
// 本仓注释密度很高（controltrust.go 的文档注释里就写着被禁的 x509.NewCertPool()），
// 不剥的话断言会被自己的注释绊倒。
func trustFuncBody(t *testing.T, path, name string) string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到 %s：%v", path, err)
	}
	i := strings.Index(string(src), name)
	if i < 0 {
		t.Fatalf("%s 里找不到 %s 的函数体（改了签名要同步改这里）", path, name)
	}
	rest := string(src)[i:]
	if e := strings.Index(rest, "\n}\n"); e >= 0 {
		rest = rest[:e]
	}
	var out []string
	for _, ln := range strings.Split(rest, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "//") {
			continue
		}
		if k := strings.Index(ln, " // "); k >= 0 {
			ln = ln[:k]
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}
