package baidimobile

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"baidi.dev/gateway/internal/knock"
)

// TestControlTrustEmptyMeansSystemStore 钉住「空 = 系统信任库，不是跳过校验」。
// ★同结构体上方的 CaPEM 空值时确实会 InsecureSkipVerify，两个字段挨着放，
// 照抄的概率很高——这条用例就是为了让照抄当场变红。
func TestControlTrustEmptyMeansSystemStore(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\t "} {
		cfg, err := controlTLSConfig(in)
		if err != nil {
			t.Fatalf("空锚不该报错：%v", err)
		}
		if cfg != nil {
			t.Fatalf("空锚必须回 nil（由 dataplane 走系统信任库），得到 %#v", cfg)
		}
	}
}

// TestControlTrustNeverSkipsVerification 反例：任何输入都不得产出一个跳过校验的配置。
func TestControlTrustNeverSkipsVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	pem := certPEM(t, srv.Certificate().Raw)
	cfg, err := controlTLSConfig(pem)
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

// TestControlTrustBadPEMIsAnError 坏锚必须报错，不得静默回落成"系统信任库"。
// ★静默回落的后果是「配了却不生效」，而现场与"根本没配"完全同形——本仓反复批判的形态。
func TestControlTrustBadPEMIsAnError(t *testing.T) {
	for _, bad := range []string{
		"not a pem at all",
		"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----", // 发错材料：私钥不是证书
	} {
		if _, err := controlTLSConfig(bad); err == nil {
			t.Errorf("坏锚必须报错而不是当空处理：%.40q", bad)
		}
	}
}

// TestControlTrustUnionsWithSystemPool 钉住「并集而不是替换」。
//
// ★为什么这条最重要：部署方哪天把控制面换成受信证书（install-remote.sh 的收尾告警里
// 第一条推荐的就是它），若从零起池，所有带锚的终端会在同一刻集体连不上——
// 而换证书的人完全预料不到，现场是「换了张更好的证书、客户端反而全挂了」。
//
// ★**双模，且一定说出自己跑的是哪一模**：macOS 的 x509.SystemCertPool() 返回的是一个
// 非 nil 但 Subjects() 为空的池（Go 不枚举钥匙串，链校验交给系统做）。于是"数张数"这种写法
// 在本机恒有 base=0、got=1 == base+1 —— 把「从零起池」这个变异照样判成通过。
// 实测过：注入 x509.NewCertPool() 之后本机全绿。所以能数的时候数（Linux / CI），
// 数不了的时候退到源码断言，绝不静默跳过——一道检查不出错误的检查比没有检查更坏。
func TestControlTrustUnionsWithSystemPool(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	cfg, err := controlTLSConfig(certPEM(t, srv.Certificate().Raw))
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
	src, err := os.ReadFile("controltrust.go")
	if err != nil {
		t.Fatalf("读不到 controltrust.go：%v", err)
	}
	// ★只看函数体，且**先剥注释**：本文件的文档注释里就写着「若这里用 x509.NewCertPool()
	// 从零起池…」，不剥的话这条断言会被自己的注释绊倒（第一版就是这么假红的）。
	body := funcBody(string(src), "func controlTLSConfig(")
	if body == "" {
		t.Fatal("controltrust.go 里找不到 controlTLSConfig 的函数体（改了签名要同步改这里）")
	}
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

// TestControlTrustMakesSelfSignedControlReachable 端到端：拿这份配置真去取一次敲门令牌。
// 不装锚必须失败（x509），装了锚必须握手成功（服务端回 401 = TLS 这一跳过了）。
func TestControlTrustMakesSelfSignedControlReachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	if _, err := knock.NewFetcher(nil).Fetch(srv.URL, "tok", "dev"); err == nil ||
		!strings.Contains(err.Error(), "不信任") {
		t.Fatalf("不装锚应当栽在证书上（且已翻成中文），得到：%v", err)
	}
	cfg, err := controlTLSConfig(certPEM(t, srv.Certificate().Raw))
	if err != nil {
		t.Fatal(err)
	}
	_, err = knock.NewFetcher(cfg).Fetch(srv.URL, "tok", "dev")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("装了锚应当握手成功、栽在 401（业务层）而不是证书，得到：%v", err)
	}
}

func certPEM(t *testing.T, der []byte) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	const w = 64
	enc := base64Std(der)
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

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// funcBody 取出 name 开头那个函数的函数体，并**剥掉行注释**（源码断言必须只看代码：
// 本仓的注释密度很高，注释里出现被禁的写法是常态，不剥就会假红）。
func funcBody(src, name string) string {
	i := strings.Index(src, name)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if e := strings.Index(rest, "\n}\n"); e >= 0 {
		rest = rest[:e]
	}
	var out []string
	for _, ln := range strings.Split(rest, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "//") {
			continue
		}
		if k := strings.Index(ln, " // "); k >= 0 {
			ln = ln[:k]
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}
