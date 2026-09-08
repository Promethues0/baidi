package main

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

// TestLoadControlTrust_空即系统信任库 钉住「没配 -control-ca ≠ 跳过校验」。
func TestLoadControlTrust_空即系统信任库(t *testing.T) {
	cfg, note, warn, err := loadControlTrust("", "https://c.example:8090")
	if err != nil {
		t.Fatalf("不配锚不该报错：%v", err)
	}
	if cfg != nil {
		t.Fatalf("不配锚必须回 nil（dataplane 据此走系统信任库），得到 %#v", cfg)
	}
	if warn {
		t.Error("「没配锚」是绝大多数部署的正常形态，不该按 WARN 打")
	}
	// 回执必须说清这不是"跳过校验"，否则读日志的人会以为这一跳没在校验证书。
	if !strings.Contains(note, "系统信任库") || !strings.Contains(note, "x509") {
		t.Errorf("未配锚的回执要点名"+
			"「走系统信任库、自签控制面会栽在 x509」，得到：%s", note)
	}
}

// TestLoadControlTrust_装载后不跳过校验且并进系统池 是本文件的主断言。
//
// ★变异：把 knock.ControlTLSFromPEM 里的 x509.SystemCertPool() 换成 x509.NewCertPool()
// （从零起池）→ 计数分支必须红（见 internal/knock/controltrust_test.go，那里是判据所在地，
// 双模：能数张数就数，macOS 数不出来退到源码断言）。这里只钉住桌面端确实用的是那份判据。
func TestLoadControlTrust_装载后不跳过校验且并进系统池(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	path := writeTemp(t, certPEMOfDER(t, srv.Certificate().Raw))

	cfg, note, _, err := loadControlTrust(path, "https://c.example:8090")
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("配了锚必须产出带 RootCAs 的配置")
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("控制面这一跳永远不许跳过校验：零信任链路的第一跳，开了口子就再也拆不掉")
	}
	if sys, serr := x509.SystemCertPool(); serr == nil && sys != nil {
		base := len(sys.Subjects())                            //nolint:staticcheck // 只数张数
		if base > 0 && len(cfg.RootCAs.Subjects()) != base+1 { //nolint:staticcheck // 同上
			t.Fatalf("锚必须并进系统池（系统 %d 张 + 锚 1 张），实得 %d："+
				"从零起池会让部署方换成受信证书那天全员掉线", base, len(cfg.RootCAs.Subjects()))
		}
	}
	if !strings.Contains(note, "已装载") || !strings.Contains(note, "系统池") {
		t.Errorf("装载成功的回执要说清池子构成，得到：%s", note)
	}
}

// TestLoadControlTrust_坏锚一律致命 反例：读不到/空/不是证书，三种都必须报错。
// **绝不静默回落成系统信任库**——那正是「配了却不生效」，且与"根本没配"在现场完全同形。
func TestLoadControlTrust_坏锚一律致命(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"文件不存在": filepath.Join(dir, "没有这个文件.pem"),
		"空文件":   writeTemp(t, "   \n"),
		"不是证书":  writeTemp(t, "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"),
		"纯文本":   writeTemp(t, "hello"),
	}
	for name, p := range cases {
		if _, _, _, err := loadControlTrust(p, "https://c.example:8090"); err == nil {
			t.Errorf("%s 必须当场报错退出（fail-closed），不得静默走系统信任库", name)
		}
	}
}

// TestLoadControlTrust_明文控制面要当面告警 是一条"配了却不生效"的回执。
// 配了锚的人默认以为这一跳已经安全了，而 http:// 下敲门令牌是明文过网的。
//
// ★断言用带星号的 `**锚不生效**` 而不是裸的「不生效」：回执里含临时文件路径，
// 而 t.TempDir() 的路径里带测试函数名——第一版函数名就叫「…要当面说锚不生效」，
// 于是反向那条断言被自己的函数名匹配上，假红了一次。
func TestLoadControlTrust_明文控制面要当面告警(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	path := writeTemp(t, certPEMOfDER(t, srv.Certificate().Raw))

	_, note, warn, err := loadControlTrust(path, "http://127.0.0.1:8090")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "**锚不生效**") {
		t.Errorf("http:// 的控制面下必须当面说锚不生效，得到：%s", note)
	}
	if !warn {
		t.Error("「配了锚但这一跳根本没加密」必须按 WARN 打：INFO 会被当成一切正常划过去")
	}
	if _, note2, _, _ := loadControlTrust(path, "https://127.0.0.1:8090"); strings.Contains(note2, "**锚不生效**") {
		t.Errorf("https 时不该报锚不生效，得到：%s", note2)
	}
}

// TestLoadControlTrust_回执不得撞上桌面端的故障关键词 是上面那条注释的执行方。
//
// ★桌面客户端在拿不到健康行时，用 /失败|未敲门成功|panic|fatal|退出/ 从 baidi-tun 的日志
// 尾巴里捞"最近一次故障"（clients/desktop/src/lib/tunnel.ts）。一句正常的启动回执若含这些词，
// 一次成功的接入会在界面上显示成红的——本仓最讨厌的那种"两端都没错、合起来是错的"。
func TestLoadControlTrust_回执不得撞上桌面端的故障关键词(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	path := writeTemp(t, certPEMOfDER(t, srv.Certificate().Raw))

	var notes []string
	for _, tc := range []struct{ p, c string }{
		{"", "https://c.example:8090"},
		{path, "https://c.example:8090"},
		{path, "http://127.0.0.1:8090"},
	} {
		_, note, _, err := loadControlTrust(tc.p, tc.c)
		if err != nil {
			t.Fatal(err)
		}
		notes = append(notes, note)
	}
	for _, note := range notes {
		for _, kw := range []string{"失败", "未敲门成功", "panic", "fatal", "退出"} {
			if strings.Contains(strings.ToLower(note), strings.ToLower(kw)) {
				t.Errorf("回执里出现故障关键词 %q，会被桌面端捞成"+
					"「最近一次故障」显示给用户：%s", kw, note)
			}
		}
	}
}

// TestMain接线了ControlTLS 源码断言：**入参存在 ≠ 已接线**。
//
// ★本轨修的缺口正是这种形态——dataplane.Config.ControlTLS 字段一直存在、移动端一直在传，
// 桌面端构造 Config 时从不传，于是恒 nil。这条断言让"加了 -control-ca 却忘了塞进 Config"
// 当场变红，而不是等到自签部署上表现为"门永远敲不开"。
func TestMain接线了ControlTLS(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, `flag.String("control-ca"`) {
		t.Error("main.go 里找不到 -control-ca 入参")
	}
	i := strings.Index(s, "cfg := &dataplane.Config{")
	if i < 0 {
		t.Fatal("main.go 里找不到 dataplane.Config 的构造点（改了写法要同步改这里）")
	}
	lit := s[i:]
	if e := strings.Index(lit, "\n\t}"); e >= 0 {
		lit = lit[:e]
	}
	if !strings.Contains(lit, "ControlTLS:") {
		t.Error("dataplane.Config 构造时没传 ControlTLS —— 入参加了但没接线，" +
			"自签控制面下敲门令牌永远取不到，而代码看起来一切正常")
	}
}

func certPEMOfDER(t *testing.T, der []byte) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	enc := base64.StdEncoding.EncodeToString(der)
	for i := 0; i < len(enc); i += 64 {
		j := i + 64
		if j > len(enc) {
			j = len(enc)
		}
		b.WriteString(enc[i:j] + "\n")
	}
	b.WriteString("-----END CERTIFICATE-----\n")
	return b.String()
}
