package knock

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

// 真自签服务端 + 真 TLS 握手：这正是 2026-09-03 安卓真机上撞到的那一档。
//
// ★为什么用 httptest.NewTLSServer 而不是手搓一个 x509.UnknownAuthorityError：
// 真正要守的是"FetchToken 这条路径上的错误**确实**能被 errors.As 认出来"。
// crypto/tls 从 Go 1.20 起把 x509 错误包进了 CertificateVerificationError，
// http.Client 又包一层 *url.Error——手搓的错误跳过了这两层包装，
// 于是包装方式一变，用例照绿而真机上照旧吐英文原文。
func TestFetchTokenExplainsSelfSignedControl(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"x"}`))
	}))
	defer srv.Close()

	_, err := FetchToken(srv.URL, "sess-token", "FP-TEST")
	if err == nil {
		t.Fatal("对着一张自签证书应当握手失败")
	}
	if got := err.Error(); got != msgUnknownCA {
		t.Fatalf("应换成中文归因，实得：%s", got)
	}
	// 原错误链必须还在：丢了链就等于"给人看懂了、给程序看瞎了"
	var unknownCA x509.UnknownAuthorityError
	if !errors.As(err, &unknownCA) {
		t.Error("ClassifyControlErr 必须保留原错误链（Unwrap），否则调用方再也判不出具体成因")
	}
}

// 认不出的错误**原样返回**。
//
// ★这是这一族改造里最容易破的一条：给"其余情况"补一句泛泛的兜底文案，
// 读起来体面得多，代价是把唯一有信息量的原文盖掉了——用户拿着一句
// 「网络异常，请稍后重试」，而真实原因（比如 HTTP/2 协议错、代理返回了垃圾）永远看不到。
func TestClassifyControlErrPassesThroughUnknown(t *testing.T) {
	orig := errors.New("某种谁也没预料到的传输层错误")
	if got := ClassifyControlErr(orig); got != orig {
		t.Fatalf("认不出的错误必须原样返回（同一个 error 值），实得 %#v", got)
	}
	if ClassifyControlErr(nil) != nil {
		t.Error("nil 进 nil 出")
	}
	// 认得出是 net.OpError、但不是被拒也不是超时的那种，同样原样返回
	op := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("network is unreachable")}
	if got := ClassifyControlErr(op); got != error(op) {
		t.Errorf("认不出具体成因的 net.OpError 也应原样返回，实得 %v", got)
	}
	// CertificateInvalidError 的非 Expired 档：补救动作与"证书过期"完全不同，不许套同一句话
	other := x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}
	if got := ClassifyControlErr(other); got != error(other) {
		t.Errorf("非 Expired 的证书错误应原样返回（不许猜成「过期」），实得 %v", got)
	}
}

// 逐档都要「说清事实 + 说得出下一步」，且各档必须互不相同——
// 两档给同一句话等于没分档，而分档的全部价值就在于下一步动作不一样。
func TestClassifyControlErrBuckets(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want []string // 必须出现的关键信息（事实 + 下一步）
	}{
		{"自签未受信", x509.UnknownAuthorityError{}, []string{"不信任", "根证书"}},
		{"主机名对不上", x509.HostnameError{Host: "gw.example.com"}, []string{"gw.example.com", "重新签发"}},
		{"证书过期", x509.CertificateInvalidError{Reason: x509.Expired}, []string{"过期", "系统时间"}},
		{"DNS 解析不了", &net.DNSError{Name: "control.internal", Err: "no such host"}, []string{"control.internal", "DNS"}},
		{"连接被拒", &net.OpError{Op: "dial", Err: syscallConnRefused()}, []string{"拒绝", "端口"}},
		{"超时", &net.OpError{Op: "dial", Err: timeoutErr{}}, []string{"超时", "丢包"}},
	}
	seen := map[string]string{}
	for _, c := range cases {
		got := ClassifyControlErr(c.err).Error()
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s：归因里应提到 %q，实得：%s", c.name, w, got)
			}
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%s 与 %s 给了同一句话——分了档却说同样的话等于没分档", c.name, prev)
		}
		seen[got] = c.name
		assertHealthLineSafe(t, c.name, got)
	}
	assertHealthLineSafe(t, "自签未受信", msgUnknownCA)
}

// assertHealthLineSafe 断言文案能原样穿过 dataplane.sanitizeReason（健康行值域的唯一消毒口）。
//
// ★消毒口在 internal/dataplane，这里是它的上游、导不过来（反向依赖），所以在这一侧
// 断言的是那三条规则的**属性**：单行、无裸 `=`、长度在上限内、首尾无空白且没有连续空白。
// 逐字不变的端到端验证在 internal/dataplane 侧另有一条用例（真跑 sanitizeReason）。
// 为什么值得两头都验：文案被消毒口改写不会报任何错，只会在真机日志与界面上出现
// 一句被削过的话（比如 `=` 变成全角、末尾挂上"已截断"），而写文案的人根本看不到。
func assertHealthLineSafe(t *testing.T, name, msg string) {
	t.Helper()
	if strings.ContainsAny(msg, "\n\r\t") {
		t.Errorf("%s：归因必须是单行（健康行按行解析）：%q", name, msg)
	}
	if strings.Contains(msg, "=") {
		t.Errorf("%s：归因里不得出现 ASCII `=`（会被消毒成全角，且可能被客户端误当成字段起点）：%s", name, msg)
	}
	if strings.TrimSpace(msg) != msg || strings.Contains(msg, "  ") {
		t.Errorf("%s：归因首尾不得有空白、也不得有连续空白（消毒口会折掉）：%q", name, msg)
	}
	// 上限 200 rune 是 dataplane.healthReasonMax；健康行里还会带 "取敲门令牌失败：" 这 8 个字的前缀，
	// 故这里留出余量，免得正常文案在真机上被"…（原因过长已截断）"削掉尾巴。
	if n := len([]rune(msg)); n > 180 {
		t.Errorf("%s：归因 %d 个字符，超出健康行余量（上限 200，另有 8 字前缀）：%s", name, n, msg)
	}
}

// timeoutErr 是一个只声称「我超时了」的最小错误，用来打 net.Error.Timeout() 那一档。
type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }

// syscallConnRefused 返回本平台的「连接被拒」errno。
// ★用 syscall.ECONNREFUSED 而不是拿 err.Error() 匹配 "connection refused"：
// 那串文字在 Windows 上根本不长这样，而 baidi-tun 是要出 .exe 的。
func syscallConnRefused() error { return syscall.ECONNREFUSED }

// TestFetchTokenExplainsBadStatus 钉住非 2xx 那一支也翻人话，且**认不出的保留状态码**。
//
// 502 是参考部署里最容易出现、又最容易被读反的一档：nginx 活着而 baidi-control 挂了。
// 改造前它显示成「control 返回 502」，用户会去查自己的网络——而该看的是服务端进程。
func TestFetchTokenExplainsBadStatus(t *testing.T) {
	cases := []struct {
		code int
		want string // 期望出现在错误里的片段；"" = 期望保留 control 返回 %d 的原样
	}{
		{401, "登录状态已过期"},
		{502, "反向代理连不上后端进程"},
		{503, "反向代理连不上后端进程"},
		{504, "反向代理连不上后端进程"},
		{418, ""}, // 认不出的一律原样：泛泛兜底会把状态码这条唯一线索抹掉
		{500, ""}, // 500 是控制面自己出错，与"进程没起来"成因不同，刻意不并档
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.code)
		}))
		_, err := FetchToken(srv.URL, "tok", "dev")
		srv.Close()
		if err == nil {
			t.Fatalf("HTTP %d 应当报错", c.code)
		}
		got := err.Error()
		if c.want == "" {
			if !strings.Contains(got, fmt.Sprintf("control 返回 %d", c.code)) {
				t.Errorf("HTTP %d 认不出时应保留状态码原样，得到：%s", c.code, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("HTTP %d 期望含 %q，得到：%s", c.code, c.want, got)
		}
		if !strings.Contains(got, fmt.Sprintf("HTTP %d", c.code)) {
			t.Errorf("HTTP %d 翻成人话之后**仍要带上状态码**（排障时它是唯一能对上服务端日志的东西），得到：%s", c.code, got)
		}
		assertHealthLineSafe(t, fmt.Sprintf("HTTP %d", c.code), got)
	}
}

// TestClassifyControlStatusDoesNotSwallow403 —— 403 有自己的语义（ErrDenied：停止接入、不再重试），
// 绝不能被这里翻成一句"稍后重试"，否则被封禁的客户端会照着提示徒劳空转。
func TestClassifyControlStatusDoesNotSwallow403(t *testing.T) {
	if msg := ClassifyControlStatus(403); msg != "" {
		t.Fatalf("403 必须留给 ErrDenied 那条路径，这里应回空串，得到：%s", msg)
	}
}
