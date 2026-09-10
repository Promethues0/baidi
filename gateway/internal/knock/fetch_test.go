package knock

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 403（强制下线/账号禁用）是定性拒绝：FetchToken 必须返回 ErrDenied，
// 且带出 control 错误信封里的原因——好让数据面停接入并向用户显示理由，
// 而不是把它当"取令牌失败"回退会话令牌继续傻敲。
func TestFetchTokenDeniedOn403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"已被强制下线，暂时无法接入"}}`))
	}))
	defer srv.Close()

	_, err := FetchToken(srv.URL, "sess-token", "FP-TEST")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("403 应返回 ErrDenied，得到 %v", err)
	}
	if got := err.Error(); got == "" || !contains(got, "已被强制下线") {
		t.Fatalf("ErrDenied 应带 control 原因，得到 %q", got)
	}
}

// 瞬时错误（500/网络）不是定性拒绝：不应报成 ErrDenied，
// 数据面据此保留回退会话令牌 + 重试的行为。
func TestFetchTokenTransientNotDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchToken(srv.URL, "sess-token", "FP-TEST")
	if err == nil {
		t.Fatal("500 应返回错误")
	}
	if errors.Is(err, ErrDenied) {
		t.Fatalf("500 是瞬时错误，不应报 ErrDenied，得到 %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// 指纹随请求体上报：控制面的授信终端准入闸靠它判定。
// ★这条用例守的是"指纹真的发出去了"——漏发的症状是严格模式下所有终端一律被拒，
// 而客户端日志里只有一句"接入被拒"，看不出是自己没带指纹。
func TestFetchTokenSendsDeviceFingerprint(t *testing.T) {
	var got struct {
		Device string `json:"device"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"tok"}`))
	}))
	defer srv.Close()

	tok, err := FetchToken(srv.URL, "sess-token", "FP-ABC")
	if err != nil || tok != "tok" {
		t.Fatalf("取令牌应成功: %q %v", tok, err)
	}
	if got.Device != "FP-ABC" {
		t.Fatalf("请求体应带终端指纹, got %q", got.Device)
	}
}

// ── wave11 行动 3：同一次调用还带回 L4 隧道身份票据 ──
//
// ★两样东西必须来自同一次调用：它们是控制面跑完同一套闸（封禁 / 账号状态 / 终端合规 /
// 设备准入 / 接入策略）之后一起签出的。分成两个端点去取的话，客户端会为每条业务 TCP 流
// 各取一次票，把控制面塞进数据路径。
func TestFetchGrantCarriesTunnelTicket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"tok-1","tunnelTicket":"tk-1","tunnelTicketExpiresIn":300}`))
	}))
	defer srv.Close()
	g, err := NewFetcher(nil).FetchGrant(srv.URL, "sess", "dev-1")
	if err != nil {
		t.Fatalf("取 Grant 失败：%v", err)
	}
	if g.Knock != "tok-1" || g.Tunnel != "tk-1" {
		t.Fatalf("Grant 应同时带回敲门令牌与隧道票据，实得 %+v", g)
	}
}

// TestFetchGrantOldControlHasNoTicket 旧控制面不发 tunnelTicket —— **不是错误**。
//
// ★在客户端这里 fail-closed 是错的方向：控制面没升级时敲门这件事照样成立，
// 该不该收一条没票据的连接由网关决定（它知道自己的严格姿态）。在这里报错的话，
// 「控制面还没升级」会表现为客户端整体连不上，而真正的原因在另一台机器上。
func TestFetchGrantOldControlHasNoTicket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"tok-1","expires_in":90}`))
	}))
	defer srv.Close()
	g, err := NewFetcher(nil).FetchGrant(srv.URL, "sess", "")
	if err != nil {
		t.Fatalf("旧控制面不发票据不该报错：%v", err)
	}
	if g.Knock != "tok-1" || g.Tunnel != "" {
		t.Fatalf("应拿到敲门令牌、票据为空（= 控制面未升级，不是「不需要」），实得 %+v", g)
	}
}
