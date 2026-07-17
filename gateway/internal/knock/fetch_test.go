package knock

import (
	"errors"
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

	_, err := FetchToken(srv.URL, "sess-token")
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

	_, err := FetchToken(srv.URL, "sess-token")
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
