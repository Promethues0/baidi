package api

// 灰度观察的节流必须同时拦住**库读**，不只是审计写（wave9）。
//
// ★改造前 PostureVerdict 排在节流判定之前：节流拦下的只有审计写，而每个 gray
// 账号每轮仍真查一次库。这条 N+1 的库成本完全不受节流约束，还随网关台数相乘
// （每台网关每 15s 各跑一遍策略下发）。

import (
	"context"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// verdictCounter 数 PostureVerdict 被调了几次，其余全部透传。
type verdictCounter struct {
	store.Store
	n int32
}

func (c *verdictCounter) PostureVerdict(ctx context.Context, account string) (store.PostureReport, bool, error) {
	atomic.AddInt32(&c.n, 1)
	return c.Store.PostureVerdict(ctx, account)
}

func TestGray节流同时拦住库读(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "gray.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	ctx := context.Background()
	// 三个 gray 账号：N+1 的 N 要大于 1，否则"省掉几次查询"看不出来。
	for _, acc := range []string{"gray.a", "gray.b", "gray.c"} {
		if err := st.SavePostureReport(ctx, store.PostureReport{
			User: acc, Device: "dev-1", Platform: "macOS", Verdict: store.DisposalGray,
			Reasons: []string{"主机防火墙未开启"}, TS: 1754800000,
		}); err != nil {
			t.Fatal(err)
		}
	}

	cnt := &verdictCounter{Store: st}
	s := New(cnt, st, testKeys, "test", t.TempDir(), nil, nil, true)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	// 第一轮：三个账号各查一次。
	if code, _ := doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil); code != http.StatusOK {
		t.Fatal("第一轮策略下发失败")
	}
	first := atomic.LoadInt32(&cnt.n)
	if first < 3 {
		t.Fatalf("第一轮应对每个 gray 账号各查一次判定，实得 %d 次", first)
	}

	// 第二轮：全部落在节流窗口内 —— **一次库读都不该发生**。
	if code, _ := doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil); code != http.StatusOK {
		t.Fatal("第二轮策略下发失败")
	}
	if second := atomic.LoadInt32(&cnt.n); second != first {
		t.Fatalf("节流窗口内仍查了 %d 次库（%d → %d）——"+
			"节流拦的只是审计写，库成本没拦住，且随网关台数相乘",
			second-first, first, second)
	}
}
