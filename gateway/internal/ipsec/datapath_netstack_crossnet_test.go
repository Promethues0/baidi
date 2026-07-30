package ipsec

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// 跨网段往返。
//
// ★这条与 TestNetstackDatapathRealTCP 只差一个字：那条两端同在 10.60.0.0/24，
// 而 IPSec 的**真实场景恒为跨网段**（站点 A 的 10.90.0.0/24 ↔ 站点 B 的 10.91.0.0/24）。
// 同网段跑得通不代表跨网段跑得通：目的地址落在本地前缀之外时，协议栈要走的是
// "默认路由 + 无网关直发"这条分支，与同网段的直连分支根本不是同一段代码。
//
// 少了这条测试，数据面本身的跨网段缺陷会一路潜伏到 e2e 才炸，而那时怀疑对象
// 是十几个环节（IKE 协商？SPD 选路？ESP 加解密？），排查成本天差地别。
func TestNetstackDatapathCrossSubnetTCP(t *testing.T) {
	client, err := NewNetstackDatapath(netip.MustParsePrefix("10.90.0.1/24"), 1400)
	if err != nil {
		t.Fatalf("建客户端协议栈失败：%v", err)
	}
	defer client.Close()
	// ★不同网段：这正是站点组网的常态。
	server, err := NewNetstackDatapath(netip.MustParsePrefix("10.91.0.1/24"), 1400)
	if err != nil {
		t.Fatalf("建服务端协议栈失败：%v", err)
	}
	defer server.Close()

	nstRelay(t, client, server)
	nstRelay(t, server, client)

	ln, err := server.ListenTCP(8080)
	if err != nil {
		t.Fatalf("服务端监听失败：%v", err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "跨网段可达")
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	cli := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DialContext: client.DialContext},
	}
	resp, err := cli.Get("http://10.91.0.1:8080/")
	if err != nil {
		t.Fatalf("跨网段 HTTP 失败：%v\n"+
			"（若同网段的 TestNetstackDatapathRealTCP 是绿的而这条红，"+
			"说明协议栈缺少到对端网段的路由——IPSec 的每一条隧道都是跨网段的，"+
			"这会让隧道协商全绿而业务一个包都不通）", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "跨网段可达" {
		t.Fatalf("响应内容不符：%q", string(b))
	}
}

// 确保上面用到的 ctx 变量不被 lint 判为未使用（保持与既有测试同款结构）。
var _ = context.Background
