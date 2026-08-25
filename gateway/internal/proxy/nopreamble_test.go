package proxy

import (
	"net"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/secevent"
	"baidi.dev/gateway/internal/spa"
)

// 无 CONNECT 前导的连接**默认必须被拒**，且要留痕。
//
// ★这条路径此前直连 reg.Default 且完全跳过 Lookup / Authorize / DenyUsers——
// 「五道门」的第 5 道在上面根本不执行，而参考部署把 Default 设成了控制面自身的
// 回环口（baidi-gateway.service 的 -backend 127.0.0.1:<CONTROL_PORT>）。后果是
// 任意能敲开门的 role=user 账号都能把请求直送控制面：绕过 nginx 那份限流；
// 控制面看到对端是 127.0.0.1、落在 defaultTrustedProxies 内，于是采信请求方
// 自带的 X-Forwarded-For（审计源 IP、攻击源统计、以及认证策略里 trustedNetwork
// 那条**削弱二次认证**的豁免判据全可伪造），还能反向刷别人的办公出口 IP 把它锁掉。
//
// 触发它连"构造畸形包"都不需要：readPreamble 只在首字节为 'C' 时才认前导，
// 一个普通的 `GET / HTTP/1.1` 就走这条路——gateway/demo.sh 的步骤③ 正是如此。
func startBackend(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起后端失败：%v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("BACKEND-REACHED"))
			_ = c.Close()
		}
	}()
	return ln
}

// noPreambleRun 已敲门的连接直接发一个普通 HTTP 请求（无前导），返回读到的字节与上报记录。
func noPreambleRun(t *testing.T, allowNoPreamble bool) (string, *capture) {
	t.Helper()
	backend := startBackend(t)
	reg := resource.New(backend.Addr().String())
	reg.AllowNoPreamble = allowNoPreamble
	// 注册表里**有**资源：证明拒绝与"资源表为空"无关，就是无前导本身被拒。
	reg.Replace([]resource.Resource{{
		ID: "res-git", Backend: backend.Addr().String(), AllowUsers: []string{"zhang.wei"},
	}})

	al := spa.NewAllowlist()
	al.Allow("127.0.0.1", "zhang.wei", "user", time.Minute) // 已敲门，门票是真的

	cap := &capture{}
	cli, srv := tcpPair(t)
	done := make(chan struct{})
	go func() { handle(srv, reg, al, secevent.New(cap.sink)); close(done) }()

	_ = cli.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = cli.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) // 首字节 'G'
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := cli.Read(buf)
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle 没有返回")
	}
	return string(buf[:n]), cap
}

func Test无前导默认拒绝且留痕(t *testing.T) {
	got, cap := noPreambleRun(t, false)
	if strings.Contains(got, "BACKEND-REACHED") {
		t.Fatal("无前导的连接不得抵达默认后端——那条路不做任何资源鉴权，" +
			"而参考部署里默认后端就是控制面自身的回环口")
	}
	var hit bool
	for _, r := range cap.recs {
		if r.cat == "proxy-nopreamble" && !r.allow {
			hit = true
		}
	}
	if !hit {
		t.Error("拒绝必须经 secevent 留痕（类别 proxy-nopreamble）：" +
			"只写本机 slog 的话，网关一重启即灭失，中心侧查不到有人在探这条路")
	}
}

// 逃生舱开着时保持旧行为——但**必须留痕**（此前这里只有一行本机 slog）。
func Test无前导逃生舱开启时放行但留痕(t *testing.T) {
	got, cap := noPreambleRun(t, true)
	if !strings.Contains(got, "BACKEND-REACHED") {
		t.Fatalf("开了 -allow-no-preamble 应保持旧行为（兼容老客户端），实得 %q", got)
	}
	var hit bool
	for _, r := range cap.recs {
		if r.cat == "tunnel-nopreamble" && r.allow && strings.Contains(r.detail, "未经资源鉴权") {
			hit = true
		}
	}
	if !hit {
		t.Error("兼容模式下的放行必须留痕并写明「未经资源鉴权」：" +
			"否则「谁在用这条不鉴权的路」在中心侧完全查不到")
	}
}
