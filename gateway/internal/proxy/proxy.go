// Package proxy 是受 SPA 门控的 TLS 隧道代理：
// 仅当来源 IP 在 SPA 放行窗口内才终止 TLS 并转发到后端业务；否则立即断开（隐身）。
package proxy

import (
	"io"
	"log/slog"
	"net"
	"time"

	"crypto/tls"

	"gitee.com/Trisia/gotlcp/tlcp"

	"baidi.dev/gateway/internal/spa"
)

// Serve 启动通用 TLS 代理监听。backend 为后端业务地址（host:port）。
func Serve(addr string, cert tls.Certificate, backend string, al *spa.Allowlist) error {
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	slog.Info("SSL 隧道代理监听（通用 TLS）", "addr", addr, "backend", backend)
	return serve(ln, backend, al)
}

// ServeTLCP 启动国密 TLCP 代理监听（SM2 双证书 + SM3/SM4 套件）。
func ServeTLCP(addr string, certs []tlcp.Certificate, backend string, al *spa.Allowlist) error {
	ln, err := tlcp.Listen("tcp", addr, &tlcp.Config{Certificates: certs})
	if err != nil {
		return err
	}
	slog.Info("SSL 隧道代理监听（国密 TLCP）", "addr", addr, "backend", backend)
	return serve(ln, backend, al)
}

// serve 是两种监听共享的接受循环（门控 + 代理逻辑与加密层无关）。
func serve(ln net.Listener, backend string, al *spa.Allowlist) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, backend, al)
	}
}

func handle(c net.Conn, backend string, al *spa.Allowlist) {
	ip := hostOf(c.RemoteAddr().String())
	user, ok := al.Allowed(ip)
	if !ok {
		// 未敲门 → 立即断开（业务对未授权者隐身；生产可在防火墙层 DROP）
		slog.Warn("代理拒绝（无 SPA 授权）", "src", ip)
		_ = c.Close()
		return
	}
	b, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		slog.Error("后端不可达", "backend", backend, "err", err.Error())
		_ = c.Close()
		return
	}
	slog.Info("隧道建立 · 代理转发", "src", ip, "user", user, "backend", backend)
	// 双向拷贝（TLS 终止于网关，向后端转发明文）
	go func() { _, _ = io.Copy(b, c); _ = b.Close() }()
	_, _ = io.Copy(c, b)
	_ = c.Close()
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
