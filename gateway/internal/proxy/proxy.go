// Package proxy 是受 SPA 门控的隧道代理：
// 仅当来源 IP 在 SPA 放行窗口内才终止 TLS/TLCP 并转发到后端；否则立即断开（隐身）。
// 支持按目的多资源路由：隧道内首行 "CONNECT <resource-id>\n" 选择后端（查注册表 + 授权），
// 无前导则回退默认后端（兼容旧客户端）。防 SSRF：后端地址只来自注册表，绝不取自客户端。
package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"

	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/spa"
)

const (
	preamblePrefix = "CONNECT " // 8 字节
	preambleMax    = 256        // 前导单行最长，防滥用
)

// Serve 启动通用 TLS 代理监听。reg.Default 为默认回退后端。
func Serve(addr string, cert tls.Certificate, reg *resource.Registry, al *spa.Allowlist) error {
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	slog.Info("SSL 隧道代理监听（通用 TLS）", "addr", addr, "default_backend", reg.Default, "resources", reg.Count())
	return serve(ln, reg, al)
}

// ServeTLCP 启动国密 TLCP 代理监听（SM2 双证书 + SM3/SM4 套件）。
func ServeTLCP(addr string, certs []tlcp.Certificate, reg *resource.Registry, al *spa.Allowlist) error {
	ln, err := tlcp.Listen("tcp", addr, &tlcp.Config{Certificates: certs})
	if err != nil {
		return err
	}
	slog.Info("SSL 隧道代理监听（国密 TLCP）", "addr", addr, "default_backend", reg.Default, "resources", reg.Count())
	return serve(ln, reg, al)
}

// serve 是两种监听共享的接受循环（门控/路由逻辑与加密层无关）。
func serve(ln net.Listener, reg *resource.Registry, al *spa.Allowlist) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, reg, al)
	}
}

func handle(c net.Conn, reg *resource.Registry, al *spa.Allowlist) {
	ip := hostOf(c.RemoteAddr().String())
	user, role, ok := al.Allowed(ip)
	if !ok {
		// 未敲门 → 立即断开（业务对未授权者隐身；内核态 DROP 见 -pf）
		slog.Warn("代理拒绝（无 SPA 授权）", "src", ip)
		_ = c.Close()
		return
	}

	br := bufio.NewReader(c)
	backend := reg.Default

	// 偷看前 8 字节判断是否带 CONNECT 前导；Peek 不消费，故无前导时全部字节留在 br 不丢。
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	prefix, _ := br.Peek(len(preamblePrefix))
	_ = c.SetReadDeadline(time.Time{})

	if string(prefix) == preamblePrefix {
		// 有前导：消费这一行，解析 resource-id
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		line, err := br.ReadString('\n')
		_ = c.SetReadDeadline(time.Time{})
		if err != nil || len(line) > preambleMax {
			slog.Warn("代理拒绝（前导异常）", "src", ip, "user", user)
			_ = c.Close()
			return
		}
		rid := strings.TrimSpace(strings.TrimPrefix(line, preamblePrefix))
		res, found := reg.Lookup(rid) // ★ 白名单查表：唯一允许的取后端途径（SSRF 防线）
		if !found {
			slog.Warn("代理拒绝（资源未注册/疑似 SSRF）", "src", ip, "user", user, "resource", rid)
			_ = c.Close()
			return
		}
		if !reg.Authorize(user, role, res) {
			slog.Warn("代理拒绝（无资源授权）", "src", ip, "user", user, "role", role, "resource", rid)
			_ = c.Close()
			return
		}
		backend = res.Backend
		slog.Info("隧道路由命中", "src", ip, "user", user, "role", role, "resource", rid, "backend", backend)
	} else {
		slog.Info("隧道无前导 · 回退默认后端", "src", ip, "user", user, "backend", backend)
	}

	b, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		slog.Error("后端不可达", "backend", backend, "err", err.Error())
		_ = c.Close()
		return
	}
	slog.Info("隧道建立 · 代理转发", "src", ip, "user", user, "backend", backend)
	// 关键：向后端拷贝用 br（含 Peek/未消费的缓冲字节），不能用裸 c，否则丢应用数据。
	go func() { _, _ = io.Copy(b, br); _ = b.Close() }()
	_, _ = io.Copy(c, b)
	_ = c.Close()
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
