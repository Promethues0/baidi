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
	"sync"
	"sync/atomic"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"

	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/spa"
)

// active 当前活跃隧道连接数（已通过 SPA 授权、正在代理中）；供网关向控制面上报真实负载。
var active atomic.Int64

// Active 返回当前活跃隧道连接数。
func Active() int { return int(active.Load()) }

// conns 活跃隧道连接登记表：账号 → 连接集合（强制下线按账号切断）。
var conns = struct {
	mu sync.Mutex
	m  map[string]map[net.Conn]struct{}
}{m: map[string]map[net.Conn]struct{}{}}

// normUser 与 spa.normUser 同义：账号匹配键规范化（去首尾空格 + 小写），
// 保证按账号切断隧道对大小写/空格变体一致命中，杜绝换形态绕过强制下线。
func normUser(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func track(user string, c net.Conn) {
	key := normUser(user)
	conns.mu.Lock()
	defer conns.mu.Unlock()
	set := conns.m[key]
	if set == nil {
		set = map[net.Conn]struct{}{}
		conns.m[key] = set
	}
	set[c] = struct{}{}
}

func untrack(user string, c net.Conn) {
	key := normUser(user)
	conns.mu.Lock()
	defer conns.mu.Unlock()
	if set := conns.m[key]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(conns.m, key)
		}
	}
}

// KillUser 关闭某账号的全部活跃隧道连接（强制下线的数据面执行），返回切断条数。
// Close 会打断双向 io.Copy，隧道立即真实断开。摘除与关闭同步完成，
// 幂等（重复调用返回 0）；handle 退出时的 defer untrack 对已摘除连接是无害空操作。
func KillUser(user string) int {
	key := normUser(user)
	conns.mu.Lock()
	list := make([]net.Conn, 0, len(conns.m[key]))
	for c := range conns.m[key] {
		list = append(list, c)
	}
	delete(conns.m, key)
	conns.mu.Unlock()
	for _, c := range list {
		_ = c.Close()
	}
	return len(list)
}

const (
	preamblePrefix  = "CONNECT " // 8 字节
	preambleMax     = 256        // 前导单行最长，防滥用/无界缓冲
	preambleTimeout = 3 * time.Second
	maxConcurrent   = 1024 // 同时处于握手/前导阶段的连接上限，封顶内存/goroutine
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

// serve 是两种监听共享的接受循环（门控/路由逻辑与加密层无关）；信号量封顶并发。
func serve(ln net.Listener, reg *resource.Registry, al *spa.Allowlist) error {
	sem := make(chan struct{}, maxConcurrent)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			handle(c, reg, al)
		}()
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
	// 已授权连接计入活跃隧道数（供上报控制面）并按账号登记（强制下线可按账号切断）；handle 返回即回落
	active.Add(1)
	defer active.Add(-1)
	track(user, c)
	defer untrack(user, c)
	// 登记后复核放行窗口：若在 Allowed→track 空档遭强制下线（applyRevoked 先撤窗再 KillUser，
	// 本连接恰在 KillUser 扫描后落表则漏杀），此处 Allowed 已为 false → 立即断开，杜绝连接逃逸切断。
	if _, _, ok := al.Allowed(ip); !ok {
		slog.Warn("代理拒绝（登记后放行窗口已失效，疑似强制下线竞态）", "src", ip, "user", user)
		_ = c.Close()
		return
	}

	// 显式完成握手，与前导读取的短超时解耦：crypto/tls 的 Accept 不在 Accept 内握手，
	// 若把握手推迟到带 3s deadline 的前导 Peek 里触发会与之卡死（gotlcp 在 Accept 即握手故无此问题）。
	if hs, isHS := c.(interface{ Handshake() error }); isHS {
		_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
		if err := hs.Handshake(); err != nil {
			slog.Warn("握手失败", "src", ip, "err", err.Error())
			_ = c.Close()
			return
		}
		_ = c.SetReadDeadline(time.Time{})
	}

	br := bufio.NewReaderSize(c, 4096) // 固定缓冲，前导用 ReadSlice 受此封顶（防无界缓冲 OOM）
	rid, hasPreamble, good := readPreamble(c, br)
	if !good {
		// 疑似前导但未在预算内读全（截断/超时）→ fail-closed，绝不降级回退默认后端
		slog.Warn("代理拒绝（前导不完整/超时，fail-closed）", "src", ip, "user", user)
		_ = c.Close()
		return
	}

	backend := reg.Default
	if hasPreamble {
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

// readPreamble 解析隧道首部是否带 "CONNECT <id>\n" 前导。
// 返回 good=false 表示"疑似前导但未读全"，调用方必须 fail-closed（不得降级默认后端）。
// 按"已收字节是否仍是 CONNECT 前缀"决策，避免正常 TCP 分段把慢到达的前导误判为无前导：
//   - 首字节非 'C' → 立即判无前导（不阻塞 server-speaks-first 协议）
//   - 收到的是 CONNECT 真前缀但在预算内没凑齐 → fail-closed
//   - 凑齐 "CONNECT " → 限长读取该行解析 id
func readPreamble(c net.Conn, br *bufio.Reader) (rid string, hasPreamble, good bool) {
	_ = c.SetReadDeadline(time.Now().Add(preambleTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	for n := 1; n <= len(preamblePrefix); n++ {
		p, err := br.Peek(n) // Peek 不消费 → 无前导字节留在 br 不丢
		if err != nil {
			switch {
			case len(p) == 0:
				return "", false, true // 无任何字节（空闲）→ 视作无前导，回退默认
			case string(p) == preamblePrefix[:len(p)]:
				return "", false, false // 是 CONNECT 真前缀但没凑齐 → fail-closed
			default:
				return "", false, true // 已分叉，非前导业务流
			}
		}
		if string(p) != preamblePrefix[:n] {
			return "", false, true // 第 n 字节分叉 → 无前导
		}
	}

	// 凑齐 "CONNECT "：限长读这一行（ReadSlice 受 br 固定缓冲封顶，超长即拒）
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > preambleMax {
		return "", false, false // 行过长/读错 → fail-closed
	}
	rid = strings.TrimSpace(strings.TrimPrefix(string(line), preamblePrefix))
	if rid == "" {
		return "", false, false // 空 id → fail-closed
	}
	return rid, true, true
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
