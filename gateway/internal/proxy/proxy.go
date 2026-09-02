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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"

	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/secevent"
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
	// maxConcurrent 单台网关**同时活跃的隧道连接**上限，封顶内存/goroutine。
	//
	// ★这个名字以前的注释写的是「同时处于握手/前导阶段的连接上限」，比实际窄得多：
	// 信号量的 slot 在 handle() 返回后才释放，而 handle 末尾是同步的 io.Copy——
	// 整条隧道会话的寿命里 slot 一直占着。所以它是会话数上限，不是握手数上限。
	// 按窄的那个读会严重高估容量（握手是毫秒级，会话是小时级）。
	maxConcurrent = 1024
)

// Serve 启动通用 TLS 代理监听。reg.Default 为默认回退后端。
// rep 为安全事件上报器（nil 安全）：拒绝除本机日志外，经节流上报控制面留痕。
func Serve(addr string, cert tls.Certificate, reg *resource.Registry, al *spa.Allowlist, rep *secevent.Reporter) error {
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	slog.Info("SSL 隧道代理监听（通用 TLS）", "addr", addr, "default_backend", reg.Default, "resources", reg.Count())
	return serve(ln, reg, al, rep, maxConcurrent)
}

// ServeTLCP 启动国密 TLCP 代理监听（SM2 双证书 + SM3/SM4 套件）。
func ServeTLCP(addr string, certs []tlcp.Certificate, reg *resource.Registry, al *spa.Allowlist, rep *secevent.Reporter) error {
	ln, err := tlcp.Listen("tcp", addr, &tlcp.Config{Certificates: certs})
	if err != nil {
		return err
	}
	slog.Info("SSL 隧道代理监听（国密 TLCP）", "addr", addr, "default_backend", reg.Default, "resources", reg.Count())
	return serve(ln, reg, al, rep, maxConcurrent)
}

// serve 是两种监听共享的接受循环（门控/路由逻辑与加密层无关）；信号量封顶并发。
// limit 由调用方传入（生产恒为 maxConcurrent）：用例要真的把并发打满才能证明
// 「到顶时拒绝并留痕」，而 1024 条真连接在单测里既慢又不稳。
func serve(ln net.Listener, reg *resource.Registry, al *spa.Allowlist, rep *secevent.Reporter, limit int) error {
	sem := make(chan struct{}, limit)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		// ★打满时**拒绝并留痕**，不阻塞 accept 循环。
		// 原先是 `sem <- struct{}{}` 直接阻塞：到顶后新连接停在内核 backlog 里，
		// 客户端表现为拨号后挂住到超时，而网关不拒绝、不记日志、不上报、不落审计——
		// 控制台上与「一切正常」完全同形。容量到顶是真实运维信号（本项目做不了压测，
		// 更没有规格表），至少要让它可见：管理员该做的是扩容，而挂住不会告诉他这件事。
		select {
		case sem <- struct{}{}:
		default:
			ip := hostOf(c.RemoteAddr().String())
			slog.Warn("代理拒绝（网关并发已达上限）", "src", ip, "limit", limit)
			rep.Report("proxy-capacity", ip, "网关同时活跃隧道连接已达上限 "+strconv.Itoa(limit)+"，新连接被拒")
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			handle(c, reg, al, rep)
		}()
	}
}

func handle(c net.Conn, reg *resource.Registry, al *spa.Allowlist, rep *secevent.Reporter) {
	ip := hostOf(c.RemoteAddr().String())
	user, role, ok := al.Allowed(ip)
	if !ok {
		// 未敲门 → 立即断开（业务对未授权者隐身；内核态 DROP 见 -pf）
		slog.Warn("代理拒绝（无 SPA 授权）", "src", ip)
		rep.Report("proxy-unauth", ip, "隧道代理拒绝（无 SPA 授权，直连被断）")
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
		rep.Report("proxy-revoked", ip, "隧道代理拒绝（账号 "+user+" 放行窗口已被撤销）")
		_ = c.Close()
		return
	}
	// 记一次业务活跃（FR-POLICY-30「无业务流量超时注销」的信号源）。
	// ★位置刻意在**两道放行复核之后**：未授权连接不该刷新活跃时刻，
	// 否则任何人往隧道口打一个包就能替别人的会话续命。
	al.Touch(ip)

	// 显式完成握手，与前导读取的短超时解耦：crypto/tls 与 gotlcp（v1.4.5 `listener.Accept` 只是
	// `Server(c, cfg)` 包一层，同样不握手）的 Accept 都不在 Accept 内握手，若把握手推迟到带 3s deadline
	// 的前导 Peek 里触发会与之卡死——两种监听都走下面这个 Handshake() 分支（*tlcp.Conn 同样实现了它）。
	// （此处此前写作「gotlcp 在 Accept 即握手故无此问题」，是错的；行为上没受影响，因为这个分支两者都命中。）
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
		rep.Report("proxy-preamble", ip, "隧道代理拒绝（前导不完整/超时，账号 "+user+"）")
		_ = c.Close()
		return
	}

	backend := reg.Default
	if hasPreamble {
		res, found := reg.Lookup(rid) // ★ 白名单查表：唯一允许的取后端途径（SSRF 防线）
		if !found {
			slog.Warn("代理拒绝（资源未注册/疑似 SSRF）", "src", ip, "user", user, "resource", rid)
			rep.Report("proxy-ssrf", ip, "隧道代理拒绝（资源 "+rid+" 未注册/疑似 SSRF，账号 "+user+"）")
			_ = c.Close()
			return
		}
		if !reg.Authorize(user, role, res) {
			slog.Warn("代理拒绝（无资源授权）", "src", ip, "user", user, "role", role, "resource", rid)
			rep.Report("proxy-authz", ip, "隧道代理拒绝（账号 "+user+" 无资源 "+rid+" 授权）")
			_ = c.Close()
			return
		}
		backend = res.Backend
		slog.Info("隧道路由命中", "src", ip, "user", user, "role", role, "resource", rid, "backend", backend)
		// ★放行也要留痕（wave8 行动 8）。此前这一行只进本机 slog——网关一重启即灭失，
		// 「某账号何时经哪台网关访问了哪个资源」在中心侧查不到，外送 SIEM 的证据链只有半边。
		// 节流键是 (账号,资源) 而不是源 IP：同一个人访问三个资源是三件事。
		rep.ReportAllow("tunnel-allow", ip, user+"|"+rid,
			"隧道放行：账号 "+user+" 经隧道访问资源 "+rid+"（后端 "+backend+"）")
	} else if !reg.AllowNoPreamble {
		// ★fail-closed：无前导 = 不知道要访问哪个资源 = 无法鉴权，直接断。
		//   与上面「前导不完整」那条同一条纪律（那里的注释写着"绝不降级回退默认后端"）。
		//   放行的话，Lookup / Authorize / DenyUsers 一个都不执行，而参考部署里
		//   Default 正是控制面自身的回环口——详见 resource.Registry.AllowNoPreamble。
		slog.Warn("代理拒绝（无 CONNECT 前导，fail-closed）", "src", ip, "user", user,
			"提示", "客户端未声明目标资源；若确需兼容无前导的老客户端，用 -allow-no-preamble 显式开启（该路径不做资源鉴权）")
		rep.Report("proxy-nopreamble", ip, "隧道代理拒绝（未声明目标资源，账号 "+user+"）")
		_ = c.Close()
		return
	} else {
		// 兼容模式（-allow-no-preamble）：**必须留痕**。此前这里只有一行本机 slog，
		// 网关一重启即灭失——「谁在用这条不鉴权的路」在中心侧完全查不到。
		slog.Warn("隧道无前导 · 回退默认后端（该路径不做资源鉴权）", "src", ip, "user", user, "backend", backend)
		rep.ReportAllow("tunnel-nopreamble", ip, user+"|<default>",
			"隧道放行：账号 "+user+" 未声明资源，按兼容模式直连默认后端 "+backend+"（**未经资源鉴权**）")
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
