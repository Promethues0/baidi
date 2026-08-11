package webproxy

// 已升级连接（WebSocket / 其它 101 Upgrade）的台账与执行方。
//
// ── 为什么非有不可 ──
//
// 七层的核心是**逐请求重新鉴权**：强制下线、风险降权（DenyUsers）、JIT 到期都在
// 下一个请求上生效。但 101 之后连接被 httputil 劫持成双向 io.Copy，此后**再也不会
// 产生任何 http.Request**——一条 Web 终端 / 在线 IDE / 客服系统的 WS 连接因此
// 完全逃出那道闸，且没有任何生命周期上界：网关自己都没有手段终止它。
//
// 对照 L4：隧道那侧有 proxy.track/untrack + proxy.KillUser，强制下线时逐条切断并
// 在回执里报"切断 N 条隧道"。L7 此前没有等价物，于是管理台显示"已切断"、
// 审计写着"已下线"，而那条 WS 仍在网关里搬运业务数据，直到用户自己关标签页。
//
// ── 两条执行路径 ──
//
//	① 周期复查（recheck）：与策略轮询同量级，判据与 handleAny 逐请求那段**同源**
//	   （UserDenied / Lookup / Authorize），不过是把"下一个请求"换成"下一个滴答"。
//	② 寿命上界：连接绝不比签发它的那张会话 Cookie 活得久。没有上界的话，
//	   一条在建立那一刻合法的连接可以永久存在，而 Cookie 早就过期了。

import (
	"net"
	"strings"
	"sync"
	"time"
)

// upgradedConn 一条已升级连接的台账项。
type upgradedConn struct {
	user string
	res  string
	conn net.Conn
	done chan struct{}
}

// upgradeTracker 按账号索引的已升级连接台账（并发安全）。
type upgradeTracker struct {
	mu sync.Mutex
	m  map[string]map[*upgradedConn]struct{}
}

func newUpgradeTracker() *upgradeTracker {
	return &upgradeTracker{m: map[string]map[*upgradedConn]struct{}{}}
}

// normUser 账号归一化：与 spa.Allowlist / proxy 的封禁名单同口径（大小写/空白不该
// 让一次强制下线漏掉一条连接）。
func normUser(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

func (t *upgradeTracker) add(user, res string, c net.Conn) *upgradedConn {
	uc := &upgradedConn{user: user, res: res, conn: c, done: make(chan struct{})}
	key := normUser(user)
	t.mu.Lock()
	defer t.mu.Unlock()
	set := t.m[key]
	if set == nil {
		set = map[*upgradedConn]struct{}{}
		t.m[key] = set
	}
	set[uc] = struct{}{}
	return uc
}

// remove 摘除台账项并叫停它的守护 goroutine（幂等）。
func (t *upgradeTracker) remove(uc *upgradedConn) {
	if uc == nil {
		return
	}
	key := normUser(uc.user)
	t.mu.Lock()
	if set := t.m[key]; set != nil {
		delete(set, uc)
		if len(set) == 0 {
			delete(t.m, key)
		}
	}
	t.mu.Unlock()
	uc.stop()
}

func (uc *upgradedConn) stop() {
	select {
	case <-uc.done:
	default:
		close(uc.done)
	}
}

// killUser 切断某账号全部已升级连接，返回条数。摘除与关闭同步完成，幂等。
func (t *upgradeTracker) killUser(user string) int {
	key := normUser(user)
	t.mu.Lock()
	list := make([]*upgradedConn, 0, len(t.m[key]))
	for uc := range t.m[key] {
		list = append(list, uc)
	}
	delete(t.m, key)
	t.mu.Unlock()
	for _, uc := range list {
		_ = uc.conn.Close() // Close 打断双向 io.Copy，连接立即真实断开
		uc.stop()
	}
	return len(list)
}

// count 当前已升级连接总数（供日志与自检）。
func (t *upgradeTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, set := range t.m {
		n += len(set)
	}
	return n
}

// isUpgradeRequest 报告这是不是一次协议升级请求（101 的前置条件）。
func isUpgradeRequest(connHdr, upgradeHdr string) bool {
	if strings.TrimSpace(upgradeHdr) == "" {
		return false
	}
	for _, tok := range strings.Split(connHdr, ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

// defaultUpgradeRecheck 已升级连接的默认复查节奏。与控制面策略轮询（默认 15s）同量级：
// 更密只是空转，更疏会让"已下线"与"真的断开"之间出现肉眼可见的窗口。
const defaultUpgradeRecheck = 10 * time.Second
