package ipsec

import (
	"fmt"
	"net/netip"
	"sync"
)

// MemNet 是一张**进程内的假 UDP 网**：按 AddrPort 绑定端点，Send 直接投递到对端队列。
//
// 它不是 _test.go 文件，因为除单测外，ipsec-e2e 自检二进制也要用它在同一进程里
// 对拨两个完整站点。有了它，「起两台网关跑真协商」不再需要 root、不需要真端口、
// 也不需要 Docker——这是本轮设计能被验证的地基。
//
// 刻意保留的三条真实 UDP 语义（去掉任何一条都会让测试比现实宽松，掩盖真 bug）：
//  1. 对端未绑定 = 黑洞，Send 成功返回但没人收到（这样才测得出重传与超时判死）；
//  2. 队列满 = 丢包，不阻塞（测得出重传路径，不会把测试挂死）；
//  3. 报文是拷贝，收发双方不共享底层数组（共享会掩盖「持有了别人的 buf」这类 bug）。
type MemNet struct {
	mu     sync.RWMutex
	binds  map[netip.AddrPort]*MemTransport
	filter func(Datagram) (Datagram, bool)
}

// NewMemNet 建一张空的内存网。
func NewMemNet() *MemNet {
	return &MemNet{binds: make(map[netip.AddrPort]*MemTransport)}
}

// SetFilter 注入中间人：可丢包（返回 false）、可篡改字节、可改写 Remote 模拟 NAT 重映射。
// 抗篡改、NAT 检测、重传退避这三类测试全靠它，不必真去搭 NAT 环境。
func (n *MemNet) SetFilter(f func(Datagram) (Datagram, bool)) {
	n.mu.Lock()
	n.filter = f
	n.mu.Unlock()
}

// Bind 占用一个地址端口，返回该端点的 Transport。重复绑定报错（等价于 EADDRINUSE）。
func (n *MemNet) Bind(addr netip.AddrPort) (*MemTransport, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.binds[addr]; ok {
		return nil, fmt.Errorf("ipsec: 内存网地址 %s 已被占用", addr)
	}
	t := &MemTransport{
		net:  n,
		addr: addr,
		in:   make(chan Datagram, 256),
		done: make(chan struct{}),
	}
	n.binds[addr] = t
	return t, nil
}

// MemTransport MemNet 上的一个端点，实现 Transport。
type MemTransport struct {
	net  *MemNet
	addr netip.AddrPort
	in   chan Datagram
	done chan struct{}
	once sync.Once
}

// Local 本端点绑定的地址。
func (t *MemTransport) Local() netip.AddrPort { return t.addr }

// Send 投递一个报文。Local 一律以实际绑定地址覆盖——调用方填错也不会影响测试可信度。
func (t *MemTransport) Send(d Datagram) error {
	select {
	case <-t.done:
		return ErrClosed
	default:
	}
	d.Local = t.addr

	t.net.mu.RLock()
	f := t.net.filter
	t.net.mu.RUnlock()
	if f != nil {
		var keep bool
		if d, keep = f(d); !keep {
			return nil // 丢包与真实 UDP 一致：不报错
		}
	}

	t.net.mu.RLock()
	peer := t.net.binds[d.Remote]
	t.net.mu.RUnlock()
	if peer == nil {
		return nil // 对端没起：黑洞
	}
	rd := Datagram{
		Kind:    d.Kind,
		Local:   d.Remote, // 接收方视角：Local 是它自己被投递到的地址
		Remote:  d.Local,
		Payload: append([]byte(nil), d.Payload...),
	}
	select {
	case peer.in <- rd:
	case <-peer.done:
	default: // 队列溢出即丢，等价于 UDP 缓冲区满
	}
	return nil
}

// Recv 阻塞取下一个报文。
func (t *MemTransport) Recv() (Datagram, error) {
	select {
	case d := <-t.in:
		return d, nil
	case <-t.done:
		return Datagram{}, ErrClosed
	}
}

// Close 解绑并唤醒所有阻塞的 Recv。
func (t *MemTransport) Close() error {
	t.once.Do(func() {
		close(t.done)
		t.net.mu.Lock()
		delete(t.net.binds, t.addr)
		t.net.mu.Unlock()
	})
	return nil
}
