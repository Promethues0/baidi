package ipsec

import (
	"fmt"
	"sync"
)

// PairDatapath 是把两个 Datapath **背靠背接成一根虚拟网线**的测试用实现：
// 一端写进去的入向包，会从另一端作为出向包被读出来。
//
//	NewPairDatapath 返回 (a, b)：
//
//	         ┌──────────── 隧道侧（交给 site 的泵）────────────┐
//	         │  a.ReadOutbound  ◄──────────┐                  │
//	         │  a.WriteInbound  ──────────┐│                  │
//	         └────────────────────────────││──────────────────┘
//	                                      ▼│
//	         ┌──────────── 网络侧（测试扮演的"受保护网络里的主机"）────┐
//	         │  b.ReadOutbound  ◄──────────┘  收隧道解封出来的包        │
//	         │  b.WriteInbound  ───────────►  灌一个待进隧道的包        │
//	         └──────────────────────────────────────────────────────┘
//
// 典型用法（pump 的往返测试与 e2e 都是这个姿态）：
//
//	a, host := NewPairDatapath(1400)   // a 交给 site.Backend
//	host.WriteInbound(ipPkt)           // 模拟"内网主机发了个包" → 会被 a.ReadOutbound 读走进隧道
//	n, _ := host.ReadOutbound(buf)     // 观察"从隧道解封后投递进内网"的包
//
// ★为什么队列满了要**报错**而不是像真 NIC 那样丢包：这是测试替身。
// 真实 UDP 丢包语义放在 MemNet 里（那里丢包是刻意保留的真实语义），
// 但数据面管道一旦悄悄丢包，一个"泵卡住了/消费者太慢"的真 bug 就会退化成
// 「偶尔少几个包」的抖动，反复重跑也定位不到。宁可当场炸出来。
type PairDatapath struct {
	// out 是本端 ReadOutbound 的来源；对端 WriteInbound 往这里投递。
	out chan []byte
	// peerOut 是对端 ReadOutbound 的来源；本端 WriteInbound 往这里投递。
	peerOut chan []byte

	mtu  int
	done chan struct{}
	once *sync.Once
}

// pairQueueLen 单向队列深度。够深到能容下一次突发，又浅到"消费者不消费"会很快暴露。
const pairQueueLen = 256

// NewPairDatapath 建一对背靠背的内存数据面。mtu <= 0 时取 DefaultTunnelMTU。
//
// 两端共享同一个关闭信号：这是一根网线，剪断一头另一头也就没了。
// 任一端 Close 后，两端的 ReadOutbound/WriteInbound 一律返回 ErrClosed。
func NewPairDatapath(mtu int) (a, b Datapath) {
	if mtu <= 0 {
		mtu = DefaultTunnelMTU
	}
	ca := make(chan []byte, pairQueueLen)
	cb := make(chan []byte, pairQueueLen)
	done := make(chan struct{})
	once := &sync.Once{}
	return &PairDatapath{out: ca, peerOut: cb, mtu: mtu, done: done, once: once},
		&PairDatapath{out: cb, peerOut: ca, mtu: mtu, done: done, once: once}
}

// ReadOutbound 阻塞取一个待保护的出向包。buf 不够长时**报错而不是截断**：
// 截断会产出一个长度自洽、内容被腰斩的 IP 包，它照样能被加密、被对端解密，
// 然后在应用层表现为"连接莫名其妙挂住"——这类症状离根因太远了。
func (d *PairDatapath) ReadOutbound(buf []byte) (int, error) {
	select {
	case p := <-d.out:
		if len(p) > len(buf) {
			return 0, fmt.Errorf("ipsec: 出向包 %d 字节装不进 %d 字节缓冲（缓冲至少要能容下 MTU %d）", len(p), len(buf), d.mtu)
		}
		return copy(buf, p), nil
	case <-d.done:
		return 0, ErrClosed
	}
}

// WriteInbound 投递一个解封出来的入向包给对端读取。
func (d *PairDatapath) WriteInbound(ipPkt []byte) error {
	select {
	case <-d.done:
		return ErrClosed
	default:
	}
	// 必须拷贝：调用方（泵）的解封缓冲下一轮就会被复用，
	// 不拷贝的话对端读到的是一段随时会变的内存——这类 bug 只在高并发下现形。
	cp := append([]byte(nil), ipPkt...)
	select {
	case d.peerOut <- cp:
		return nil
	case <-d.done:
		return ErrClosed
	default:
		return fmt.Errorf("ipsec: 内存数据面队列已满（%d）：对端没有在消费，这通常意味着泵卡住了", pairQueueLen)
	}
}

// MTU 链路 MTU。
func (d *PairDatapath) MTU() int { return d.mtu }

// Close 剪断这根虚拟网线（两端同时失效）。可重复调用。
func (d *PairDatapath) Close() error {
	d.once.Do(func() { close(d.done) })
	return nil
}
