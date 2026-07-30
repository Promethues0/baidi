package site

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"baidi.dev/gateway/internal/ipsec"
)

// demux 把**一条** Transport 分成两条给不同消费者用。
//
// # 为什么必须有这一层
//
// IKE 与 ESP 共用同一条 UDP socket（NAT 映射按五元组建立，ESP 另开端口在 NAT 后
// 必然收不到——见 ipsec.UDPTransport 的说明）。但消费者是两个：
//
//	IKE 状态机   Engine.Run 自己阻塞在 Transport.Recv 上收控制报文
//	ESP 入向泵   pumpInbound 阻塞在 Transport.Recv 上收数据报文
//
// 一条 channel 只有一个读者能拿到某个报文。若让两者共读同一个 Transport，
// ★ESP 包会有一部分被状态机吞掉、IKE 包会有一部分被泵吞掉，
// 表现为「握手偶尔卡住、流量偶尔丢包」，且丢的比例随负载变化——
// 这类竞态在低负载的测试里几乎不复现，正是最贵的一种 bug。
//
// 所以这里放一个唯一的读者做分流，两个消费者各拿一条只读支路。
// 发送方向不需要分流：Send 直接透传给底层 Transport（它自己会按 Kind 选端口、加 marker）。
type demux struct {
	src ipsec.Transport
	log *slog.Logger

	ikeCh chan ipsec.Datagram
	espCh chan ipsec.Datagram

	dropIKE    atomic.Uint64 // IKE 支路队列满而丢弃（正常情况下应恒为 0）
	dropESP    atomic.Uint64 // ESP 支路队列满而丢弃（等价于网卡丢包）
	keepalives atomic.Uint64 // 收到的 NAT keepalive（直接丢弃，但要可见）

	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

// 两条支路的队列深度。
//
// IKE 深度小是有意的：任一方向最多一个未完成请求（窗口=1），正常情况下队列里
// 不会超过个位数报文。它一旦溢出，说明状态机的事件循环卡住了——那是必须暴露的
// 严重问题，用大缓冲把它藏起来只会让故障推迟到更难查的时候。
//
// ESP 深度大是因为它承载业务流量，突发是常态。
const (
	ikeQueueLen = 64
	espQueueLen = 1024
)

func newDemux(src ipsec.Transport, log *slog.Logger) *demux {
	d := &demux{
		src:   src,
		log:   log,
		ikeCh: make(chan ipsec.Datagram, ikeQueueLen),
		espCh: make(chan ipsec.Datagram, espQueueLen),
		done:  make(chan struct{}),
	}
	d.wg.Add(1)
	go d.run()
	return d
}

// run 唯一的读者：从底层 Transport 取包，按 Kind 投到对应支路。
func (d *demux) run() {
	defer d.wg.Done()
	for {
		dg, err := d.src.Recv()
		if err != nil {
			// 底层通道关了（Close 或 socket 出错）：唤醒两条支路的读者。
			d.stop()
			return
		}
		switch dg.Kind {
		case ipsec.KindIKE:
			d.push(d.ikeCh, dg, &d.dropIKE, "IKE")
		case ipsec.KindESP:
			d.push(d.espCh, dg, &d.dropESP, "ESP")
		case ipsec.KindKeepalive:
			// RFC 3948 §4：收到单字节 0xFF 直接丢弃，它的全部作用是在发送方向上
			// 刷新 NAT 映射的老化计时器。这里计数而不是彻底无视——
			// 「对端到底有没有在发 keepalive」是排查"隧道静置几分钟后单向不通"的关键线索。
			d.keepalives.Add(1)
		}
	}
}

// push 投递到支路。队列满就丢并计数——绝不阻塞。
//
// 阻塞的后果比丢包严重得多：分流协程是**唯一**的读者，它一卡，
// 另一条支路也跟着收不到任何东西，一个慢消费者会让整条隧道两个方向同时停摆。
func (d *demux) push(ch chan ipsec.Datagram, dg ipsec.Datagram, ctr *atomic.Uint64, name string) {
	select {
	case ch <- dg:
	case <-d.done:
	default:
		n := ctr.Add(1)
		// 限频打印：队列一旦持续溢出，逐条打日志本身就会成为压垮进程的那根稻草。
		if n == 1 || n%1000 == 0 {
			d.log.Warn("分流队列已满，丢弃报文（消费者跟不上）",
				"支路", name, "累计丢弃", n, "队列深度", cap(ch))
		}
	}
}

// ikeSide / espSide 两条只读支路（Send 透传给底层）。
func (d *demux) ikeSide() ipsec.Transport { return &branch{d: d, in: d.ikeCh} }
func (d *demux) espSide() ipsec.Transport { return &branch{d: d, in: d.espCh} }

// stats 三个计数，供状态上报与日志使用。
func (d *demux) stats() (dropIKE, dropESP, keepalives uint64) {
	return d.dropIKE.Load(), d.dropESP.Load(), d.keepalives.Load()
}

// stop 只停分流与两条支路，**不关闭底层 Transport**。
//
// ★所有权原则：本层没有创建 Transport，就不负责关闭它。
// 副作用要说清楚——stop 之后分流协程若正阻塞在 src.Recv() 上，会一直阻塞到
// 调用方关闭底层 Transport 为止。这是刻意的：替调用方关掉它，会让
// "Backend 关了但 socket 还要继续给别人用"的场景无法实现，而那种越权关闭
// 造成的 "use of closed network connection" 极难追溯到是谁关的。
func (d *demux) stop() {
	d.once.Do(func() { close(d.done) })
}

// branch 一条只读支路。
type branch struct {
	d  *demux
	in chan ipsec.Datagram
}

// Send 透传给底层 Transport（端口选择与 non-ESP marker 由它独占处理）。
func (b *branch) Send(dg ipsec.Datagram) error { return b.d.src.Send(dg) }

// Recv 取本支路的下一个报文。
func (b *branch) Recv() (ipsec.Datagram, error) {
	select {
	case dg := <-b.in:
		return dg, nil
	case <-b.d.done:
		return ipsec.Datagram{}, ipsec.ErrClosed
	}
}

// Close 关闭分流（两条支路一起失效），不动底层 Transport。
func (b *branch) Close() error {
	b.d.stop()
	return nil
}
