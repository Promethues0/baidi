package notify

import (
	"context"
	"log/slog"
	"sync"
)

// ── 异步派发：有界队列 + 单 worker ──
//
// 消费方（登录防爆破锁定、终端判 block）都在**主流程**上。这两处的共同要求是：
// 通知发不出去绝不能影响已经做出的安全处置——锁定已经生效了、接入已经收缩了，
// 发通知只是让人知道，不是执行动作。所以：
//
//   - 入队**非阻塞**：一台连不上的 SMTP 服务器不得把登录接口拖成 15 秒一次；
//   - 队列**有界**：控制面被爆破时事件是成串来的，无界队列会让内存跟着涨；
//   - 溢出**丢新保旧**：首次发生的那几条最有诊断价值，溢出期的重复事件价值递减
//     （与 gateway 回执队列"丢最旧"的取舍相反，因为那边是状态回执、新的覆盖旧的，
//     这边是事件流、第一条最重要）；丢弃要计数并暴露给控制台，不许静默。

// Message 一条待发通知。
//
// ★入队时必须是**自包含**的：不带 *http.Request、不带请求 ctx。请求 ctx 在 handler
// 返回那一刻就被取消，异步 worker 拿着它发信只会立刻拿到 context canceled——
// 而这类失败发生在主流程之外，没人会注意到通知其实一条都没发出去。
type Message struct {
	// Event 事件键（lockout / posture-block / test…）。进审计与 webhook 载荷。
	Event   string
	Subject string
	Body    string
}

// Sink 真正的投递动作。由上层（api 层）注入：它知道怎么读通道配置、解凭据、
// 记发送结果与审计。Dispatcher 只负责"不阻塞主流程地把它跑起来"。
type Sink func(ctx context.Context, m Message)

// DefaultQueueSize 默认队列深度。
//
// 128 ≈ 一次密集爆破（多个账号 × 多个 IP）产生的锁定条数量级。超过它说明控制面
// 正在被持续攻击，此时"每一条都送到"已经不是重点，"别把自己撑爆"才是。
const DefaultQueueSize = 128

// Dispatcher 有界异步派发器。零值不可用，必须经 NewDispatcher 构造。
type Dispatcher struct {
	ch   chan Message
	sink Sink
	log  *slog.Logger

	mu       sync.Mutex
	cond     *sync.Cond
	inflight int // 已入队但尚未投递完成的条数（Wait 的判据）
	dropped  int
	closed   bool

	wg sync.WaitGroup
}

// NewDispatcher 构造并启动派发器。size ≤ 0 取 DefaultQueueSize。
func NewDispatcher(size int, sink Sink, log *slog.Logger) *Dispatcher {
	if size <= 0 {
		size = DefaultQueueSize
	}
	if log == nil {
		log = slog.Default()
	}
	d := &Dispatcher{ch: make(chan Message, size), sink: sink, log: log}
	d.cond = sync.NewCond(&d.mu)
	d.wg.Add(1)
	go d.run()
	return d
}

func (d *Dispatcher) run() {
	defer d.wg.Done()
	for m := range d.ch {
		// ★每条消息一个独立的 background ctx。用一个长生命周期的共享 ctx 会让
		// 关闭时正在发的那条被腰斩并记成失败；投递本身的上界由各通道自己的 Timeout 管。
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					// worker 只有一个。sink 里 panic 一次就再也没有通知了，
					// 而且没有任何征兆——必须兜住并留痕。
					d.log.Error("消息通道派发 panic，已恢复（本条通知丢失）", "event", m.Event, "panic", rec)
				}
			}()
			d.sink(context.Background(), m)
		}()
		d.mu.Lock()
		d.inflight--
		d.cond.Broadcast()
		d.mu.Unlock()
	}
}

// Enqueue 非阻塞入队。返回 false 表示队列已满（或已关闭）、该条被丢弃。
//
// 调用方**不应**因为 false 而改变主流程行为：通知是观测通道，不是执行通道。
func (d *Dispatcher) Enqueue(m Message) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	select {
	case d.ch <- m:
		d.inflight++
		return true
	default:
		d.dropped++
		d.log.Warn("消息通道队列已满，丢弃一条通知（安全处置本身不受影响）",
			"event", m.Event, "queue", cap(d.ch), "dropped", d.dropped)
		return false
	}
}

// Dropped 返回累计被丢弃的通知条数。
// ★这是给控制台看的**真实**计数，不是估算：通道页显示它，管理员才知道
// "我没收到告警"是因为队列溢出而不是没发生。
func (d *Dispatcher) Dropped() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dropped
}

// Wait 阻塞至队列中所有已入队消息投递完毕（测试与优雅关闭用）。
func (d *Dispatcher) Wait() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for d.inflight > 0 {
		d.cond.Wait()
	}
}

// Close 停止派发器：先等在途消息投递完，再关闭 worker。可重复调用。
func (d *Dispatcher) Close() {
	d.Wait()
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	close(d.ch)
	d.mu.Unlock()
	d.wg.Wait()
}
