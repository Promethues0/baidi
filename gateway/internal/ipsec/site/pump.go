package site

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// 两条泵是整个数据面唯一搬运字节的地方：
//
//	出向  Datapath.ReadOutbound ─► Protector.Protect ─► Transport.Send(KindESP)
//	入向  Transport.Recv(KindESP) ─► Protector.Unprotect ─► Datapath.WriteInbound
//
// 它们刻意写得很笨：没有批处理、没有零拷贝、没有 worker 池。
// 理由是这一层的每一个分支都关系到"包去哪了"，而性能优化会引入
// "偶尔丢一个包"的可能性——在一个连"流量到底有没有走隧道"都要靠反例断言来证明的
// 子系统里，可读性远比吞吐重要。需要吞吐时再优化，但不是在还没有互通验证之前。

// pumpBufLen 出向读缓冲。
//
// ★不能按 MTU 取。Linux 上开了 GRO/USO 的 TUN 一次可以吐出远超 MTU 的合并段，
// 按 MTU 分配会直接越界或被截断；截断出来的半个 IP 包会被正常加密、被对端正常解密，
// 然后表现为"连接莫名挂住"，离根因十万八千里。取满值 64KB，超长的包交给 esp 层
// 用 ErrOversize 明确拒绝并计数（可见的丢弃 > 静默的截断）。
const pumpBufLen = 65535

// maxConsecutiveErrors 连续失败多少次就放弃这条泵。
//
// 没有这个上限的话，一个"每次都立刻返回错误"的数据面（例如 TUN 被拔掉）会让泵
// 进入 100% CPU 的空转，且日志被限频压掉之后从外面完全看不出异常。
const maxConsecutiveErrors = 64

// pumpOutbound 出向泵：读明文 → 封装 → 发出去。
func (b *GoBackend) pumpOutbound(ctx context.Context) {
	defer b.pumps.Done()
	buf := make([]byte, pumpBufLen)
	var th throttle
	fails := 0

	for {
		if ctx.Err() != nil {
			return
		}
		n, err := b.dp.ReadOutbound(buf)
		if err != nil {
			if isClosed(err) || ctx.Err() != nil {
				return
			}
			fails++
			if cnt, ok := th.allow(time.Now(), 5*time.Second); ok {
				b.log.Warn("出向泵：读数据面失败", "err", err.Error(), "本周期次数", cnt)
			}
			if fails >= maxConsecutiveErrors {
				b.log.Error("出向泵：连续读失败，停止本泵（数据面已不可用）",
					"连续失败", fails, "最后错误", err.Error())
				return
			}
			continue
		}
		fails = 0
		if n == 0 {
			continue
		}

		espPkt, dst, err := b.prot.Protect(buf[:n])
		if err != nil {
			b.onProtectError(err, n)
			// ★到这里必须 continue。
			// 唯一正确的处理是**丢弃**：任何"出错了就把原包照常发出去"的写法，
			// 都会让本该加密的业务流量以明文从网关直连出去，而且隧道状态一切正常、
			// 日志一行没有。这正是 CLAUDE.md 里 `-route` 那条事故的形态。
			// esp 层的 ErrNoPolicy 返回 espPkt=nil 就是为了让这种写法根本写不出来。
			continue
		}
		if err := b.espTr.Send(ipsec.Datagram{
			Kind:    ipsec.KindESP,
			Remote:  dst,
			Payload: espPkt,
		}); err != nil {
			if isClosed(err) {
				return
			}
			if cnt, ok := th.allow(time.Now(), 5*time.Second); ok {
				b.log.Warn("出向泵：发送 ESP 报文失败", "对端", dst.String(), "err", err.Error(), "本周期次数", cnt)
			}
		}
	}
}

// onProtectError 把封装失败分门别类地记下来。
//
// 计数在 esp 引擎里已经做了（按站点），这里只负责"让人看见"：
// 不同的错误对应完全不同的排障动作，混成一句"封装失败"等于没说。
func (b *GoBackend) onProtectError(err error, size int) {
	switch {
	case errors.Is(err, ipsec.ErrNoPolicy):
		n := b.noPolicy.Add(1)
		// ★这是最该被盯着的一条：有流量本该进隧道，却没有任何 SA 收它。
		// 可能是隧道还没建好（启动瞬间正常），也可能是控制面下发的网段与实际
		// 业务地址对不上（此时隧道显示 up、业务却全程直连，无任何报错）。
		// 因此第一次以及每翻一个数量级都要打一条，且必须把"这意味着什么"写进去。
		if n == 1 || isPowerOfTen(n) {
			b.log.Warn("出向包没有匹配的 IPSec 策略，已丢弃（未明文放行）",
				"累计", n, "包长", size,
				"含义", "该目的地址不在任何站点的 remoteSubnet 内，或对应站点尚未建立 Child SA；"+
					"若隧道显示 up 而这个数字持续增长，说明业务地址与下发的网段对不上，流量正在被丢弃而不是走隧道")
		}
	case errors.Is(err, ipsec.ErrClosed):
		// 正常停机路径，不吵。
	default:
		var th = &b.protErrTh
		if cnt, ok := th.allow(time.Now(), 5*time.Second); ok {
			b.log.Warn("出向封装失败，已丢弃", "err", err.Error(), "包长", size, "本周期次数", cnt)
		}
	}
}

// pumpInbound 入向泵：收 ESP → 解封 → 投递进数据面。
func (b *GoBackend) pumpInbound(ctx context.Context) {
	defer b.pumps.Done()
	var th throttle
	fails := 0

	for {
		if ctx.Err() != nil {
			return
		}
		dg, err := b.espTr.Recv()
		if err != nil {
			return // 支路关闭是唯一的退出路径
		}
		if dg.Kind != ipsec.KindESP || len(dg.Payload) == 0 {
			continue // 分流器保证不会走到这里，留着是防御
		}

		ipPkt, err := b.prot.Unprotect(dg.Payload, dg.Remote)
		if err != nil {
			// esp 引擎已按站点分类计数（认证失败/重放/内层越权/未知 SPI），
			// 这里只做限频日志。★不要在这里"宽容处理"：解封失败的报文一律丢弃，
			// 尤其不能把解密失败的密文当明文投进数据面。
			if cnt, ok := th.allow(time.Now(), 5*time.Second); ok {
				b.log.Warn("入向 ESP 解封失败，已丢弃",
					"来源", dg.Remote.String(), "spi", spiOf(dg.Payload),
					"err", err.Error(), "本周期次数", cnt)
			}
			continue
		}

		// ★先 Touch 再投递：Touch 告诉状态机"这条 SA 上有真实数据在流"，
		// 可以省掉一轮 DPD 探活。放在投递之后的话，数据面阻塞时 DPD 会误判对端失联，
		// 进而拆掉一条其实活得好好的隧道。
		b.ike.Touch(spiOf(dg.Payload))

		if err := b.dp.WriteInbound(ipPkt); err != nil {
			if isClosed(err) || ctx.Err() != nil {
				return
			}
			fails++
			if cnt, ok := th.allow(time.Now(), 5*time.Second); ok {
				b.log.Warn("入向泵：写数据面失败", "err", err.Error(), "本周期次数", cnt)
			}
			if fails >= maxConsecutiveErrors {
				b.log.Error("入向泵：连续写失败，停止本泵（数据面已不可用）",
					"连续失败", fails, "最后错误", err.Error())
				return
			}
			continue
		}
		fails = 0
	}
}

// spiOf 取 ESP 报文的 SPI（首 4 字节，大端）。长度不足返回 0。
func spiOf(espPkt []byte) uint32 {
	if len(espPkt) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(espPkt[:4])
}

// isClosed 判定"这是正常关闭"而不是故障。
func isClosed(err error) bool {
	return errors.Is(err, ipsec.ErrClosed) || errors.Is(err, context.Canceled)
}

// isPowerOfTen 用于"第 1、10、100、1000… 次才打一条日志"的递减频率告警。
// 比固定间隔限频更适合这种"要么是启动瞬间的正常现象、要么是持续性事故"的计数。
func isPowerOfTen(n uint64) bool {
	for p := uint64(10); p <= n; p *= 10 {
		if p == n {
			return true
		}
		if p > n/10 {
			break
		}
	}
	return false
}

// throttle 一个极小的限频器：每 every 至多放行一次，并告诉调用方这段时间里
// 一共发生了多少次（"本周期次数"比单纯的一条日志有用得多——它区分了
// "偶发一次"与"每秒几千次"，而这两种情况的排障方向完全不同）。
type throttle struct {
	mu   sync.Mutex
	last time.Time
	n    uint64
}

func (t *throttle) allow(now time.Time, every time.Duration) (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.n++
	if t.last.IsZero() || now.Sub(t.last) >= every {
		n := t.n
		t.last, t.n = now, 0
		return n, true
	}
	return 0, false
}
