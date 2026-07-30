package esp

import (
	"fmt"

	"baidi.dev/gateway/internal/ipsec"
)

// WindowSize 反重放滑动窗口宽度（RFC 4303 §3.4.3 建议 ≥32，默认 64）。
//
// 取 64 是因为它正好等于一个 uint64 的位宽：整个窗口就是一个字，
// 判重与推窗各是一条位运算，没有环形缓冲区的下标算术，也就没有那类下标 off-by-one。
const WindowSize = 64

// replayWindow 64 位滑动窗口反重放状态。**非并发安全**，由持有它的 sa 用自己的锁串行化。
//
// 位图约定：bit i 表示序号 `highest - i` 已被接收过，因此 **bit 0 就是 highest 自己**。
// ★这条约定必须记牢：推窗时忘记把 bit 0 置 1，同一个包就能被接收两次——
// 而且只在「刚好是当前最大序号」这一种情形下出现，普通往返测试永远撞不到。
//
// highest 为 0 表示这条 SA 还没收到过任何认证通过的报文（序号从 1 开始，0 是非法值）。
type replayWindow struct {
	highest uint64
	bitmap  uint64
}

// check 判断 seq 是否可接受，**不改变窗口状态**。
//
// ★这是刻意拆成两步的：check 在解密之前跑（廉价地挡掉明显的重放洪水，
// 省下 AES/HMAC 的开销），advance 必须在 ICV 校验**通过之后**才跑。
// 顺序反了的后果很具体：攻击者伪造一个序号极大的包（内容全是垃圾），
// 窗口被推到远处，之后**合法**报文全部落在窗口左侧被判为陈旧而丢弃——
// 一个不需要任何密钥的单包 DoS，且现象是「隧道显示 up，就是不通」。
func (w *replayWindow) check(seq uint64) error {
	if seq == 0 {
		return fmt.Errorf("esp: 序号 0 非法（RFC 4303 规定首包序号为 1；出现 0 只可能是伪造或对端计数器回绕）: %w", ipsec.ErrReplay)
	}
	if seq > w.highest {
		return nil
	}
	diff := w.highest - seq
	if diff >= WindowSize {
		return fmt.Errorf("esp: 序号 %d 落在反重放窗口左侧并被丢弃（当前最高 %d，窗口宽 %d）——"+
			"若这类丢弃持续出现且不是攻击，多半是链路乱序超过了窗口宽度: %w",
			seq, w.highest, WindowSize, ipsec.ErrReplay)
	}
	if w.bitmap&(uint64(1)<<diff) != 0 {
		return fmt.Errorf("esp: 序号 %d 已接收过（窗口内重复，当前最高 %d）: %w", seq, w.highest, ipsec.ErrReplay)
	}
	return nil
}

// advance 在报文**通过完整性校验之后**把 seq 记入窗口。
//
// 内部会再 check 一次：check 与 advance 之间隔着一次解密，期间同一条 SA 上
// 可能已有另一个 goroutine 把同一个序号记进去了（收包泵将来若并发化就会发生）。
// 这次重查在同一把锁下完成，是「同一个包被投递两次」的最后一道闸。
func (w *replayWindow) advance(seq uint64) error {
	if err := w.check(seq); err != nil {
		return err
	}
	if seq > w.highest {
		shift := seq - w.highest
		if shift >= WindowSize {
			// 跳变超过一个窗口宽：老的位全部失效，直接清空。
			// 用 `bitmap <<= shift` 在 Go 里对 shift ≥ 64 的结果是 0，行为其实一致，
			// 但显式写出来才看得懂——移位量 ≥ 位宽的语义各语言不同，是经典的移植陷阱。
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1 // bit 0 = 新的 highest 自己
		w.highest = seq
		return nil
	}
	w.bitmap |= uint64(1) << (w.highest - seq)
	return nil
}
