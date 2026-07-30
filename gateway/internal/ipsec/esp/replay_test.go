package esp

import (
	"errors"
	"testing"

	"baidi.dev/gateway/internal/ipsec"
)

// espFeed check+advance 一步到位（模拟一个通过了 ICV 校验的报文）。
func espFeed(w *replayWindow, seq uint64) error {
	if err := w.check(seq); err != nil {
		return err
	}
	return w.advance(seq)
}

// TestReplaySequential 顺序递增全部接受，且 highest 跟着走。
func TestReplaySequential(t *testing.T) {
	var w replayWindow
	for i := uint64(1); i <= 1000; i++ {
		if err := espFeed(&w, i); err != nil {
			t.Fatalf("序号 %d 应被接受：%v", i, err)
		}
		if w.highest != i {
			t.Fatalf("收到序号 %d 后 highest=%d", i, w.highest)
		}
	}
}

// TestReplayDuplicate 重复投递必须被拒——含「重复的正是当前最高序号」这一种。
//
// ★最后那一种是 bit 0 约定的专属测试：推窗时忘记把 bit 0 置 1 的话，
// 顺序往返测试全绿，只有重放当前最新的那个包能被接受两次。
func TestReplayDuplicate(t *testing.T) {
	var w replayWindow
	for _, s := range []uint64{1, 2, 3, 10, 11} {
		if err := espFeed(&w, s); err != nil {
			t.Fatalf("序号 %d 应被接受：%v", s, err)
		}
	}
	for _, s := range []uint64{1, 2, 3, 10, 11} {
		err := espFeed(&w, s)
		if !errors.Is(err, ipsec.ErrReplay) {
			t.Fatalf("重复的序号 %d 应被判为重放，实得：%v", s, err)
		}
	}
	if w.highest != 11 {
		t.Fatalf("重放尝试改变了 highest：%d", w.highest)
	}
}

// TestReplayOutOfOrderInsideWindow 窗口内的乱序必须被接受（真实链路一定会乱序），
// 但同一个乱序包第二次到达必须被拒。
func TestReplayOutOfOrderInsideWindow(t *testing.T) {
	var w replayWindow
	if err := espFeed(&w, 100); err != nil {
		t.Fatalf("序号 100 应被接受：%v", err)
	}
	// 窗口宽 64，highest=100，故 37..99 都在窗口内（100-63=37）。
	for _, s := range []uint64{99, 80, 37} {
		if err := espFeed(&w, s); err != nil {
			t.Fatalf("窗口内乱序序号 %d 应被接受：%v", s, err)
		}
	}
	for _, s := range []uint64{99, 80, 37} {
		if err := espFeed(&w, s); !errors.Is(err, ipsec.ErrReplay) {
			t.Fatalf("窗口内重复序号 %d 应被拒，实得：%v", s, err)
		}
	}
	// 36 恰好落在窗口左侧一格之外。
	if err := espFeed(&w, 36); !errors.Is(err, ipsec.ErrReplay) {
		t.Fatalf("序号 36（highest=100，窗口宽 %d）应落在窗口外，实得：%v", WindowSize, err)
	}
}

// TestReplayWindowEdges 窗口左右边界逐格判定。
//
// ★这条测试排除「窗口只判最大序号」的伪反重放：那种实现下 37 与 36 的处置完全一样。
func TestReplayWindowEdges(t *testing.T) {
	var w replayWindow
	if err := espFeed(&w, WindowSize*2); err != nil {
		t.Fatalf("初始序号应被接受：%v", err)
	}
	highest := uint64(WindowSize * 2)
	// diff = 1..WindowSize-1 在窗口内；diff = WindowSize 起在窗口外。
	for diff := uint64(1); diff < WindowSize; diff++ {
		if err := espFeed(&w, highest-diff); err != nil {
			t.Fatalf("diff=%d（序号 %d）应在窗口内被接受：%v", diff, highest-diff, err)
		}
	}
	if err := espFeed(&w, highest-WindowSize); !errors.Is(err, ipsec.ErrReplay) {
		t.Fatalf("diff=%d 应恰好落在窗口外，实得：%v", WindowSize, err)
	}
}

// TestReplayBigJump 序号跳变超过一个窗口宽时，老位必须全部作废。
func TestReplayBigJump(t *testing.T) {
	var w replayWindow
	for i := uint64(1); i <= 10; i++ {
		if err := espFeed(&w, i); err != nil {
			t.Fatalf("序号 %d 应被接受：%v", i, err)
		}
	}
	if err := espFeed(&w, 1000); err != nil {
		t.Fatalf("大跳变序号 1000 应被接受：%v", err)
	}
	if w.bitmap != 1 {
		t.Fatalf("跳变超过一个窗口后位图应只剩 bit0，实得 0x%016x", w.bitmap)
	}
	// 老序号现在全在窗口左侧。
	for _, s := range []uint64{1, 10, 936} {
		if err := espFeed(&w, s); !errors.Is(err, ipsec.ErrReplay) {
			t.Fatalf("跳变后序号 %d 应被拒，实得：%v", s, err)
		}
	}
	// 恰好在新窗口内的旧序号仍可接受。
	if err := espFeed(&w, 937); err != nil {
		t.Fatalf("序号 937（highest=1000，diff=63）应在窗口内：%v", err)
	}
}

// TestReplayZeroSeq 序号 0 非法（RFC 4303 规定首包为 1）。
func TestReplayZeroSeq(t *testing.T) {
	var w replayWindow
	if err := w.check(0); !errors.Is(err, ipsec.ErrReplay) {
		t.Fatalf("序号 0 应被拒，实得：%v", err)
	}
}

// TestReplayCheckDoesNotMutate check 必须是纯查询：它跑在解密之前，
// 若它顺手推了窗，未认证的伪造包就能把窗口推走（不需要任何密钥的单包 DoS）。
func TestReplayCheckDoesNotMutate(t *testing.T) {
	var w replayWindow
	if err := espFeed(&w, 5); err != nil {
		t.Fatalf("序号 5 应被接受：%v", err)
	}
	before := w
	for _, s := range []uint64{6, 7, 1000, 1<<32 - 1} {
		if err := w.check(s); err != nil {
			t.Fatalf("check(%d) 不应报错：%v", s, err)
		}
	}
	if w != before {
		t.Fatalf("check 改变了窗口状态：前 %+v 后 %+v——"+
			"这会让未经认证的伪造包把窗口推走，之后合法报文全部被判陈旧", before, w)
	}
}
