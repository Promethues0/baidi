package notify

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatcher_按序投递并可等待(t *testing.T) {
	var mu sync.Mutex
	var got []string
	d := NewDispatcher(8, func(_ context.Context, m Message) {
		mu.Lock()
		got = append(got, m.Event)
		mu.Unlock()
	}, nil)
	defer d.Close()

	for _, e := range []string{"a", "b", "c"} {
		if !d.Enqueue(Message{Event: e}) {
			t.Fatalf("入队 %s 失败", e)
		}
	}
	d.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("投递顺序/条数不对: %v", got)
	}
}

// ★核心断言：sink 卡住时入队仍然立刻返回，队满后丢弃并计数。
//
// 这条钉住的是「通知发送失败不阻塞主流程」——消费方（登录接口、posture 上报）
// 都在主流程上，一台连不上的 SMTP 服务器不得把它们拖成 15 秒一次。
func TestDispatcher_队列满时丢弃且入队不阻塞(t *testing.T) {
	release := make(chan struct{})
	var handled atomic.Int32
	d := NewDispatcher(2, func(_ context.Context, _ Message) {
		<-release // 第一条卡在这里，模拟一台装死的 SMTP 服务器
		handled.Add(1)
	}, nil)

	// 1 条被 worker 取走并卡住 + 2 条填满缓冲 = 之后全部丢弃。
	accepted, dropped := 0, 0
	start := time.Now()
	for i := 0; i < 50; i++ {
		if d.Enqueue(Message{Event: "flood"}) {
			accepted++
		} else {
			dropped++
		}
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("★入队被阻塞了 %v——主流程会被通知拖住", elapsed)
	}
	if dropped == 0 {
		t.Fatal("★队列没有上界：50 条全部入队了")
	}
	if accepted > 4 {
		t.Errorf("入队条数 %d 超出队列容量+在途，队列上界没生效", accepted)
	}
	if d.Dropped() != dropped {
		t.Errorf("丢弃计数 = %d，实际丢弃 %d（计数必须真实，控制台要靠它区分'没触发'与'队满没发出'）",
			d.Dropped(), dropped)
	}

	close(release)
	d.Close()
	if int(handled.Load()) != accepted {
		t.Errorf("最终投递 %d 条，入队 %d 条", handled.Load(), accepted)
	}
}

// sink panic 不能杀死 worker：只有一个 worker，panic 一次就再也没有任何通知，
// 而且没有任何征兆。
func TestDispatcher_sink_panic不杀worker(t *testing.T) {
	var ok atomic.Int32
	d := NewDispatcher(4, func(_ context.Context, m Message) {
		if m.Event == "boom" {
			panic("模拟 sink 崩溃")
		}
		ok.Add(1)
	}, nil)
	defer d.Close()
	d.Enqueue(Message{Event: "boom"})
	d.Enqueue(Message{Event: "fine"})
	d.Wait()
	if ok.Load() != 1 {
		t.Fatalf("panic 之后的消息没有被投递（worker 已死），ok=%d", ok.Load())
	}
}

// 关闭之后入队返回 false 而不是 panic（关服务瞬间还有请求在跑）。
func TestDispatcher_关闭后入队安全(t *testing.T) {
	d := NewDispatcher(2, func(context.Context, Message) {}, nil)
	d.Close()
	if d.Enqueue(Message{Event: "late"}) {
		t.Fatal("已关闭的派发器不该接受新消息")
	}
	d.Close() // 可重复调用
}
