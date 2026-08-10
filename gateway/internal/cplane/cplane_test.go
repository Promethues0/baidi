package cplane

// 数据面回执通道的单元测试：入队/溢出/随心跳带走/发送成功即清/失败留队。
// 复用 ipsec_test.go 的 newTestClient（内部测试直拼 Client 打 httptest，
// 本文件验的是队列语义与 JSON 契约，不是 TLS 握手）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// 队列有界：超过 maxQueuedEvents 时丢最旧并计数，最新的回执永远保得住
// （最近发生的处置比几分钟前的更值得带到控制面）。
func TestEventQueueOverflowDropsOldest(t *testing.T) {
	var q eventQueue
	const n = maxQueuedEvents + 6
	for i := 0; i < n; i++ {
		q.push(Event{Kind: fmt.Sprintf("k%d", i)})
	}
	got := q.snapshot()
	if len(got) != maxQueuedEvents {
		t.Fatalf("队列长度 %d，期望上界 %d", len(got), maxQueuedEvents)
	}
	if got[0].Kind != "k6" {
		t.Errorf("溢出应丢最旧：队首 %s，期望 k6", got[0].Kind)
	}
	if got[len(got)-1].Kind != fmt.Sprintf("k%d", n-1) {
		t.Errorf("最新回执必须保住：队尾 %s，期望 k%d", got[len(got)-1].Kind, n-1)
	}
	if q.droppedCount() != 6 {
		t.Errorf("丢弃计数 %d，期望 6", q.droppedCount())
	}
}

// ack 只清「本次 snapshot 带走的那批」：发送期间新入队的回执不能被误清。
func TestEventQueueAckKeepsNewerEvents(t *testing.T) {
	var q eventQueue
	q.push(Event{Kind: "a"})
	q.push(Event{Kind: "b"})
	batch := q.snapshot()
	q.push(Event{Kind: "c"}) // 模拟发送期间新入队
	q.ack(len(batch))
	rest := q.snapshot()
	if len(rest) != 1 || rest[0].Kind != "c" {
		t.Fatalf("ack 后应只剩发送期间新入队的 c，实际 %+v", rest)
	}
}

// 心跳请求体携带 version 与 events，且字段名与控制面 handleGatewayRegister 的解码口径一致；
// 发送成功后队列清空，下次心跳不重复上报。
func TestRegisterCarriesVersionAndEventsAndClearsOnSuccess(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("请求体不是合法 JSON：%v", err)
		}
		fmt.Fprint(w, `{"ok":true,"id":"gw-1"}`)
	})
	c.SetVersion("v1.2.3")
	c.QueueEvent("revoke-applied", "已撤销用户 li.fang 的放行窗口：封禁敲门至 12:00:00、撤销放行 1 个源IP、切断 1 条隧道")
	c.QueueEvent("policy-applied", "资源授权策略已生效：资源数 3→4")

	if err := c.Register(1, 2, 60, nil); err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	if got["version"] != "v1.2.3" {
		t.Errorf("version=%v，期望 v1.2.3", got["version"])
	}
	evs, _ := got["events"].([]any)
	if len(evs) != 2 {
		t.Fatalf("events 长度 %d，期望 2", len(evs))
	}
	first, _ := evs[0].(map[string]any)
	for _, k := range []string{"ts", "kind", "detail"} {
		if _, ok := first[k]; !ok {
			t.Errorf("回执缺字段 %s（控制面按 gwEvent 的 JSON 名解码，对不上就是静默丢字段）", k)
		}
	}
	if first["kind"] != "revoke-applied" {
		t.Errorf("kind=%v，期望 revoke-applied", first["kind"])
	}
	// 发送成功即清：下次心跳不带旧回执（否则控制面审计会重复记同一事实）。
	if rest := c.events.snapshot(); len(rest) != 0 {
		t.Errorf("发送成功后队列应清空，实际还剩 %d 条", len(rest))
	}
}

// 发送失败（控制面 5xx / 不可达）时回执必须留队，随下次心跳重试——
// 否则一次控制面抖动就会让「已生效」的事实永远进不了审计。
func TestRegisterFailureKeepsEvents(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c.QueueEvent("revoke-applied", "已撤销用户 x 的放行窗口")
	if err := c.Register(0, 0, 1, nil); err == nil {
		t.Fatal("500 应返回错误")
	}
	if rest := c.events.snapshot(); len(rest) != 1 {
		t.Fatalf("发送失败后回执应留队重试，实际剩 %d 条", len(rest))
	}
}
