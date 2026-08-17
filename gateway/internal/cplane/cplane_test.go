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
	got, _ := q.snapshot()
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
	_, through := q.snapshot()
	q.push(Event{Kind: "c"}) // 模拟发送期间新入队
	q.ack(through)
	rest, _ := q.snapshot()
	if len(rest) != 1 || rest[0].Kind != "c" {
		t.Fatalf("ack 后应只剩发送期间新入队的 c，实际 %+v", rest)
	}
}

// 发送期间恰好溢出：push 从队首挤掉一条、队尾补一条，队列长度不变。
// 若 ack 按条数清理，会把队尾那条从未发出的新回执一并砍掉（静默丢回执）；
// 按序号清理必须保住它。这是 ack 从 len(batch) 改成序号口径的原因。
func TestEventQueueAckKeepsEventQueuedDuringOverflow(t *testing.T) {
	var q eventQueue
	for i := 0; i < maxQueuedEvents; i++ {
		q.push(Event{Kind: fmt.Sprintf("k%d", i)})
	}
	batch, through := q.snapshot()
	if len(batch) != maxQueuedEvents {
		t.Fatalf("前置条件：队列应满，实际 %d", len(batch))
	}
	q.push(Event{Kind: "new"}) // 发送期间入队，触发溢出：挤掉 k0，长度仍为上界
	q.ack(through)
	rest, _ := q.snapshot()
	if len(rest) != 1 || rest[0].Kind != "new" {
		t.Fatalf("发送期间入队的回执必须留存待下次心跳，实际 %+v", rest)
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
	if rest, _ := c.events.snapshot(); len(rest) != 0 {
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
	if rest, _ := c.events.snapshot(); len(rest) != 1 {
		t.Fatalf("发送失败后回执应留队重试，实际剩 %d 条", len(rest))
	}
}

// 策略下发的线上契约：控制面的 camelCase `denyUsers` 必须原样落进 resource.Resource。
//
// ★这是"控制面算好、网关机械执行"那条链路唯一的字段名接缝。JSON 字段名对不上不是
// 编译错误也不是运行期错误，而是**降权静默失效**：控制面日志显示已下发否决名单，
// 网关这边解出来是空切片，被降权的终端照样打开高敏资源。
func TestPolicyDecodesDenyUsers(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/gateways/policy" {
			t.Errorf("路径不对：%s", r.URL.Path)
		}
		fmt.Fprint(w, `{"resources":[
  {"id":"fin","name":"财务","backend":"10.20.3.21:443","allowRoles":["user"],"allowUsers":[],"denyUsers":["li.fang"]},
  {"id":"oa","name":"OA","backend":"10.20.1.10:8080","allowRoles":["user"],"allowUsers":[]}
],"revoked":[]}`)
	})
	rs, _, err := c.Policy()
	if err != nil {
		t.Fatalf("拉策略失败：%v", err)
	}
	byID := map[string][]string{}
	for _, r := range rs {
		byID[r.ID] = r.DenyUsers
	}
	if len(byID["fin"]) != 1 || byID["fin"][0] != "li.fang" {
		t.Fatalf("高敏资源的 denyUsers 未解出：%v", byID["fin"])
	}
	// 旧控制面（不下发该字段）→ 空切片 → 行为与改造前一致，不得凭空拒人。
	if len(byID["oa"]) != 0 {
		t.Fatalf("未下发 denyUsers 的资源应解出空名单：%v", byID["oa"])
	}
}

// 安全事件（sec-deny）的 src/cat/count 三个机读字段必须随心跳序列化——
// 控制面攻击源统计按它们分类计数，字段名对不上就是统计永远为零且无报错。
func TestRegisterCarriesSecEventFields(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"id":"gw-1"}`)
	})
	c.QueueSecEvent("knock-replay", "203.0.113.9", "SPA 敲门拒绝（一次性令牌已用）", 37, false)

	if err := c.Register(0, 0, 1, nil); err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	evs, _ := got["events"].([]any)
	if len(evs) != 1 {
		t.Fatalf("events 长度 %d，期望 1", len(evs))
	}
	ev, _ := evs[0].(map[string]any)
	if ev["kind"] != "sec-deny" || ev["src"] != "203.0.113.9" || ev["cat"] != "knock-replay" {
		t.Fatalf("sec-deny 机读字段不符：%v", ev)
	}
	if n, _ := ev["count"].(float64); int(n) != 37 {
		t.Fatalf("count=%v，期望 37", ev["count"])
	}
	// 回执类事件不带这三个字段（omitempty）：旧控制面视角下报文形状不变。
	c2 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"id":"gw-1"}`)
	})
	c2.QueueEvent("policy-applied", "x")
	if err := c2.Register(0, 0, 1, nil); err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	evs, _ = got["events"].([]any)
	ev, _ = evs[0].(map[string]any)
	for _, k := range []string{"src", "cat", "count"} {
		if _, present := ev[k]; present {
			t.Errorf("回执类事件不应携带 %s 字段", k)
		}
	}
}

// 后端可达性拨测结果随心跳捎带；未装拨测源时连字段都不出现（三态兼容）。
func TestRegisterCarriesReach(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"id":"gw-1"}`)
	})
	c.SetReach(func() []ReachResult {
		return []ReachResult{
			{ID: "res-oa", OK: true, MS: 3, TS: 1754800000},
			{ID: "res-db", OK: false, Err: "connection refused", TS: 1754800000},
		}
	})
	if err := c.Register(0, 0, 1, nil); err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	rs, _ := got["reach"].([]any)
	if len(rs) != 2 {
		t.Fatalf("reach 应 2 条，实得 %v", got["reach"])
	}
	first, _ := rs[0].(map[string]any)
	if first["id"] != "res-oa" || first["ok"] != true {
		t.Fatalf("字段名须与控制面解码口径一致，实得 %v", first)
	}
	second, _ := rs[1].(map[string]any)
	if second["err"] != "connection refused" {
		t.Fatalf("失败原因应携带，实得 %v", second)
	}

	// 未装拨测源：字段缺席（旧网关形态，控制面按"未上报"三态处理）。
	// ★Decode 进已有 map 不清旧键，先重置再收。
	got = nil
	c2 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"id":"gw-1"}`)
	})
	if err := c2.Register(0, 0, 1, nil); err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	if _, present := got["reach"]; present {
		t.Fatal("未装拨测源不应出现 reach 字段")
	}
}

// TestQueueSecEventAllowKind 放行事件的 Kind 是 sec-allow（wave8 行动 8）。
//
// ★控制面按 Kind 分流：sec-deny 落 verdict=deny 并计入攻击源，sec-allow 落
// verdict=allow 且**不**计攻击源。Kind 弄错的话，一次正常访问会被数进
// 「攻击源 TOP」——最容易误导排障的一种错记，而两侧都不报错。
func TestQueueSecEventAllowKind(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true,"id":"gw-1"}`)
	})
	c.QueueSecEvent("tunnel-allow", "10.0.0.9", "隧道放行：账号 zhang 访问 res-git", 1, true)
	if err := c.Register(0, 0, 1, nil); err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	evs, _ := got["events"].([]any)
	if len(evs) != 1 {
		t.Fatalf("events 长度 %d，期望 1", len(evs))
	}
	ev, _ := evs[0].(map[string]any)
	if ev["kind"] != "sec-allow" {
		t.Fatalf("放行事件的 kind 应为 sec-allow，得到 %v", ev["kind"])
	}
	if ev["src"] != "10.0.0.9" || ev["cat"] != "tunnel-allow" {
		t.Fatalf("字段丢失：%v", ev)
	}
}
