package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"baidi.dev/control/internal/notify"
)

// 上线风险通知（FR-POLICY-35）四类事件里，「新终端首次登录」此前没接线。
//
// ★零信任产品里「你的账号在一台从没见过的机器上登录了」是账号被盗最直接的用户侧信号，
// 也是 PRD 把这条列成 P1 的原因。通道体系（SMTP 真实现、有界异步队列、发送成败都落审计、
// 通道页 UI 齐全）与信号源（EnrollDevice 的 created）两头都就绪，中间少一根线：
// 管理员配好邮件通道后，账号被爆破会收到邮件，而「有人在一台新机器上用你的账号登录成功了」不会。
func TestNewDeviceTriggersNotice(t *testing.T) {
	f := newIsoFixture(t)

	var mu sync.Mutex
	var got []notify.Message
	f.s.notices = notify.NewDispatcher(0, func(_ context.Context, m notify.Message) {
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}, slog.Default())
	t.Cleanup(func() { f.s.notices.Close() })

	report := func(device string) (int, map[string]any) {
		return doJSON(t, f.h, "POST", "/api/v1/posture", userToken("li.fang"), map[string]any{
			"device": device, "platform": "macOS", "os": "macOS 15", "clientVersion": "0.1.0",
			"checks": []map[string]any{{"key": "disk_encrypted", "label": "磁盘已加密", "ok": true}},
		})
	}
	if code, out := report("aa11:bb22"); code != http.StatusOK {
		t.Fatalf("首次上报应成功 %d: %v", code, out)
	}
	// 派发是异步的：Close 会把队列排空后返回
	f.s.notices.Close()

	mu.Lock()
	defer mu.Unlock()
	var hit *notify.Message
	for i := range got {
		if got[i].Event == "device-first-seen" {
			hit = &got[i]
		}
	}
	if hit == nil {
		t.Fatalf("新终端首次登记必须发一条通知（FR-POLICY-35），实得事件：%v", eventsOf(got))
	}
	for _, want := range []string{"li.fang", "aa11"} {
		if !strings.Contains(hit.Subject+hit.Body, want) {
			t.Errorf("通知正文应点名账号与设备指纹，缺 %q：%s", want, hit.Body)
		}
	}
	if !strings.Contains(hit.Body, "若这不是本人操作") {
		t.Error("通知必须给出下一步动作（改口令 / 吊销设备）——只说「有新设备」等于没说")
	}
}

func eventsOf(ms []notify.Message) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Event)
	}
	return out
}
