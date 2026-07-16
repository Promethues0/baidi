package spa

import (
	"testing"
	"time"
)

func TestDenyUser(t *testing.T) {
	al := NewAllowlist()
	until := time.Now().Add(time.Hour)

	if !al.DenyUser("li.fang", until) {
		t.Fatal("首次封禁应返回 true（新封禁）")
	}
	if al.DenyUser("li.fang", until) {
		t.Fatal("同一截止时间重复封禁应返回 false（幂等，避免轮询重复执行处置）")
	}
	if !al.UserDenied("li.fang") {
		t.Fatal("封禁期内 UserDenied 应为 true")
	}
	if al.UserDenied("ext.zhou") {
		t.Fatal("未封禁用户 UserDenied 应为 false")
	}

	// 延长封禁视作新动作（控制台可再次 kick 续封）
	if !al.DenyUser("li.fang", until.Add(time.Minute)) {
		t.Fatal("延长封禁截止应返回 true")
	}
}

func TestDenyUserExpiry(t *testing.T) {
	al := NewAllowlist()
	if al.DenyUser("li.fang", time.Now().Add(-time.Second)) {
		t.Fatal("已过期的封禁不应生效")
	}
	if al.UserDenied("li.fang") {
		t.Fatal("过期封禁 UserDenied 应为 false")
	}

	// 生效后过期 → 懒清理恢复可用
	al.DenyUser("ext.zhou", time.Now().Add(20*time.Millisecond))
	if !al.UserDenied("ext.zhou") {
		t.Fatal("封禁期内应为 true")
	}
	time.Sleep(30 * time.Millisecond)
	if al.UserDenied("ext.zhou") {
		t.Fatal("封禁到期后应自动失效")
	}
}

func TestRevokeUser(t *testing.T) {
	al := NewAllowlist()
	al.Allow("10.0.0.1", "li.fang", "user", time.Minute)
	al.Allow("10.0.0.2", "li.fang", "user", time.Minute)
	al.Allow("10.0.0.3", "ext.zhou", "user", time.Minute)

	ips := al.RevokeUser("li.fang")
	if len(ips) != 2 {
		t.Fatalf("应撤销 li.fang 的 2 个放行窗口，实际 %v", ips)
	}
	if _, _, ok := al.Allowed("10.0.0.1"); ok {
		t.Fatal("撤销后 10.0.0.1 不应再在放行窗口内")
	}
	if _, _, ok := al.Allowed("10.0.0.2"); ok {
		t.Fatal("撤销后 10.0.0.2 不应再在放行窗口内")
	}
	if _, _, ok := al.Allowed("10.0.0.3"); !ok {
		t.Fatal("其他用户的放行窗口不应被殃及")
	}
	if got := al.RevokeUser("li.fang"); len(got) != 0 {
		t.Fatalf("重复撤销应为空，实际 %v", got)
	}
}
