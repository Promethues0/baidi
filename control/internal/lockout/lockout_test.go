package lockout

import (
	"context"
	"testing"
	"time"

	"baidi.dev/control/internal/store"
)

// newTestGuard 纯内存守卫 + 可拨时钟。
func newTestGuard() (*Guard, *time.Time) {
	g := New(nil)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	return g, &now
}

var ctx = context.Background()

// 阈值语义：第 5 次失败即建锁（账号 + IP 双维度），锁定期内 Check 命中。
func TestThresholdLocksBothDimensions(t *testing.T) {
	g, _ := newTestGuard()
	for i := 0; i < 4; i++ {
		if created := g.Fail(ctx, "u", "1.2.3.4"); len(created) != 0 {
			t.Fatalf("第 %d 次失败不应触发锁定: %v", i+1, created)
		}
		if _, hit := g.Check("u", "1.2.3.4"); hit {
			t.Fatalf("第 %d 次失败后不应已锁", i+1)
		}
	}
	created := g.Fail(ctx, "u", "1.2.3.4")
	if len(created) != 2 {
		t.Fatalf("第 5 次失败应同时触发账号锁 + IP 锁: %v", created)
	}
	if lk, hit := g.Check("u", "9.9.9.9"); !hit || lk.Kind != store.LockKindAccount {
		t.Fatalf("换 IP 也应命中账号锁: %+v %v", lk, hit)
	}
	if lk, hit := g.Check("other", "1.2.3.4"); !hit || lk.Kind != store.LockKindIP {
		t.Fatalf("换账号也应命中 IP 锁: %+v %v", lk, hit)
	}
	if len(g.Active()) != 2 {
		t.Fatalf("Active 应列出 2 条锁定")
	}
}

// 滑动窗：窗口外的失败滑出不累计；锁定到期自动解除。
func TestWindowSlideAndExpiry(t *testing.T) {
	g, now := newTestGuard()
	for i := 0; i < 4; i++ {
		g.Fail(ctx, "u", "")
	}
	*now = now.Add(11 * time.Minute) // 超出 10m 窗口，前 4 次全部滑出
	for i := 0; i < 4; i++ {
		if created := g.Fail(ctx, "u", ""); len(created) != 0 {
			t.Fatalf("窗口外历史失败不应累计（第 %d 次新失败即锁）: %v", i+1, created)
		}
	}
	if created := g.Fail(ctx, "u", ""); len(created) != 1 {
		t.Fatalf("窗口内第 5 次失败应触发锁定: %v", created)
	}
	if _, hit := g.Check("u", ""); !hit {
		t.Fatal("锁定期内应命中")
	}
	*now = now.Add(16 * time.Minute) // 超过 15m 锁定时长
	if _, hit := g.Check("u", ""); hit {
		t.Fatal("锁定到期应自动解除")
	}
	if len(g.Active()) != 0 {
		t.Fatal("到期锁定不应再出现在 Active")
	}
}

// 成功登录清零账号计数；IP 计数刻意不清（防「混入一次成功重置 IP 维度」的绕过）。
func TestSuccessClearsAccountNotIP(t *testing.T) {
	g, _ := newTestGuard()
	for i := 0; i < 4; i++ {
		g.Fail(ctx, "u", "1.2.3.4")
	}
	g.Success("u")
	for i := 0; i < 4; i++ {
		if created := g.Fail(ctx, "u", ""); len(created) != 0 {
			t.Fatalf("成功后计数应从零起算: %v", created)
		}
	}
	// IP 维度已累计 4 次（Success 不清）：再来 1 次即锁 IP
	created := g.Fail(ctx, "other", "1.2.3.4")
	if len(created) != 1 || created[0].Kind != store.LockKindIP {
		t.Fatalf("IP 计数不应被账号成功清零: %v", created)
	}
}

// 维度开关：关闭的维度既不计数也不拦（消费方语义，不是摆设开关）。
func TestDimensionToggle(t *testing.T) {
	g, _ := newTestGuard()
	cfg := g.Config()
	cfg.IPEnabled = false
	if err := g.SetConfig(ctx, cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	for i := 0; i < 5; i++ {
		for _, lk := range g.Fail(ctx, "u", "1.2.3.4") {
			if lk.Kind == store.LockKindIP {
				t.Fatalf("IP 维度关闭时不应建 IP 锁: %+v", lk)
			}
		}
	}
	if lk, hit := g.Check("other", "1.2.3.4"); hit {
		t.Fatalf("IP 维度关闭时不应命中 IP 锁: %+v", lk)
	}
	if _, hit := g.Check("u", ""); !hit {
		t.Fatal("账号维度应照常锁定")
	}
}

// Unlock：解掉生效锁定并清残余计数；解不存在的返回 false。
func TestUnlock(t *testing.T) {
	g, _ := newTestGuard()
	for i := 0; i < 5; i++ {
		g.Fail(ctx, "u", "")
	}
	if _, hit := g.Check("u", ""); !hit {
		t.Fatal("应已锁定")
	}
	if ok, err := g.Unlock(ctx, store.LockKindAccount, "u"); err != nil || !ok {
		t.Fatalf("unlock 应成功: %v %v", ok, err)
	}
	if _, hit := g.Check("u", ""); hit {
		t.Fatal("解锁后应立即放行")
	}
	if ok, _ := g.Unlock(ctx, store.LockKindAccount, "u"); ok {
		t.Fatal("重复解锁应报未找到")
	}
}

// 配置校验边界。
func TestConfigValidate(t *testing.T) {
	base := Config{Threshold: 5, WindowSec: 600, DurationSec: 900, IPEnabled: true, AccountEnabled: true}
	if err := base.Validate(); err != nil {
		t.Fatalf("默认配置应合法: %v", err)
	}
	for _, bad := range []Config{
		{Threshold: 0, WindowSec: 600, DurationSec: 900},
		{Threshold: 101, WindowSec: 600, DurationSec: 900},
		{Threshold: 5, WindowSec: 30, DurationSec: 900},
		{Threshold: 5, WindowSec: 600, DurationSec: 90000},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("非法配置应被拒: %+v", bad)
		}
	}
}

// 环境变量默认：非法值回落默认而不是关闭防护。
func TestFromEnv(t *testing.T) {
	t.Setenv("BAIDI_LOCKOUT_THRESHOLD", "3")
	t.Setenv("BAIDI_LOCKOUT_WINDOW", "5m")
	t.Setenv("BAIDI_LOCKOUT_DURATION", "垃圾值")
	c := FromEnv()
	if c.Threshold != 3 || c.WindowSec != 300 || c.DurationSec != 900 {
		t.Fatalf("环境变量解析: %+v", c)
	}
	if !c.IPEnabled || !c.AccountEnabled {
		t.Fatalf("两个维度默认应开启: %+v", c)
	}
}
