package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// 锁定记录落库 + 重启（关库重开同一文件）不丢：这是防爆破的硬需求——
// 重启控制面不能成为攻击者的解锁按钮。
func TestLockoutSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "lock.db")
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	until := time.Now().Add(15 * time.Minute).Unix()
	if err := st.SaveLockout(ctx, Lockout{Kind: LockKindAccount, Key: "li.fang", Until: until,
		Reason: "10 分钟内连续 5 次登录失败", CreatedAt: "2026-08-10 10:00:00"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := st.SaveLockout(ctx, Lockout{Kind: LockKindIP, Key: "203.0.113.9", Until: until, Reason: "r", CreatedAt: "c"}); err != nil {
		t.Fatalf("save ip: %v", err)
	}
	st.Close()

	st2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { st2.Close() })
	ls, err := st2.ActiveLockouts(ctx)
	if err != nil || len(ls) != 2 {
		t.Fatalf("重开后应仍有 2 条锁定: %v %v", ls, err)
	}
	if ls[0].Kind != LockKindAccount || ls[0].Key != "li.fang" || ls[0].Until != until {
		t.Fatalf("锁定字段应完整回读: %+v", ls[0])
	}
}

// 到期行被 ActiveLockouts 懒清理；同键重复触发 upsert 刷新截止时间；删除返回是否真删到。
func TestLockoutExpiryUpsertDelete(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	// 已到期的锁定：不在清单里，且被懒清理
	if err := st.SaveLockout(ctx, Lockout{Kind: LockKindAccount, Key: "old", Until: now - 10, Reason: "r", CreatedAt: "c"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if ls, err := st.ActiveLockouts(ctx); err != nil || len(ls) != 0 {
		t.Fatalf("到期锁定不应出现在清单: %v %v", ls, err)
	}
	// upsert 刷新
	if err := st.SaveLockout(ctx, Lockout{Kind: LockKindIP, Key: "1.2.3.4", Until: now + 100, Reason: "a", CreatedAt: "c"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := st.SaveLockout(ctx, Lockout{Kind: LockKindIP, Key: "1.2.3.4", Until: now + 900, Reason: "b", CreatedAt: "c2"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	ls, _ := st.ActiveLockouts(ctx)
	if len(ls) != 1 || ls[0].Until != now+900 || ls[0].Reason != "b" {
		t.Fatalf("upsert 应刷新截止/原因: %+v", ls)
	}
	// 删除：真删到 true，再删 false
	if ok, err := st.DeleteLockout(ctx, LockKindIP, "1.2.3.4"); err != nil || !ok {
		t.Fatalf("delete 应删到: %v %v", ok, err)
	}
	if ok, err := st.DeleteLockout(ctx, LockKindIP, "1.2.3.4"); err != nil || ok {
		t.Fatalf("重复 delete 应报未删到: %v %v", ok, err)
	}
}

// settings 键值：not found 无错；upsert 覆盖。
func TestSettingRoundtrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if _, ok, err := st.Setting(ctx, "lockout_config"); err != nil || ok {
		t.Fatalf("未写入时应 not found 无错: %v %v", ok, err)
	}
	if err := st.SetSetting(ctx, "lockout_config", `{"threshold":3}`); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := st.SetSetting(ctx, "lockout_config", `{"threshold":7}`); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	v, ok, err := st.Setting(ctx, "lockout_config")
	if err != nil || !ok || v != `{"threshold":7}` {
		t.Fatalf("应读到最后一次写入: %q %v %v", v, ok, err)
	}
}
