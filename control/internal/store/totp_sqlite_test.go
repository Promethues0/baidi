package store

import (
	"context"
	"testing"
)

// 注册→读回→确认→重注册复位：TOTP 密文行的生命周期。
func TestTotpLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, found, err := s.TotpFor(ctx, "alice"); err != nil || found {
		t.Fatalf("未注册应 found=false: %v %v", found, err)
	}
	if err := s.SaveTotpSecret(ctx, "  Alice ", []byte("n1"), []byte("c1")); err != nil {
		t.Fatal(err)
	}
	rec, found, err := s.TotpFor(ctx, "ALICE")
	if err != nil || !found {
		t.Fatalf("规范化匹配应读回: %v %v", found, err)
	}
	if rec.Confirmed || string(rec.Cipher) != "c1" {
		t.Fatalf("新行应未确认且密文原样: %+v", rec)
	}

	if err := s.ConfirmTotp(ctx, "alice", 100); err != nil {
		t.Fatal(err)
	}
	rec, _, _ = s.TotpFor(ctx, "alice")
	if !rec.Confirmed || rec.LastCounter != 100 {
		t.Fatalf("确认后应 confirmed=1 且落确认码计数器: %+v", rec)
	}

	// 重注册（换认证器）：覆盖密文并复位确认态与计数器
	if err := s.SaveTotpSecret(ctx, "alice", []byte("n2"), []byte("c2")); err != nil {
		t.Fatal(err)
	}
	rec, _, _ = s.TotpFor(ctx, "alice")
	if rec.Confirmed || rec.LastCounter != 0 || string(rec.Cipher) != "c2" {
		t.Fatalf("重注册应复位: %+v", rec)
	}

	if ok, err := s.DeleteTotp(ctx, "alice"); err != nil || !ok {
		t.Fatalf("删除应成功: %v %v", ok, err)
	}
	if ok, _ := s.DeleteTotp(ctx, "alice"); ok {
		t.Fatal("再删应幂等地报未删")
	}
}

// 防重放计数：同计数器只能消费一次、旧计数器拒、未确认行拒。
func TestConsumeTotpCounter(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_ = s.SaveTotpSecret(ctx, "bob", []byte("n"), []byte("c"))
	// 未确认的行不参与登录判定，消费一律失败
	if ok, _ := s.ConsumeTotpCounter(ctx, "bob", 5); ok {
		t.Fatal("未确认行不应可消费")
	}
	_ = s.ConfirmTotp(ctx, "bob", 10)

	if ok, _ := s.ConsumeTotpCounter(ctx, "bob", 10); ok {
		t.Fatal("确认码的计数器不得再用（确认码也是用过的码）")
	}
	if ok, _ := s.ConsumeTotpCounter(ctx, "bob", 11); !ok {
		t.Fatal("新计数器应消费成功")
	}
	if ok, _ := s.ConsumeTotpCounter(ctx, "bob", 11); ok {
		t.Fatal("同计数器第二次应拒（重放）")
	}
	if ok, _ := s.ConsumeTotpCounter(ctx, "bob", 9); ok {
		t.Fatal("旧计数器应拒")
	}
	if ok, _ := s.ConsumeTotpCounter(ctx, "nobody", 99); ok {
		t.Fatal("不存在的账号应拒")
	}
}
