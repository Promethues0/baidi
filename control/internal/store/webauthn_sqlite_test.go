package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newCred(account, credID string, count uint32) WebauthnCredential {
	return WebauthnCredential{
		UserID: "u-" + account, Account: account, CredentialID: credID,
		PublicKey: "cHVibGljLWtleQ", SignCount: count, Transports: `["internal"]`, Name: "Touch ID",
	}
}

// 凭据落库 + 账号规范化 + credential_id 唯一守卫。
func TestSaveWebauthnCredential(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	c, err := s.SaveWebauthnCredential(ctx, newCred("  Bob ", "cred-aaa", 0))
	if err != nil {
		t.Fatalf("首次注册应成功: %v", err)
	}
	if c.Account != "bob" || c.ID == "" {
		t.Fatalf("账号应规范化且生成 id: %+v", c)
	}
	// 规范化匹配读回
	list, _ := s.WebauthnCredentialsFor(ctx, "BOB")
	if len(list) != 1 || list[0].CredentialID != "cred-aaa" {
		t.Fatalf("应能按规范化账号读回: %+v", list)
	}
	if n, _ := s.WebauthnCredentialCount(ctx, "bob"); n != 1 {
		t.Fatalf("计数应为 1: %d", n)
	}
	// 同一认证器重复注册 → 拒
	if _, err := s.SaveWebauthnCredential(ctx, newCred("bob", "cred-aaa", 0)); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("重复 credential_id 应 ErrCredentialExists: %v", err)
	}
	// 按 credentialID 点查（断言校验用）
	got, found, _ := s.WebauthnCredentialByID(ctx, "cred-aaa")
	if !found || got.Account != "bob" || got.PublicKey == "" {
		t.Fatalf("点查应命中且带公钥: %+v %v", got, found)
	}
	if _, found, _ := s.WebauthnCredentialByID(ctx, "ghost"); found {
		t.Fatal("不存在的 credentialID 应 found=false")
	}
}

// ★签名计数器：counter>0 时严格单调（防克隆）；counter==0（同步 passkey）跳过校验不误报。
func TestUpdateSignCount(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, _ = s.SaveWebauthnCredential(ctx, newCred("bob", "cred-hw", 5))

	// 正常前进
	if err := s.UpdateSignCount(ctx, "cred-hw", 6); err != nil {
		t.Fatalf("计数器前进应成功: %v", err)
	}
	got, _, _ := s.WebauthnCredentialByID(ctx, "cred-hw")
	if got.SignCount != 6 || got.LastUsedAt == "" {
		t.Fatalf("计数器与最后使用时间应更新: %+v", got)
	}
	// 倒退 → 克隆告警
	if err := s.UpdateSignCount(ctx, "cred-hw", 3); !errors.Is(err, ErrSignCountRegression) {
		t.Fatalf("计数器倒退应 ErrSignCountRegression: %v", err)
	}
	// 相等也算未前进（重放）
	if err := s.UpdateSignCount(ctx, "cred-hw", 6); !errors.Is(err, ErrSignCountRegression) {
		t.Fatalf("计数器不前进应 ErrSignCountRegression: %v", err)
	}

	// ★同步 passkey：库存 0、上报 0 —— 必须放行，否则 iCloud/Google passkey 被锁死
	_, _ = s.SaveWebauthnCredential(ctx, newCred("alice", "cred-sync", 0))
	if err := s.UpdateSignCount(ctx, "cred-sync", 0); err != nil {
		t.Fatalf("signCount=0 的同步 passkey 应放行: %v", err)
	}
	sync, _, _ := s.WebauthnCredentialByID(ctx, "cred-sync")
	if sync.SignCount != 0 || sync.LastUsedAt == "" {
		t.Fatalf("同步 passkey 应只更新时间: %+v", sync)
	}
}

// ★challenge 按值+类型单次消费：重放拒、跨仪式复用拒、过期拒。
func TestConsumeWebauthnChallenge(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	ch, err := s.CreateWebauthnChallenge(ctx, WebauthnChallenge{
		Account: "  Bob ", Challenge: "chal-value-1", Type: "login", SessionData: `{"k":1}`,
	})
	if err != nil || ch.ID == "" || ch.Account != "bob" {
		t.Fatalf("challenge 落库异常: %+v %v", ch, err)
	}

	// 跨仪式复用（login challenge 拿去 register）→ 拒
	if _, err := s.ConsumeWebauthnChallenge(ctx, "chal-value-1", "register"); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("跨仪式复用应拒: %v", err)
	}
	// 正常消费
	got, err := s.ConsumeWebauthnChallenge(ctx, "chal-value-1", "login")
	if err != nil || got.Account != "bob" || got.SessionData != `{"k":1}` {
		t.Fatalf("首次消费应成功并带回 SessionData: %+v %v", got, err)
	}
	// 重放（第二次消费）→ 拒
	if _, err := s.ConsumeWebauthnChallenge(ctx, "chal-value-1", "login"); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("重放应 ErrChallengeInvalid: %v", err)
	}
	// 不存在 → 拒
	if _, err := s.ConsumeWebauthnChallenge(ctx, "nope", "login"); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("不存在的 challenge 应拒: %v", err)
	}

	// 过期 → 拒（白盒直插一条过期行）
	if _, err := s.db.Exec(`INSERT INTO webauthn_challenges(id,account,challenge,type,session_data,expires_at,consumed) VALUES(?,?,?,?,?,?,0)`,
		"chal-old", "bob", "chal-expired", "login", "{}", time.Now().Unix()-10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeWebauthnChallenge(ctx, "chal-expired", "login"); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("过期 challenge 应拒: %v", err)
	}
}

// challenge 清理：过期与已消费的行被回收（防匿名刷 begin 无界堆积）。
func TestPurgeExpiredChallenges(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, _ = s.CreateWebauthnChallenge(ctx, WebauthnChallenge{Account: "bob", Challenge: "live", Type: "login"})
	_, _ = s.CreateWebauthnChallenge(ctx, WebauthnChallenge{Account: "bob", Challenge: "used", Type: "login"})
	_, _ = s.ConsumeWebauthnChallenge(ctx, "used", "login")
	_, _ = s.db.Exec(`INSERT INTO webauthn_challenges(id,account,challenge,type,session_data,expires_at,consumed) VALUES('c-x','bob','stale','login','{}',?,0)`,
		time.Now().Unix()-100)

	n, err := s.PurgeExpiredChallenges(ctx)
	if err != nil || n != 2 { // used(已消费) + stale(过期)
		t.Fatalf("应清理 2 行: n=%d err=%v", n, err)
	}
	// 未过期未消费的仍在
	if _, err := s.ConsumeWebauthnChallenge(ctx, "live", "login"); err != nil {
		t.Fatalf("有效 challenge 不应被清理: %v", err)
	}
}

// 删除凭据：仅限本人、最后一个不许删（防把自己锁在门外）。
func TestDeleteWebauthnCredential(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, _ = s.SaveWebauthnCredential(ctx, newCred("bob", "cred-1", 0))

	// 最后一个不许删
	if err := s.DeleteWebauthnCredential(ctx, "bob", "cred-1"); !errors.Is(err, ErrLastCredential) {
		t.Fatalf("最后一个 passkey 应拒删: %v", err)
	}
	// 加第二个后可删
	c2, _ := s.SaveWebauthnCredential(ctx, newCred("bob", "cred-2", 0))
	if err := s.DeleteWebauthnCredential(ctx, "  BOB ", c2.ID); err != nil {
		t.Fatalf("非最后一个应可删（账号规范化匹配）: %v", err)
	}
	if n, _ := s.WebauthnCredentialCount(ctx, "bob"); n != 1 {
		t.Fatalf("删后应剩 1: %d", n)
	}
	// 跨账号删 → 拒（alice 删不掉 bob 的）
	_, _ = s.SaveWebauthnCredential(ctx, newCred("alice", "cred-a1", 0))
	_, _ = s.SaveWebauthnCredential(ctx, newCred("alice", "cred-a2", 0))
	all, _ := s.WebauthnCredentialsFor(ctx, "bob")
	if err := s.DeleteWebauthnCredential(ctx, "alice", all[0].ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("跨账号删应 ErrCredentialNotFound: %v", err)
	}
}
