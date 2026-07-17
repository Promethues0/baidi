package store

import (
	"context"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
)

func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "cred.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// 种子用户带真实 bcrypt 口令哈希（demo 口令 baidi@123 不变，但走真实校验）；
// admin 账号进用户体系、role=admin；普通用户 role=user。
func TestSeededCredentialsHaveRealHashes(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	cases := []struct {
		account, role string
	}{
		{"li.fang", "user"},
		{"admin", "admin"},
	}
	for _, c := range cases {
		cred, ok, err := st.Credential(ctx, c.account)
		if err != nil {
			t.Fatalf("Credential(%s): %v", c.account, err)
		}
		if !ok {
			t.Fatalf("账号 %s 应存在", c.account)
		}
		if cred.Role != c.role {
			t.Errorf("%s role=%q, want %q", c.account, cred.Role, c.role)
		}
		if cred.PassHash == "" {
			t.Errorf("%s 应有口令哈希", c.account)
		}
		if !auth.VerifyPassword(cred.PassHash, "baidi@123") {
			t.Errorf("%s 应能用 baidi@123 验过", c.account)
		}
		if auth.VerifyPassword(cred.PassHash, "wrong") {
			t.Errorf("%s 错误口令不应验过", c.account)
		}
	}
}

// 大小写/空格规范化匹配账号；不存在账号返回 found=false（不报错）。
func TestCredentialLookupNormalizesAndMisses(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if _, ok, _ := st.Credential(ctx, "  LI.FANG "); !ok {
		t.Error("规范化后应命中 li.fang")
	}
	if _, ok, err := st.Credential(ctx, "nobody"); err != nil || ok {
		t.Errorf("不存在账号应 found=false 无错，得到 ok=%v err=%v", ok, err)
	}
}

// 重置口令：新哈希落库，旧口令失效、新口令生效。
func TestSetUserPassword(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	cred, _, _ := st.Credential(ctx, "li.fang")
	newHash, _ := auth.HashPassword("N3w-Pass!")
	if err := st.SetUserPassword(ctx, cred.ID, newHash); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	after, _, _ := st.Credential(ctx, "li.fang")
	if !auth.VerifyPassword(after.PassHash, "N3w-Pass!") {
		t.Error("新口令应验过")
	}
	if auth.VerifyPassword(after.PassHash, "baidi@123") {
		t.Error("旧口令应失效")
	}
}

// 新建用户带初始口令：能查到凭据并验过。
func TestCreateUserWithPassword(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	h, _ := auth.HashPassword("init-pw-9")
	u := DirUser{Name: "测试员", Account: "test.user", Org: "研发部", OrgKey: "dev", Roles: []string{"研发"}, PassHash: h}
	created, err := st.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.Role != "user" {
		t.Errorf("默认 role 应为 user，得到 %q", created.Role)
	}
	cred, ok, _ := st.Credential(ctx, "test.user")
	if !ok || !auth.VerifyPassword(cred.PassHash, "init-pw-9") {
		t.Error("新建用户应能用初始口令验过")
	}
}
