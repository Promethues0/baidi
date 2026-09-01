package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func openUserStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// store 层的两道守卫。
//
// ★这两条在 api 层测不到：`handleUpdateUser` / `handleDeleteUser` 都先做一次
// `lookupDirUser`，目标不存在时直接 404，根本走不到 store。它们是**并发窗口**的
// 兜底——查完之后、写之前，另一个管理员把这个账号删了。
// 变异实测过：把这两道去掉，api 层那几条用例照样全绿。
func TestUserWriteGuardsAtStoreLayer(t *testing.T) {
	st := openUserStore(t)
	ctx := context.Background()

	// ① 改一个不存在的 id 必须报 ErrUserNotFound，而不是静默成功。
	//    SQLite 对不存在的 id 不报错，不查 RowsAffected 的话 UPDATE 影响 0 行也是"成功"。
	name := "幽灵"
	if _, err := st.UpdateUserProfile(ctx, "no-such-id", UserProfilePatch{Name: &name}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("改不存在的账号应报 ErrUserNotFound，got %v", err)
	}

	// ② 删一个不存在的 id 同样要报，而不是回 nil。
	//    回 nil 会让上层落一条「删除账号 X」的审计——审计里出现一件没发生过的事。
	if err := st.DeleteUser(ctx, "no-such-id"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("删不存在的账号应报 ErrUserNotFound，got %v", err)
	}

	// ③ 反向：真实存在的账号照常改得动、删得掉（只测拒绝的话，
	//    一个"什么都拒"的实现也能让上面两条全绿）。
	b, err := st.Users(ctx)
	if err != nil || len(b.Users) == 0 {
		t.Fatalf("种子目录应非空: %v", err)
	}
	var victim DirUser
	for _, u := range b.Users {
		if u.Role != "admin" { // 避开防自锁
			victim = u
			break
		}
	}
	if victim.ID == "" {
		t.Fatal("找不到一个非管理员账号")
	}
	newName := victim.Name + "（改过）"
	got, err := st.UpdateUserProfile(ctx, victim.ID, UserProfilePatch{Name: &newName})
	if err != nil || got.Name != newName {
		t.Fatalf("改真实账号应成功，got %v / %v", got.Name, err)
	}
	if err := st.DeleteUser(ctx, victim.ID); err != nil {
		t.Fatalf("删真实账号应成功，got %v", err)
	}
	// 删完之后再删同一个：这时走的正是那条并发窗口。
	if err := st.DeleteUser(ctx, victim.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("重复删除应报 ErrUserNotFound，got %v", err)
	}
}

// 连带清理：账号维度的数据要一起删，而资源授权与 JIT 授予**刻意保留**。
func TestDeleteUserCascadesAccountScopedRowsOnly(t *testing.T) {
	st := openUserStore(t)
	ctx := context.Background()

	b, _ := st.Users(ctx)
	var victim DirUser
	for _, u := range b.Users {
		if u.Role != "admin" {
			victim = u
			break
		}
	}
	acc := victim.Account

	// 造点账号维度的连带数据
	if _, err := st.SaveWebauthnCredential(ctx, WebauthnCredential{
		Account: acc, CredentialID: "raw-x", PublicKey: "pk", Name: "测试器",
	}); err != nil {
		t.Fatalf("造 passkey: %v", err)
	}

	blast, err := st.UserDeleteBlastRadius(ctx, victim.ID)
	if err != nil {
		t.Fatalf("影响面: %v", err)
	}
	if blast.MFA != 1 {
		t.Fatalf("影响面应数出 1 项二次认证绑定，got %d", blast.MFA)
	}
	if blast.Account != acc {
		t.Fatalf("影响面账号对不上：%q vs %q", blast.Account, acc)
	}

	if err := st.DeleteUser(ctx, victim.ID); err != nil {
		t.Fatalf("删除: %v", err)
	}
	// 账号维度的：清干净
	if creds, _ := st.WebauthnCredentialsFor(ctx, acc); len(creds) != 0 {
		t.Fatalf("passkey 应随账号一并删除，还剩 %d 条", len(creds))
	}
}
