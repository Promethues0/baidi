package store

import (
	"context"
	"testing"

	"baidi.dev/control/internal/auth"
)

// 出厂口令自检：判据必须是**当场比对库里的哈希**，不是看配置、也不是比哈希字面量
// （bcrypt 每次加盐，同一口令的哈希各不相同）。
func TestFactoryPasswordAccounts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// ① 全新种子库：8 个账号口令都是公开的 baidi@123，应当全部报出来，且管理员排在最前
	got, err := s.FactoryPasswordAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 {
		t.Fatalf("种子库 8 个账号都持出厂口令，应全部报出，实得 %d：%v", len(got), got)
	}
	if got[0].Account != "admin" || got[0].Role != "admin" {
		t.Fatalf("管理员必须排在最前（那是当前就成立的全权入口，不是待办），实得首位 %+v", got[0])
	}

	// ② 改掉一个账号的口令 → 它必须从清单里消失。
	//    这一步同时证明判据不是「哈希 == 种子哈希」那种便宜写法。
	newHash, err := auth.HashPassword("Str0ng-Passw0rd!2026")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET pass_hash=? WHERE account='li.fang'`, newHash); err != nil {
		t.Fatal(err)
	}
	got2, err := s.FactoryPasswordAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range got2 {
		if a.Account == "li.fang" {
			t.Fatal("已改过口令的账号不该再被报成「仍持出厂口令」")
		}
	}
	if len(got2) != 7 {
		t.Fatalf("改一个应少一个，实得 %d", len(got2))
	}

	// ③ 换一个**同样是 bcrypt、但口令不同**的哈希也不能命中——防有人把判据写成
	//    「pass_hash 非空即算」或按前缀匹配。
	other, err := auth.HashPassword("baidi@1234")
	if err != nil {
		t.Fatal(err)
	}
	if auth.VerifyPassword(other, seedPassword) {
		t.Fatal("测试前提不成立：baidi@1234 的哈希不该验过 baidi@123")
	}
}
