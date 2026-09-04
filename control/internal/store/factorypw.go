package store

import (
	"context"

	"baidi.dev/control/internal/auth"
)

// FactoryPwAccount 一个仍持出厂口令（seedPassword）的账号。
type FactoryPwAccount struct {
	Account   string
	Name      string
	Role      string // admin | user
	AdminRole string // admin_roles."key"，非管理员为空
}

// FactoryPasswordAccounts 列出口令仍是**公开的种子口令**的账号，管理员排在前面。
//
// ★为什么需要它：`BAIDI_SEED_MUST_CHANGE` 只保证「谁先登谁改」——它拦不住一个知道公开口令的人
// 抢在正主之前登进去把口令改成自己的，也完全覆盖不到**已经装出去**的机器。而代码改不了存量库：
// 2026-09-04 发现种子循环曾用中文展示标签推导权威角色，导致每台旧机器上都有第二名
// admin_role='root' 的超级管理员（zhang.wei），口令正是 baidi@123；修掉推导只对**新建库**生效。
// 所以判据不能是「代码现在对不对」，只能是**当场拿库里的哈希去比对出厂口令**。
//
// 实现上是逐行 bcrypt 比对（种子库 8 行、真实部署也就几十到几千行，一次启动一遍）：
// 不能用「哈希等于种子哈希」这种便宜写法——bcrypt 每次加盐，同一口令的哈希各不相同。
func (s *SQLiteStore) FactoryPasswordAccounts(ctx context.Context) ([]FactoryPwAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT account, name, COALESCE(role,''), COALESCE(admin_role,''), COALESCE(pass_hash,'')
		   FROM users WHERE COALESCE(pass_hash,'') <> ''
		  ORDER BY CASE WHEN COALESCE(role,'')='admin' THEN 0 ELSE 1 END, account`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FactoryPwAccount
	for rows.Next() {
		var a FactoryPwAccount
		var hash string
		if err := rows.Scan(&a.Account, &a.Name, &a.Role, &a.AdminRole, &hash); err != nil {
			return nil, err
		}
		if auth.VerifyPassword(hash, seedPassword) {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}
