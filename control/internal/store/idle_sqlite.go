package store

import (
	"context"
	"sort"
	"time"
)

// IdleAccounts 按阈值（天）列出闲置账号。只看 status='active' 的行——
// 已禁用/锁定/挂起的账号都被处置过，不该重复出现在"待治理"清单里。
func (s *SQLiteStore) IdleAccounts(ctx context.Context, thresholdDays int) ([]IdleAccount, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, COALESCE(name,''), account, COALESCE(last_login,''), COALESCE(created_at,''), COALESCE(role,'')
FROM users WHERE status='active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	out := []IdleAccount{}
	for rows.Next() {
		var id, name, account, lastLogin, createdAt, role string
		if err := rows.Scan(&id, &name, &account, &lastLogin, &createdAt, &role); err != nil {
			return nil, err
		}
		days, never, hit := ClassifyIdle(lastLogin, createdAt, now, thresholdDays)
		if !hit {
			continue
		}
		out = append(out, IdleAccount{
			ID: id, Name: name, Account: account, LastLogin: lastLogin,
			IdleDays: days, NeverRecorded: never, IsAdmin: role == "admin",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 最闲的排最前；同天数按账号名稳定排序（清单不跳动）。
	sort.Slice(out, func(i, j int) bool {
		if out[i].IdleDays != out[j].IdleDays {
			return out[i].IdleDays > out[j].IdleDays
		}
		return out[i].Account < out[j].Account
	})
	return out, nil
}
