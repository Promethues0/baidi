package store

import "context"

// SubjectIndex 现算「组织子树 / 用户组 → 账号」展开索引。
//
// ★每次调用都现算、**不缓存**，这是一条安全属性而不是性能疏忽：
// 授权主体的展开结果必须随目录变动立即生效。把人从组织里移走、把他踢出用户组，
// 期望是"下一次网关轮询就连不上了"；一旦缓存，撤权与生效之间就出现一段谁都说不清
// 多长的窗口，而撤权恰恰是最不能含糊的场景。展开本身是两条全表扫描 + 内存合并，
// 在目录规模面前远比一层需要失效逻辑的缓存便宜。
func (s *SQLiteStore) SubjectIndex(ctx context.Context) (SubjectIndex, error) {
	// 账号 → 所属组织的物化路径。JOIN 而不是先读 users 再逐个查组织：
	// 只有 org_id 真的指向一条存在的组织行才算数（悬空归属不该凭空生成主体）。
	rows, err := s.db.QueryContext(ctx, `
SELECT lower(trim(u.account)), COALESCE(o.path,'')
FROM users u JOIN org_units o ON o.id = u.org_id
WHERE COALESCE(u.org_id,'') <> ''`)
	if err != nil {
		return SubjectIndex{}, err
	}
	defer rows.Close()
	userOrgPath := map[string]string{}
	for rows.Next() {
		var acct, path string
		if err := rows.Scan(&acct, &path); err != nil {
			return SubjectIndex{}, err
		}
		userOrgPath[acct] = path
	}
	if err := rows.Err(); err != nil {
		return SubjectIndex{}, err
	}

	// 组成员反向索引：复用 GroupMemberships，角色组（kind=role）的派生成员因此
	// 自动一并纳入——另写一份 SQL 就会漏掉派生那半边，而漏掉是静默的。
	memberships, err := s.GroupMemberships(ctx)
	if err != nil {
		return SubjectIndex{}, err
	}
	groupAccounts := map[string][]string{}
	for acct, gids := range memberships {
		for _, gid := range gids {
			groupAccounts[gid] = append(groupAccounts[gid], acct)
		}
	}
	return buildSubjectIndex(userOrgPath, groupAccounts), nil
}
