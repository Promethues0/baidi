package store

import "context"

// SubjectIndex 现算「组织子树 / 用户组 → 账号」展开索引。
//
// ★每次调用都现算、**不缓存**，这是一条安全属性而不是性能疏忽：
// 授权主体的展开结果必须随目录变动立即生效。把人从组织里移走、把他踢出用户组，
// 期望是"下一次网关轮询就连不上了"；一旦缓存，撤权与生效之间就出现一段谁都说不清
// 多长的窗口，而撤权恰恰是最不能含糊的场景。
//
// ★实际成本（wave9 实测后改正）：**4 条查询、其中 2 次 users 全表扫**——
//
//	① users JOIN org_units（取物化路径；users.org_id 无索引）
//	② user_groups 全表（groupRows，只要 id/name/kind）
//	③ roleMembers：users 全表 + 逐行 json.Unmarshal(roles)
//	④ user_group_members 全量
//
// 此前这里写的是「两条全表扫描」，比实际少算了一半——而这句话正是四处调用点
// 不加缓存的**依据**，说小了等于给一个没算准的决策背书。改造前更贵：
// GroupMemberships 走的是 UserGroups，多付一次 user_group_members 的 GROUP BY，
// 且 roleMembers 被调两遍（同一条 SQL 跑两次）。
//
// 什么时候该重新评估：网关策略轮询是 G 台 × 每 15s 各跑一次，与目录规模**相乘**
// ——这是全系统规模敏感度最高的一条路径（另一条是敲门）。要缓存的话，失效必须由
// 「目录写操作」驱动而不是 TTL，否则上面那段撤权窗口的推理就白写了。
// 基准见 store 包的 BenchmarkSubjectIndex*。
func (s *SQLiteStore) SubjectIndex(ctx context.Context) (SubjectIndex, error) {
	// 请求作用域备忘（见 subjects_memo.go）：调用方没开就是直接现算，行为不变。
	return memoizedSubjectIndex(ctx, s.subjectIndex)
}

func (s *SQLiteStore) subjectIndex(ctx context.Context) (SubjectIndex, error) {
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
