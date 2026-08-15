package store

import (
	"context"
	"strings"
)

// ExportUsers 逐行流出用户台账（见 userexport.go 的字段取舍）。
//
// ★列是**逐一点名**的，绝不用 SELECT *：users 表里躺着 pass_hash，而这条查询的
// 结果最终会变成一个可下载的文件。点名写列意味着"往导出里加一列"必须是一次显式修改；
// SELECT * 则意味着任何一次给 users 补列的迁移，都可能顺手把新列送进导出文件。
func (s *SQLiteStore) ExportUsers(ctx context.Context, fn func(UserExportRow) error) error {
	// 组名与归属是**两次定量查询**（组数与成员数与用户数同阶，但不随导出行放大），
	// 在流式循环外一次取齐：放进循环就是逐用户查一次组，1000 个账号 = 1000 次往返。
	groups, err := s.UserGroups(ctx)
	if err != nil {
		return err
	}
	nameByID := make(map[string]string, len(groups))
	for _, g := range groups {
		nameByID[g.ID] = g.Name
	}
	memberships, err := s.GroupMemberships(ctx)
	if err != nil {
		return err
	}

	// ORDER BY 规范化账号：导出是拿去比对/归档的，两次导出之间顺序必须稳定，
	// 且与唯一索引（lower(trim(account))）同一口径——按 created_at 排的话，
	// 两份台账的 diff 会被新建账号的插入位置搅乱。
	rows, err := s.db.QueryContext(ctx, `
SELECT u.account, u.name, COALESCE(u.org,''), COALESCE(o.name,''), COALESCE(u.org_id,''),
       COALESCE(u.status,''), COALESCE(NULLIF(u.role,''),'user'), COALESCE(u.admin_role,''),
       COALESCE(u.email,''), COALESCE(u.last_login,''), COALESCE(u.created_at,'')
FROM users u LEFT JOIN org_units o ON o.id = u.org_id
ORDER BY lower(trim(u.account))`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r UserExportRow
		var orgLegacy, orgName string
		if err := rows.Scan(&r.Account, &r.Name, &orgLegacy, &orgName, &r.OrgID,
			&r.Status, &r.Role, &r.AdminRole, &r.Email, &r.LastLogin, &r.CreatedAt); err != nil {
			return err
		}
		// 与 SQLiteStore.Users 同一条优先级：组织表有名字就以它为准，
		// users.org 只是组织表出现前留下的展示遗物。
		r.Org = orgLegacy
		if r.OrgID != "" && orgName != "" {
			r.Org = orgName
		}
		for _, gid := range memberships[strings.ToLower(strings.TrimSpace(r.Account))] {
			if n := nameByID[gid]; n != "" {
				r.Groups = append(r.Groups, n)
			}
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}
