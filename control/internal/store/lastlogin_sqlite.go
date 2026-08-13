package store

import "context"

// TouchLastLogin 把某账号的 users.last_login 刷成当前时刻（登录成功时调）。
//
// ★回归背景（wave7 行动 8①）：last_login 列建号时置 "—"、页面渲染、导出携带——
// 唯独**全仓没有任何写入方**。用户页「最后登录」整列永远停在建号时刻，
// 而「闲置账号治理」「license 席位提示里的'删除闲置账号'」都要靠它判闲置。
// 典型的展示失真：字段在、页面在、语义死了。
//
// 按账号规范化匹配（与 Credential 同口径）。匹配不到不报错：外部目录首登时
// 建号与登录在同一事务里，行一定在；真匹配不到（并发删号）也不值得让登录失败。
func (s *SQLiteStore) TouchLastLogin(ctx context.Context, account string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET last_login=? WHERE lower(trim(account))=lower(trim(?))`, nowStr(), account)
	return err
}
