package store

import "context"

// ClientVersionStats 按 (平台, 客户端版本) 聚合当前 posture 台账里的终端数。
//
// 数据源是 posture_reports（每个 (账号,设备) 一行最新报告），不是审计流水——
// 要回答的是「此刻现场跑着什么版本」，不是「历史上出现过什么版本」。
func (s *SQLiteStore) ClientVersionStats(ctx context.Context) ([]ClientVersionStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(platform,''), COALESCE(client_version,''), COUNT(*)
FROM posture_reports GROUP BY platform, client_version ORDER BY platform, client_version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientVersionStat{}
	for rows.Next() {
		var v ClientVersionStat
		if err := rows.Scan(&v.Platform, &v.Version, &v.Count); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
