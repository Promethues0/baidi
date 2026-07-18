package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// ── 终端 posture 报告（每 (user,device) 只存最新；历史轨迹走审计日志）──

const postureCols = `user,device,platform,os,client_version,checks_json,verdict,score,level,reasons_json,ts`

// SavePostureReport 落库一份终端环境报告（按 (user,device) upsert；User 由 api 层规范化）。
func (s *SQLiteStore) SavePostureReport(ctx context.Context, r PostureReport) error {
	checks, _ := json.Marshal(r.Checks)
	reasons, _ := json.Marshal(r.Reasons)
	_, err := s.db.ExecContext(ctx, `INSERT INTO posture_reports(`+postureCols+`)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(user,device) DO UPDATE SET platform=excluded.platform, os=excluded.os, client_version=excluded.client_version,
  checks_json=excluded.checks_json, verdict=excluded.verdict, score=excluded.score, level=excluded.level,
  reasons_json=excluded.reasons_json, ts=excluded.ts`,
		r.User, r.Device, r.Platform, r.OS, r.ClientVersion, string(checks), r.Verdict, r.Score, r.Level, string(reasons), r.TS)
	return err
}

func scanPostureRows(rows *sql.Rows) ([]PostureReport, error) {
	defer rows.Close()
	out := []PostureReport{}
	for rows.Next() {
		var r PostureReport
		var checks, reasons string
		if err := rows.Scan(&r.User, &r.Device, &r.Platform, &r.OS, &r.ClientVersion, &checks, &r.Verdict, &r.Score, &r.Level, &reasons, &r.TS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(checks), &r.Checks)
		_ = json.Unmarshal([]byte(reasons), &r.Reasons)
		if r.Checks == nil {
			r.Checks = []PostureCheckResult{}
		}
		if r.Reasons == nil {
			r.Reasons = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PostureReports 全部设备的最新报告（ts 新者在前，供安全中心「终端合规」）。
func (s *SQLiteStore) PostureReports(ctx context.Context) ([]PostureReport, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+postureCols+` FROM posture_reports ORDER BY ts DESC`)
	if err != nil {
		return nil, err
	}
	return scanPostureRows(rows)
}

// PostureVerdict 某账号（规范化匹配）跨设备的最差判定：处置严厉度高者优先，同级取最新。
func (s *SQLiteStore) PostureVerdict(ctx context.Context, account string) (PostureReport, bool, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	rows, err := s.db.QueryContext(ctx, `SELECT `+postureCols+` FROM posture_reports WHERE user=?`, key)
	if err != nil {
		return PostureReport{}, false, err
	}
	reports, err := scanPostureRows(rows)
	if err != nil || len(reports) == 0 {
		return PostureReport{}, false, err
	}
	rank := map[string]int{"allow": 0, "degrade": 1, "gray": 2, "block": 3}
	worst := reports[0]
	for _, r := range reports[1:] {
		if rank[r.Verdict] > rank[worst.Verdict] || (rank[r.Verdict] == rank[worst.Verdict] && r.TS > worst.TS) {
			worst = r
		}
	}
	return worst, true, nil
}

// PostureReportFor 某 (user,device) 的最新报告（供判定转换审计）。
func (s *SQLiteStore) PostureReportFor(ctx context.Context, user, device string) (PostureReport, bool, error) {
	key := strings.ToLower(strings.TrimSpace(user))
	rows, err := s.db.QueryContext(ctx, `SELECT `+postureCols+` FROM posture_reports WHERE user=? AND device=?`, key, device)
	if err != nil {
		return PostureReport{}, false, err
	}
	reports, err := scanPostureRows(rows)
	if err != nil || len(reports) == 0 {
		return PostureReport{}, false, err
	}
	return reports[0], true, nil
}

// PostureBlockedUsers 任一设备最新判定为 block 的账号（供网关策略并入撤销名单，堵 8h 会话令牌直连洞）。
func (s *SQLiteStore) PostureBlockedUsers(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT user FROM posture_reports WHERE verdict='block'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
