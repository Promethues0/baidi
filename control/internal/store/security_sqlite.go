package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// ── 安全基线（落库覆盖 Memory 种子；posture 风险引擎的规则源）──

// Baselines 从库读安全基线清单。
func (s *SQLiteStore) Baselines(ctx context.Context) ([]BaselinePolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,type,scope,disposal,status,platforms_json,checks_json FROM baseline_policies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BaselinePolicy{}
	for rows.Next() {
		var b BaselinePolicy
		var plats, checks string
		if err := rows.Scan(&b.ID, &b.Name, &b.Type, &b.Scope, &b.Disposal, &b.Status, &plats, &checks); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(plats), &b.Platforms)
		_ = json.Unmarshal([]byte(checks), &b.Checks)
		if b.Platforms == nil {
			b.Platforms = []string{}
		}
		if b.Checks == nil {
			b.Checks = []BaselineCheck{}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) upsertBaseline(ctx context.Context, b BaselinePolicy) error {
	plats, _ := json.Marshal(b.Platforms)
	checks, _ := json.Marshal(b.Checks)
	_, err := s.db.ExecContext(ctx, `INSERT INTO baseline_policies(id,name,type,scope,disposal,status,platforms_json,checks_json,updated_at)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, type=excluded.type, scope=excluded.scope, disposal=excluded.disposal,
  status=excluded.status, platforms_json=excluded.platforms_json, checks_json=excluded.checks_json, updated_at=excluded.updated_at`,
		b.ID, b.Name, b.Type, b.Scope, b.Disposal, b.Status, string(plats), string(checks), nowStr())
	return err
}

// SaveBaseline 新增/修改一条安全基线（upsert）。
func (s *SQLiteStore) SaveBaseline(ctx context.Context, b BaselinePolicy) (BaselinePolicy, error) {
	if b.ID == "" {
		b.ID = "bl-" + uuid.NewString()[:8]
	}
	if b.Checks == nil {
		b.Checks = []BaselineCheck{}
	}
	if b.Platforms == nil {
		b.Platforms = []string{}
	}
	if err := s.upsertBaseline(ctx, b); err != nil {
		return BaselinePolicy{}, err
	}
	return b, nil
}

// DeleteBaseline 删除一条安全基线。
func (s *SQLiteStore) DeleteBaseline(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM baseline_policies WHERE id=?`, id)
	return err
}

// Security 覆盖：baselines 走库（可编辑、被风险引擎消费），Spa 概览沿用种子。
func (s *SQLiteStore) Security(ctx context.Context) (SecurityBundle, error) {
	b, err := s.Memory.Security(ctx)
	if err != nil {
		return SecurityBundle{}, err
	}
	bls, err := s.Baselines(ctx)
	if err != nil {
		return SecurityBundle{}, err
	}
	b.Baselines = bls
	return b, nil
}
