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

// Security 安全中心页：只有基线一段，且整段走库（可编辑、被风险引擎消费）。
//
// ★不再以 s.Memory.Security(ctx) 打底：那样写的时候，"顺手继承"的 Spa 段
// （已隐身 / 敲门正常 / G3）在页面上与真实的基线并排显示，看不出哪个是库里的事实。
// 现在整个 bundle 逐字段构造，SecurityBundle 加了新段落而这里忘了填，是编译期
// 就能看见的零值，不是一份看起来很像真的种子。
func (s *SQLiteStore) Security(ctx context.Context) (SecurityBundle, error) {
	bls, err := s.Baselines(ctx)
	if err != nil {
		return SecurityBundle{}, err
	}
	return SecurityBundle{Baselines: bls}, nil
}
