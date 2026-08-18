package store

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

// ── 安全基线（落库覆盖 Memory 种子；posture 风险引擎的规则源）──

// Baselines 从库读安全基线清单。
func (s *SQLiteStore) Baselines(ctx context.Context) ([]BaselinePolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,disposal,status,platforms_json,checks_json,
  COALESCE(scope_orgs,'[]'),COALESCE(scope_groups,'[]') FROM baseline_policies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BaselinePolicy{}
	for rows.Next() {
		var b BaselinePolicy
		var plats, checks, sorgs, sgroups string
		if err := rows.Scan(&b.ID, &b.Name, &b.Disposal, &b.Status, &plats, &checks, &sorgs, &sgroups); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(plats), &b.Platforms)
		_ = json.Unmarshal([]byte(checks), &b.Checks)
		_ = json.Unmarshal([]byte(sorgs), &b.ScopeOrgs)
		_ = json.Unmarshal([]byte(sgroups), &b.ScopeGroups)
		if b.Platforms == nil {
			b.Platforms = []string{}
		}
		if b.Checks == nil {
			b.Checks = []BaselineCheck{}
		}
		// ★空数组而不是 nil：两者在 JSON 里是 [] 与 null，前端对 null 会渲染成
		// "未配置范围"而不是"对全体生效"——同一件事两个说法。
		if b.ScopeOrgs == nil {
			b.ScopeOrgs = []string{}
		}
		if b.ScopeGroups == nil {
			b.ScopeGroups = []string{}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) upsertBaseline(ctx context.Context, b BaselinePolicy) error {
	plats, _ := json.Marshal(b.Platforms)
	checks, _ := json.Marshal(b.Checks)
	sorgs, _ := json.Marshal(nonNil(b.ScopeOrgs))
	sgroups, _ := json.Marshal(nonNil(b.ScopeGroups))
	// type/scope 两列保留但恒写空串（删列要重建表；它们已无人读，见 BaselinePolicy 注释）。
	_, err := s.db.ExecContext(ctx, `INSERT INTO baseline_policies(id,name,type,scope,disposal,status,platforms_json,checks_json,scope_orgs,scope_groups,updated_at)
VALUES(?,?,'','',?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, disposal=excluded.disposal,
  status=excluded.status, platforms_json=excluded.platforms_json, checks_json=excluded.checks_json,
  scope_orgs=excluded.scope_orgs, scope_groups=excluded.scope_groups, updated_at=excluded.updated_at`,
		b.ID, b.Name, b.Disposal, b.Status, string(plats), string(checks), string(sorgs), string(sgroups), nowStr())
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

// clientVersionLabelMarker 一次性回填标记（wave8 行动 2）。
const clientVersionLabelMarker = "baseline.clientversion.label.v1"

// backfillClientVersionCheckLabel 把既有库里 client_version 检测项的 label/expect 改准。
//
// ★为什么必须有这道回填：改 seedApps/Memory 里的种子**只影响全新库**。既有部署
// （含在线演示站）那一行是首启时落库的，此后没有任何 UPDATE——于是行为改成了
// 「控制面按灰度稳定版判」，而页面上那一格仍写着「客户端为最新版本 / ≥ v0.1.0」。
// 后者现在是错的：判据既不是「最新」，也不是 v0.1.0。这正是 CLAUDE.md 记的
// 「补列迁移必须配回填」同一条坑，只是这次踩在种子行的**语义**上而不是新列上。
//
// 只改这一个 key 的 label/expect，其余检测项与管理员改过的东西一律不碰；
// 一次性标记保证管理员之后自己改的文案不会被下次启动覆盖回去。
func (s *SQLiteStore) backfillClientVersionCheckLabel() error {
	ctx := context.Background()
	if _, done, err := s.Setting(ctx, clientVersionLabelMarker); err != nil {
		return err
	} else if done {
		return nil
	}
	spec, ok := CheckSpecOf(CheckKeyClientVersion)
	if !ok {
		return nil // 目录里没有这一项就没什么可回填的
	}
	bls, err := s.Baselines(ctx)
	if err != nil {
		return err
	}
	for _, b := range bls {
		changed := false
		for i := range b.Checks {
			c := &b.Checks[i]
			if c.Key != CheckKeyClientVersion {
				continue
			}
			// 只改**旧种子那两个字面值**。管理员若已自行改过文案，保持原样——
			// 回填是修历史遗留，不是把所有人的配置拉回出厂设置。
			if c.Label == "客户端为最新版本" {
				c.Label, changed = spec.Label, true
			}
			if strings.HasPrefix(c.Expect, "≥ v") {
				c.Expect, changed = spec.Expect, true
			}
		}
		if !changed {
			continue
		}
		if _, err := s.SaveBaseline(ctx, b); err != nil {
			return err
		}
	}
	return s.SetSetting(ctx, clientVersionLabelMarker, "1")
}

// backfillBaselineScope 给既有基线补上空的适用范围（= 对全体生效）。
//
// ★必须回填：补列只加列不填值，留 NULL 的话 COALESCE 虽能兜住读，
// 但「未配置」与「对全体生效」在页面上会变成两种说法。回填成 '[]' 让它们统一，
// 且与改造前自由文本时代的实际行为（没人读那个字段 = 对全体生效）逐字一致。
func (s *SQLiteStore) backfillBaselineScope() error {
	for _, col := range []string{"scope_orgs", "scope_groups"} {
		if _, err := s.db.Exec(
			`UPDATE baseline_policies SET ` + col + `='[]' WHERE ` + col + ` IS NULL OR trim(` + col + `)=''`); err != nil {
			return err
		}
	}
	return nil
}
