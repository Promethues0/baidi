package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// ── 认证策略（落库覆盖 Memory 种子）──

// AuthPolicies 从库读取认证策略，按目录 + 优先级排序（优先级小者先匹配）。
//
// ★one_click 列不再读：它对应的「一键上线」已从模型删除（见 authpolicy.go 注释）。
// 列留在表里只为旧库可直接启动，任何读写路径都不再碰它。
func (s *SQLiteStore) AuthPolicies(ctx context.Context) ([]AuthPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,directory,is_default,scope,priority,enabled,pc,mobile,exempt,enhance,
  COALESCE(scope_orgs,'[]'),COALESCE(scope_groups,'[]'),authz_apps FROM auth_policies ORDER BY directory, priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuthPolicy{}
	for rows.Next() {
		var p AuthPolicy
		var isDef, enabled int
		var pc, mobile, exempt, enhance, scopeOrgs, scopeGroups string
		if err := rows.Scan(&p.ID, &p.Name, &p.Directory, &isDef, &p.Scope, &p.Priority, &enabled,
			&pc, &mobile, &exempt, &enhance, &scopeOrgs, &scopeGroups, &p.AuthzApps); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(pc), &p.PC)
		_ = json.Unmarshal([]byte(mobile), &p.Mobile)
		_ = json.Unmarshal([]byte(exempt), &p.Exempt)
		_ = json.Unmarshal([]byte(enhance), &p.Enhance)
		_ = json.Unmarshal([]byte(scopeOrgs), &p.ScopeOrgs)
		_ = json.Unmarshal([]byte(scopeGroups), &p.ScopeGroups)
		// 切片列一律回退成空数组，避免前端拿到 null 渲染报错、以及判定侧再多一种形态要特判。
		p.PC.Secondary = nonNil(p.PC.Secondary)
		p.Mobile.Secondary = nonNil(p.Mobile.Secondary)
		p.Exempt.Networks = nonNil(p.Exempt.Networks)
		p.ScopeOrgs = nonNil(p.ScopeOrgs)
		p.ScopeGroups = nonNil(p.ScopeGroups)
		if p.Enhance.WorkDays == nil {
			p.Enhance.WorkDays = []int{}
		}
		p.IsDefault = isDef == 1
		p.Enabled = enabled == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) upsertAuthPolicy(ctx context.Context, p AuthPolicy) error {
	pc, _ := json.Marshal(p.PC)
	mobile, _ := json.Marshal(p.Mobile)
	exempt, _ := json.Marshal(p.Exempt)
	enhance, _ := json.Marshal(p.Enhance)
	scopeOrgs, _ := json.Marshal(nonNil(p.ScopeOrgs))
	scopeGroups, _ := json.Marshal(nonNil(p.ScopeGroups))
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_policies(id,name,directory,is_default,scope,priority,enabled,pc,mobile,exempt,enhance,scope_orgs,scope_groups,authz_apps,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, directory=excluded.directory, is_default=excluded.is_default,
  scope=excluded.scope, priority=excluded.priority, enabled=excluded.enabled, pc=excluded.pc, mobile=excluded.mobile,
  exempt=excluded.exempt, enhance=excluded.enhance, scope_orgs=excluded.scope_orgs, scope_groups=excluded.scope_groups,
  authz_apps=excluded.authz_apps, updated_at=excluded.updated_at`,
		p.ID, p.Name, p.Directory, b2i(p.IsDefault), p.Scope, p.Priority, b2i(p.Enabled),
		string(pc), string(mobile), string(exempt), string(enhance),
		string(scopeOrgs), string(scopeGroups), p.AuthzApps, nowStr())
	return err
}

// SaveAuthPolicy 新增 / 修改一条认证策略（upsert）。
// 语义校验（冻结开关、可信网络必配网段、非默认策略必须绑定范围）在 API 层，
// 与"保存即校验、不静默接受不生效的配置"的口径一致。
func (s *SQLiteStore) SaveAuthPolicy(ctx context.Context, p AuthPolicy) (AuthPolicy, error) {
	if p.ID == "" {
		p.ID = "ap-" + uuid.NewString()[:8]
	}
	if p.Priority == 0 {
		p.Priority = 50
	}
	p.PC.Secondary = nonNil(p.PC.Secondary)
	p.Mobile.Secondary = nonNil(p.Mobile.Secondary)
	p.Exempt.Networks = nonNil(p.Exempt.Networks)
	p.ScopeOrgs = nonNil(p.ScopeOrgs)
	p.ScopeGroups = nonNil(p.ScopeGroups)
	if err := s.upsertAuthPolicy(ctx, p); err != nil {
		return AuthPolicy{}, err
	}
	return p, nil
}

// DeleteAuthPolicy 删除一条认证策略；默认策略（自动生成）不允许删除。
func (s *SQLiteStore) DeleteAuthPolicy(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_policies WHERE id=? AND is_default=0`, id)
	return err
}
