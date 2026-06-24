package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// ── 认证策略（落库覆盖 Memory 种子）──

// AuthPolicies 从库读取认证策略，按目录 + 优先级排序（优先级小者先匹配）。
func (s *SQLiteStore) AuthPolicies(ctx context.Context) ([]AuthPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,directory,is_default,scope,priority,enabled,pc,mobile,exempt,one_click,enhance,authz_apps FROM auth_policies ORDER BY directory, priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuthPolicy{}
	for rows.Next() {
		var p AuthPolicy
		var isDef, enabled, oneClick int
		var pc, mobile, exempt, enhance string
		if err := rows.Scan(&p.ID, &p.Name, &p.Directory, &isDef, &p.Scope, &p.Priority, &enabled, &pc, &mobile, &exempt, &oneClick, &enhance, &p.AuthzApps); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(pc), &p.PC)
		_ = json.Unmarshal([]byte(mobile), &p.Mobile)
		_ = json.Unmarshal([]byte(exempt), &p.Exempt)
		_ = json.Unmarshal([]byte(enhance), &p.Enhance)
		// Secondary 为空时回退成空数组，避免前端拿到 null 渲染报错。
		if p.PC.Secondary == nil {
			p.PC.Secondary = []string{}
		}
		if p.Mobile.Secondary == nil {
			p.Mobile.Secondary = []string{}
		}
		p.IsDefault = isDef == 1
		p.Enabled = enabled == 1
		p.OneClick = oneClick == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) upsertAuthPolicy(ctx context.Context, p AuthPolicy) error {
	pc, _ := json.Marshal(p.PC)
	mobile, _ := json.Marshal(p.Mobile)
	exempt, _ := json.Marshal(p.Exempt)
	enhance, _ := json.Marshal(p.Enhance)
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_policies(id,name,directory,is_default,scope,priority,enabled,pc,mobile,exempt,one_click,enhance,authz_apps,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, directory=excluded.directory, is_default=excluded.is_default,
  scope=excluded.scope, priority=excluded.priority, enabled=excluded.enabled, pc=excluded.pc, mobile=excluded.mobile,
  exempt=excluded.exempt, one_click=excluded.one_click, enhance=excluded.enhance, authz_apps=excluded.authz_apps,
  updated_at=excluded.updated_at`,
		p.ID, p.Name, p.Directory, b2i(p.IsDefault), p.Scope, p.Priority, b2i(p.Enabled),
		string(pc), string(mobile), string(exempt), b2i(p.OneClick), string(enhance), p.AuthzApps, nowStr())
	return err
}

// SaveAuthPolicy 新增 / 修改一条认证策略（upsert）。
func (s *SQLiteStore) SaveAuthPolicy(ctx context.Context, p AuthPolicy) (AuthPolicy, error) {
	if p.ID == "" {
		p.ID = "ap-" + uuid.NewString()[:8]
	}
	if p.Priority == 0 {
		p.Priority = 50
	}
	if p.PC.Secondary == nil {
		p.PC.Secondary = []string{}
	}
	if p.Mobile.Secondary == nil {
		p.Mobile.Secondary = []string{}
	}
	if err := s.upsertAuthPolicy(ctx, p); err != nil {
		return AuthPolicy{}, err
	}
	return p, nil
}

// DeleteAuthPolicy 删除一条策略；默认策略（自动生成）不允许删除。
func (s *SQLiteStore) DeleteAuthPolicy(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_policies WHERE id=? AND is_default=0`, id)
	return err
}
