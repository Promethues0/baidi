package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// admin_roles / users.admin_role 的 SQLite 实现。
//
// ★注意 SQLite 里 `key` 是关键字，列名一律加双引号引用。

// adminRoleBackfillMarker settings 表里的一次性标记：既有 admin 账号回填成 root 只做一次。
//
// ★为什么必须一次性：若每次启动都把「role=admin 但没有 admin_role」的行补成 root，
// 那么任何能造出这种行的路径（例如某天有人给 POST /users 加回 role 字段）都变成了
// 「重启即提权到超管」。做成一次性之后，升级那一刻的存量管理员被保住（不会被自己
// 锁在门外），此后出现的异常行 fail-closed 落到「无角色 → 403」而不是静默提权。
const adminRoleBackfillMarker = "admin.role.backfill.v1"

// backfillAdminRoles 建齐内置三权角色，并把既有管理员回填到超管角色。
//
// ★调用点在 seed()/ensureCredentials() **之后**（见 OpenSQLite）：全新库跑 migrate 时
// users 表还是空的，放 migrate 里第 2 步会静默空转——与 backfillOrgUnits 同一条理由。
func (s *SQLiteStore) backfillAdminRoles(ctx context.Context) error {
	// 1) 内置四角色幂等 upsert。name/power/scope_json 每次启动按代码里的定义覆盖：
	//    将来新增权限键时内置角色自动跟上，不必再补一次数据迁移。
	for _, r := range BuiltinAdminRoles() {
		perms, err := json.Marshal(r.Perms)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO admin_roles("key",name,power,builtin,scope_json,created_at) VALUES(?,?,?,1,?,?)
ON CONFLICT("key") DO UPDATE SET name=excluded.name, power=excluded.power, builtin=1, scope_json=excluded.scope_json`,
			r.Key, r.Name, r.Power, string(perms), nowStr()); err != nil {
			return err
		}
	}
	// 3) 非管理员的列归位成空串（补列迁移只加列不填值，留 NULL 会让读侧只能靠
	//    COALESCE 兜底，而"这一行到底分派过没有"在库里看不出来）。
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET admin_role='' WHERE admin_role IS NULL`); err != nil {
		return err
	}
	// 2) 存量管理员 → 超管。**这条是升级不被自己锁在门外的唯一保证**：
	//    admin_role 为空的账号在 requirePerm 里 fail-closed 成 403，
	//    不回填的话升级后所有既有管理员一夜之间什么都干不了，且连"给自己分配角色"
	//    这个动作本身也需要管理员权限——死锁。
	if _, done, err := s.Setting(ctx, adminRoleBackfillMarker); err != nil || done {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET admin_role=? WHERE role='admin' AND COALESCE(admin_role,'')=''`, "root"); err != nil {
		return err
	}
	return s.SetSetting(ctx, adminRoleBackfillMarker, nowStr())
}

// scanAdminRole 从一行 admin_roles 装配 AdminRole（含派生的 Scope 摘要）。
func scanAdminRole(key, name, power, scopeJSON string, builtin int, members int) AdminRole {
	r := AdminRole{Key: key, Name: name, Power: power, Builtin: builtin == 1, Members: members}
	_ = json.Unmarshal([]byte(scopeJSON), &r.Perms)
	if r.Perms == nil {
		r.Perms = []string{}
	}
	r.Scope = ScopeText(r.Perms)
	return r
}

// AdminRoles 全部管理员角色（成员数实算自 users.admin_role）。
func (s *SQLiteStore) AdminRoles(ctx context.Context) ([]AdminRole, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT r."key", r.name, r.power, COALESCE(r.builtin,0), COALESCE(r.scope_json,'[]'),
       (SELECT COUNT(*) FROM users u WHERE u.role='admin' AND u.admin_role=r."key")
FROM admin_roles r ORDER BY r.builtin DESC, r.created_at, r."key"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminRole{}
	for rows.Next() {
		var key, name, power, scope string
		var builtin, members int
		if err := rows.Scan(&key, &name, &power, &builtin, &scope, &members); err != nil {
			return nil, err
		}
		out = append(out, scanAdminRole(key, name, power, scope, builtin, members))
	}
	return out, rows.Err()
}

// AdminRoleFor 解析某账号当前生效的管理员角色。
//
// ★每次请求现算、不进令牌：角色若写进 8h 会话令牌，一次降权要等到令牌过期才生效，
// 而三权分立的全部价值就在于"改了立刻算数"（与组织子树展开不缓存同一条纪律）。
// role≠admin 或 admin_role 悬空（角色被删/从未分派）一律 found=false → 调用方 fail-closed。
func (s *SQLiteStore) AdminRoleFor(ctx context.Context, account string) (AdminRole, bool, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	var rk, name, power, scope string
	var builtin int
	err := s.db.QueryRowContext(ctx, `
SELECT r."key", r.name, r.power, COALESCE(r.builtin,0), COALESCE(r.scope_json,'[]')
FROM users u JOIN admin_roles r ON r."key" = u.admin_role
WHERE lower(trim(u.account))=? AND u.role='admin'`, key).Scan(&rk, &name, &power, &builtin, &scope)
	switch err {
	case nil:
		return scanAdminRole(rk, name, power, scope, builtin, 0), true, nil
	case sql.ErrNoRows:
		return AdminRole{}, false, nil
	default:
		return AdminRole{}, false, err
	}
}

// System 系统管理页数据：角色 + 管理员账号 + 集群状态。全部来自库（集群恒为未部署）。
func (s *SQLiteStore) System(ctx context.Context) (SystemBundle, error) {
	roles, err := s.AdminRoles(ctx)
	if err != nil {
		return SystemBundle{}, err
	}
	byKey := map[string]AdminRole{}
	for _, r := range roles {
		byKey[r.Key] = r
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT u.id, u.name, u.account, COALESCE(u.admin_role,''), COALESCE(u.last_login,''), COALESCE(u.status,''),
       (SELECT COUNT(*) FROM webauthn_credentials c WHERE c.account = lower(trim(u.account)))
FROM users u WHERE u.role='admin' ORDER BY u.created_at, u.account`)
	if err != nil {
		return SystemBundle{}, err
	}
	defer rows.Close()
	admins := []AdminAccount{}
	for rows.Next() {
		var a AdminAccount
		var creds int
		if err := rows.Scan(&a.ID, &a.Name, &a.Account, &a.RoleKey, &a.LastLogin, &a.Status, &creds); err != nil {
			return SystemBundle{}, err
		}
		if r, ok := byKey[a.RoleKey]; ok {
			a.RoleName, a.Power = r.Name, r.Power
		} else {
			// 角色悬空：requirePerm 会 fail-closed 拒绝这名管理员的一切操作，页面上必须
			// 也如实显示，否则管理员看到的是"有角色"而实际什么都做不了。
			a.RoleName, a.Power = "未分配", ""
		}
		// 认证方式按实算：注册过 passkey 才写"口令 + passkey"。此前这一列是种子里
		// 编的"密码 + 商密证书 / UKey"——白帝根本没有这两种认证方式。
		a.TwoFA = creds > 0
		a.Auth = "本地口令"
		if a.TwoFA {
			a.Auth = "本地口令 + passkey"
		}
		admins = append(admins, a)
	}
	if err := rows.Err(); err != nil {
		return SystemBundle{}, err
	}
	return SystemBundle{Roles: roles, Admins: admins, Cluster: clusterNotDeployed()}, nil
}

// SaveAdminRole 新建/修改**自定义**角色（内置四角色一律拒绝）。
// Perms 必须落在 system/security/audit 三权内（见 NormalizeCustomPerms）。
func (s *SQLiteStore) SaveAdminRole(ctx context.Context, r AdminRole) (AdminRole, error) {
	key := strings.ToLower(strings.TrimSpace(r.Key))
	if key == "" || strings.TrimSpace(r.Name) == "" {
		return AdminRole{}, fmt.Errorf("角色标识与名称不能为空")
	}
	for _, b := range BuiltinAdminRoles() {
		if b.Key == key {
			return AdminRole{}, ErrAdminRoleBuiltin
		}
	}
	// 既有行若是内置（理论上被上面挡住了，这里防止将来内置清单变动后留下漏网行）
	var builtin int
	switch err := s.db.QueryRowContext(ctx, `SELECT COALESCE(builtin,0) FROM admin_roles WHERE "key"=?`, key).Scan(&builtin); err {
	case nil:
		if builtin == 1 {
			return AdminRole{}, ErrAdminRoleBuiltin
		}
	case sql.ErrNoRows:
	default:
		return AdminRole{}, err
	}
	perms, err := NormalizeCustomPerms(r.Perms)
	if err != nil {
		return AdminRole{}, err
	}
	raw, err := json.Marshal(perms)
	if err != nil {
		return AdminRole{}, err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_roles("key",name,power,builtin,scope_json,created_at) VALUES(?,?,?,0,?,?)
ON CONFLICT("key") DO UPDATE SET name=excluded.name, scope_json=excluded.scope_json`,
		key, strings.TrimSpace(r.Name), PowerCustom, string(raw), nowStr()); err != nil {
		return AdminRole{}, err
	}
	saved := AdminRole{Key: key, Name: strings.TrimSpace(r.Name), Power: PowerCustom, Perms: perms, Scope: ScopeText(perms)}
	return saved, nil
}

// DeleteAdminRole 删除自定义角色。内置角色拒删；仍有成员拒删（不做级联降权——
// 静默失去权限比一条 409 难查得多，与组织删除守卫同纪律）。
func (s *SQLiteStore) DeleteAdminRole(ctx context.Context, key string) error {
	key = strings.ToLower(strings.TrimSpace(key))
	var builtin int
	switch err := s.db.QueryRowContext(ctx, `SELECT COALESCE(builtin,0) FROM admin_roles WHERE "key"=?`, key).Scan(&builtin); err {
	case nil:
	case sql.ErrNoRows:
		return ErrAdminRoleNotFound
	default:
		return err
	}
	if builtin == 1 {
		return ErrAdminRoleBuiltin
	}
	var members int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role='admin' AND admin_role=?`, key).Scan(&members); err != nil {
		return err
	}
	if members > 0 {
		return ErrAdminRoleInUse
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_roles WHERE "key"=?`, key)
	return err
}

// rootAdminCount 当前超管人数（power=root 的角色下、role=admin 且未被禁用/锁定的账号）。
//
// ★把禁用/锁定的账号排除在外：留着一个已禁用的 root 当"还有超管"，等于系统实际
// 已经没有人能登录来分配权限，而防自锁闸却认为还安全。
func (s *SQLiteStore) rootAdminCount(ctx context.Context, tx *sql.Tx, excludeAccount string) (int, error) {
	q := `SELECT COUNT(*) FROM users u JOIN admin_roles r ON r."key"=u.admin_role
WHERE u.role='admin' AND r.power=? AND u.status NOT IN ('disabled','locked') AND lower(trim(u.account))<>?`
	var n int
	var err error
	if tx != nil {
		err = tx.QueryRowContext(ctx, q, PowerRoot, excludeAccount).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, q, PowerRoot, excludeAccount).Scan(&n)
	}
	return n, err
}

// adminRow 一名候选管理员的关键列（防自锁判定用）。
type adminRow struct {
	id, account, role, adminRole, status string
}

func (s *SQLiteStore) adminRowByAccount(ctx context.Context, tx *sql.Tx, account string) (adminRow, bool, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	q := `SELECT id, account, COALESCE(role,''), COALESCE(admin_role,''), COALESCE(status,'')
FROM users WHERE lower(trim(account))=?`
	var r adminRow
	var err error
	if tx != nil {
		err = tx.QueryRowContext(ctx, q, key).Scan(&r.id, &r.account, &r.role, &r.adminRole, &r.status)
	} else {
		err = s.db.QueryRowContext(ctx, q, key).Scan(&r.id, &r.account, &r.role, &r.adminRole, &r.status)
	}
	switch err {
	case nil:
		return r, true, nil
	case sql.ErrNoRows:
		return adminRow{}, false, nil
	default:
		return adminRow{}, false, err
	}
}

// isRootRole 报告某角色 key 的权别是否 root。
func (s *SQLiteStore) isRootRole(ctx context.Context, tx *sql.Tx, key string) (bool, error) {
	q := `SELECT power FROM admin_roles WHERE "key"=?`
	var power string
	var err error
	if tx != nil {
		err = tx.QueryRowContext(ctx, q, key).Scan(&power)
	} else {
		err = s.db.QueryRowContext(ctx, q, key).Scan(&power)
	}
	switch err {
	case nil:
		return power == PowerRoot, nil
	case sql.ErrNoRows:
		return false, ErrAdminRoleNotFound
	default:
		return false, err
	}
}

// SetAdminRole 把账号置为管理员并分派角色（提升普通用户 / 改派已有管理员皆走这里）。
//
// 防自锁：目标本人是最后一名可登录的超管、且新角色不是 root 时拒绝（ErrLastRootAdmin）。
// 整个「查重 + 改写」在一个 immediate 事务里完成，杜绝两个并发请求各自认为"还有别的 root"。
func (s *SQLiteStore) SetAdminRole(ctx context.Context, account, roleKey string) error {
	key := strings.ToLower(strings.TrimSpace(account))
	roleKey = strings.ToLower(strings.TrimSpace(roleKey))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	u, found, err := s.adminRowByAccount(ctx, tx, key)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: %s", ErrUnknownAccount, account)
	}
	newIsRoot, err := s.isRootRole(ctx, tx, roleKey)
	if err != nil {
		return err
	}
	if !newIsRoot {
		wasRoot, err := s.isRootRole(ctx, tx, u.adminRole)
		if err != nil && err != ErrAdminRoleNotFound {
			return err
		}
		if u.role == "admin" && wasRoot {
			others, err := s.rootAdminCount(ctx, tx, key)
			if err != nil {
				return err
			}
			if others == 0 {
				return ErrLastRootAdmin
			}
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET role='admin', admin_role=? WHERE id=?`, roleKey, u.id); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveAdmin 撤销管理员身份（降为普通用户，清空角色）。最后一名超管不可撤销。
func (s *SQLiteStore) RemoveAdmin(ctx context.Context, account string) error {
	key := strings.ToLower(strings.TrimSpace(account))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	u, found, err := s.adminRowByAccount(ctx, tx, key)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: %s", ErrUnknownAccount, account)
	}
	if u.role != "admin" {
		return ErrNotAdminAccount
	}
	wasRoot, err := s.isRootRole(ctx, tx, u.adminRole)
	if err != nil && err != ErrAdminRoleNotFound {
		return err
	}
	if wasRoot {
		others, err := s.rootAdminCount(ctx, tx, key)
		if err != nil {
			return err
		}
		if others == 0 {
			return ErrLastRootAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET role='user', admin_role='' WHERE id=?`, u.id); err != nil {
		return err
	}
	return tx.Commit()
}
