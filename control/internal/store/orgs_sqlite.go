package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// ── 组织单元（org_units）──

// OrgUnits 读全部组织单元（含直属成员数），按物化路径排序。
func (s *SQLiteStore) OrgUnits(ctx context.Context) ([]Org, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT o.id, o.name, COALESCE(o.parent_id,''), COALESCE(o.path,''), COALESCE(o.sort,0), COALESCE(o.created_at,''),
       (SELECT COUNT(*) FROM users u WHERE u.org_id = o.id)
FROM org_units o ORDER BY COALESCE(o.path,''), o.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Org{}
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Name, &o.ParentID, &o.Path, &o.Sort, &o.CreatedAt, &o.Members); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// SaveOrgUnit 新增/修改一个组织单元（upsert）。
//
// ID 为空即新建；带 ID 但库里没有则按该 ID 建（回填与种子路径靠它写入固定 id）。
// 父组织必须存在，且不能是自己或自己的后代（ErrOrgCycle）。
func (s *SQLiteStore) SaveOrgUnit(ctx context.Context, o Org) (Org, error) {
	o.ID = strings.TrimSpace(o.ID)
	o.Name = strings.TrimSpace(o.Name)
	o.ParentID = strings.TrimSpace(o.ParentID)
	if o.Name == "" {
		return Org{}, fmt.Errorf("组织名称不能为空")
	}
	if o.ID != "" && o.ID == o.ParentID {
		return Org{}, ErrOrgCycle
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Org{}, err
	}
	defer tx.Rollback() //nolint:errcheck // 提交成功后回滚是空操作

	parentPath := "/"
	if o.ParentID != "" {
		switch err := tx.QueryRowContext(ctx, `SELECT COALESCE(path,'') FROM org_units WHERE id=?`, o.ParentID).Scan(&parentPath); err {
		case nil:
		case sql.ErrNoRows:
			return Org{}, ErrOrgNotFound
		default:
			return Org{}, err
		}
	}

	oldPath := ""
	if o.ID == "" {
		o.ID = "org-" + uuid.NewString()[:8]
		o.CreatedAt = nowStr()
	} else {
		var created string
		switch err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(path,''), COALESCE(created_at,'') FROM org_units WHERE id=?`, o.ID).Scan(&oldPath, &created); err {
		case nil:
			o.CreatedAt = created
		case sql.ErrNoRows:
			o.CreatedAt = nowStr() // 按显式 id 新建
		default:
			return Org{}, err
		}
	}
	// ★环检测：后代的 path 一定含 "/<自己的 id>/"。把父设成后代时这条成立，直接拒绝。
	// 判据用父的 path 而不是递归上溯，正是冗余 path 这一列存在的理由。
	if strings.Contains(parentPath, "/"+o.ID+"/") {
		return Org{}, ErrOrgCycle
	}
	o.Path = parentPath + o.ID + "/"

	if _, err := tx.ExecContext(ctx, `INSERT INTO org_units(id,name,parent_id,path,sort,created_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, parent_id=excluded.parent_id, path=excluded.path, sort=excluded.sort`,
		o.ID, o.Name, o.ParentID, o.Path, o.Sort, o.CreatedAt); err != nil {
		return Org{}, err
	}
	// 物化路径的代价：改父之后必须级联重写整棵子树的 path。漏了这一步，
	// 环检测与子树查询都会依据陈旧路径给出错误答案（而且不报错）。
	if oldPath != "" && oldPath != o.Path {
		if _, err := tx.ExecContext(ctx,
			`UPDATE org_units SET path = ? || substr(path, ?) WHERE path LIKE ? AND id <> ?`,
			o.Path, utf8.RuneCountInString(oldPath)+1, oldPath+"%", o.ID); err != nil {
			return Org{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Org{}, err
	}
	return o, nil
}

// DeleteOrgUnit 删除一个组织单元。有子部门或有成员时拒删并说明原因。
// 检查与删除同一事务（DSN 已置 _txlock=immediate，起手即取写锁，杜绝 TOCTOU）。
func (s *SQLiteStore) DeleteOrgUnit(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_units WHERE parent_id=?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrOrgHasChildren
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE org_id=?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrOrgHasMembers
	}
	if name, ok, err := authPolicyScopeRef(ctx, tx, scopeColOrgs, id); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w（策略「%s」）", ErrOrgInAuthPolicy, name)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM org_units WHERE id=?`, id)
	if err != nil {
		return err
	}
	if aff, _ := res.RowsAffected(); aff == 0 {
		return ErrOrgNotFound
	}
	return tx.Commit()
}

// SetUserOrg 改某用户的组织归属（orgID 为空 = 清空归属）。
func (s *SQLiteStore) SetUserOrg(ctx context.Context, userID, orgID string) error {
	orgID = strings.TrimSpace(orgID)
	if orgID != "" {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_units WHERE id=?`, orgID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrOrgNotFound
		}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET org_id=? WHERE id=?`, orgID, userID)
	if err != nil {
		return err
	}
	if aff, _ := res.RowsAffected(); aff == 0 {
		return fmt.Errorf("用户 %s 不存在", userID)
	}
	return nil
}

// ── 用户组（user_groups / user_group_members）──

// roleMembers 扫描 users 表，返回「展示角色 → 规范化账号清单」。
// 角色组（kind=role）的成员就是从这里派生的，不落成员表。
func (s *SQLiteStore) roleMembers(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT account, COALESCE(roles,'[]') FROM users ORDER BY account`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var account, rolesJSON string
		if err := rows.Scan(&account, &rolesJSON); err != nil {
			return nil, err
		}
		var roles []string
		_ = json.Unmarshal([]byte(rolesJSON), &roles)
		for _, r := range roles {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			out[r] = append(out[r], normAccount(account))
		}
	}
	return out, rows.Err()
}

// UserGroups 读全部用户组（含实算成员数）。
func (s *SQLiteStore) UserGroups(ctx context.Context) ([]UserGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,COALESCE(kind,''),COALESCE(description,''),COALESCE(created_at,'') FROM user_groups ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserGroup{}
	for rows.Next() {
		var g UserGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Kind, &g.Description, &g.CreatedAt); err != nil {
			return nil, err
		}
		if g.Kind == "" {
			g.Kind = GroupKindStatic
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	staticN := map[string]int{}
	crows, err := s.db.QueryContext(ctx, `SELECT group_id, COUNT(*) FROM user_group_members GROUP BY group_id`)
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var id string
		var n int
		if err := crows.Scan(&id, &n); err != nil {
			return nil, err
		}
		staticN[id] = n
	}
	if err := crows.Err(); err != nil {
		return nil, err
	}
	byRole, err := s.roleMembers(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Kind == GroupKindRole {
			out[i].Members = len(byRole[out[i].Name])
			continue
		}
		out[i].Members = staticN[out[i].ID]
	}
	return out, nil
}

// groupKind 取某组的 kind 与 name。not found → ErrGroupNotFound。
func (s *SQLiteStore) groupKind(ctx context.Context, id string) (kind, name string, err error) {
	switch e := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(kind,''), name FROM user_groups WHERE id=?`, id).Scan(&kind, &name); e {
	case nil:
		if kind == "" {
			kind = GroupKindStatic
		}
		return kind, name, nil
	case sql.ErrNoRows:
		return "", "", ErrGroupNotFound
	default:
		return "", "", e
	}
}

// GroupMembers 读一个组的成员账号（规范化、升序）。
// static 组读成员表；role 组按用户展示角色派生。
func (s *SQLiteStore) GroupMembers(ctx context.Context, groupID string) ([]string, error) {
	kind, name, err := s.groupKind(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if kind == GroupKindRole {
		byRole, err := s.roleMembers(ctx)
		if err != nil {
			return nil, err
		}
		out := append([]string{}, byRole[name]...)
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT account FROM user_group_members WHERE group_id=? ORDER BY account`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GroupMemberships 反向索引：规范化账号 → 所属组 id 清单（含角色组的派生归属）。
// 用户列表要一次性显示每个人的组，逐人查库会变成 N+1。
func (s *SQLiteStore) GroupMemberships(ctx context.Context) (map[string][]string, error) {
	groups, err := s.UserGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	byRole, err := s.roleMembers(ctx)
	if err != nil {
		return nil, err
	}
	roleGroups := map[string]string{} // 角色名 → 组 id
	for _, g := range groups {
		if g.Kind == GroupKindRole {
			roleGroups[g.Name] = g.ID
		}
	}
	for role, gid := range roleGroups {
		for _, acct := range byRole[role] {
			out[acct] = append(out[acct], gid)
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT account, group_id FROM user_group_members ORDER BY account, group_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var acct, gid string
		if err := rows.Scan(&acct, &gid); err != nil {
			return nil, err
		}
		acct = normAccount(acct)
		out[acct] = append(out[acct], gid)
	}
	return out, rows.Err()
}

// SaveUserGroup 新增/修改一个用户组（upsert）。名称规范化后不得与他组重名。
func (s *SQLiteStore) SaveUserGroup(ctx context.Context, g UserGroup) (UserGroup, error) {
	g.ID = strings.TrimSpace(g.ID)
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return UserGroup{}, fmt.Errorf("用户组名称不能为空")
	}
	if g.Kind == "" {
		g.Kind = GroupKindStatic
	}
	if !ValidGroupKind(g.Kind) {
		return UserGroup{}, fmt.Errorf("用户组类型须为 static|role")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return UserGroup{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	var dup int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_groups WHERE lower(trim(name))=? AND id<>?`,
		strings.ToLower(g.Name), g.ID).Scan(&dup); err != nil {
		return UserGroup{}, err
	}
	if dup > 0 {
		return UserGroup{}, ErrGroupExists
	}
	if g.ID == "" {
		g.ID = "grp-" + uuid.NewString()[:8]
		g.CreatedAt = nowStr()
	} else {
		var created, curKind string
		switch err := tx.QueryRowContext(ctx, `SELECT COALESCE(created_at,''), COALESCE(kind,'') FROM user_groups WHERE id=?`, g.ID).Scan(&created, &curKind); err {
		case nil:
			if curKind == GroupKindExternal {
				return UserGroup{}, ErrGroupExternal
			}
			g.CreatedAt = created
		case sql.ErrNoRows:
			g.CreatedAt = nowStr()
		default:
			return UserGroup{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_groups(id,name,kind,description,created_at) VALUES(?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, description=excluded.description`,
		g.ID, g.Name, g.Kind, g.Description, g.CreatedAt); err != nil {
		return UserGroup{}, err
	}
	if err := tx.Commit(); err != nil {
		return UserGroup{}, err
	}
	return g, nil
}

// DeleteUserGroup 删除一个用户组，连同它的成员行。
func (s *SQLiteStore) DeleteUserGroup(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if name, ok, err := authPolicyScopeRef(ctx, tx, scopeColGroups, id); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w（策略「%s」）", ErrGroupInAuthPolicy, name)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE id=?`, id)
	if err != nil {
		return err
	}
	if aff, _ := res.RowsAffected(); aff == 0 {
		return ErrGroupNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_group_members WHERE group_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// 认证策略适用范围的两列。取值只来自这两个常量，不接受调用方拼字符串（防注入）。
const (
	scopeColOrgs   = "scope_orgs"
	scopeColGroups = "scope_groups"
)

// authPolicyScopeRef 报告某个组织/用户组 id 是否被任一认证策略的适用范围引用，
// 命中时回传第一条引用它的策略名（供拒删文案指名道姓）。
//
// 逐行解 JSON 而不用 SQL 的 json 函数：这两张表都很小，而 JSON1 扩展是否可用
// 取决于构建标签——为一次删除守卫引入一个"某些构建下静默不生效"的依赖不划算，
// 而静默不生效恰恰是本项目最该防的失败形态。
func authPolicyScopeRef(ctx context.Context, tx *sql.Tx, col, id string) (string, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", false, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT name, COALESCE(`+col+`,'[]') FROM auth_policies`)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, raw string
		if err := rows.Scan(&name, &raw); err != nil {
			return "", false, err
		}
		var ids []string
		if err := json.Unmarshal([]byte(raw), &ids); err != nil {
			continue // 脏数据不该让删除永远失败；它本来也匹配不到任何账号
		}
		for _, v := range ids {
			if strings.TrimSpace(v) == id {
				return name, true, nil
			}
		}
	}
	return "", false, rows.Err()
}

// knownAccounts 返回库中全部规范化账号的集合（成员写入的存在性校验用）。
func (s *SQLiteStore) knownAccounts(ctx context.Context, q queryer) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT account FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out[normAccount(a)] = true
	}
	return out, rows.Err()
}

// queryer 让存在性校验既能在事务内也能在事务外复用。
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// SetGroupMembers 全量覆写一个 static 组的成员。
// 角色组拒绝写入（ErrGroupDerived）；清单里有不存在的账号则整批拒绝（ErrUnknownAccount）。
func (s *SQLiteStore) SetGroupMembers(ctx context.Context, groupID string, accounts []string) error {
	kind, _, err := s.groupKind(ctx, groupID)
	if err != nil {
		return err
	}
	if kind == GroupKindRole {
		return ErrGroupDerived
	}
	if kind == GroupKindExternal {
		return ErrGroupExternal
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	known, err := s.knownAccounts(ctx, tx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var uniq []string
	for _, a := range accounts {
		a = normAccount(a)
		if a == "" || seen[a] {
			continue
		}
		if !known[a] {
			return fmt.Errorf("%w: %s", ErrUnknownAccount, a)
		}
		seen[a] = true
		uniq = append(uniq, a)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_group_members WHERE group_id=?`, groupID); err != nil {
		return err
	}
	for _, a := range uniq {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_group_members(group_id,account) VALUES(?,?)`, groupID, a); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetUserGroups 全量覆写某账号所属的 static 组集合（用户编辑侧的写入口）。
// 角色组不接受这条路径的写入——它们由 users.roles 派生。
func (s *SQLiteStore) SetUserGroups(ctx context.Context, account string, groupIDs []string) error {
	acct := normAccount(account)
	if acct == "" {
		return ErrUnknownAccount
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	known, err := s.knownAccounts(ctx, tx)
	if err != nil {
		return err
	}
	if !known[acct] {
		return fmt.Errorf("%w: %s", ErrUnknownAccount, acct)
	}
	seen := map[string]bool{}
	var uniq []string
	for _, gid := range groupIDs {
		gid = strings.TrimSpace(gid)
		if gid == "" || seen[gid] {
			continue
		}
		var kind string
		switch e := tx.QueryRowContext(ctx, `SELECT COALESCE(kind,'') FROM user_groups WHERE id=?`, gid).Scan(&kind); e {
		case nil:
		case sql.ErrNoRows:
			return ErrGroupNotFound
		default:
			return e
		}
		if kind == GroupKindRole {
			return ErrGroupDerived
		}
		seen[gid] = true
		uniq = append(uniq, gid)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_group_members WHERE account=?`, acct); err != nil {
		return err
	}
	for _, gid := range uniq {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_group_members(group_id,account) VALUES(?,?)`, gid, acct); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ── 回填 ──

// orgBackfillMarker settings 表里的一次性回填标记。
//
// ★为什么要标记而不是「表空就重建」：管理员删掉某个部门后，下次启动如果按
// 「表空/缺行就补」的逻辑跑，被删的部门会安静地复活，而删除操作在审计里是成功的。
const orgBackfillMarker = "org.backfill.v1"

// backfillOrgUnits 把内存种子里的组织树建成真实 org_units 行，并按 users.org_key
// 把既有用户回填到对应 org_id。整体只跑一次（orgBackfillMarker），且每一步都幂等。
//
// ★调用点在 seed() **之后**（见 OpenSQLite），不在 migrate() 里：全新库执行
// migrate 时 users 表还是空的，回填放在那儿会静默空转，种子用户永远没有 org_id
// ——正是 apps.resource_id 那次静默断链的同一种形态。
func (s *SQLiteStore) backfillOrgUnits(ctx context.Context) error {
	if _, done, err := s.Setting(ctx, orgBackfillMarker); err != nil || done {
		return err
	}
	seed, err := s.Memory.Users(ctx)
	if err != nil {
		return err
	}
	// 1) 种子组织树 → 真实行（沿用种子里的 key 作为 id，users.org_key 才对得上）
	var walk func(nodes []OrgUnit, parent string) error
	walk = func(nodes []OrgUnit, parent string) error {
		for i, n := range nodes {
			if _, err := s.SaveOrgUnit(ctx, Org{ID: n.Key, Name: n.Title, ParentID: parent, Sort: i}); err != nil {
				return err
			}
			if err := walk(n.Children, n.Key); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(seed.OrgTree, ""); err != nil {
		return err
	}
	rootID := ""
	if len(seed.OrgTree) > 0 {
		rootID = seed.OrgTree[0].Key
	}
	// 2) 用户身上出现过、但种子树里没有的 org_key（如 admin 的 sec/安全运营）
	//    补建成根的子部门——否则这批人回填完仍然无归属，组织树上凭空少几个人。
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT COALESCE(org_key,''), COALESCE(org,'') FROM users WHERE COALESCE(org_key,'')<>''`)
	if err != nil {
		return err
	}
	type pair struct{ key, name string }
	var extra []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.key, &p.name); err != nil {
			rows.Close()
			return err
		}
		extra = append(extra, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range extra {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_units WHERE id=?`, p.key).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		name := p.name
		if name == "" {
			name = p.key
		}
		if _, err := s.SaveOrgUnit(ctx, Org{ID: p.key, Name: name, ParentID: rootID, Sort: 90}); err != nil {
			return err
		}
	}
	// 3) 回填 users.org_id（只填仍为空的行；管理员后来改过的一律不动）
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET org_id=org_key WHERE COALESCE(org_id,'')='' AND COALESCE(org_key,'')<>''
		   AND org_key IN (SELECT id FROM org_units)`); err != nil {
		return err
	}
	return s.SetSetting(ctx, orgBackfillMarker, nowStr())
}

// ── PolicyBundle 脱种子 ──

// PolicyBundle 策略继承树：**整棵树由 org_units 真实数据构建**（此前整棵树是
// Memory 里硬编码的四个部门，节点 key 与库里任何东西都对不上——按节点保存的
// 策略覆盖因此永远落在一批虚构 key 上）。
//
// ★不再以 s.Memory.PolicyBundle(ctx) 打底：那条路径顺手继承了 List 那 5 条
// 编造的策略清单（详见 store/policy.go 顶部）。Memory 版本已删除，这里逐字段构造。
func (s *SQLiteStore) PolicyBundle(ctx context.Context) (PolicyBundle, error) {
	orgs, err := s.OrgUnits(ctx)
	if err != nil {
		return PolicyBundle{}, err
	}
	return PolicyBundle{Tree: toPolicyTree(buildOrgTree(orgs))}, nil
}
