package store

// 用户目录的**改**与**删**（PRD FR-USER-02「本地新建与修改」、FR-USER-15 席位释放）。
//
// ★这两条此前整个不存在，而它们的缺席各自引出一条死路：
//
//   · 改：写路径只有建号 / 改口令 / 改归属三条，`grep` 全仓没有 `PUT /users/{id}`。
//     建号时把姓名打错、或部门重组后要改显示名，在控制台上**无法纠正**——
//     只能禁用旧号重建一个，而重建又撞上下面那条（删不掉），于是每错一次
//     就永久多一行僵尸账号。邮箱更别扭：CSV 导入写得进去、CSV 导出读得出来，
//     页面上既看不见也改不了。
//
//   · 删：`license.go` 的注释与 409 文案、闲置治理弹窗的说明，三处都把管理员
//     指向「删除闲置账号释放席位」，而**全仓没有任何删除账号的路径**
//     （`grep -rn DeleteUser` 只命中 DeleteUserGroup）。席位满了就真的没辙。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// ErrUserNotFound 目标账号不存在（改/删都用它，回 404 而不是静默成功）。
var ErrUserNotFound = errors.New("用户不存在")

// UserProfilePatch 可改的目录字段。
//
// ★**account 不在里面，且永远不该进来**：它是令牌主体（JWT Sub），
// 也是 JIT 授予 / 封禁名单 / posture 报告 / 用户组成员 / 认证源绑定的关联键。
// 改它等于把这些关系整段挂空，而那些表里没有一处会报错——
// 表现是「这个人的授权、终端、组关系一夜之间全没了」。
// 要换账号名只能新建 + 迁移，那是一次有意识的操作，不是一次编辑。
type UserProfilePatch struct {
	Name  *string // nil = 不改
	Email *string
}

// UpdateUserProfile 改姓名 / 邮箱。返回改后的行。
func (s *SQLiteStore) UpdateUserProfile(ctx context.Context, id string, p UserProfilePatch) (DirUser, error) {
	sets, args := []string{}, []any{}
	if p.Name != nil {
		n := strings.TrimSpace(*p.Name)
		if n == "" {
			return DirUser{}, errors.New("姓名不能为空")
		}
		sets, args = append(sets, "name=?"), append(args, n)
	}
	if p.Email != nil {
		sets, args = append(sets, "email=?"), append(args, strings.TrimSpace(*p.Email))
	}
	if len(sets) == 0 {
		return DirUser{}, errors.New("没有要修改的字段")
	}
	args = append(args, id)
	res, err := s.db.ExecContext(ctx, `UPDATE users SET `+strings.Join(sets, ",")+` WHERE id=?`, args...)
	if err != nil {
		return DirUser{}, err
	}
	// ★查 RowsAffected：SQLite 对不存在的 id 不报错，改一个已被删掉的账号会
	// **静默成功**，接口回 200 而库里什么都没变（同 apps 那条纪律）。
	//
	// 说明边界：这一行在**当前实现下是冗余的纵深**——下面紧接着 `userByID`
	// 读回改后的行，目标不存在时它同样报 ErrUserNotFound（变异实测：把这个判断
	// 去掉，两层的用例都还是绿的）。留着是因为它让"改不到就要报错"这条意图**显式**，
	// 而 `userByID` 那条回读将来完全可能被换成"直接把入参拼成返回值"的写法——
	// 那一刻这行就是唯一的守卫了。
	if n, _ := res.RowsAffected(); n == 0 {
		return DirUser{}, ErrUserNotFound
	}
	return s.userByID(ctx, id)
}

// userByID 取一行目录用户（复用 Users() 的完整投影，避免第二套字段拼装）。
func (s *SQLiteStore) userByID(ctx context.Context, id string) (DirUser, error) {
	b, err := s.Users(ctx)
	if err != nil {
		return DirUser{}, err
	}
	for _, u := range b.Users {
		if u.ID == id {
			return u, nil
		}
	}
	return DirUser{}, ErrUserNotFound
}

// jsonStrings 解一列 JSON 字符串数组；解不出按空处理（存量行可能是空串或坏值）。
func jsonStrings(raw string) []string {
	var out []string
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil
	}
	return out
}

// UserDeleteBlast 删一个账号会连带影响什么（删之前算，删之后就查不到了）。
type UserDeleteBlast struct {
	Account string
	Name    string
	// Grants 该账号名下**有效**的 JIT 授予数（删账号不会把它们收回，只是失去主体）。
	Grants int
	// Devices 授信终端台账行数（与 posture 报告一一对应，同删）。
	Devices int
	// Resources 在 resources.allow_users 里点名授权给他的资源 id。
	//
	// ★这一项最要紧：删账号**不会**把他从资源的允许名单里摘掉，那是一串
	// 悬空的账号名，日后若有人建了同名账号，他会**直接继承**这些授权。
	Resources []string
	// GroupRefs 用户组成员关系数。
	GroupRefs int
	// MFA 已注册的第二因子数（passkey + TOTP）。
	MFA int
}

// Note 影响面的人话（回执与审计共用一份，别在页面上另编一句）。
func (b UserDeleteBlast) Note() string {
	parts := []string{}
	if len(b.Resources) > 0 {
		parts = append(parts, "该账号仍被 "+strconv.Itoa(len(b.Resources))+
			" 个受控资源按账号名点名授权（"+strings.Join(b.Resources, "、")+
			"）——删除**不会**把它从这些名单里摘掉，日后若有人建了同名账号将直接继承这些授权，请去「资源策略」逐条清理")
	}
	if b.Grants > 0 {
		parts = append(parts, "名下还有 "+strconv.Itoa(b.Grants)+" 条有效的 JIT 授予（已随账号一并失去主体）")
	}
	if b.Devices > 0 {
		parts = append(parts, "已连带删除 "+strconv.Itoa(b.Devices)+" 台授信终端登记与其环境报告")
	}
	if b.MFA > 0 {
		parts = append(parts, "已连带删除 "+strconv.Itoa(b.MFA)+" 项二次认证绑定")
	}
	if b.GroupRefs > 0 {
		parts = append(parts, "已从 "+strconv.Itoa(b.GroupRefs)+" 个用户组中移除")
	}
	if len(parts) == 0 {
		return "该账号没有任何连带引用。"
	}
	return strings.Join(parts, "；") + "。"
}

// UserDeleteBlastRadius 算删除影响面。
func (s *SQLiteStore) UserDeleteBlastRadius(ctx context.Context, id string) (UserDeleteBlast, error) {
	u, err := s.userByID(ctx, id)
	if err != nil {
		return UserDeleteBlast{}, err
	}
	acc := strings.ToLower(strings.TrimSpace(u.Account))
	b := UserDeleteBlast{Account: u.Account, Name: u.Name, Resources: []string{}}
	_ = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM jit_grants WHERE lower(trim(user))=? AND status='active'`, acc).Scan(&b.Grants)
	_ = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trusted_devices WHERE lower(trim(account))=?`, acc).Scan(&b.Devices)
	_ = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_group_members WHERE lower(trim(account))=?`, acc).Scan(&b.GroupRefs)
	var creds, totps int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_credentials WHERE account=?`, acc).Scan(&creds)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM totp_secrets WHERE account=?`, acc).Scan(&totps)
	b.MFA = creds + totps
	// 资源点名授权：allow_users 是 JSON 数组，逐行解出来比对（规模是资源数，不是用户数）。
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(allow_users,'[]') FROM resources`)
	if err != nil {
		return b, nil // 影响面算不全不该挡住删除本身；回执里少一项好过删不掉
	}
	defer rows.Close()
	for rows.Next() {
		var rid, raw string
		if rows.Scan(&rid, &raw) != nil {
			continue
		}
		for _, a := range jsonStrings(raw) {
			if strings.ToLower(strings.TrimSpace(a)) == acc {
				b.Resources = append(b.Resources, rid)
				break
			}
		}
	}
	return b, nil
}

// DeleteUser 删除一个账号及其**账号维度**的连带数据。
//
// 防自锁与 SetUserStatus / SetAdminRole 同一条：最后一名可登录的超管删不掉
// （否则一次误删就是整套系统再也没人能进管理台）。
func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var account, role, adminRole string
	switch err := tx.QueryRowContext(ctx,
		`SELECT account, COALESCE(role,''), COALESCE(admin_role,'') FROM users WHERE id=?`, id).
		Scan(&account, &role, &adminRole); err {
	case nil:
	case sql.ErrNoRows:
		// ★不静默成功：回 404 让接口如实说「已经没有这个账号了」。
		// 回 200 会在审计里落下一条「删除用户 X」，而那件事没有发生。
		return ErrUserNotFound
	default:
		return err
	}
	if role == "admin" {
		isRoot, err := s.isRootRole(ctx, tx, adminRole)
		if err != nil && err != ErrAdminRoleNotFound {
			return err
		}
		if isRoot {
			others, err := s.rootAdminCount(ctx, tx, strings.ToLower(strings.TrimSpace(account)))
			if err != nil {
				return err
			}
			if others == 0 {
				return ErrLastRootAdmin
			}
		}
	}
	acc := strings.ToLower(strings.TrimSpace(account))
	// 账号维度的连带数据一并清掉。★刻意**不动** resources.allow_users 与 jit_grants：
	//   · allow_users 是安全授权，删账号顺手改别的资源的授权面属于越权动作，
	//     且它一旦被静默清掉，管理员就再也看不出这个资源原来授权过谁——
	//     影响面回执把它当面列出来，由人去决定怎么清（同 apps 下架不级联删资源）。
	//   · jit_grants 保留是为了审计可追溯：那些授予**确实发生过**。
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM auth_source_bindings WHERE user_id=?`, []any{id}},
		{`DELETE FROM user_group_members WHERE lower(trim(account))=?`, []any{acc}},
		{`DELETE FROM webauthn_credentials WHERE account=?`, []any{acc}},
		{`DELETE FROM totp_secrets WHERE account=?`, []any{acc}},
		// 授信终端与环境报告按 (账号,指纹) 一一对应，两表同删（同 MaxDevicesPerAccount 那条纪律）。
		{`DELETE FROM trusted_devices WHERE lower(trim(account))=?`, []any{acc}},
		{`DELETE FROM posture_reports WHERE lower(trim(user))=?`, []any{acc}},
		{`DELETE FROM device_sessions WHERE lower(trim(account))=?`, []any{acc}},
		{`DELETE FROM users WHERE id=?`, []any{id}},
	} {
		if _, err := tx.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
