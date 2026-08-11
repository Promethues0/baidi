package store

import (
	"context"
	"database/sql"
	"strings"
)

// ── 应用分类字典的 SQLite 实现（表 app_categories，见 migrate）──

// AppCategories 分类字典（按 sort 升序，同序按 key 稳定排列）。
// Count 用子查询现算：分类下有几个应用是**每次都要正确**的数（删除守卫判它，页面也显示它），
// 缓存一份计数列就多一处会过期的真相。
func (s *SQLiteStore) AppCategories(ctx context.Context) ([]AppCategoryDef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c."key", c.label, c.sort, c.builtin,
  (SELECT COUNT(*) FROM apps a WHERE a.category=c."key")
FROM app_categories c ORDER BY c.sort, c."key"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AppCategoryDef{}
	for rows.Next() {
		var d AppCategoryDef
		var builtin int
		if err := rows.Scan(&d.Key, &d.Label, &d.Sort, &builtin, &d.Count); err != nil {
			return nil, err
		}
		d.Builtin = builtin != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// CreateAppCategory 新建一个自定义分类。
//
// 刻意不做 upsert：建分类时把 key 打成一个已存在的值，upsert 会静默把那个分类改名，
// 而管理员以为自己新建了一条。改名与排序走 UpdateAppCategory。
//
// 入参的 Sort / Builtin **一律忽略**：
//   - Sort 排到末尾（新分类插在中间没有任何语义，界面上用 ↑↓ 调即可）；
//   - Builtin 恒为 false——REST 若能建出 builtin=1 的行，「内置不可删」这道守卫
//     就成了任何管理员都能自己发的免死金牌。
func (s *SQLiteStore) CreateAppCategory(ctx context.Context, c AppCategoryDef) (AppCategoryDef, error) {
	c, err := normalizeAppCategory(c)
	if err != nil {
		return AppCategoryDef{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AppCategoryDef{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_categories WHERE "key"=?`, c.Key).Scan(&n); err != nil {
		return AppCategoryDef{}, err
	}
	if n > 0 {
		return AppCategoryDef{}, ErrAppCategoryExists
	}
	var maxSort sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(sort) FROM app_categories`).Scan(&maxSort); err != nil {
		return AppCategoryDef{}, err
	}
	c.Sort = int(maxSort.Int64) + 10
	c.Builtin = false
	c.Count = 0 // 新分类下必然没有应用
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO app_categories("key",label,sort,builtin,created_at) VALUES(?,?,?,0,?)`,
		c.Key, c.Label, c.Sort, nowStr()); err != nil {
		return AppCategoryDef{}, err
	}
	return c, tx.Commit()
}

// UpdateAppCategory 改分类的名称与排序，返回 (改动前, 改动后) 供审计如实措辞。
//
// ★key 不可改，内置与自定义一视同仁：key 是主键，且被 apps.category 按值引用
// （没有外键约束，改了就是把这一批应用悬空）。「改名」的诉求由 label 承担。
// 内置分类允许走这里改 label / sort——不然管理员连把「财务高敏」改成本单位叫法都做不到。
func (s *SQLiteStore) UpdateAppCategory(ctx context.Context, key, label string, sort int) (AppCategoryDef, AppCategoryDef, error) {
	label = strings.TrimSpace(label)
	if err := checkAppCategoryLabel(label); err != nil {
		return AppCategoryDef{}, AppCategoryDef{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AppCategoryDef{}, AppCategoryDef{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	before, err := scanAppCategoryTx(ctx, tx, key)
	if err != nil {
		return AppCategoryDef{}, AppCategoryDef{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE app_categories SET label=?, sort=? WHERE "key"=?`,
		label, sort, key); err != nil {
		return AppCategoryDef{}, AppCategoryDef{}, err
	}
	after := before
	after.Label, after.Sort = label, sort
	return before, after, tx.Commit()
}

// DeleteAppCategory 删除一个自定义分类。
//
// 两道守卫，都在同一个事务里（DSN 带 _txlock=immediate，起手即取写锁，杜绝
// 「查的时候是空的、删完才有应用挂进来」）：
//   - 内置分类拒删（ErrAppCategoryBuiltin）；
//   - 分类下还有应用拒删（ErrAppCategoryInUse，带数量）。**不做级联置空**：
//     悄悄把这批应用的 category 清掉，它们会从筛选条上整体消失且没有任何提示。
func (s *SQLiteStore) DeleteAppCategory(ctx context.Context, key string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	d, err := scanAppCategoryTx(ctx, tx, key)
	if err != nil {
		return err
	}
	if d.Builtin {
		return ErrAppCategoryBuiltin
	}
	var used int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM apps WHERE category=?`, key).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return ErrAppCategoryInUse{Key: key, Apps: used}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_categories WHERE "key"=?`, key); err != nil {
		return err
	}
	return tx.Commit()
}

// scanAppCategoryTx 事务内取一行分类（不带 Count——调用方要么不需要，要么自己现算）。
func scanAppCategoryTx(ctx context.Context, tx *sql.Tx, key string) (AppCategoryDef, error) {
	var d AppCategoryDef
	var builtin int
	switch err := tx.QueryRowContext(ctx,
		`SELECT "key",label,sort,builtin FROM app_categories WHERE "key"=?`, key).
		Scan(&d.Key, &d.Label, &d.Sort, &builtin); err {
	case nil:
		d.Builtin = builtin != 0
		return d, nil
	case sql.ErrNoRows:
		return AppCategoryDef{}, ErrAppCategoryNotFound
	default:
		return AppCategoryDef{}, err
	}
}

// appCatBackfillMarker settings 表里的一次性标记：分类回填只跑这一次。
//
// ★纪律与 sensBackfillMarker 同源：回填是一次**语义迁移**（把常量搬成行），
// 不是每次启动的对账。少了标记，「管理员删掉的分类下次重启复活」这类
// 「改了、重启就变回去」的缺陷随时会长出来——它最难自证，因为管理员看到的是
// 自己的操作没保存，而日志里保存明明成功了。
//
// 诚实边界：以今天的守卫（内置分类不可删、收养行只在仍被应用引用时才会被再次
// 收养），还没有哪一条管理员操作能真的触发复活。标记在这里是把「只跑一次」
// **写进结构里**，而不是靠另外两道守卫碰巧兜住——将来若放开内置分类删除，
// 不必再回头想起这件事。
const appCatBackfillMarker = "app.categories.backfill.v1"

// backfillAppCategories 把分类从「包级常量」迁成真实行。
//
// ★调用点必须在 seed() 之后（见 OpenSQLite）：除了 4 个内置分类，它还要收养
// **库里 apps.category 已经出现过、却不在内置清单里**的值——旧版 POST /apps 不校验
// 分类，那一列一直是自由文本。放在 migrate 里的话，全新库此时 apps 还是空表，
// 收养这一步静默空转（backfillOrgUnits 踩过的正是这个坑）。
//
// 收养行的 label 先用 key 顶着（历史值只有 key，没有别的信息可用），builtin=0
// 因此管理员改名或删掉它都行。不收养的后果是这批应用在筛选条上任何一栏都不出现。
func (s *SQLiteStore) backfillAppCategories(ctx context.Context) error {
	if _, done, err := s.Setting(ctx, appCatBackfillMarker); err != nil || done {
		return err
	}
	for _, d := range builtinAppCategories() {
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO app_categories("key",label,sort,builtin,created_at) VALUES(?,?,?,1,?)`,
			d.Key, d.Label, d.Sort, nowStr()); err != nil {
			return err
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT category FROM apps
WHERE COALESCE(category,'')<>'' AND category NOT IN (SELECT "key" FROM app_categories)`)
	if err != nil {
		return err
	}
	var orphans []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close() //nolint:errcheck
			return err
		}
		orphans = append(orphans, k)
	}
	rows.Close() //nolint:errcheck
	if err := rows.Err(); err != nil {
		return err
	}
	// 历史值可能不满足现在的 key 格式约束（旧接口没校验），照收不误：
	// 校验管的是**新写入**，回填的职责是别让既有数据在界面上消失。
	sort := len(builtinAppCategories())*10 + 10
	for _, k := range orphans {
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO app_categories("key",label,sort,builtin,created_at) VALUES(?,?,?,0,?)`,
			k, k, sort, nowStr()); err != nil {
			return err
		}
		sort += 10
	}
	return s.SetSetting(ctx, appCatBackfillMarker, nowStr())
}

// fillAppAuth 为一批应用现算授权面（AuthedUsers/AuthScope）。取数在这里，判定在
// resolveAppAuth——与资源授权的其余两个出口（网关策略下发、客户端剖面）共用同一套
// 「四维皆空即不限」语义，不另起一份口径。
func (s *SQLiteStore) fillAppAuth(ctx context.Context, apps []App) error {
	if len(apps) == 0 {
		return nil
	}
	resList, err := s.Resources(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]Resource, len(resList))
	for _, r := range resList {
		byID[r.ID] = r
	}
	ix, err := s.SubjectIndex(ctx)
	if err != nil {
		return err
	}
	// 鉴权角色（users.role）→ 账号。注意不是 users.roles 那个展示角色列表：
	// 资源 ACL 的 AllowRoles 比对的是令牌里的 role，展示角色不参与鉴权。
	rows, err := s.db.QueryContext(ctx, `SELECT lower(trim(account)), lower(trim(COALESCE(role,''))) FROM users`)
	if err != nil {
		return err
	}
	defer rows.Close()
	roleAccounts := map[string][]string{}
	total := 0
	for rows.Next() {
		var acct, role string
		if err := rows.Scan(&acct, &role); err != nil {
			return err
		}
		total++
		if role != "" {
			roleAccounts[role] = append(roleAccounts[role], acct)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	resolveAppAuth(apps, byID, ix, roleAccounts, total)
	return nil
}
