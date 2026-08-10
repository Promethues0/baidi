package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const authSrcCols = `id,name,kind,enabled,priority,config,created_at,updated_at`

func (s *SQLiteStore) scanAuthSource(row interface{ Scan(...any) error }) (AuthSourceRec, error) {
	var r AuthSourceRec
	var enabled int
	err := row.Scan(&r.ID, &r.Name, &r.Kind, &enabled, &r.Priority, &r.Config, &r.CreatedAt, &r.UpdatedAt)
	r.Enabled = enabled != 0
	return r, err
}

// AuthSources 返回全部认证源，按 priority 升序（本地目录恒排最前）。
func (s *SQLiteStore) AuthSources(ctx context.Context) ([]AuthSourceRec, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+authSrcCols+` FROM auth_sources ORDER BY (kind='local') DESC, priority, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuthSourceRec{}
	for rows.Next() {
		r, err := s.scanAuthSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 凭据的**存在性与指纹**单独补：不与配置同表读，免得哪天有人把密文顺手 SELECT 出来。
	// 这里只取 fingerprint 列，不取 nonce/cipher——列表路径根本碰不到密文。
	for i := range out {
		has, fp, err := s.authSourceSecretMeta(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].HasSecret, out[i].SecretFingerprint = has, fp
	}
	return out, nil
}

func (s *SQLiteStore) AuthSourceByID(ctx context.Context, id string) (AuthSourceRec, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+authSrcCols+` FROM auth_sources WHERE id=?`, id)
	r, err := s.scanAuthSource(row)
	if err == sql.ErrNoRows {
		return AuthSourceRec{}, false, nil
	}
	if err != nil {
		return AuthSourceRec{}, false, err
	}
	has, fp, err := s.authSourceSecretMeta(ctx, id)
	if err != nil {
		return AuthSourceRec{}, false, err
	}
	r.HasSecret, r.SecretFingerprint = has, fp
	return r, true, nil
}

// SaveAuthSource 新增 / 修改一条认证源（upsert）。
//
// ★ON CONFLICT 分支里刻意**不含** created_at，也不碰凭据表：
// 改一次配置就把凭据清掉，会让"改个显示名"变成"隧道/登录突然全挂"。
func (s *SQLiteStore) SaveAuthSource(ctx context.Context, rec AuthSourceRec) (AuthSourceRec, error) {
	if strings.TrimSpace(rec.ID) == "" {
		rec.ID = "as-" + uuid.NewString()[:8]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_sources(`+authSrcCols+`)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind,
  enabled=excluded.enabled, priority=excluded.priority, config=excluded.config,
  updated_at=excluded.updated_at`,
		rec.ID, rec.Name, rec.Kind, b2i(rec.Enabled), rec.Priority, rec.Config, nowStr(), nowStr())
	if err != nil {
		return AuthSourceRec{}, err
	}
	out, _, err := s.AuthSourceByID(ctx, rec.ID)
	return out, err
}

// DeleteAuthSource 删除认证源，连同它的凭据与身份绑定。
//
// ★绑定必须一起删：留着孤儿绑定的话，管理员删掉再重建同名源时，
// 老绑定会把新源的用户接到旧的本地账号上——一个凭空出现的越权路径。
func (s *SQLiteStore) DeleteAuthSource(ctx context.Context, id string) error {
	if id == "local" {
		return fmt.Errorf("本地目录不可删除")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM auth_source_secrets WHERE source_id=?`,
		`DELETE FROM auth_source_bindings WHERE source_id=?`,
		`DELETE FROM auth_sources WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// authSourceSecretMeta 只读凭据的**元信息**（是否存在 + 指纹），绝不触碰密文。
// 列表与详情走这条路，AuthSourceSecret（取密文）只被 buildProvider 一处调用。
func (s *SQLiteStore) authSourceSecretMeta(ctx context.Context, id string) (bool, string, error) {
	var fp sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT fingerprint FROM auth_source_secrets WHERE source_id=?`, id).Scan(&fp)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, fp.String, nil
}

func (s *SQLiteStore) SaveAuthSourceSecret(ctx context.Context, sec AuthSourceSecret) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_source_secrets(source_id,nonce,cipher,fingerprint,updated_at) VALUES(?,?,?,?,?)
ON CONFLICT(source_id) DO UPDATE SET nonce=excluded.nonce, cipher=excluded.cipher,
  fingerprint=excluded.fingerprint, updated_at=excluded.updated_at`,
		sec.SourceID, sec.Nonce, sec.Cipher, sec.Fingerprint, nowStr())
	return err
}

func (s *SQLiteStore) AuthSourceSecret(ctx context.Context, id string) (AuthSourceSecret, bool, error) {
	var sec AuthSourceSecret
	sec.SourceID = id
	err := s.db.QueryRowContext(ctx,
		`SELECT nonce,cipher FROM auth_source_secrets WHERE source_id=?`, id).Scan(&sec.Nonce, &sec.Cipher)
	if err == sql.ErrNoRows {
		return AuthSourceSecret{}, false, nil
	}
	if err != nil {
		return AuthSourceSecret{}, false, err
	}
	return sec, true, nil
}

// ── 外部身份绑定 ──

// UserBySubject 按 (认证源, 权威 subject) 查已绑定的本地用户。
func (s *SQLiteStore) UserBySubject(ctx context.Context, sourceID, subject string) (Credential, bool, error) {
	var uid string
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM auth_source_bindings WHERE source_id=? AND subject=?`, sourceID, subject).Scan(&uid)
	if err == sql.ErrNoRows {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, err
	}
	var c Credential
	err = s.db.QueryRowContext(ctx,
		`SELECT id,name,account,COALESCE(role,''),COALESCE(status,'active'),COALESCE(pass_hash,'') FROM users WHERE id=?`, uid).
		Scan(&c.ID, &c.Name, &c.Account, &c.Role, &c.Status, &c.PassHash)
	if err == sql.ErrNoRows {
		// 绑定指向一个已被删除的用户：当成未绑定处理，让下次登录重建。
		return Credential{}, false, nil
	}
	return c, err == nil, err
}

// BindExternalUser 建立（或刷新）外部身份 → 本地用户的绑定。
//
// 首次见到某个 subject 时建一个本地用户承载它；之后一律按 subject 找回同一个用户。
//
// ★外部用户的 pass_hash 恒为空字符串。这不是省事——它是一道闸：
// `auth.VerifyPassword` 对空哈希必须返回 false（调用方已保证），于是外部账号
// **没有任何本地口令可以登录**。不置空的后果是，哪天管理员把这个认证源停掉/删掉，
// 那个账号会退回成"用某个本地口令也能登录"，而那个口令是谁设的、什么时候设的，
// 没有人说得清。
func (s *SQLiteStore) BindExternalUser(ctx context.Context, sourceID string, ext ExternalIdentity) (Credential, error) {
	if strings.TrimSpace(ext.Subject) == "" {
		return Credential{}, fmt.Errorf("外部身份缺少 subject，拒绝绑定")
	}
	if c, ok, err := s.UserBySubject(ctx, sourceID, ext.Subject); err != nil {
		return Credential{}, err
	} else if ok {
		return c, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Credential{}, err
	}
	defer tx.Rollback()

	// 账号名可能与本地已有账号撞名（外部目录里有个 admin 是完全可能的）。
	// ★撞名时**不复用**那个本地账号，而是给外部账号加来源后缀——
	// 复用等于把外部目录的控制权变成本地管理员的控制权。
	//
	// ★★加了后缀还要**继续查重**，直到真的不撞为止：只查一次基名的话，
	// 同一认证源里两个用户名都归一成 alice（UserFilter 按 mail 唯一命中、
	// UsernameAttr 却配的是 displayName 这类非唯一属性时完全可能），
	// 两次都得到同一个 "alice@源id"，于是两个**不同的真实身份**共享一个 account。
	// 而 account 是令牌主体（JWT Sub）与 JIT 授予/封禁/posture 的键——
	// 身份混同意味着后来者直接继承前者的授权。这正是按 Subject 绑定要防的事，
	// 不能在后缀分支上又漏回来。
	account := strings.ToLower(strings.TrimSpace(ext.Username))
	if account == "" {
		account = "ext-" + uuid.NewString()[:8]
	}
	base := account
	for i := 0; ; i++ {
		var dup int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE lower(trim(account))=?`, account).Scan(&dup); err != nil {
			return Credential{}, err
		}
		if dup == 0 {
			break
		}
		switch i {
		case 0:
			account = base + "@" + sourceID
		default:
			// 后缀也撞：挂随机短码。用随机而不是自增序号，是因为自增要再查一轮
			// 才知道下一个空号是几，而这里只需要"不撞"。
			account = base + "@" + sourceID + "-" + uuid.NewString()[:6]
		}
	}

	name := strings.TrimSpace(ext.DisplayName)
	if name == "" {
		name = account
	}
	// 组织归属必须落 org_id，不能只写展示用的 org/org_key。
	//
	// ★此前这里写的是 org='外部目录', org_key='ext'，org_id 留空，症状分两头且都不报错：
	//   - 控制台按 orgKey 过滤组织树，这批人**看起来**就在「外包人员」部门下；
	//   - 而 store.SubjectIndex 是 users JOIN org_units ON o.id=u.org_id，org_id 为空
	//     的行直接被排除 → 把资源授权给该组织、或把「一律二次认证」策略绑到该组织，
	//     对外部目录来的账号一律不生效。资源侧 fail-closed（连不上，可查），
	//     策略侧 fail-open（该强制二次认证的人静默走单因素）——后者正是要防的。
	orgID, orgName, err := ensureExternalOrgUnit(ctx, tx)
	if err != nil {
		return Credential{}, err
	}
	id := "u-" + uuid.NewString()[:8]
	// role 恒为 user：外部目录说你是谁，不代表你在白帝里是管理员。
	// 提权必须是白帝这侧的显式动作，否则谁能改 AD 的组，谁就能给自己发管理员。
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users(id,name,account,org,org_key,org_id,device,ip,auth,last_login,online,status,risk,roles,created_at,pass_hash,role)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, name, account, orgName, orgID, orgID, "—", "—", "外部认证源", "—", 0, "active", "none",
		`["外部用户"]`, nowStr(), "", "user"); err != nil {
		return Credential{}, err
	}
	// ★upsert 而非裸 INSERT：主键是 (source_id, subject)，而这里的前置检查
	// （UserBySubject）跑在事务外，两个并发首登都能通过它。裸 INSERT 会让后到的
	// 那次撞主键 → 整个事务回滚 → 用户看到「认证服务暂时不可用」，而认证源好好的。
	// 另一种撞法更难查：绑定行还在、它指向的用户已被删，UserBySubject 按"未绑定"
	// 返回并声称"下次登录重建"，但重建必然撞上那行没被删的旧主键——该身份从此
	// **永久**登录失败，面貌同样是"认证服务不可用"。改写旧绑定正是那句注释的兑现。
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO auth_source_bindings(source_id,subject,user_id,username,created_at) VALUES(?,?,?,?,?)
ON CONFLICT(source_id,subject) DO UPDATE SET user_id=excluded.user_id, username=excluded.username,
  created_at=excluded.created_at`,
		sourceID, ext.Subject, id, account, nowStr()); err != nil {
		return Credential{}, err
	}
	if err := tx.Commit(); err != nil {
		return Credential{}, err
	}
	return Credential{ID: id, Name: name, Account: account, Role: "user", Status: "active", PassHash: ""}, nil
}

// externalOrgUnitID 外部目录账号的组织归属 id。
//
// 沿用种子组织树里「外包人员」那个 id：既有库升级上来时它已经存在（backfillOrgUnits
// 建的），种子策略 ap-ext-strict 的适用范围也正是它——换一个新 id 反而会让存量授权
// 与策略集体落空。
const externalOrgUnitID = "ext"

// extUserOrgBackfillMarker 一次性标记：把外部账号的 org_id 从 org_key 补齐只做一次。
//
// ★做成一次性而不是每次启动都补：管理员完全可能显式把某个账号的组织归属清空
// （org_id=''），每次启动都按陈旧的 org_key 补回去，等于管理员的操作被静默撤销。
const extUserOrgBackfillMarker = "org.extuser.orgid.v1"

// ensureExternalOrgUnit 确保「外部目录」这个组织单元存在，返回它的 id 与名称。
//
// 为什么要当场建而不是"没有就算了"：没有组织归属的外部账号既不被任何组织授权覆盖，
// 也不被任何按组织生效的认证策略覆盖——后者是 fail-open 的（该二次认证的人不被要求），
// 而且从页面上完全看不出来。宁可多一个组织单元，也不要一批"谁都管不到"的账号。
func ensureExternalOrgUnit(ctx context.Context, tx *sql.Tx) (string, string, error) {
	var name string
	switch err := tx.QueryRowContext(ctx,
		`SELECT name FROM org_units WHERE id=?`, externalOrgUnitID).Scan(&name); err {
	case nil:
		return externalOrgUnitID, name, nil
	case sql.ErrNoRows:
	default:
		return "", "", err
	}
	// 挂到根组织下（有根就挂根，没有就做一个顶层组织）。物化 path 的算法与
	// SaveOrgUnit 一致：父 path + 自己的 id + "/"，否则子树查询会漏掉它。
	parent, parentPath := "", "/"
	switch err := tx.QueryRowContext(ctx,
		`SELECT id, COALESCE(path,'/') FROM org_units WHERE COALESCE(parent_id,'')='' ORDER BY COALESCE(created_at,''), id LIMIT 1`).
		Scan(&parent, &parentPath); err {
	case nil:
	case sql.ErrNoRows:
		parent, parentPath = "", "/"
	default:
		return "", "", err
	}
	name = "外部目录"
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO org_units(id,name,parent_id,path,sort,created_at) VALUES(?,?,?,?,?,?)`,
		externalOrgUnitID, name, parent, parentPath+externalOrgUnitID+"/", 95, nowStr()); err != nil {
		return "", "", err
	}
	return externalOrgUnitID, name, nil
}

// backfillExternalUserOrg 给「有 org_key、没 org_id」的存量行补上组织归属。
//
// 直接受益的是外部目录账号：BindExternalUser 在本轮之前只写 org_key='ext'，
// 那批行在 SubjectIndex 里被 JOIN 排除，组织授权与策略适用范围一个都覆盖不到。
// 语句与 backfillOrgUnits 第 3 步同形，但**独立标记**——那一步的标记早已置位，
// 借它的车这批行永远补不上（补列/回填只跑一次这条纪律的另一面）。
func (s *SQLiteStore) backfillExternalUserOrg(ctx context.Context) error {
	if _, done, err := s.Setting(ctx, extUserOrgBackfillMarker); err != nil || done {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET org_id=org_key WHERE COALESCE(org_id,'')='' AND COALESCE(org_key,'')<>''
		   AND org_key IN (SELECT id FROM org_units)`); err != nil {
		return err
	}
	return s.SetSetting(ctx, extUserOrgBackfillMarker, nowStr())
}

// AuthSrc 认证源页顶部聚合：**只由 auth_sources 真实行构建**，与
// GET /api/v1/authsrc/sources 同一份数据（此前它整段来自 Memory 演示种子，
// 与同一页下半截的真实配置各说各话）。
//
// ★这里刻意不复用 AuthSources()：那条路径会顺带去 auth_source_secrets 取
// 凭据指纹，而本聚合是给"看一眼有哪些源"用的只读视图，没有任何回显凭据的
// 理由——少一条碰凭据表的调用点，就少一处将来被人 SELECT * 的机会。
func (s *SQLiteStore) AuthSrc(ctx context.Context) (AuthSrcBundle, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,kind,enabled,priority FROM auth_sources ORDER BY (kind='local') DESC, priority, id`)
	if err != nil {
		return AuthSrcBundle{}, err
	}
	defer rows.Close()
	out := AuthSrcBundle{Sources: []AuthSource{}}
	for rows.Next() {
		var a AuthSource
		var enabled int
		if err := rows.Scan(&a.Key, &a.Name, &a.Type, &enabled, &a.Priority); err != nil {
			return AuthSrcBundle{}, err
		}
		a.Enabled = enabled != 0
		out.Sources = append(out.Sources, a)
	}
	if err := rows.Err(); err != nil {
		return AuthSrcBundle{}, err
	}
	bound, local, err := s.authSourceAccountCounts(ctx)
	if err != nil {
		return AuthSrcBundle{}, err
	}
	for i := range out.Sources {
		if out.Sources[i].Type == "local" {
			out.Sources[i].BoundAccounts = local
			continue
		}
		out.Sources[i].BoundAccounts = bound[out.Sources[i].Key]
	}
	return out, nil
}

// authSourceAccountCounts 返回「外部源 id → 已绑定账号数」与「本地账号数」。
//
// 本地口径取"没有任何外部绑定的 users 行"而不是"pass_hash 非空"：外部账号的
// pass_hash 恒空没错，但存量本地行里也可能有空口令（待改密的新建号），
// 按口令判会把它们从本地目录里抹掉——按绑定关系判才是这两类账号的真实分界。
func (s *SQLiteStore) authSourceAccountCounts(ctx context.Context) (map[string]int, int, error) {
	bound := map[string]int{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT source_id, COUNT(*) FROM auth_source_bindings GROUP BY source_id`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, 0, err
		}
		bound[id] = n
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	// ★子查询必须滤掉 NULL/空 user_id：SQL 里 `x NOT IN (…, NULL)` 恒为 NULL（假），
	// 只要绑定表出现一条 user_id 为空的行，本地账号数就会**静默变成 0**。
	var local int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE id NOT IN
		   (SELECT user_id FROM auth_source_bindings WHERE COALESCE(user_id,'')<>'')`).
		Scan(&local); err != nil {
		return nil, 0, err
	}
	return bound, local, nil
}

// seedLocalAuthSource 确保「本地目录」这条认证源恒存在。
//
// ★这是迁移期的回填，不是普通播种：既有库升级上来时 auth_sources 表是空的，
// 而登录链路会按「先本地、再外部源」的顺序问下去——表里一条都没有的话，
// 界面上会显示「没有任何认证源」，让人以为登录已经不工作了（实际本地登录照常）。
// 与 backfillAppResourceID / backfillIpsecEnabled 并列挂在 migrate 收尾处。
//
// 刻意**只**播这一条。原来那 5 条（AD/RADIUS/OAuth/短信/商密证书）是纯编造的
// 内存种子，连「AD 域 1160 用户」这个数字都是凭空写的——留着一个假磁贴，
// 比没有这个磁贴更不诚实。
func (s *SQLiteStore) seedLocalAuthSource() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth_sources WHERE id='local'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO auth_sources(`+authSrcCols+`) VALUES(?,?,?,?,?,?,?,?)`,
		"local", "本地用户目录", "local", 1, 0, "{}", nowStr(), nowStr())
	return err
}
