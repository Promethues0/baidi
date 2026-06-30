package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Writer 是控制中心的写接口（落库的可变实体）。SQLiteStore 实现之；
// Memory 仅作只读种子，不实现 Writer。
type Writer interface {
	CreateApp(ctx context.Context, a App) (App, error)
	DecideApproval(ctx context.Context, id, decision, reason string) error
	SavePolicyOverride(ctx context.Context, node, title, settings string, customCount int) error
	GetPolicyOverride(ctx context.Context, node string) (PolicyOverride, bool, error)
	CreateUser(ctx context.Context, u DirUser) (DirUser, error)
	SetUserStatus(ctx context.Context, id, status string) error
	SaveResource(ctx context.Context, r Resource) error
	DeleteResource(ctx context.Context, id string) error
	SaveIpsecSite(ctx context.Context, s IpsecSite) (IpsecSite, error)
	DeleteIpsecSite(ctx context.Context, id string) error
	ToggleIpsecSite(ctx context.Context, id string) (string, error)
	SaveAddrObject(ctx context.Context, o AddrObject) (AddrObject, error)
	SaveServiceObject(ctx context.Context, o ServiceObject) (ServiceObject, error)
	SaveTimeObject(ctx context.Context, o TimeObject) (TimeObject, error)
	DeleteObject(ctx context.Context, kind, id string) error
	DeleteObjectIfUnreferenced(ctx context.Context, kind, id string) (bool, error)
	SaveAuthPolicy(ctx context.Context, p AuthPolicy) (AuthPolicy, error)
	DeleteAuthPolicy(ctx context.Context, id string) error
	RecordAudit(ctx context.Context, e AuditEntry) error
}

// PolicyOverride 持久化的用户策略覆盖（按组织/组节点）。
type PolicyOverride struct {
	Node        string `json:"node"`
	Title       string `json:"title"`
	Settings    string `json:"settings"` // 前端 sections 的 JSON 快照
	CustomCount int    `json:"customCount"`
	UpdatedAt   string `json:"updatedAt"`
}

// SQLiteStore 在内存种子（*Memory）之上，把 apps / approvals / policy_overrides
// 三类可变实体落到 SQLite；其余只读 bundle 直接走 Memory 种子。
type SQLiteStore struct {
	*Memory
	db *sql.DB
}

// OpenSQLite 打开/初始化数据库（建表 + 首次播种）。
func OpenSQLite(path string) (*SQLiteStore, error) {
	// _txlock=immediate：事务起手即取写锁，让「检查后写」类守卫（如对象删除前的引用复核）原子化，杜绝 TOCTOU。
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &SQLiteStore{Memory: NewMemory(), db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	if err := s.seed(); err != nil {
		return nil, err
	}
	return s, nil
}

// Ping 探测底层数据库连接健康（供运维自检 /diag 调用）。
func (s *SQLiteStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY, name TEXT, addr TEXT, mode TEXT, category TEXT, node TEXT,
  authed_users INTEGER, status TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, usr TEXT, device TEXT, fingerprint TEXT, submitted_at TEXT,
  reason TEXT, status TEXT, timeline TEXT, decided_at TEXT, decide_reason TEXT
);
CREATE TABLE IF NOT EXISTS policy_overrides (
  node TEXT PRIMARY KEY, title TEXT, settings TEXT, custom_count INTEGER, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT, account TEXT, org TEXT, org_key TEXT, device TEXT,
  ip TEXT, auth TEXT, last_login TEXT, online INTEGER, status TEXT, risk TEXT, roles TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS resources (
  id TEXT PRIMARY KEY, name TEXT, backend TEXT, allow_roles TEXT, allow_users TEXT, addr_ref TEXT, svc_ref TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS ipsec_sites (
  id TEXT PRIMARY KEY, name TEXT, peer TEXT, local_subnet TEXT, remote_subnet TEXT,
  ike_version TEXT, auth TEXT, suite TEXT, phase1 TEXT, phase2 TEXT, pfs INTEGER, pq_hybrid INTEGER,
  status TEXT, rx_bytes INTEGER, tx_bytes INTEGER, last_up TEXT, local_ref TEXT, remote_ref TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS addr_objects (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, value TEXT, descr TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS service_objects (
  id TEXT PRIMARY KEY, name TEXT, proto TEXT, ports TEXT, descr TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS time_objects (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, spec TEXT, descr TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS auth_policies (
  id TEXT PRIMARY KEY, name TEXT, directory TEXT, is_default INTEGER, scope TEXT, priority INTEGER, enabled INTEGER,
  pc TEXT, mobile TEXT, exempt TEXT, one_click INTEGER, enhance TEXT, authz_apps TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, category TEXT, actor TEXT, src_ip TEXT, event TEXT, verdict TEXT
);`)
	if err != nil {
		return err
	}
	// 对象库引用列：旧库表已存在时 CREATE TABLE IF NOT EXISTS 不会补列，逐列幂等 ALTER（忽略已存在）。
	for _, c := range []struct{ table, col string }{
		{"resources", "addr_ref"}, {"resources", "svc_ref"},
		{"ipsec_sites", "local_ref"}, {"ipsec_sites", "remote_ref"},
	} {
		if e := s.addColumnIfMissing(c.table, c.col); e != nil {
			return e
		}
	}
	return nil
}

// addColumnIfMissing 幂等地为表补一列 TEXT；列已存在（duplicate column name）视为成功。
func (s *SQLiteStore) addColumnIfMissing(table, col string) error {
	_, err := s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` TEXT`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	return nil
}

// seed 仅在表为空时把内存种子灌入（保证首启有内容、之后以库为准）。
func (s *SQLiteStore) seed() error {
	ctx := context.Background()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM apps`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		b, _ := s.Memory.Apps(ctx)
		for _, a := range b.Apps {
			if _, err := s.db.Exec(`INSERT INTO apps(id,name,addr,mode,category,node,authed_users,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
				a.ID, a.Name, a.Addr, a.Mode, a.Category, a.Node, a.AuthedUsers, a.Status, nowStr()); err != nil {
				return err
			}
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM approvals`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		b, _ := s.Memory.Devices(ctx)
		for _, ap := range b.Approvals {
			tl, _ := json.Marshal(ap.Timeline)
			if _, err := s.db.Exec(`INSERT INTO approvals(id,usr,device,fingerprint,submitted_at,reason,status,timeline,decided_at,decide_reason) VALUES(?,?,?,?,?,?,?,?,'','')`,
				ap.ID, ap.User, ap.Device, ap.Fingerprint, ap.SubmittedAt, ap.Reason, ap.Status, string(tl)); err != nil {
				return err
			}
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		b, _ := s.Memory.Users(ctx)
		for _, u := range b.Users {
			if err := s.insertUser(u); err != nil {
				return err
			}
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM resources`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		rs, _ := s.Memory.Resources(ctx)
		for _, r := range rs {
			if err := s.SaveResource(ctx, r); err != nil {
				return err
			}
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ipsec_sites`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		sites, _ := s.Memory.Ipsec(ctx)
		for _, st := range sites {
			if err := s.upsertIpsecSite(ctx, st); err != nil {
				return err
			}
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM addr_objects`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		ob, _ := s.Memory.Objects(ctx)
		for _, o := range ob.Addrs {
			if _, err := s.SaveAddrObject(ctx, o); err != nil {
				return err
			}
		}
		for _, o := range ob.Services {
			if _, err := s.SaveServiceObject(ctx, o); err != nil {
				return err
			}
		}
		for _, o := range ob.Times {
			if _, err := s.SaveTimeObject(ctx, o); err != nil {
				return err
			}
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM auth_policies`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		pols, _ := s.Memory.AuthPolicies(ctx)
		for _, p := range pols {
			if err := s.upsertAuthPolicy(ctx, p); err != nil {
				return err
			}
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		b, _ := s.Memory.Audit(ctx)
		// 种子日志按新→旧排列；逆序插入，使最新条目拿到最大 id（读取 ORDER BY id DESC 即新→旧）。
		for i := len(b.Logs) - 1; i >= 0; i-- {
			if err := s.RecordAudit(ctx, b.Logs[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// Resources 从库读受控资源清单（覆盖 Memory 种子）。
func (s *SQLiteStore) Resources(ctx context.Context) ([]Resource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,backend,allow_roles,allow_users,COALESCE(addr_ref,''),COALESCE(svc_ref,'') FROM resources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Resource{}
	for rows.Next() {
		var r Resource
		var roles, users string
		if err := rows.Scan(&r.ID, &r.Name, &r.Backend, &roles, &users, &r.AddrRef, &r.SvcRef); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(roles), &r.AllowRoles)
		_ = json.Unmarshal([]byte(users), &r.AllowUsers)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveResource 落库（upsert）一条受控资源。
func (s *SQLiteStore) SaveResource(ctx context.Context, r Resource) error {
	roles, _ := json.Marshal(r.AllowRoles)
	users, _ := json.Marshal(r.AllowUsers)
	_, err := s.db.ExecContext(ctx, `INSERT INTO resources(id,name,backend,allow_roles,allow_users,addr_ref,svc_ref,updated_at)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, backend=excluded.backend,
  allow_roles=excluded.allow_roles, allow_users=excluded.allow_users,
  addr_ref=excluded.addr_ref, svc_ref=excluded.svc_ref, updated_at=excluded.updated_at`,
		r.ID, r.Name, r.Backend, string(roles), string(users), r.AddrRef, r.SvcRef, nowStr())
	return err
}

// DeleteResource 删除一条受控资源。
func (s *SQLiteStore) DeleteResource(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM resources WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) insertUser(u DirUser) error {
	roles, _ := json.Marshal(u.Roles)
	_, err := s.db.Exec(`INSERT INTO users(id,name,account,org,org_key,device,ip,auth,last_login,online,status,risk,roles,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Name, u.Account, u.Org, u.OrgKey, u.Device, u.IP, u.Auth, u.LastLogin, b2i(u.Online), u.Status, u.Risk, string(roles), nowStr())
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Users 覆盖：身份源/组织树走种子，用户清单从库读取。
func (s *SQLiteStore) Users(ctx context.Context) (UserDirBundle, error) {
	b, err := s.Memory.Users(ctx)
	if err != nil {
		return UserDirBundle{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,account,org,org_key,device,ip,auth,last_login,online,status,risk,roles FROM users ORDER BY created_at`)
	if err != nil {
		return UserDirBundle{}, err
	}
	defer rows.Close()
	var us []DirUser
	for rows.Next() {
		var u DirUser
		var online int
		var roles string
		if err := rows.Scan(&u.ID, &u.Name, &u.Account, &u.Org, &u.OrgKey, &u.Device, &u.IP, &u.Auth, &u.LastLogin, &online, &u.Status, &u.Risk, &roles); err != nil {
			return UserDirBundle{}, err
		}
		u.Online = online == 1
		_ = json.Unmarshal([]byte(roles), &u.Roles)
		us = append(us, u)
	}
	b.Users = us
	return b, nil
}

// CreateUser 新增用户落库。
func (s *SQLiteStore) CreateUser(ctx context.Context, u DirUser) (DirUser, error) {
	u.ID = "u-" + uuid.NewString()[:8]
	if u.Status == "" {
		u.Status = "active"
	}
	if u.Risk == "" {
		u.Risk = "none"
	}
	if u.LastLogin == "" {
		u.LastLogin = "—"
	}
	if u.Roles == nil {
		u.Roles = []string{}
	}
	if err := s.insertUser(u); err != nil {
		return DirUser{}, err
	}
	return u, nil
}

// SetUserStatus 改用户状态（禁用/启用/解锁）落库。
func (s *SQLiteStore) SetUserStatus(ctx context.Context, id, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET status=? WHERE id=?`, status, id)
	return err
}

func nowStr() string { return time.Now().Format("2006-01-02 15:04:05") }

var catLabels = map[string]string{"office": "办公协同", "finance": "财务高敏", "dev": "研发运维", "global": "全网资源"}
var catOrder = []string{"office", "finance", "dev", "global"}

// Apps 覆盖：从库读取应用 + 动态聚合分类计数。
func (s *SQLiteStore) Apps(ctx context.Context) (AppBundle, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,addr,mode,category,node,authed_users,status FROM apps ORDER BY created_at`)
	if err != nil {
		return AppBundle{}, err
	}
	defer rows.Close()
	var apps []App
	counts := map[string]int{}
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.Name, &a.Addr, &a.Mode, &a.Category, &a.Node, &a.AuthedUsers, &a.Status); err != nil {
			return AppBundle{}, err
		}
		apps = append(apps, a)
		counts[a.Category]++
	}
	cats := []AppCategory{{Key: "all", Label: "全部应用", Count: len(apps)}}
	for _, k := range catOrder {
		cats = append(cats, AppCategory{Key: k, Label: catLabels[k], Count: counts[k]})
	}
	return AppBundle{Categories: cats, Apps: apps}, nil
}

// CreateApp 落库新发布的应用。
func (s *SQLiteStore) CreateApp(ctx context.Context, a App) (App, error) {
	a.ID = "app-" + uuid.NewString()[:8]
	if a.Status == "" {
		a.Status = "running"
	}
	if a.Node == "" {
		a.Node = "华东出口"
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO apps(id,name,addr,mode,category,node,authed_users,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.Addr, a.Mode, a.Category, a.Node, a.AuthedUsers, a.Status, nowStr()); err != nil {
		return App{}, err
	}
	return a, nil
}

// Devices 覆盖：设备 + 信任设置走种子，待审批队列从库读取（只取 pending）。
func (s *SQLiteStore) Devices(ctx context.Context) (DeviceBundle, error) {
	b, err := s.Memory.Devices(ctx)
	if err != nil {
		return DeviceBundle{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,usr,device,fingerprint,submitted_at,reason,status,timeline FROM approvals WHERE status='pending' ORDER BY submitted_at DESC`)
	if err != nil {
		return DeviceBundle{}, err
	}
	defer rows.Close()
	var aps []TrustApproval
	for rows.Next() {
		var ap TrustApproval
		var tl string
		if err := rows.Scan(&ap.ID, &ap.User, &ap.Device, &ap.Fingerprint, &ap.SubmittedAt, &ap.Reason, &ap.Status, &tl); err != nil {
			return DeviceBundle{}, err
		}
		_ = json.Unmarshal([]byte(tl), &ap.Timeline)
		aps = append(aps, ap)
	}
	b.Approvals = aps
	return b, nil
}

// DecideApproval 审批落库（通过/驳回 + 理由 + 决策时间），并追加一条时间线事件。
func (s *SQLiteStore) DecideApproval(ctx context.Context, id, decision, reason string) error {
	var tl string
	if err := s.db.QueryRowContext(ctx, `SELECT timeline FROM approvals WHERE id=?`, id).Scan(&tl); err != nil {
		return err
	}
	var events []ApprovalEvent
	_ = json.Unmarshal([]byte(tl), &events)
	title, kind := "审批通过", "notify"
	if decision == "rejected" {
		title, kind = "审批驳回", "risk"
	}
	events = append(events, ApprovalEvent{Time: nowStr(), Kind: kind, Title: title, Detail: pick(reason, "管理员已处置，已通知申请人")})
	nb, _ := json.Marshal(events)
	_, err := s.db.ExecContext(ctx, `UPDATE approvals SET status=?, decided_at=?, decide_reason=?, timeline=? WHERE id=?`,
		decision, nowStr(), reason, string(nb), id)
	return err
}

// SavePolicyOverride upsert 用户策略覆盖。
func (s *SQLiteStore) SavePolicyOverride(ctx context.Context, node, title, settings string, customCount int) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO policy_overrides(node,title,settings,custom_count,updated_at) VALUES(?,?,?,?,?)
ON CONFLICT(node) DO UPDATE SET title=excluded.title, settings=excluded.settings, custom_count=excluded.custom_count, updated_at=excluded.updated_at`,
		node, title, settings, customCount, nowStr())
	return err
}

// GetPolicyOverride 读取某节点的已存覆盖。
func (s *SQLiteStore) GetPolicyOverride(ctx context.Context, node string) (PolicyOverride, bool, error) {
	var po PolicyOverride
	err := s.db.QueryRowContext(ctx, `SELECT node,title,settings,custom_count,updated_at FROM policy_overrides WHERE node=?`, node).
		Scan(&po.Node, &po.Title, &po.Settings, &po.CustomCount, &po.UpdatedAt)
	if err == sql.ErrNoRows {
		return PolicyOverride{}, false, nil
	}
	if err != nil {
		return PolicyOverride{}, false, err
	}
	return po, true, nil
}

func pick(a, b string) string {
	if a == "" {
		return b
	}
	return a
}
