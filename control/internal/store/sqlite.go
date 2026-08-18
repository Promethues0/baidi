package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Writer 是控制中心的写接口（落库的可变实体）。SQLiteStore 实现之；
// Memory 仅作只读种子，不实现 Writer。
type Writer interface {
	// CreateApp 发布应用。分类必须是 app_categories 里已存在的 key，否则 ErrUnknownAppCategory。
	CreateApp(ctx context.Context, a App) (App, error)
	// ── 应用分类字典（管理员可自建可修改）──
	// 建：key 唯一 + 格式校验，builtin 恒 false（内置行只能由回填产生）。
	// 改：只动 label 与 sort，内置分类同样可改；key 不可改（apps.category 按值引用它）。
	// 删：内置拒删、分类下有应用拒删（ErrAppCategoryInUse，不做级联置空）。
	CreateAppCategory(ctx context.Context, c AppCategoryDef) (AppCategoryDef, error)
	UpdateAppCategory(ctx context.Context, key, label string, sort int) (AppCategoryDef, AppCategoryDef, error)
	DeleteAppCategory(ctx context.Context, key string) error
	// DecideApproval 设备绑定审批落库，**同事务**把关联设备置为 trusted / revoked。
	// 返回被联动的设备（found=false = 该审批单没有关联设备，迁移前遗留的单子）。
	DecideApproval(ctx context.Context, id, decision, reason, by string) (Device, bool, error)
	// ── 授信终端生命周期（PRD ch9 FR-EP-10/12/13/14/15）──
	// EnrollDevice 终端上报时的登记（幂等；created=true 才是新设备）。单账号上限
	// MaxDevicesPerAccount 在同一事务内判定，超限回 ErrDeviceCap。
	EnrollDevice(ctx context.Context, account, fingerprint, name, platform, bind string) (Device, bool, error)
	// SetDeviceStatus 批准 / 吊销 / 打回。返回 (改动前, 改动后)，供审计如实措辞。
	SetDeviceStatus(ctx context.Context, id, status, by, reason string) (Device, Device, error)
	RenameDevice(ctx context.Context, id, name string) (Device, error)
	// SetDeviceAsset 改资产分类与标签（wave7 行动 15）。返回 (改动前, 改动后)——
	// 分类是准入判据，审计必须写得出"从 X 改成 Y"。
	SetDeviceAsset(ctx context.Context, id, assetClass string, tags []string) (Device, Device, error)
	// DeleteDevice 删设备登记 + 同删它的 posture 报告（两表口径统一的执行处）。
	DeleteDevice(ctx context.Context, id string) (Device, error)
	// PurgeStaleDevices 清理陈旧设备（跳过 revoked，理由见实现顶部）。
	PurgeStaleDevices(ctx context.Context, staleDays int) ([]Device, error)
	SaveDeviceTrustSetting(ctx context.Context, st DeviceTrustSetting) (DeviceTrustSetting, error)
	CreateUser(ctx context.Context, u DirUser) (DirUser, error)
	SetUserStatus(ctx context.Context, id, status string) error
	// SetUserPassword 落口令哈希 + 首登改密标志 + 口令强度标记（strength 见 auth.PasswordStrength）。
	SetUserPassword(ctx context.Context, id, hash string, mustChange bool, strength string) error
	SaveResource(ctx context.Context, r Resource) error
	DeleteResource(ctx context.Context, id string) error
	// ★IPSec 的读写不在 Writer 里，收敛到 IpsecStore（见 ipsec_state.go）：
	// 那组方法里有「读 PSK 密文」这种只该被两个 handler 调用的能力，
	// 挂在人人可得的 Writer 上等于把密钥访问面摊给全体 handler。
	SaveAddrObject(ctx context.Context, o AddrObject) (AddrObject, error)
	SaveServiceObject(ctx context.Context, o ServiceObject) (ServiceObject, error)
	SaveTimeObject(ctx context.Context, o TimeObject) (TimeObject, error)
	DeleteObject(ctx context.Context, kind, id string) error
	DeleteObjectIfUnreferenced(ctx context.Context, kind, id string) (bool, error)
	SaveAuthPolicy(ctx context.Context, p AuthPolicy) (AuthPolicy, error)
	DeleteAuthPolicy(ctx context.Context, id string) error
	RecordAudit(ctx context.Context, e AuditEntry) error
	SaveBaseline(ctx context.Context, b BaselinePolicy) (BaselinePolicy, error)
	DeleteBaseline(ctx context.Context, id string) error
	SavePostureReport(ctx context.Context, r PostureReport) error
	DeletePostureReport(ctx context.Context, user, device string) (bool, error)
	// JIT 即时访问：申请落库 + 审批（同事务建授予）+ 撤销授予
	CreateAccessRequest(ctx context.Context, req AccessRequest) (AccessRequest, error)
	DecideAccessRequest(ctx context.Context, id, decision, reason, decidedBy string, ttlOverride int) (AccessRequest, JitGrant, error)
	RevokeGrant(ctx context.Context, id, reason string) (JitGrant, error)
	// WebAuthn：凭据落库/删除、签名计数器更新、challenge 生成与单次消费
	SaveWebauthnCredential(ctx context.Context, c WebauthnCredential) (WebauthnCredential, error)
	DeleteWebauthnCredential(ctx context.Context, account, id string) error
	UpdateSignCount(ctx context.Context, credentialID string, newCount uint32) error
	CreateWebauthnChallenge(ctx context.Context, ch WebauthnChallenge) (WebauthnChallenge, error)
	ConsumeWebauthnChallenge(ctx context.Context, challenge, typ string) (WebauthnChallenge, error)
	PurgeExpiredChallenges(ctx context.Context) (int64, error)
	// TOTP：密钥落库（密文）/ 确认转正 / 防重放计数消费 / 解绑
	SaveTotpSecret(ctx context.Context, account string, nonce, cipher []byte) error
	ConfirmTotp(ctx context.Context, account string, counter uint64) error
	ConsumeTotpCounter(ctx context.Context, account string, counter uint64) (bool, error)
	DeleteTotp(ctx context.Context, account string) (bool, error)
	// 网关客户端证书：签发登记 + 吊销
	SaveGatewayCert(ctx context.Context, c GatewayCert) error
	RevokeGatewayCert(ctx context.Context, fingerprint, reason string) error
	// 组织与用户组：组织树增删改 + 用户组增删改 + 成员/归属写入
	SaveOrgUnit(ctx context.Context, o Org) (Org, error)
	DeleteOrgUnit(ctx context.Context, id string) error
	SaveUserGroup(ctx context.Context, g UserGroup) (UserGroup, error)
	DeleteUserGroup(ctx context.Context, id string) error
	SetGroupMembers(ctx context.Context, groupID string, accounts []string) error
	SetUserOrg(ctx context.Context, userID, orgID string) error
	SetUserGroups(ctx context.Context, account string, groupIDs []string) error
	// 业务告警：规则增删改 + 产生告警（自带冷却期去重）+ 处置状态机。
	// RaiseAlert 的 created=false 表示"冷却期内已有同规则同对象的告警"，不是错误。
	SaveAlertRule(ctx context.Context, r AlertRule) (AlertRule, error)
	DeleteAlertRule(ctx context.Context, id string) error
	RaiseAlert(ctx context.Context, a Alert, cooldownSec int) (Alert, bool, error)
	SetAlertStatus(ctx context.Context, id, status, by string, at int64) (Alert, error)
	// AppendGatewayMetric 落一条网关宿主机采样点（数据面心跳带上来的设备状态）。
	// ★这是全系统唯一的高频写入口（每网关 15s 一条），配套的留存清理见
	// PurgeExpiredGatewayMetrics——它不在本接口里，因为调用方只有 main 的清理循环。
	AppendGatewayMetric(ctx context.Context, p GatewayMetricPoint) error
	// 管理员分级分权：自定义角色增删 + 管理员角色分派/撤销。
	// 三个写方法都自带「最后一名超管不可删/不可降权」的事务内防自锁守卫。
	SaveAdminRole(ctx context.Context, r AdminRole) (AdminRole, error)
	DeleteAdminRole(ctx context.Context, key string) error
	SetAdminRole(ctx context.Context, account, roleKey string) error
	RemoveAdmin(ctx context.Context, account string) error
}

// ★这里原先有 PolicyOverride（按组织/组节点存的"用户策略覆盖"）与它的读写方法。
// 那套东西的消费方只有控制台自己：8 个设置项序列化成 JSON 存进 policy_overrides.settings，
// 读出来再渲染回同一个编辑器，**控制面从不解析它，数据面更不知道它存在**，
// 而保存成功的提示写着「已下发至「X」的代理网关」。整套已摘除（wave8 行动 13-①），
// 换成 store.AccessPolicy 那两条**真有执行方**的规则（FR-POLICY-29/30，执行点是敲门令牌）。
//
// policy_overrides 表本身保留不删：删表要重建库，而一张没人读的空表不构成任何风险；
// 留着它也让"曾经存过什么"在事故排查时还查得到。

// SQLiteStore 在内存种子（*Memory）之上，把 apps / approvals / policy_overrides
// 三类可变实体落到 SQLite；其余只读 bundle 直接走 Memory 种子。
type SQLiteStore struct {
	*Memory
	db *sql.DB
	// path 数据库文件路径。诊断的磁盘水位实测（AuditDiskStat）要拿它量库文件
	// 与所在文件系统的真实占用——没有它就只能报种子编的数字。
	path string
	// auditKey 审计防篡改链的 HMAC-SM3 密钥（BAIDI_AUDIT_HMAC_KEY_FILE，首启自动生成 0600）。
	// 落在 store 而非 config：migrate 回填与 RecordAudit 落库都要用它，密钥与链同生命周期。
	auditKey []byte
	// auditKeyPath 上面那把密钥的落盘路径（含默认推导的结果）。配置备份要按它取文件——
	// 备份侧自己重读环境变量会漏掉默认路径这一整类部署，见 AuditKeyPath。
	auditKeyPath string
	// auditRetainDays 审计留存天数展示值。由 main 用「purge 循环真正消费的那份配置」注入
	// （SetAuditRetentionDays）；0 = 未配置滚动清理。刻意不在 store 里重复读环境变量——
	// 展示值必须来自数据面真正在用的那份，而不是又解析一遍可能不一致的副本。
	auditRetainDays int
	// fwdQueueMax 每个审计外送出口的队列上界，由 main 注入（SetAuditForwardQueueMax）。
	// 与 auditRetainDays 同一条纪律：入队时判丢弃用的就是这一份，页面显示的也是它。
	fwdQueueMax int
}

// OpenSQLite 打开/初始化数据库（建表 + 首次播种）。
// DBPath 返回本 store 实际打开的数据库文件路径。
//
// ★配置备份必须问它、而不是自己重新读 BAIDI_DB 推导：两处推导逻辑一旦不一致
// （运维改用别的方式指定路径、或进程 cwd 变了），备份会**静默不含数据库**，
// 而管理员以为自己有一份完整备份——这类错误只在真正需要恢复的那天才暴露。
func (s *SQLiteStore) DBPath() string { return s.path }

// AuditKeyPath 返回本 store 实际在用的审计链 HMAC 密钥文件路径。
//
// ★与 DBPath 同一条纪律，而且这里踩过一次：配置备份原先按
// `os.Getenv("BAIDI_AUDIT_HMAC_KEY_FILE")` 收集这份密钥，而该变量**默认是空的**
// （默认路径由 OpenSQLite 按库文件所在目录推导），于是标准部署导出的备份里
// 根本没有审计链密钥。恢复后 control 会重新生成一把新的，结果是
// **全链校验永久失败**——审计数据都在、每一条都验不过，而且只在有人点
// 「审计链校验」的那天才发现。问 store 要，不自己重推。
func (s *SQLiteStore) AuditKeyPath() string { return s.auditKeyPath }

// SnapshotTo 产出一份**事务一致**的数据库快照到 path（该文件必须尚不存在）。
//
// ★配置备份/温备同步**必须**走它，绝不能直接读 DBPath() 那个文件。
//
// 库开在 WAL 模式（见 OpenSQLite 的 DSN），提交只落 `baidi.db-wal`，主库文件要等到
// checkpoint（默认攒够约 4MB WAL）才被写回；连接池里长期有空闲连接，也就不会发生
// 「关最后一个连接顺带 checkpoint」。于是直接整读主库文件拿到的是「上一次 checkpoint
// 为止」的内容——今天上午改的策略、建的账号可能一条都不在里面。而这份备份解得开、
// 也含 baidi.db，所有校验都通过，页面照常显示「同步新鲜 · RPO = 10 分钟」，
// 真实 RPO 是「距上次 checkpoint 多久」，**没有上界**。只在切换那天暴露。
// 第二个后果同样致命：读文件时若正赶上 checkpoint 回写页，拷贝可能内部不一致
// （恢复时报 database disk image is malformed），两处"校验"也发现不了。
//
// `VACUUM INTO` 在一个读事务里把整库写成一个新文件：内容一致、不含 -wal 边车、
// 顺带整理碎片。不用「先 wal_checkpoint(TRUNCATE) 再拷文件」是因为那两步之间
// 仍有写入窗口——一致性靠时间差碰运气不算一致性。
func (s *SQLiteStore) SnapshotTo(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("快照目标已存在：%s", path)
	}
	// 路径进 SQL 只能走字面量（VACUUM INTO 不接受占位参数），故必须自己转义单引号。
	quoted := "'" + strings.ReplaceAll(path, "'", "''") + "'"
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO "+quoted); err != nil {
		return fmt.Errorf("生成数据库一致性快照失败: %w", err)
	}
	return nil
}

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
	// 审计链密钥必须先于 migrate 就绪：既有库的补列回填要用它补算全链。
	keyPath := os.Getenv("BAIDI_AUDIT_HMAC_KEY_FILE")
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(path), "audit-hmac.key")
	}
	auditKey, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("审计链 HMAC 密钥: %w", err)
	}
	s := &SQLiteStore{Memory: NewMemory(), db: db, path: path, auditKey: auditKey, auditKeyPath: keyPath}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	if err := s.seed(); err != nil {
		return nil, err
	}
	if err := s.ensureCredentials(); err != nil {
		return nil, err
	}
	// ★管理员角色回填同样必须排在 ensureCredentials 之后：它要给既有 role='admin' 的
	// 账号（含这一步刚补建的 admin）分派超管角色，那批行在 migrate 阶段还不存在。
	if err := s.backfillAdminRoles(context.Background()); err != nil {
		return nil, err
	}
	// ★组织回填必须排在 seed/ensureCredentials 之后：它要按 users.org_key 把既有
	// 用户挂到组织上，而全新库在 migrate 阶段 users 表还是空的（放 migrate 里会
	// 静默空转，种子用户永远没有 org_id）。这条顺序依赖是 backfillOrgUnits 唯一的
	// 前提，改动建库流程时别把它挪回 migrate。
	if err := s.backfillOrgUnits(context.Background()); err != nil {
		return nil, err
	}
	// ★必须排在 backfillOrgUnits 之后：它只补「org_key 指向一个真实存在的组织」的行，
	// 而那些组织正是上一步建出来的。补的是本轮之前 BindExternalUser 留下的
	// 「org_key='ext' 但 org_id 为空」——那批行在 SubjectIndex 里被 JOIN 排除。
	if err := s.backfillExternalUserOrg(context.Background()); err != nil {
		return nil, err
	}
	// ★应用分类回填同样必须排在 seed() 之后，理由与 backfillOrgUnits 同款：
	// 它除了建 4 个内置分类，还要把**库里 apps.category 已出现过、却不在内置清单里**
	// 的历史值收养成真实行；全新库在 migrate 阶段 apps 还是空表，放那儿会静默空转。
	if err := s.backfillAppCategories(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

// seedPassword 演示口令；种子/回填用它生成真实 bcrypt 哈希，demo 登录体验不变但机制真实。
const seedPassword = "baidi@123"

// ensureCredentials 幂等回填旧库的凭据地基（迁移场景）：
//   - 权威 role 列空的用户按展示角色推断补齐；
//   - pass_hash 空的用户回填 demo 口令哈希（否则迁移后无人能登录）；
//   - admin 账号不存在则补建（role=admin）。
//
// 全新库 seed() 已设好，这里对其为幂等空操作。
func (s *SQLiteStore) ensureCredentials() error {
	ctx := context.Background()
	// role 回填
	rows, err := s.db.QueryContext(ctx, `SELECT id,roles FROM users WHERE role IS NULL OR role=''`)
	if err != nil {
		return err
	}
	type ru struct{ id, roles string }
	var pending []ru
	for rows.Next() {
		var r ru
		if err := rows.Scan(&r.id, &r.roles); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, r)
	}
	rows.Close()
	for _, r := range pending {
		var roles []string
		_ = json.Unmarshal([]byte(r.roles), &roles)
		if _, err := s.db.ExecContext(ctx, `UPDATE users SET role=? WHERE id=?`, roleFromDisplay(roles), r.id); err != nil {
			return err
		}
	}
	// pass_hash 回填（迁移库的历史用户从来没有口令）
	var missing int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE pass_hash IS NULL OR pass_hash=''`).Scan(&missing); err != nil {
		return err
	}
	if missing > 0 {
		hash, err := auth.HashPassword(seedPassword)
		if err != nil {
			return err
		}
		// 回填的是 demo 口令，强度如实标记（与 seed 同口径）。
		if _, err := s.db.ExecContext(ctx,
			`UPDATE users SET pass_hash=?, pw_strength=? WHERE pass_hash IS NULL OR pass_hash=''`,
			hash, auth.PasswordStrength("", seedPassword)); err != nil {
			return err
		}
	}
	// admin 账号兜底
	var adminN int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE lower(trim(account))='admin'`).Scan(&adminN); err != nil {
		return err
	}
	if adminN == 0 {
		hash, err := auth.HashPassword(seedPassword)
		if err != nil {
			return err
		}
		return s.insertUser(DirUser{
			ID: "u-admin", Name: "安全管理员", Account: "admin", Org: "安全运营", OrgKey: "sec",
			Device: "—", IP: "—", Auth: "口令+MFA", LastLogin: "—", Status: "active", Risk: "none",
			Roles: []string{"系统管理员"}, Role: "admin", PassHash: hash,
			PwStrength: auth.PasswordStrength("admin", seedPassword),
		})
	}
	return nil
}

// Ping 探测底层数据库连接健康（供运维自检 /diag 调用）。
func (s *SQLiteStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY, name TEXT, addr TEXT, mode TEXT, category TEXT, node TEXT,
  authed_users INTEGER, status TEXT, created_at TEXT, resource_id TEXT
);
-- 应用分类字典。改造前它是两个包级常量（catLabels/catOrder），管理员改不了也加不了。
-- 内置四类由 backfillAppCategories 建成 builtin=1 的真实行（一次性标记，删了不复活）。
-- apps.category 按值引用 "key"，刻意不建外键：那会让「先建应用再补分类」的历史数据
-- 在迁移期整批插入失败，而引用完整性已由 CreateApp 的字典校验与删除守卫两头守住。
CREATE TABLE IF NOT EXISTS app_categories (
  "key" TEXT PRIMARY KEY, label TEXT NOT NULL, sort INTEGER NOT NULL DEFAULT 0,
  builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT
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
  ip TEXT, auth TEXT, last_login TEXT, online INTEGER, status TEXT, risk TEXT, roles TEXT, created_at TEXT,
  pass_hash TEXT, role TEXT, must_change_pw INTEGER, pw_strength TEXT
);
CREATE TABLE IF NOT EXISTS resources (
  id TEXT PRIMARY KEY, name TEXT, backend TEXT, allow_roles TEXT, allow_users TEXT,
  allow_groups TEXT, allow_orgs TEXT, sensitivity TEXT, addr_ref TEXT, svc_ref TEXT, updated_at TEXT
);
-- ipsec_sites 只放**配置**（管理员权威）。status/rx_bytes/tx_bytes/last_up 四列已冻结：
-- 它们是运行态与配置混表时代的遗物，代码不再读写，运行态一律去 ipsec_sa_state。
-- 留着不删是为了让旧库直接可用（DROP COLUMN 在老 SQLite 上不可用，且没有收益）。
CREATE TABLE IF NOT EXISTS ipsec_sites (
  id TEXT PRIMARY KEY, name TEXT, gateway_id TEXT, enabled INTEGER,
  peer TEXT, local_subnet TEXT, remote_subnet TEXT, local_id TEXT, remote_id TEXT,
  ike_version TEXT, auth TEXT, suite TEXT, phase1 TEXT, phase2 TEXT, pfs INTEGER, pq_hybrid INTEGER,
  psk_version INTEGER,
  peer_nat_port INTEGER,
  status TEXT, rx_bytes INTEGER, tx_bytes INTEGER, last_up TEXT, local_ref TEXT, remote_ref TEXT, updated_at TEXT
);
-- ipsec_secrets 独立成表放 PSK 密文（AES-256-GCM，AAD 绑 site_id）。
-- 物理分表让「某天有人写了 SELECT * 拼站点清单」不可能顺手把密钥带出去——
-- GET /api/v1/ipsec 历史上就漏过一次 requireAdmin，同结构体时那次等于整表泄密钥。
CREATE TABLE IF NOT EXISTS ipsec_secrets (
  site_id TEXT PRIMARY KEY, alg TEXT, nonce BLOB, cipher BLOB,
  fingerprint TEXT, version INTEGER, updated_at TEXT
);
-- ipsec_sa_state 是网关权威的实测运行态，15s 全量覆写；管理员写不进这张表。
-- 主键含 gateway_id：两台网关抢同一条站点时两行并存，界面上看得见，
-- 而不是第二台悄悄覆盖第一台、只剩一条抖动的状态。
CREATE TABLE IF NOT EXISTS ipsec_sa_state (
  site_id TEXT, gateway_id TEXT, state TEXT,
  ike_spi_i TEXT, ike_spi_r TEXT, child_spi_in INTEGER, child_spi_out INTEGER,
  rx_bytes INTEGER, tx_bytes INTEGER, packets_in INTEGER, packets_out INTEGER,
  negotiated TEXT, established_at INTEGER, rekey_at INTEGER, expires_at INTEGER,
  last_error TEXT, last_error_at INTEGER, reported_at INTEGER,
  PRIMARY KEY(site_id, gateway_id)
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
-- auth_policies.one_click 已冻结：对应的「一键上线」从模型删除（要一整套设备绑定的
-- 长效免认证票据，本轮不做），代码不再读写该列。留着不删只为旧库能直接启动。
-- scope_orgs / scope_groups 才是参与匹配的适用范围（scope 一列是文字说明，仅展示）。
CREATE TABLE IF NOT EXISTS auth_policies (
  id TEXT PRIMARY KEY, name TEXT, directory TEXT, is_default INTEGER, scope TEXT, priority INTEGER, enabled INTEGER,
  pc TEXT, mobile TEXT, exempt TEXT, one_click INTEGER, enhance TEXT, authz_apps TEXT, updated_at TEXT,
  scope_orgs TEXT, scope_groups TEXT
);
-- audit_log 带 HMAC-SM3 防篡改链：seq 链内序号（1 起）、mac = HMAC(key, prev_mac‖字段)。
-- 事后 UPDATE 任何一行都会让 GET /api/v1/audit/verify 指出断点。
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, category TEXT, actor TEXT, src_ip TEXT, event TEXT, verdict TEXT,
  seq INTEGER, mac TEXT
);
-- audit_meta 审计子系统的键值元数据。目前只存留存轮转后的链锚点
-- （被清理段末行的 seq/mac），verify 从锚点起算——否则轮转会把链打断。
CREATE TABLE IF NOT EXISTS audit_meta (
  k TEXT PRIMARY KEY, v TEXT
);
CREATE TABLE IF NOT EXISTS baseline_policies (
  id TEXT PRIMARY KEY, name TEXT, type TEXT, scope TEXT, disposal TEXT, status TEXT,
  platforms_json TEXT, checks_json TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS posture_reports (
  user TEXT, device TEXT, platform TEXT, os TEXT, client_version TEXT,
  checks_json TEXT, verdict TEXT, score INTEGER, level TEXT, reasons_json TEXT, ts INTEGER,
  PRIMARY KEY(user, device)
);
-- ── 授信终端（PRD ch9 FR-EP-10/12/13/14/15）──
-- 设备是一等实体：pending|trusted|revoked 状态机 + 敲门令牌签发时的准入判据
-- （api.deviceAdmissionGate）。此前"硬件指纹"只被上报和展示，从来不是任何判据。
--
-- ★UNIQUE(account,fingerprint) 而不是把指纹设成全局主键：同一台机器可能有多个
-- 账号登录（共用工位机），各账号的授信是各自的事——按指纹全局唯一的话，A 的设备
-- 被吊销会连带把 B 挡在门外，而页面上完全看不出这两条记录是同一台机器。
-- 与 posture_reports 的主键 (user, device) 是同一套键，两表按 (账号,指纹) 一一对应。
-- asset_class 资产分类（enterprise|personal|managed）是**准入判据**：personal 受
-- 准入设置里的 personalPolicy 约束（api.deviceAdmissionGate）。tags 是自由标签，
-- **没有任何执行方**，只用于台账筛选/导出/盘点。两列的旧库补列 + 回填见 backfillDeviceAsset。
CREATE TABLE IF NOT EXISTS trusted_devices (
  id TEXT PRIMARY KEY, account TEXT, fingerprint TEXT, name TEXT, platform TEXT,
  status TEXT, first_seen INTEGER, last_seen INTEGER,
  approved_by TEXT, approved_at INTEGER, approval_id TEXT, revoke_reason TEXT,
  asset_class TEXT, tags TEXT,
  UNIQUE(account, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_account ON trusted_devices(account);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_approval ON trusted_devices(approval_id);
-- device_sessions 终端接入会话（FR-POLICY-29 同时在线设备上限 / FR-POLICY-30 接入超时注销）。
--
-- ★与 trusted_devices 分表，理由同 ipsec_sites.status / ipsec_sa_state 那次拆分：
-- 一张表不能同时表达「管理员登记了这台设备」（台账，长期意图）与「它此刻正接入着」
-- （运行态，秒级变化）。混在一起的直接后果是台账页上的授信态随接入状态闪烁。
--
-- last_active 允许为 NULL 且**语义与 0 不同**：NULL = 没有任何网关报过这条会话的
-- 活跃时刻（旧网关 / 还没连上过），0 = 网关报了「自建立起从未有业务连接」。
-- 前者下 FR-POLICY-30 一律不生效（判据缺席不能当确定结论），后者是真的该注销。
CREATE TABLE IF NOT EXISTS device_sessions (
  account TEXT, fingerprint TEXT, platform TEXT, ip TEXT,
  first_seen INTEGER, last_knock INTEGER, last_active INTEGER,
  state TEXT, ended_reason TEXT,
  PRIMARY KEY(account, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_device_sessions_ip ON device_sessions(account, ip);
CREATE TABLE IF NOT EXISTS access_requests (
  id TEXT PRIMARY KEY, usr TEXT, resource_id TEXT, resource_name TEXT, reason TEXT,
  ttl_minutes INTEGER, status TEXT, timeline TEXT, submitted_at TEXT,
  decided_at TEXT, decide_reason TEXT, decided_by TEXT, grant_id TEXT
);
CREATE TABLE IF NOT EXISTS jit_grants (
  id TEXT PRIMARY KEY, usr TEXT, resource_id TEXT, resource_name TEXT, request_id TEXT,
  reason TEXT, granted_by TEXT, granted_at INTEGER, expires_at INTEGER, status TEXT,
  revoked_at INTEGER, revoke_reason TEXT
);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY, user_id TEXT, account TEXT, credential_id TEXT UNIQUE,
  public_key TEXT, sign_count INTEGER DEFAULT 0, transports TEXT, aaguid TEXT,
  name TEXT, created_at TEXT, last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_creds_account ON webauthn_credentials(account);
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id TEXT PRIMARY KEY, account TEXT, challenge TEXT, type TEXT, session_data TEXT,
  expires_at INTEGER, consumed INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_webauthn_chal_value ON webauthn_challenges(challenge, type);
-- 攻击源统计（数据面拒绝事件的机读聚合，wave7 行动 5）。
-- 行 = (网关, 源IP, 拒绝类别, 小时桶)；count 累加网关节流器报来的聚合数。
-- 写入率被网关侧 5min 节流钉死，读取方是安全概览（见 attack.go）。
CREATE TABLE IF NOT EXISTS attack_sources (
  gateway_id TEXT, ip TEXT, cat TEXT, bucket INTEGER, count INTEGER DEFAULT 0, last_at TEXT,
  PRIMARY KEY(gateway_id, ip, cat, bucket)
);
CREATE INDEX IF NOT EXISTS idx_attack_bucket ON attack_sources(bucket);
-- TOTP 二次认证（RFC 6238）。密钥经 secret 盒 AES-256-GCM 加密、AAD 绑账号
-- （"totp:"+account，与 auth_source_secrets 同一条纪律：密文行跨账号剪贴直接
-- 解密失败而不是悄悄生效）。last_counter 是防重放的执行点：记录已成功消费的
-- 最大时间计数器，同一 30 秒步长内的码只能成功一次（截获一次性码重放无效）。
CREATE TABLE IF NOT EXISTS totp_secrets (
  account TEXT PRIMARY KEY, nonce BLOB, cipher BLOB, confirmed INTEGER DEFAULT 0,
  last_counter INTEGER DEFAULT 0, created_at TEXT
);
-- ── 认证源接入 ──
-- 配置与凭据**物理分表**：让「某天有人写了 SELECT *」或忘加 requireAdmin 时，
-- 泄露需要显式写代码，而不是默认发生（与 ipsec_secrets 同一条推理）。
CREATE TABLE IF NOT EXISTS auth_sources (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, enabled INTEGER, priority INTEGER,
  config TEXT, created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS auth_source_secrets (
  source_id TEXT PRIMARY KEY, nonce BLOB, cipher BLOB, fingerprint TEXT, updated_at TEXT
);
-- 外部身份 → 本地用户绑定。主键是 (源, subject) 而**不是** username：
-- 按用户名绑定的话，外部目录里新建一个与本地管理员同名的账号即可冒充，
-- 而审计日志里看起来是一次完全正常的登录。
-- 外部身份准入登记（wave8 行动 10）。与 approvals 的 kind=extuser 单子按 approval_id 关联。
-- ★独立成表而不是往 approvals 里塞：那张表的列是设备形状的（usr/device/fingerprint），
-- 把源名塞进 device、subject 塞进 fingerprint 会让列名说谎。
CREATE TABLE IF NOT EXISTS ext_admissions (
  source_id TEXT, source_name TEXT, subject TEXT, username TEXT, display_name TEXT, email TEXT,
  groups_json TEXT, status TEXT, approval_id TEXT, created_at TEXT,
  decided_at TEXT, decided_by TEXT, reason TEXT,
  PRIMARY KEY(source_id, subject)
);
CREATE INDEX IF NOT EXISTS idx_extadmit_approval ON ext_admissions(approval_id);
CREATE TABLE IF NOT EXISTS auth_source_bindings (
  source_id TEXT, subject TEXT, user_id TEXT, username TEXT, created_at TEXT,
  PRIMARY KEY(source_id, subject)
);
CREATE INDEX IF NOT EXISTS idx_authbind_user ON auth_source_bindings(user_id);
CREATE TABLE IF NOT EXISTS gateway_certs (
  fingerprint TEXT PRIMARY KEY, gateway_id TEXT, issued_at TEXT, not_after TEXT,
  revoked INTEGER DEFAULT 0, revoked_at TEXT, revoke_reason TEXT
);
-- 登录防爆破锁定（FR-MON-17/18）：账号 / 源 IP 两个维度。滑动窗失败计数在内存，
-- 锁定记录落这里——重启不丢锁定；到期行由 ActiveLockouts 读取路径懒清理。
-- 新表无需回填（区别于补列迁移）：既有库此前根本没有锁定这回事。
CREATE TABLE IF NOT EXISTS login_lockouts (
  kind TEXT, key TEXT, until INTEGER, reason TEXT, created_at TEXT,
  PRIMARY KEY(kind, key)
);
-- settings 运行时配置覆盖（键值）。首个消费者：登录防爆破配置
-- （internal/lockout，BAIDI_LOCKOUT_* 环境变量的运行时覆盖）。
CREATE TABLE IF NOT EXISTS settings (
  k TEXT PRIMARY KEY, v TEXT, updated_at TEXT
);
-- ── 组织与用户组（PRD ch6 FR-USER）──
-- org_units 邻接表（parent_id）+ 冗余物化路径 path（形如 /root/dev/）。
-- 冗余 path 不是为了少写一次 JOIN，而是环检测的判据：把父设成自己的后代时，
-- 该父的 path 里必然含 "/<自己的 id>/"，一次包含判断即可拒绝（见 SaveOrgUnit）。
CREATE TABLE IF NOT EXISTS org_units (
  id TEXT PRIMARY KEY, name TEXT, parent_id TEXT, path TEXT, sort INTEGER, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_org_units_parent ON org_units(parent_id);
-- kind 决定成员从哪来：static=显式成员表；role=按 users.roles 派生（只读）。
CREATE TABLE IF NOT EXISTS user_groups (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, description TEXT, created_at TEXT
);
-- 成员按 **account**（规范化小写）存而非 user id：account 是令牌主体，
-- 也是将来「按组授权」在网关侧唯一能对齐的键。
CREATE TABLE IF NOT EXISTS user_group_members (
  group_id TEXT, account TEXT, PRIMARY KEY(group_id, account)
);
CREATE INDEX IF NOT EXISTS idx_group_members_account ON user_group_members(account);
-- ── 管理员分级分权 / 三权分立（PRD ch15.1）──
-- scope_json 存的是**权限键数组**（store.Perm*），api.requirePerm 逐端点比对的就是它；
-- power 只是"这一权叫什么"的预置标签。两者不同源会让页面文案与判定分家，
-- 故内置角色的 scope_json 每次启动按 power 重算覆盖（见 backfillAdminRoles）。
-- ★"key" 加引号：KEY 是 SQLite 关键字。
CREATE TABLE IF NOT EXISTS admin_roles (
  "key" TEXT PRIMARY KEY, name TEXT, power TEXT, builtin INTEGER, scope_json TEXT, created_at TEXT
);
-- ── 业务告警（PRD ch5 FR-MON-21~25）──
-- alert_rules 是「什么算异常」的定义，kind 决定它读哪份真实信号（见 store/alerts.go）。
-- cooldown_sec 独立成列而不塞进 threshold_json：它对所有 kind 都生效，是告警页可用性的
-- 硬约束（网关离线会持续成立，不冷却的话每轮评估刷一条，一小时把页面冲垮）。
CREATE TABLE IF NOT EXISTS alert_rules (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, threshold_json TEXT, enabled INTEGER,
  channels_json TEXT, cooldown_sec INTEGER, created_at TEXT, updated_at TEXT
);
-- alerts 是**待办实体**（区别于 audit_log 那条只追加的流水）：有状态机、有处置人。
-- object_key 是去重键的另一半：只按 rule_id 去重的话，三台网关同时离线只会留下一条，
-- 另外两台在页面上根本不存在。
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, rule_id TEXT, kind TEXT, category TEXT, severity TEXT,
  title TEXT, detail TEXT, object_key TEXT, status TEXT,
  triggered_at INTEGER, handled_at INTEGER, handled_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(rule_id, object_key, triggered_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, triggered_at);
-- ── 消息通道（PRD ch15.2）──
-- 配置与凭据**物理分表**（与 auth_source_secrets / ipsec_secrets 同一条推理）。
-- last_status/last_detail/last_event/last_at 只由**真正发出那一次**写入
-- （store.RecordNotifySend，SaveNotifyChannel 的 upsert 分支刻意不碰这四列）：
-- 让保存动作顺手写一次"成功"，页面就会在邮件根本发不出去时长期显示绿色。
-- ★新表无需回填（区别于补列迁移）：既有库此前根本没有消息通道这回事，
-- 空表就是正确的初态——"一条通道都没配"与"配了但没生效"必须能分开。
CREATE TABLE IF NOT EXISTS notify_channels (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, enabled INTEGER, config TEXT,
  last_status TEXT, last_detail TEXT, last_event TEXT, last_at INTEGER,
  created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS notify_channel_secrets (
  channel_id TEXT PRIMARY KEY, nonce BLOB, cipher BLOB, fingerprint TEXT, updated_at TEXT
);
-- ── 监控中心 · 设备状态时序（PRD ch5 FR-MON-01/02）──
-- 网关宿主机的 CPU/内存/磁盘/负载/收发速率，每网关 15s 一条，由数据面随 mTLS 心跳上报
-- （采集器 gateway/internal/sysstat，落库见 store/metrics_sqlite.go）。
-- 这也是告警规则 gateway_load（「CPU>80%」那一条）的信号源——此前它一直探测不到本表，
-- 如实回「等待数据面上报」。
--
-- 六个指标列全部**可为 NULL**：NULL = 网关如实报告「这一项采不到」（不可判定），与 0 是两回事。
-- 任何一层给它 COALESCE(...,0) 兜底，前端就再也分不出「CPU 0%」和「没采到 CPU」，
-- 而后者恰恰是「CPU>80% 告警对一台失明的网关永久沉默」那种失效。
--
-- 主键 (gateway_id, ts) 顺带把写入速率钉死在「每网关每秒最多一行」（写入走 INSERT OR REPLACE）：
-- 一台发疯或被攻陷的网关靠高频心跳撑爆库这条路直接堵死。
-- ★列名是 gateway_id 而不是 gw_id：一来与 ipsec_sa_state.gateway_id 同名（同一个概念
-- 在两张表里叫两个名字，写 JOIN 的人迟早会挑错），二来告警模块的 GatewayMetricsProbe
-- 读的就是这个列名——对不上的话它会如实回「表结构与读取口径不一致」，
-- 结果就是「CPU>80%」那条规则在页面上开着、永远不触发。
-- ★新表无需回填（区别于补列迁移）：既有库此前根本没有设备指标这回事，空表就是正确初态。
-- 留存上限见 PurgeExpiredGatewayMetrics（BAIDI_METRICS_RETENTION_HOURS，默认 72，不可关闭）。
CREATE TABLE IF NOT EXISTS gateway_metrics (
  gateway_id TEXT, ts INTEGER,
  cpu REAL, mem REAL, disk REAL, load REAL, rx_bps REAL, tx_bps REAL,
  PRIMARY KEY(gateway_id, ts)
);
-- 留存清理是 DELETE ... WHERE ts < ?，趋势查询是 ts 范围扫，两者都吃这条索引
CREATE INDEX IF NOT EXISTS idx_gateway_metrics_ts ON gateway_metrics(ts);

-- 地址转换（PRD 第 18 章）。NAT 是网关的**设备本地**能力，故每条策略必须绑定 gateway_id：
-- 不绑的话一条规则会被所有网关领走，而各网关的网卡名与拓扑根本不同。
CREATE TABLE IF NOT EXISTS nat_policies (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, gateway_id TEXT NOT NULL,
  src_iface TEXT NOT NULL, src_addr TEXT NOT NULL,
  dst_iface TEXT NOT NULL, dst_addr TEXT NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'all',
  dst_port INTEGER NOT NULL DEFAULT 0,
  translated_addr TEXT NOT NULL DEFAULT '', translated_port INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_nat_gateway ON nat_policies(gateway_id);

-- 网关实测上报的网卡清单。if_type（lan/wan）是**管理员**定的，网关无从判断，
-- 故它由 ReplaceGatewayIfaces 在整体替换时按网卡名回填保留。
CREATE TABLE IF NOT EXISTS gateway_ifaces (
  gateway_id TEXT, name TEXT, if_type TEXT, addrs_json TEXT, up INTEGER, updated_at TEXT,
  PRIMARY KEY(gateway_id, name)
);

-- 网关对外接入地址（PRD FR-SCEN-08/17，wave8 行动 4）。**管理员登记**，不是网关自报：
-- 网关无从知道自己在 NAT / 负载均衡后面对外是什么地址（与 gateway_ifaces 的
-- LAN/WAN 定性同一条理由）。两栏都可空；都空即不留行（见 SetGatewayAccess）。
--
-- ★没有这张表之前，剖面里的落点主机名是从网关自报的**监听地址**反推的，而网关默认
-- 监听 ':18201' 不带 host，于是必然落进全局兜底 127.0.0.1——客户端拨号超时，
-- 而控制台显示在线、剖面 warnings 一条不报。
CREATE TABLE IF NOT EXISTS gateway_access (
  gateway_id TEXT PRIMARY KEY, lan_host TEXT, wan_host TEXT, updated_at TEXT
);
-- ── 审计日志外送（PRD ch16 + ch21.6）──
-- 配置与凭据**物理分表**（与 notify_channel_secrets / auth_source_secrets 同一条推理）。
-- last_status/last_detail/last_at/last_ok_at/dropped 只由**真正发出那一次**（或真的丢弃那一次）
-- 写入，SaveAuditForwardTarget 的 upsert 分支刻意不碰它们。
--
-- ★start_audit_id 记的是建立该出口时 audit_log 的最大 id：页面据此如实说明
-- 「历史不会补发」。这不是过滤条件（历史行压根不进队列），是给人看的水位。
CREATE TABLE IF NOT EXISTS audit_forward_targets (
  id TEXT PRIMARY KEY, name TEXT, kind TEXT, enabled INTEGER, config TEXT,
  start_audit_id INTEGER,
  last_status TEXT, last_detail TEXT, last_at INTEGER, last_ok_at INTEGER, dropped INTEGER,
  created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_forward_secrets (
  target_id TEXT PRIMARY KEY, nonce BLOB, cipher BLOB, fingerprint TEXT, updated_at TEXT
);
-- audit_forward_queue 是持久化的待外送队列：审计落库的**同一个事务**里入队，
-- 发送成功才删行，失败留队 + 退避重试（见 store/auditfwd_sqlite.go）。
--
-- ★为什么是独立队列表而不是在 audit_log 上加一列 forwarded：加列必须配一次性回填
-- 把既有行标成已处理，漏了回填就会在**开启外送的那一刻**把 180 天历史整段重发。
-- 独立队列让"不重发历史"结构性成立——历史行从来不进队列，不需要任何回填。
-- ★新表无需回填（区别于补列迁移）：既有库此前根本没有外送这回事，空队列就是正确初态。
--
-- 载荷列（ts/category/actor/src_ip/event/verdict/seq/mac）是审计行的**副本**而不是外键：
-- 队列项要能在审计留存轮转把原行清掉之后仍然发得出去，也免得 pump 每批都去 JOIN。
CREATE TABLE IF NOT EXISTS audit_forward_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT, audit_id INTEGER,
  ts TEXT, category TEXT, actor TEXT, src_ip TEXT, event TEXT, verdict TEXT,
  seq INTEGER, mac TEXT,
  attempts INTEGER, next_at INTEGER, last_error TEXT, created_at TEXT
);
-- pump 的取批查询就是 (target_id, next_at<=now) ORDER BY id，积压计数也吃它
CREATE INDEX IF NOT EXISTS idx_audit_fwd_queue_target ON audit_forward_queue(target_id, next_at, id);

-- ── 控制面温备（warm standby，PRD 15.5 / FR-ARCH-03）──
-- 一行一台备机。node_id 的权威来源是**备机 mTLS 证书的 CN**（standby- 前缀），
-- 不是请求体里自报的名字——自报的话，一台备机可以顶着另一台的名字回报"同步正常"。
--
-- ★两个时间列语义不同，都不能省：
--   last_pull_at —— 主机观测到「它来拉过」，只证明字节发出去了；
--   last_sync_at —— 备机回报「校验通过并落盘」，由主机按**服务端时间**写（不采信客户端时钟）。
--   新鲜度只看后者。拿前者当判据，会把「准时来拉、每次校验都失败」显示成一台健康备机。
-- ★两列都可为 NULL：NULL = 一次都没发生过，与 0（1970 年）不是一回事，也不补 0。
-- ★新表无需回填（区别于补列迁移）：既有库此前没有温备这回事，空表 = "未配置备机"，
--   恰好就是既有部署的真实形态。
CREATE TABLE IF NOT EXISTS standby_nodes (
  node_id TEXT PRIMARY KEY, addr TEXT, interval_sec INTEGER,
  last_pull_at INTEGER, last_sync_at INTEGER,
  backup_version TEXT, backup_created_at TEXT, backup_sha256 TEXT,
  last_status TEXT, last_detail TEXT, updated_at INTEGER
);`)
	if err != nil {
		return err
	}
	// 对象库引用列：旧库表已存在时 CREATE TABLE IF NOT EXISTS 不会补列，逐列幂等 ALTER（忽略已存在）。
	for _, c := range []struct{ table, col, typ string }{
		{"resources", "addr_ref", "TEXT"}, {"resources", "svc_ref", "TEXT"},
		// 授权主体扩展：用户组 / 组织（含子树）。回填见 backfillResourceSubjects。
		{"resources", "allow_groups", "TEXT"},
		{"resources", "allow_orgs", "TEXT"},
		// 资源敏感度（风险降权 disposal=degrade 的唯一判据）。回填见 backfillResourceSensitivity。
		{"resources", "sensitivity", "TEXT"},
		// 七层 Web 代理：内网后端协议（回填见 backfillResourceWebScheme）+ 对外入口基址覆盖。
		// ★web_entry **刻意不回填**：空串就是"用网关默认落点"这个正确语义，
		// 与既有部署行为逐字节一致（同 ipsec_sites.peer_nat_port 那条）。
		// web_scheme 则必须回填——它是拨号参数，留 NULL 会让所有存量 HTTPS 内网应用
		// 在七层路径上被当成 http 去撞，症状是空白页而不是报错。
		{"resources", "web_scheme", "TEXT"},
		{"resources", "web_entry", "TEXT"},
		{"ipsec_sites", "local_ref", "TEXT"}, {"ipsec_sites", "remote_ref", "TEXT"},
		{"users", "pass_hash", "TEXT"}, {"users", "role", "TEXT"},
		// 首登强制改密标志（回填见 backfillMustChangePw）。
		{"users", "must_change_pw", "INTEGER"},
		{"apps", "resource_id", "TEXT"}, // JIT：磁贴 → 受控资源的权威映射列（旧库补列）
		// IPSec 组网：配置面补列。enabled 用 INTEGER 而不是复用 TEXT——
		// 它要参与 `WHERE enabled=1`，存 '1'/'0' 字符串时 SQLite 的类型亲和会
		// 悄悄比出「一条都不匹配」，症状同样是网关拉到空站点列表且零报错。
		{"ipsec_sites", "gateway_id", "TEXT"},
		{"ipsec_sites", "enabled", "INTEGER"},
		{"ipsec_sites", "local_id", "TEXT"},
		{"ipsec_sites", "remote_id", "TEXT"},
		{"ipsec_sites", "psk_version", "INTEGER"},
		// 对端 UDP 封装口。旧库补列后为 NULL，读侧 COALESCE 到 0 即「按对称假设」——
		// 与既有部署（两端都是 4500）的行为完全一致，故这一列不需要回填。
		{"ipsec_sites", "peer_nat_port", "INTEGER"},
		// 凭据指纹。★存指纹而不是在列表里解密：指纹的用途是让管理员核对"两端配的是
		// 不是同一把"，它本身只是个截断哈希、不敏感；而为了显示它去解密明文，
		// 等于在一条人人可读的列表路径上引入解密调用，与"只写不读"的姿态自相矛盾。
		// 旧库补列后为 NULL，界面上显示 •••• ——不影响功能，重设一次凭据即补齐。
		{"auth_source_secrets", "fingerprint", "TEXT"},
		// 审计防篡改链（旧库补列，回填见 backfillAuditChain）。
		{"audit_log", "seq", "INTEGER"},
		{"audit_log", "mac", "TEXT"},
		// 组织归属。★回填见 backfillOrgUnits——它**不在这里调用**而在 seed() 之后
		// （全新库跑 migrate 时 users 表还是空的，放这儿会静默空转）。
		{"users", "org_id", "TEXT"},
		// 口令强度标记（认证策略「弱密码」增强规则的唯一判据）。回填见 backfillPwStrength：
		// 既有行只能是 unknown——库里只有 bcrypt 哈希，明文早已不可得，回填成 strong
		// 等于凭空宣称"这些口令是强的"，弱密码规则会对全部存量账号静默失效。
		{"users", "pw_strength", "TEXT"},
		// 认证策略的真实适用范围（组织含子树 / 用户组）。回填见 backfillAuthPolicyScope。
		{"auth_policies", "scope_orgs", "TEXT"},
		{"auth_policies", "scope_groups", "TEXT"},
		// 管理员角色归属（三权分立）。★回填见 backfillAdminRoles——它**不在这里调用**
		// 而在 seed()/ensureCredentials() 之后（全新库跑 migrate 时 users 还是空表）。
		// 不回填的后果是升级后既有管理员全部无角色 → requirePerm fail-closed 403，
		// 而"给自己分配角色"本身也要管理员权限，等于把所有人锁在门外。
		{"users", "admin_role", "TEXT"},
		// email（wave7 行动 2）：外部认证源带回的邮箱。既有行回填空串 = "未知"
		// （无从推断历史邮箱，猜一个更糟）；本地账号暂无采集入口，恒空是如实的。
		{"users", "email", "TEXT"},
		// 终端资产分类与标签（wave7 行动 15）。★回填见 backfillDeviceAsset：
		// asset_class 必须回填成 enterprise——它是准入判据，留 NULL 的话
		// 「按分类统计/筛选」在 SQL 侧全部落空，而页面照常显示（读侧有兜底），
		// 是本项目最怕的那种两边各说一套。tags 回填 '[]'。
		{"trusted_devices", "asset_class", "TEXT"},
		{"trusted_devices", "tags", "TEXT"},
		// 审批单种类（wave8 行动 10）：device（设备绑定）| extuser（外部身份准入）。
		// ★回填见 backfillApprovalKind：**必须**回填成 device，留 NULL 的话
		// DecideApproval 那道 kind 闸会把既有设备审批单一律拒掉——升级那一刻
		// 所有待批设备都批不了，而报错说的是「这不是设备审批单」。
		{"approvals", "kind", "TEXT"},
		// 安全基线的适用范围（wave8 行动 13-④）：从自由文本 scope 换成结构化的
		// 组织/用户组，并真的接进判定。★回填成 '[]'（= 对全体生效）——那正是
		// 自由文本时代的实际行为（没人读那个字段），所以升级不改变任何人的判定。
		{"baseline_policies", "scope_orgs", "TEXT"},
		{"baseline_policies", "scope_groups", "TEXT"},
	} {
		if e := s.addColumnIfMissing(c.table, c.col, c.typ); e != nil {
			return e
		}
	}
	if err := s.backfillAppResourceID(); err != nil {
		return err
	}
	if err := s.backfillApprovalKind(); err != nil {
		return err
	}
	if err := s.backfillBaselineScope(); err != nil {
		return err
	}
	// ★两条回填并列挂在这里不是排版偏好：补列迁移只加列不填值，是本项目
	// 已经踩过一次的坑（apps.resource_id）。凡是新增**业务语义列**，
	// 回填必须与 ALTER 同一处出现，否则下一个加列的人不会想到还有这一步。
	if err := s.backfillIpsecEnabled(); err != nil {
		return err
	}
	if err := s.backfillResourceSubjects(); err != nil {
		return err
	}
	// ★必须排在 backfillAppResourceID 之后：它按「应用 category=finance → 该应用关联的资源」
	// 认定高敏，而那条关联正是 apps.resource_id。顺序反了的话既有库里刚被补上的桥接还没生效，
	// 全部资源会被回填成 normal——降权于是对财务系统静默失效。
	if err := s.backfillResourceSensitivity(); err != nil {
		return err
	}
	if err := s.backfillResourceWebScheme(); err != nil {
		return err
	}
	if err := s.backfillMustChangePw(); err != nil {
		return err
	}
	if err := s.backfillUserEmail(); err != nil {
		return err
	}
	if err := s.backfillAuditChain(); err != nil {
		return err
	}
	if err := s.backfillPwStrength(); err != nil {
		return err
	}
	if err := s.backfillAuthPolicyScope(); err != nil {
		return err
	}
	// 授信终端：用既有 posture_reports 回填设备台账。★不做这一步的后果不是"页面少点数据"，
	// 而是切到 strict 准入的那一刻全体存量终端被判未登记、集体拒发敲门令牌。
	// 放在 migrate 里安全的理由见 backfillTrustedDevices 顶部（posture_reports 从不播种）。
	if err := s.backfillTrustedDevices(); err != nil {
		return err
	}
	// 资产分类/标签回填。★必须排在 backfillTrustedDevices **之后**：那一步会用
	// posture_reports 现造设备行，顺序反了的话它造出来的行赶不上这次回填，
	// 而回填有一次性标记、下次启动不再跑——那批设备的 asset_class 会永久为 NULL。
	if err := s.backfillDeviceAsset(); err != nil {
		return err
	}
	// 一次性把 client_version 检测项的 label/expect 改准（wave8 行动 2）。
	// 改种子只影响全新库；既有部署那一行是首启落的，不回填就永远写着「客户端为最新版本 / ≥ v0.1.0」。
	if err := s.backfillClientVersionCheckLabel(); err != nil {
		return err
	}
	if err := s.ensureAccountUnique(); err != nil {
		return err
	}
	// 告警规则播种（一次性标记，见 alertRuleSeedMarker）。放 migrate 里是安全的：
	// 它**不读任何业务表**，只按 alertKindSpecs 建规则——与 backfillOrgUnits 那种
	// 「要按 users 现有行回填、必须排在 seed 之后」的回填不是一回事。
	if err := s.seedAlertRules(context.Background()); err != nil {
		return err
	}
	return s.seedLocalAuthSource()
}

// ensureAccountUnique 给 users.account 建规范化唯一索引。
//
// ★account 不只是显示名，它是**令牌主体**（JWT Sub）与 JIT 授予 / 强制下线 /
// posture 判定的键。两行同 account 意味着两个真实身份在授权层面合并成一个：
// 后来者直接继承前者的全部授权，而审计日志看起来完全正常。
// BindExternalUser 里的循环消歧是第一道闸，这条索引是并发下的最终防线
// （两个事务同时查重都判"不撞"时，靠它让后到的那次失败而不是静默共号）。
//
// 索引建在 lower(trim(account)) 上，与所有查账号的 SQL 口径一致——
// 建在裸列上会让 "Alice" 与 "alice" 被认成两个账号，而登录时它们是同一个。
// 既有库若已存在重复（本轮之前的实现有可能留下），CREATE UNIQUE INDEX 会失败：
// 此时只记警告不阻断启动——控制面起不来的代价远大于这条索引晚一步建立，
// 而重复账号需要人来判断该保留哪个，不能由迁移代劳。
func (s *SQLiteStore) ensureAccountUnique() error {
	_, err := s.db.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_norm ON users(lower(trim(account)))`)
	if err != nil {
		slog.Warn("users.account 唯一索引建立失败，库中可能已有重复账号（两个身份共用一个令牌主体，请人工核对后清理）",
			"err", err.Error())
	}
	return nil
}

// backfillAppResourceID 回填 apps.resource_id。
//
// ★补列迁移只加列、不回填，于是任何在该列出现**之前**建好的库，其种子应用的
// resource_id 永久为 NULL。而这一列是「应用磁贴 → 受控资源」的唯一桥接：为空时
//   - JIT 自助申请解析不出目标资源；
//   - 客户端接入剖面排不出路由，应用点开不走隧道。
//
// 两处都是静默失效（没有报错，只是"什么都没发生"），排障时极难指向这里。
//
// 只回填仍为空的行，且只按内置种子的 id 对应关系补——管理员后来手工改过的值一律不动。
func (s *SQLiteStore) backfillAppResourceID() error {
	seed, err := s.Memory.Apps(context.Background())
	if err != nil {
		return err
	}
	for _, a := range seed.Apps {
		if a.ResourceID == "" {
			continue
		}
		if _, err := s.db.Exec(
			`UPDATE apps SET resource_id=? WHERE id=? AND COALESCE(resource_id,'')=''`,
			a.ResourceID, a.ID); err != nil {
			return err
		}
	}
	return nil
}

// backfillResourceSubjects 回填 resources.allow_groups / allow_orgs：既有行一律补空数组。
//
// ★补列迁移只加列不填值，既有库的新列永久为 NULL——这是 apps.resource_id 踩过的坑。
// 这两列的语义是「按哪些用户组/组织授权」，空数组 = 不按该维度授权 = 与改造前行为
// 逐字节一致（判定退回只看 allow_roles/allow_users）。写成 '[]' 而不是留 NULL，
// 是为了让「这一行已经在新语义下了」这件事在库里看得见，也让读侧的 COALESCE
// 只承担兜底职责而不是唯一防线。
func (s *SQLiteStore) backfillResourceSubjects() error {
	if _, err := s.db.Exec(`UPDATE resources SET allow_groups='[]' WHERE allow_groups IS NULL`); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE resources SET allow_orgs='[]' WHERE allow_orgs IS NULL`)
	return err
}

// backfillResourceSensitivity 回填 resources.sensitivity。
//
// 两步，缺一不可：
//  1. 既有行一律补 normal —— 留 NULL 的话读侧只能靠 COALESCE 兜底，而"这一行到底评估过没有"
//     在库里看不出来；也让 `WHERE sensitivity='high'` 这类查询有确定语义。
//  2. **把改造前唯一的高敏来源迁进来**：`apps.category='finance'` 曾是全库判定高敏的唯一依据
//     （门户磁贴的"需申请"、剖面 app.sensitivity 都由它派生）。不迁的话，升级后财务系统
//     从"高敏"变成"普通"，降权对它不再生效、门户磁贴也从"需申请"变回"直接可点"——
//     这是一次**安全性下降**，且没有任何报错，纯靠对比升级前后的页面才看得出来。
//
// 只动仍为空的行：管理员后来手工评估过的值一律不覆盖（与 backfillAppResourceID 同纪律）。
//
// ★下面那句 `category='finance'` 是**业务语义**而不是分类字典的用法，分类改成可编辑
// 之后它仍然留着，理由与边界都在这里说清楚：
//   - 它是一次性的**历史语义迁移**（sensBackfillMarker 守着，只跑一次），迁的是
//     「改造前 finance 这个分类就等于高敏」这条已经作古的规则；
//   - 迁完之后高敏的唯一判据是 resources.sensitivity，与分类**再无关系**——所以
//     管理员现在把 finance 改名、甚至（在没有应用挂着时）连内置分类一起换掉，
//     都不会静默关掉降权；
//   - 反过来，若哪天有人想按「分类=某某」重新派生敏感度，那就是把这条耦合复活，
//     而分类此刻已是管理员可改的自由数据——那等于把一条安全判据交给一个可编辑的
//     显示字段。别这么做。
func (s *SQLiteStore) backfillResourceSensitivity() error {
	if _, err := s.db.Exec(
		`UPDATE resources SET sensitivity=? WHERE COALESCE(sensitivity,'')=''`, SensitivityNormal); err != nil {
		return err
	}
	// 第 2 步**只跑一次**（sensBackfillMarker）。不加这道闸的话，管理员把财务资源重新评估成
	// normal/low 之后，下次进程重启迁移又会把它抬回 high——"改了、重启就变回去"是最难自证的
	// 一类缺陷：管理员看到的是自己的操作没保存，而日志里保存明明成功了。
	ctx := context.Background()
	if _, done, err := s.Setting(ctx, sensBackfillMarker); err != nil || done {
		return err
	}
	if _, err := s.db.Exec(`UPDATE resources SET sensitivity=? WHERE sensitivity=? AND id IN (
  SELECT resource_id FROM apps WHERE category='finance' AND COALESCE(resource_id,'')<>''
)`, SensitivityHigh, SensitivityNormal); err != nil {
		return err
	}
	return s.SetSetting(ctx, sensBackfillMarker, nowStr())
}

// sensBackfillMarker settings 表里的一次性标记：finance→high 的语义迁移只做一次。
const sensBackfillMarker = "resource.sensitivity.backfill.v1"

// backfillResourceWebScheme 回填 resources.web_scheme（七层代理拨后端用的协议）。
//
// ★不带一次性标记，而是靠 `WHERE COALESCE(web_scheme,”)=”` 收敛：这一条回填
// **永远不覆盖已有值**，所以重复执行是幂等的，也不会出现「管理员改成 http、
// 重启又变回 https」那种最难自证的形态（那正是 sensBackfillMarker 存在的理由——
// 那一条会覆盖既有值，这一条不会）。
//
// 推导规则不在 SQL 里写第二遍：逐行取出 backend 交给 store.NormalizeWebScheme，
// 与保存落库、读侧兜底共用同一个函数。存量库里资源行是几十条量级，逐行更新的
// 代价可以忽略，换来的是"猜协议"这件事全库只有一处定义。
func (s *SQLiteStore) backfillResourceWebScheme() error {
	rows, err := s.db.Query(`SELECT id,COALESCE(backend,'') FROM resources WHERE COALESCE(web_scheme,'')=''`)
	if err != nil {
		return err
	}
	type row struct{ id, backend string }
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.backend); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range pending {
		if _, err := s.db.Exec(`UPDATE resources SET web_scheme=? WHERE id=?`,
			NormalizeWebScheme("", r.backend), r.id); err != nil {
			return err
		}
	}
	return nil
}

// backfillUserEmail 回填 users.email：补列后 NULL → 空串（语义"未知"）。
// 历史行的邮箱无从推断；外部账号下次登录会由认证源刷上真值。
func (s *SQLiteStore) backfillUserEmail() error {
	_, err := s.db.Exec(`UPDATE users SET email='' WHERE email IS NULL`)
	return err
}

// backfillMustChangePw 回填 users.must_change_pw：既有行一律补 0。
//
// ★回填成 0 而不是 1 是明确决策：101.43.125.131 在线演示站靠 admin/baidi@123
// 走通全部演示流程，把存量种子账号统统逼进改密页得不偿失。生产部署首启前置
// BAIDI_SEED_MUST_CHANGE=1（见 seed 与 deploy/config.env.example），种子账号
// 建库时即置 1——那条路径不经过这里。
func (s *SQLiteStore) backfillMustChangePw() error {
	_, err := s.db.Exec(`UPDATE users SET must_change_pw=0 WHERE must_change_pw IS NULL`)
	return err
}

// backfillPwStrength 回填 users.pw_strength：既有行一律补 unknown（不是 strong，也不是 weak）。
//
// ★这是本项目「补列必须配回填」这条规矩里语义最要紧的一次：
//   - 补成 strong → 「弱密码要求二次认证」对全部存量账号静默失效，页面上策略是开的；
//   - 补成 weak   → 全体存量账号登录都被抬到二次认证，且没人说得清凭什么；
//   - 补成 unknown → 如实表达「这条口令是在强度判定存在之前设的，判不了」。
//
// unknown 不命中弱密码规则（不可判定 ≠ 不合规，与 posture 三态同口径），
// 用户改一次口令即由 SetUserPassword 补齐真实判定。
func (s *SQLiteStore) backfillPwStrength() error {
	_, err := s.db.Exec(`UPDATE users SET pw_strength=? WHERE pw_strength IS NULL OR pw_strength=''`, auth.PwUnknown)
	return err
}

// backfillAuthPolicyScope 回填 auth_policies 的两列适用范围为空数组，
// 并**清掉既有行上两个已冻结的开关**（enhance.geoAnomaly / exempt.winDomain）。
//
// ★清开关这一步不是洁癖：这两条规则白帝判不了（没有 IP 地理库、没有域校验能力），
// 保存接口从此拒绝开启、控制台置灰。若不同步清掉库里已经为 true 的行，
// 界面上就会永久留着两个"打开了但永远不会生效"的勾——正是本轮要消灭的形态。
// 用 SQLite 的 json_set 原地改，避免把整列反序列化再写回（那会顺手覆盖掉未知字段）。
func (s *SQLiteStore) backfillAuthPolicyScope() error {
	if _, err := s.db.Exec(`UPDATE auth_policies SET scope_orgs='[]' WHERE scope_orgs IS NULL`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE auth_policies SET scope_groups='[]' WHERE scope_groups IS NULL`); err != nil {
		return err
	}
	if _, err := s.db.Exec(
		`UPDATE auth_policies SET enhance=json_set(enhance,'$.geoAnomaly',json('false'))
		 WHERE json_valid(enhance) AND json_extract(enhance,'$.geoAnomaly')=1`); err != nil {
		return err
	}
	if _, err := s.db.Exec(
		`UPDATE auth_policies SET exempt=json_set(exempt,'$.winDomain',json('false'))
		 WHERE json_valid(exempt) AND json_extract(exempt,'$.winDomain')=1`); err != nil {
		return err
	}
	return s.cleanFrozenSecondaryMethods()
}

// cleanFrozenSecondaryMethods 从既有策略的 pc/mobile 二次认证列表里剔除未实现的
// 方式（保存接口已拒绝、控制台已置灰，见 authpolicy.SecondaryMethods）。
// 不清的话，页面上永久留着「短信」这类打开了但永远不会生效的勾——与
// geoAnomaly/winDomain 同一条清理纪律。只 json_set 覆盖 $.secondary 一个路径，
// 不整列反序列化重写（避免覆盖未知字段）。幂等：清过的行不再命中过滤条件。
func (s *SQLiteStore) cleanFrozenSecondaryMethods() error {
	// 可用集与 authpolicy.SecondaryMethods 同步维护（store 不能反向 import authpolicy）。
	available := map[string]bool{"totp": true}
	rows, err := s.db.Query(`SELECT id, pc, mobile FROM auth_policies`)
	if err != nil {
		return err
	}
	type patch struct{ id, col, val string }
	var patches []patch
	for rows.Next() {
		var id string
		var pc, mobile sql.NullString
		if err := rows.Scan(&id, &pc, &mobile); err != nil {
			rows.Close()
			return err
		}
		for _, c := range []struct{ col, raw string }{{"pc", pc.String}, {"mobile", mobile.String}} {
			if c.raw == "" {
				continue
			}
			var ms struct {
				Secondary []string `json:"secondary"`
			}
			if json.Unmarshal([]byte(c.raw), &ms) != nil {
				continue
			}
			kept := make([]string, 0, len(ms.Secondary))
			for _, m := range ms.Secondary {
				if available[m] {
					kept = append(kept, m)
				}
			}
			if len(kept) == len(ms.Secondary) {
				continue
			}
			b, _ := json.Marshal(kept)
			patches = append(patches, patch{id, c.col, string(b)})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, p := range patches {
		if _, err := s.db.Exec(
			`UPDATE auth_policies SET `+p.col+`=json_set(`+p.col+`,'$.secondary',json(?)) WHERE id=?`,
			p.val, p.id); err != nil {
			return err
		}
	}
	return nil
}

// addColumnIfMissing 幂等地为表补一列；列已存在（duplicate column name）视为成功。
//
// ★不带 DEFAULT 是有意的：新列在既有行上就是 NULL，而 NULL 正是「这一行还没被
// 回填过」的标记，回填语句据此写 `WHERE <col> IS NULL`（幂等、且不会覆盖管理员
// 后来手工改过的值）。给了 DEFAULT 就再也分不清「默认值」与「已回填成默认值」。
func (s *SQLiteStore) addColumnIfMissing(table, col, typ string) error {
	_, err := s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + typ)
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
			if _, err := s.db.Exec(`INSERT INTO apps(id,name,addr,mode,category,node,authed_users,status,created_at,resource_id) VALUES(?,?,?,?,?,?,?,?,?,?)`,
				a.ID, a.Name, a.Addr, a.Mode, a.Category, a.Node, a.AuthedUsers, a.Status, nowStr(), a.ResourceID); err != nil {
				return err
			}
		}
	}
	// ★不播种设备绑定审批：审批单现在是设备生命周期的一环（approvals.id ↔
	// trusted_devices.approval_id）。播一批与任何真实设备都对不上的申请，点「通过」
	// 只会得到一个成功 toast 而没有任何设备被置为授信——正是"页面看起来在工作"的那类假象。
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		b, _ := s.Memory.Users(ctx)
		hash, herr := auth.HashPassword(seedPassword) // demo 口令 baidi@123 的真实 bcrypt 哈希（复用同一哈希）
		if herr != nil {
			return herr
		}
		// BAIDI_SEED_MUST_CHANGE=1：生产部署首启时把种子账号（含 admin）都置首登改密——
		// 种子口令 baidi@123 是公开的，生产不该允许它长期可用。仅首次建库时生效
		// （users 表非空不再进这个分支）；演示站不置，保住 admin/baidi@123 的演示流程。
		seedMustChange := os.Getenv("BAIDI_SEED_MUST_CHANGE") == "1"
		// 种子口令的强度**如实判定**（baidi@123 就是弱口令，不到 10 位且在常见弱口令表里）。
		// 这里是全流程中少数明文可得的地方，谎报成 strong 就等于让「弱密码」规则从首启起失灵。
		seedStrength := auth.PasswordStrength("", seedPassword)
		for _, u := range b.Users {
			u.PassHash = hash
			u.Role = roleFromDisplay(u.Roles)
			u.MustChangePw = seedMustChange
			u.PwStrength = seedStrength
			if err := s.insertUser(u); err != nil {
				return err
			}
		}
		// 管理员账号纳入统一用户体系（role=admin），登录走真实哈希校验而非硬编码
		if err := s.insertUser(DirUser{
			ID: "u-admin", Name: "安全管理员", Account: "admin", Org: "安全运营", OrgKey: "sec",
			Device: "—", IP: "—", Auth: "口令+MFA", LastLogin: "—", Status: "active", Risk: "none",
			Roles: []string{"系统管理员"}, Role: "admin", PassHash: hash, MustChangePw: seedMustChange,
			PwStrength: seedStrength,
		}); err != nil {
			return err
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
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM baseline_policies`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		bls, _ := s.Memory.Baselines(ctx)
		for _, b := range bls {
			if err := s.upsertBaseline(ctx, b); err != nil {
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
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,backend,allow_roles,allow_users,
COALESCE(allow_groups,''),COALESCE(allow_orgs,''),COALESCE(sensitivity,''),
COALESCE(web_scheme,''),COALESCE(web_entry,''),COALESCE(addr_ref,''),COALESCE(svc_ref,'') FROM resources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Resource{}
	for rows.Next() {
		var r Resource
		var roles, users, groups, orgs string
		if err := rows.Scan(&r.ID, &r.Name, &r.Backend, &roles, &users, &groups, &orgs, &r.Sensitivity,
			&r.WebScheme, &r.WebEntry, &r.AddrRef, &r.SvcRef); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(roles), &r.AllowRoles)
		_ = json.Unmarshal([]byte(users), &r.AllowUsers)
		_ = json.Unmarshal([]byte(groups), &r.AllowGroups)
		_ = json.Unmarshal([]byte(orgs), &r.AllowOrgs)
		// 回填保证库里不该有空值，这里仍收敛一次：读侧永远拿到三档之一，
		// 免得每个消费方各自判空（判漏一处就是"未标注的资源被当成高敏/低敏"）。
		r.Sensitivity = NormalizeSensitivity(r.Sensitivity)
		r.WebScheme = NormalizeWebScheme(r.WebScheme, r.Backend)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveResource 落库（upsert）一条受控资源。
func (s *SQLiteStore) SaveResource(ctx context.Context, r Resource) error {
	roles, _ := json.Marshal(nonNil(r.AllowRoles))
	users, _ := json.Marshal(nonNil(r.AllowUsers))
	groups, _ := json.Marshal(nonNil(r.AllowGroups))
	orgs, _ := json.Marshal(nonNil(r.AllowOrgs))
	_, err := s.db.ExecContext(ctx, `INSERT INTO resources(id,name,backend,allow_roles,allow_users,allow_groups,allow_orgs,sensitivity,web_scheme,web_entry,addr_ref,svc_ref,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, backend=excluded.backend,
  allow_roles=excluded.allow_roles, allow_users=excluded.allow_users,
  allow_groups=excluded.allow_groups, allow_orgs=excluded.allow_orgs,
  sensitivity=excluded.sensitivity,
  web_scheme=excluded.web_scheme, web_entry=excluded.web_entry,
  addr_ref=excluded.addr_ref, svc_ref=excluded.svc_ref, updated_at=excluded.updated_at`,
		r.ID, r.Name, r.Backend, string(roles), string(users), string(groups), string(orgs),
		NormalizeSensitivity(r.Sensitivity), NormalizeWebScheme(r.WebScheme, r.Backend),
		strings.TrimSpace(r.WebEntry), r.AddrRef, r.SvcRef, nowStr())
	return err
}

// nonNil 让 nil 切片序列化成 "[]" 而不是 "null"——库里那一列的口径与回填后的
// 既有行保持一致（都是 '[]'），少一种要在读侧特判的形态。
func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// DeleteResource 删除一条受控资源。
func (s *SQLiteStore) DeleteResource(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM resources WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) insertUser(u DirUser) error {
	roles, _ := json.Marshal(u.Roles)
	// PwStrength 空 = 建号方没有判过强度（只可能是没走 API 的历史路径），如实落 unknown。
	if u.PwStrength == "" {
		u.PwStrength = auth.PwUnknown
	}
	_, err := s.db.Exec(`INSERT INTO users(id,name,account,org,org_key,device,ip,auth,last_login,online,status,risk,roles,created_at,pass_hash,role,must_change_pw,org_id,pw_strength,admin_role,email)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Name, u.Account, u.Org, u.OrgKey, u.Device, u.IP, u.Auth, u.LastLogin, b2i(u.Online), u.Status, u.Risk, string(roles), nowStr(), u.PassHash, u.Role, b2i(u.MustChangePw), u.OrgID, u.PwStrength, u.AdminRole, u.Email)
	return err
}

// roleFromDisplay 从展示角色推断权威鉴权角色：含"管理员"→admin，否则 user。
func roleFromDisplay(roles []string) string {
	for _, r := range roles {
		if strings.Contains(r, "管理员") {
			return "admin"
		}
	}
	return "user"
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Users 访问者目录页：身份源 + 组织树 + 用户组 + 用户清单，**四段全部来自库**。
//
// ★不再以 s.Memory.Users(ctx) 打底：那种"打底再局部覆盖"的写法让 Directories
// 一字未改地继承了种子的「本地目录 124 / 总部 AD 域 1160」，而同一个响应里的
// 用户清单是真实的 8 行——同一张页面上两个数字，一个真一个假，看不出区别。
// 现在整个 bundle 逐字段构造，缺哪段就是编译错误，不会再有字段"悄悄躺着"。
// 同类残留的防扩散守卫见 memory_fallback_guard_test.go。
//
// ★展示用的 org / org_key 两列是组织表出现之前的遗物。org_id 一旦有值就以
// org_units 为准覆盖它们——否则改了部门名，用户列表里还挂着旧名字，
// 而两个数字都"看起来是真的"。org_key 同步成 org_id，让前端按组织过滤
// 与组织树的节点 key 天然对齐。
func (s *SQLiteStore) Users(ctx context.Context) (UserDirBundle, error) {
	var b UserDirBundle
	dirs, err := s.userDirectories(ctx)
	if err != nil {
		return UserDirBundle{}, err
	}
	b.Directories = dirs
	orgs, err := s.OrgUnits(ctx)
	if err != nil {
		return UserDirBundle{}, err
	}
	b.OrgTree = buildOrgTree(orgs)
	groups, err := s.UserGroups(ctx)
	if err != nil {
		return UserDirBundle{}, err
	}
	b.Groups = groups
	memberships, err := s.GroupMemberships(ctx)
	if err != nil {
		return UserDirBundle{}, err
	}
	// ★u.role（权威鉴权角色 admin|user）必须选出来：DirUser.Role 此前恒为空串，
	// 而"目标账号是不是管理员"正是 api.guardAdminTarget 的判据——读不到就等于
	// 把所有管理员都当成普通用户，那道闸会静默失效（不报错、不留痕）。
	rows, err := s.db.QueryContext(ctx, `
SELECT u.id,u.name,u.account,u.org,u.org_key,u.device,u.ip,u.auth,u.last_login,u.online,u.status,u.risk,u.roles,
       COALESCE(u.org_id,''), COALESCE(o.name,''), COALESCE(u.role,'user'), COALESCE(u.email,'')
FROM users u LEFT JOIN org_units o ON o.id = u.org_id ORDER BY u.created_at`)
	if err != nil {
		return UserDirBundle{}, err
	}
	defer rows.Close()
	us := []DirUser{}
	for rows.Next() {
		var u DirUser
		var online int
		var roles, orgName string
		if err := rows.Scan(&u.ID, &u.Name, &u.Account, &u.Org, &u.OrgKey, &u.Device, &u.IP, &u.Auth, &u.LastLogin,
			&online, &u.Status, &u.Risk, &roles, &u.OrgID, &orgName, &u.Role, &u.Email); err != nil {
			return UserDirBundle{}, err
		}
		u.Online = online == 1
		_ = json.Unmarshal([]byte(roles), &u.Roles)
		if u.OrgID != "" && orgName != "" {
			u.Org, u.OrgKey = orgName, u.OrgID
		}
		u.GroupIDs = memberships[strings.ToLower(strings.TrimSpace(u.Account))]
		if u.GroupIDs == nil {
			u.GroupIDs = []string{}
		}
		us = append(us, u)
	}
	if err := rows.Err(); err != nil {
		return UserDirBundle{}, err
	}
	b.Users = us
	return b, nil
}

// CreateUser 新增用户落库（含组织归属与 static 组成员）。
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
	if u.Role == "" {
		u.Role = roleFromDisplay(u.Roles)
	}
	// 组织归属：id 必须真实存在，同时把展示用的 org/org_key 对齐到组织表，
	// 否则新用户的列表行会显示调用方随手传来的部门名。
	if u.OrgID = strings.TrimSpace(u.OrgID); u.OrgID != "" {
		var name string
		switch err := s.db.QueryRowContext(ctx, `SELECT name FROM org_units WHERE id=?`, u.OrgID).Scan(&name); err {
		case nil:
			u.Org, u.OrgKey = name, u.OrgID
		case sql.ErrNoRows:
			return DirUser{}, ErrOrgNotFound
		default:
			return DirUser{}, err
		}
	}
	if err := s.insertUser(u); err != nil {
		return DirUser{}, err
	}
	if len(u.GroupIDs) > 0 {
		if err := s.SetUserGroups(ctx, u.Account, u.GroupIDs); err != nil {
			return DirUser{}, err
		}
	}
	if u.GroupIDs == nil {
		u.GroupIDs = []string{}
	}
	return u, nil
}

// Credential 按账号（规范化匹配）取登录凭据（含口令哈希）。not found → ok=false 无错。
func (s *SQLiteStore) Credential(ctx context.Context, account string) (Credential, bool, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,account,COALESCE(role,''),status,COALESCE(pass_hash,''),COALESCE(must_change_pw,0),
  COALESCE(NULLIF(pw_strength,''),?) FROM users WHERE lower(trim(account))=? LIMIT 1`, auth.PwUnknown, key)
	var c Credential
	var mustChange int
	switch err := row.Scan(&c.ID, &c.Name, &c.Account, &c.Role, &c.Status, &c.PassHash, &mustChange, &c.PwStrength); err {
	case nil:
		c.MustChangePw = mustChange == 1
		if c.Role == "" {
			c.Role = "user"
		}
		return c, true, nil
	case sql.ErrNoRows:
		return Credential{}, false, nil
	default:
		return Credential{}, false, err
	}
}

// SetUserPassword 落库某用户的口令哈希（bcrypt）、首登改密标志与**口令强度标记**。
// 管理员重置传 mustChange=true（初始口令必须被本人换掉），自助改密传 false（清标志）。
// 三者同语句原子更新——分几条写，中间挤进一次登录就会拿到彼此不一致的判定材料。
//
// ★strength 必须在这里落：登录链路只有 bcrypt 哈希，判不出强度（见 auth/strength.go）。
// 调用方传 auth.PasswordStrength(account, 明文) 的结果；传空视为 unknown（不命中弱密码规则）。
func (s *SQLiteStore) SetUserPassword(ctx context.Context, id, hash string, mustChange bool, strength string) error {
	if strength == "" {
		strength = auth.PwUnknown
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET pass_hash=?, must_change_pw=?, pw_strength=? WHERE id=?`,
		hash, b2i(mustChange), strength, id)
	return err
}

// SetUserStatus 改用户状态（禁用/启用/解锁）落库。
// SetUserStatus 改账号状态。
//
// 防自锁：禁用/锁定最后一名可登录的超管一律拒绝（ErrLastRootAdmin）。「把最后一个 root
// 禁用」与「把他降权」是同一种自锁，只是走了另一个端点——只堵改派那条路等于没堵。
func (s *SQLiteStore) SetUserStatus(ctx context.Context, id, status string) error {
	if status == "disabled" || status == "locked" {
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
			return nil // 目标不存在：与既有行为一致（UPDATE 影响 0 行也不报错）
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
		if _, err := tx.ExecContext(ctx, `UPDATE users SET status=? WHERE id=?`, status, id); err != nil {
			return err
		}
		return tx.Commit()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET status=? WHERE id=?`, status, id)
	return err
}

func nowStr() string { return time.Now().Format("2006-01-02 15:04:05") }

// Apps 覆盖：从库读取应用 + 动态聚合分类计数。
//
// ★分类栏由 app_categories 表构建。此前它来自两个包级常量（catLabels/catOrder），
// 那两个常量已删除：分类既然能在页面上增删改，再留一份编译进二进制的清单，
// 就是第二个真相来源（管理员改完库，筛选条仍按常量显示与排序）。
func (s *SQLiteStore) Apps(ctx context.Context) (AppBundle, error) {
	// ★不选 authed_users：那一列已废弃（种子写死的 860/64/210/1284，全库无 UPDATE）。
	// 授权面在下面按关联资源的真实 ACL 现算，见 App.AuthedUsers 的注释。
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,addr,mode,category,node,status,COALESCE(resource_id,'') FROM apps ORDER BY created_at`)
	if err != nil {
		return AppBundle{}, err
	}
	defer rows.Close()
	var apps []App
	counts := map[string]int{}
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.Name, &a.Addr, &a.Mode, &a.Category, &a.Node, &a.Status, &a.ResourceID); err != nil {
			return AppBundle{}, err
		}
		apps = append(apps, a)
		counts[a.Category]++
	}
	if err := rows.Err(); err != nil {
		return AppBundle{}, err
	}
	if err := s.fillAppAuth(ctx, apps); err != nil {
		return AppBundle{}, err
	}
	defs, err := s.AppCategories(ctx)
	if err != nil {
		return AppBundle{}, err
	}
	cats := []AppCategory{{Key: AppCategoryAllKey, Label: AppCategoryAllLabel, Count: len(apps)}}
	for _, d := range defs {
		// 计数用**上面这批刚读到的应用**现算，而不是 defs 里那份子查询结果：
		// 筛选条上的数字与表格里的行数必须出自同一次读取，否则并发写入时两者会对不上，
		// 而那种不一致在页面上看起来像是筛选坏了。
		cats = append(cats, AppCategory{Key: d.Key, Label: d.Label, Count: counts[d.Key]})
	}
	return AppBundle{Categories: cats, Apps: apps}, nil
}

// CreateApp 落库新发布的应用。
//
// ★分类必须是字典里真实存在的一行。不校验的后果是静默的：一个拼错（或已被删掉）的
// category 会让这个应用在分类筛选条的任何一栏都不出现——只有「全部应用」看得到——
// 而接口照回 201，管理员以为发布成功了。
//
// ★校验与 INSERT 必须在**同一个事务**里（DSN 带 _txlock=immediate，起手即取写锁）。
// 分两次自动提交的话，DeleteAppCategory 的那道「分类下还有应用就拒删」守卫挡不住
// 这中间的缝：管理员 A 校验通过（此刻分类还在）→ 管理员 B 把这个空分类删掉（此刻确实
// 一个应用都没挂着，守卫如实放行）→ 管理员 A 的 INSERT 落地。结果正是这套功能本来
// 要消灭的那种孤儿应用，且 apps 表没有改分类的入口，此后没有任何办法把它救回来。
func (s *SQLiteStore) CreateApp(ctx context.Context, a App) (App, error) {
	a.Category = strings.TrimSpace(a.Category)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return App{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM app_categories WHERE "key"=?`, a.Category).Scan(&n); err != nil {
		return App{}, err
	}
	if n == 0 {
		return App{}, ErrUnknownAppCategory
	}
	a.ID = "app-" + uuid.NewString()[:8]
	if a.Status == "" {
		a.Status = "running"
	}
	if a.Node == "" {
		a.Node = "华东出口"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO apps(id,name,addr,mode,category,node,authed_users,status,created_at,resource_id) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.Addr, a.Mode, a.Category, a.Node, a.AuthedUsers, a.Status, nowStr(), a.ResourceID); err != nil {
		return App{}, err
	}
	return a, tx.Commit()
}

func pick(a, b string) string {
	if a == "" {
		return b
	}
	return a
}
