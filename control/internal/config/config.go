// Package config 加载白帝控制中心的运行配置（环境变量优先，带合理默认）。
package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/store"
)

// DefaultJWTSecret 是未注入 BAIDI_JWT_SECRET 时的开发用默认密钥（可猜，仅限 dev）。
const DefaultJWTSecret = "baidi-dev-secret-change-me"

// InsecureProdSecret 报告"生产环境仍在用默认/空 JWT 密钥"——这是致命错配：
// 密钥可猜则任何人都能伪造 admin 令牌，控制面形同虚设。main 据此拒绝启动（fail-closed）。
func InsecureProdSecret(env, secret string) bool {
	return env == "prod" && (secret == "" || secret == DefaultJWTSecret)
}

// Config 控制中心服务端配置。
type Config struct {
	Addr               string        // 监听地址，默认 :8090
	AllowOrigin        string        // CORS 允许来源（开发期 console），默认 *
	ShutdownTimeout    time.Duration // 优雅关闭超时
	Env                string        // dev / prod
	DBPath             string        // SQLite 数据库文件路径
	JWTSecret          string        // JWT 签名密钥（生产务必经 BAIDI_JWT_SECRET 注入）
	DownloadsDir       string        // 客户端安装包目录（manifest.json + 安装包）
	WebauthnRPID       string        // WebAuthn RP ID（可注册域名，如 vpn.example.com / localhost）
	WebauthnOrigins    string        // WebAuthn 允许来源，逗号分隔（如 https://vpn.example.com）
	JWTKeyPath         string        // 会话令牌 Ed25519 私钥 PEM（缺失则首启生成；公钥写同名 .pub）
	JWTKnockKeyPath    string        // 敲门令牌 Ed25519 私钥 PEM；其 .pub 分发给网关的 SPA 敲门监听
	JWTWebKeyPath      string        // 七层 Web 代理票据 Ed25519 私钥 PEM；其 .pub 分发给网关的 L7 监听
	AcceptHS256        bool          // 是否接受存量 HS256 令牌（阶段4 起默认 false；=1 为过渡逃生舱）
	PKIDir             string        // 内部 CA 目录（签发网关 mTLS 客户端证书）；空=禁用 mTLS
	MTLSAddr           string        // 网关接口的 mTLS 监听地址（如 127.0.0.1:8092）；空=不监听
	GwPlaintextCompat  bool          // 明文口是否仍挂网关接口（阶段4 起默认 false；=1 为过渡逃生舱）
	AuditRetentionDays int           // 审计日志留存天数（超期滚动清理并锚定防篡改链）；0=不清理
	// AuditMaxDiskPercent 审计库允许占文件系统的百分比上限（0 = 不启用按水位回收）。
	// ★与留存天数是**或**的关系（PRD FR-AUDIT-10），任一条件满足即回收最早一天。
	AuditMaxDiskPercent int
	// AlertInterval 业务告警周期评估间隔；<=0 关闭周期评估（只剩管理员手动「立即检测」）。
	AlertInterval time.Duration
	// AlertChainInterval 审计防篡改链自检间隔（全链重算比其余信号贵，单独节流）。
	// ★这条循环就是「防篡改链有人定期查」的执行方——链没人查，防篡改只是个说法。
	AlertChainInterval time.Duration
	// AlertRetentionDays 业务告警的留存天数（只轮转**已处置**的行，pending 一律留着）。
	// ★恒为正：告警是只追加的，而多条规则的条件长期成立（网关持续离线、应用长期未关联
	// 资源、过期授予没有回收动作），没有轮转就是一张只增不减的表。非法/缺省值落回
	// DefaultAlertRetentionDays，**没有"关闭清理"这一档**（同 MetricsRetentionHours）。
	AlertRetentionDays int
	// ExtRecheckInterval 外部账号状态回验间隔（wave7 行动 3）；<=0 关闭回验（启动时告警：
	// 外部目录禁号后已签发会话将继续有效至自然过期）。默认 5 分钟——这就是
	// 「AD 禁号 → 白帝断连」的最大失效窗，按需收紧，代价是对目录的查询频率。
	ExtRecheckInterval time.Duration

	// ExtAuthTimeout **一次外部认证调用**的总预算（NFR-PERF-03）。
	//
	// ★这是一个「只包住外部认证那一次调用」的预算，**不是** handler 的整体 deadline。
	// 给 handler 加 deadline 是错的：口令校验（bcrypt）不吃 ctx 打不断；而 deadline
	// 一过期，后面所有吃 ctx 的动作会一起失败——审计写不进库（`/diag` 的 audit-write
	// 还会翻红并把运维指向磁盘可写性）、锁定落不了库、`stepUpDecision` 的两次库读
	// 失败即 **fail-closed 拒登录**。那等于把「目录慢」升级成「全员登录不了」，
	// 而用户看到的文案是「认证策略暂不可用」。
	//
	// 默认 8s：PRD 的 3s 是 P95 验收目标，不是容错阈值——跨广域网 AD 的
	// StartTLS + bind + search 链路慢过 3s 是常态，按 3s 截断等于把「慢但可用的目录」
	// 判成「认证源不可用」，而那条路径不计入锁定，用户重试也永远进不去。
	// <=0 表示不设预算（回到改造前的行为，逃生舱）。
	ExtAuthTimeout time.Duration

	// LDAPConnectTimeout / LDAPRequestTimeout 下发给 ldapsrc 的两个超时。
	// ★改造前 api 层**从不设**这两个字段，恒取 go-ldap 侧的缺省（5s / 10s），
	// 管理员在页面上根本没有这个旋钮。而 RequestTimeout 是逐请求的，
	// 一次口令认证要走两次拨号 + StartTLS + 服务账号 bind + search + 用户 bind。
	LDAPConnectTimeout time.Duration
	LDAPRequestTimeout time.Duration

	// IdleLockInterval 闲置账号自动锁定循环的间隔；<=0 关闭（策略里开了也不会有动作，启动时告警）。
	IdleLockInterval time.Duration
	// 主机侧定期自动备份（NFR-AVL-04）。BackupDir 或 BackupPassphrase 为空即不启用，
	// 启动时打一行告警并在 /diag 上如实显示「未启用」——绝不静默地什么都不做。
	BackupDir        string
	BackupInterval   time.Duration
	BackupPassphrase string
	BackupKeep       int
	// AuditForwardInterval 审计外送投递循环的间隔；<=0 关闭投递（队列只增不减，启动时告警）。
	// ★这条循环是外送功能唯一的执行方——没有它，配置齐全但 SIEM 永远收不到东西。
	AuditForwardInterval time.Duration
	// AuditForwardQueueMax 每个外送出口的待发队列上界（条），超出即丢新保旧并计数。
	// 非正值落回 store.DefaultForwardQueueMax：没有上界等于留一个"对端一挂就把磁盘写满"
	// 的按钮，而磁盘写满会让**审计本身**落不了库——方向完全反了。
	AuditForwardQueueMax int
	// MetricsRetentionHours 网关设备状态时序的留存小时数（超期滚动清理）。
	// ★恒为正：非法/缺省值一律落到 DefaultMetricsRetentionHours，**没有"关闭清理"这一档**。
	// gateway_metrics 是每网关 15s 一条的写入热点，留一个能关掉清理的开关，
	// 等于留一个把库撑爆的按钮，而且撑爆前毫无征兆（与审计留存的 0=不清理刻意不同）。
	MetricsRetentionHours int
	// AttackRetentionDays 攻击源小时桶（attack_sources）的留存天数。同样没有
	// "关闭清理"这一档——写入率虽被网关侧节流钉死，被扫描的公网机器日积月累
	// 照样能堆出一张大表。默认 30 天：概览只看 24h，30 天够做月度回溯。
	AttackRetentionDays int
}

// DefaultAlertRetentionDays 已处置告警默认留存 90 天。
// 够覆盖一个季度的复盘（"上季度这类告警出过几次、谁处理的"），再长就该导出。
const DefaultAlertRetentionDays = 90

// MinAlertRetentionDays 留存下限：低于 7 天的话"上周那条是谁处理的"就查不到了。
const MinAlertRetentionDays = 7

// clampAlertRetention 把告警留存夹到合法区间（非正数不代表"关掉清理"）。
func clampAlertRetention(d int) int {
	if d < MinAlertRetentionDays {
		return DefaultAlertRetentionDays
	}
	return d
}

// DefaultMetricsRetentionHours 设备状态时序默认留存 72 小时。
// 三天足够覆盖「上周末那次抖动」这类回溯，再长就该导出到时序库而不是压在 SQLite 里。
const DefaultMetricsRetentionHours = 72

// MinMetricsRetentionHours 留存下限：低于 1 小时的话趋势页的「小时」档自己就看不全了。
const MinMetricsRetentionHours = 1

// Load 从环境变量装载配置。
func Load() Config {
	return Config{
		Addr:            env("BAIDI_ADDR", ":8090"),
		AllowOrigin:     env("BAIDI_CORS_ORIGIN", "*"),
		ShutdownTimeout: envDuration("BAIDI_SHUTDOWN_TIMEOUT", 10*time.Second),
		Env:             env("BAIDI_ENV", "dev"),
		DBPath:          env("BAIDI_DB", "baidi.db"),
		JWTSecret:       env("BAIDI_JWT_SECRET", DefaultJWTSecret),
		DownloadsDir:    env("BAIDI_DOWNLOADS", "downloads"), // 客户端安装包目录（manifest.json + 安装包）
		// WebAuthn（passkey 二次认证）：RP ID 必须是可注册域名或 localhost——
		// 浏览器规范不允许裸 IP 作 RP ID，故 IP 演示站（101.43.125.131）无法启用 WebAuthn。
		// 两者任一为空即视为未启用，登录回落 legacy 演示验证码路径（见 api.webauthnEnabled）。
		WebauthnRPID:    env("BAIDI_WEBAUTHN_RPID", ""),
		WebauthnOrigins: env("BAIDI_WEBAUTHN_ORIGIN", ""),
		// 令牌签名私钥：control 独有，绝不下发给网关（网关只拿 .pub）。
		JWTKeyPath: env("BAIDI_JWT_KEY", "jwt-ed25519.pem"),
		// 按用途分密钥：网关只装 knock 公钥，会话令牌在数据面从密码学上就验不过。
		JWTKnockKeyPath: env("BAIDI_JWT_KNOCK_KEY", "jwt-ed25519-knock.pem"),
		// 七层 Web 代理票据再分一把：L7 监听只装它的公钥，敲门令牌在那条路上同样验不过。
		JWTWebKeyPath: env("BAIDI_JWT_WEB_KEY", "jwt-ed25519-web.pem"),
		// 阶段 4 已收口：默认不再接受 HS256 存量令牌。逃生舱 BAIDI_ACCEPT_HS256=1
		// 仅供「升级瞬间还有未过期的 8h 会话」时临时打开，存量过期后应立即关回。
		AcceptHS256: envBool("BAIDI_ACCEPT_HS256", false),
		// 网关机器身份走 mTLS：CA 目录默认启用（首启自动生成），监听地址默认关闭——
		// 开了才真正提供 mTLS 口，避免未配置证书的部署无谓占端口。
		PKIDir:   env("BAIDI_PKI_DIR", "pki"),
		MTLSAddr: env("BAIDI_MTLS_ADDR", ""),
		// 阶段 4 已收口：网关接口只挂 mTLS 监听，明文口不再挂载该路由。
		GwPlaintextCompat: envBool("BAIDI_GW_PLAINTEXT_COMPAT", false),
		// 审计留存：启动时 + 每 24h 清理超期行，清理段末的链锚点写 audit_meta（见 store.PurgeExpiredAudit）。
		AuditRetentionDays: envInt("BAIDI_AUDIT_RETENTION_DAYS", 180),
		// 审计磁盘水位上限（FR-AUDIT-10 的另一半）：审计库文件占文件系统超过这个
		// 百分比时，额外按天回收最早的记录。**默认 0 = 不启用**——自动删审计是破坏性
		// 策略，得由部署方明确要求；不配时唯一的上界仍是保留天数。
		// 判据是"审计库占了多大"而不是"文件系统满没满"，理由见 store.PurgeAuditByDisk。
		AuditMaxDiskPercent: clampDiskPct(envInt("BAIDI_AUDIT_MAX_DISK_PERCENT", 0)),
		// 业务告警：默认每分钟评估一轮，审计链自检每 15 分钟一次。
		AlertInterval:      envDuration("BAIDI_ALERT_INTERVAL", time.Minute),
		AlertChainInterval: envDuration("BAIDI_ALERT_CHAIN_INTERVAL", 15*time.Minute),
		// 告警留存：启动时 + 每 24h 清一次**已处置**的超期行（见 store.PurgeExpiredAlerts）。
		AlertRetentionDays: clampAlertRetention(envInt("BAIDI_ALERT_RETENTION_DAYS", DefaultAlertRetentionDays)),
		// 审计外送：默认每 5s 投递一轮（够快到"刚发生的事很快就在 SIEM 里"，
		// 又不至于把一个空队列查成热点）。上界的唯一定义在 store，别在这里另抄一份。
		AuditForwardInterval: envDuration("BAIDI_AUDIT_FORWARD_INTERVAL", 5*time.Second),
		// 闲置账号自动锁定：默认每小时跑一轮。★这个间隔只决定"多久检查一次"，
		// 不决定"要不要锁"——那由落库策略的 AutoLock 决定，且默认是关的。
		IdleLockInterval: envDuration("BAIDI_IDLE_LOCK_INTERVAL", time.Hour),
		// 自动备份：默认**不启用**（没有目录与口令就不跑）。口令不给默认值——
		// 备份里装着 CA 私钥与全部凭据，一个编译进二进制的默认口令等于没加密。
		BackupDir:            os.Getenv("BAIDI_BACKUP_DIR"),
		BackupInterval:       envDuration("BAIDI_BACKUP_INTERVAL", 24*time.Hour),
		BackupPassphrase:     os.Getenv("BAIDI_BACKUP_PASSPHRASE"),
		BackupKeep:           envInt("BAIDI_BACKUP_KEEP", 7),
		ExtRecheckInterval:   envDuration("BAIDI_EXTAUTH_RECHECK", 5*time.Minute),
		ExtAuthTimeout:       envDuration("BAIDI_EXTAUTH_TIMEOUT", 8*time.Second),
		LDAPConnectTimeout:   envDuration("BAIDI_LDAP_CONNECT_TIMEOUT", 3*time.Second),
		LDAPRequestTimeout:   envDuration("BAIDI_LDAP_REQUEST_TIMEOUT", 5*time.Second),
		AuditForwardQueueMax: envInt("BAIDI_AUDIT_FORWARD_QUEUE_MAX", store.DefaultForwardQueueMax),
		// 设备状态留存：启动时 + 每小时清理超期采样点（见 store.PurgeExpiredGatewayMetrics）。
		MetricsRetentionHours: clampMetricsRetention(envInt("BAIDI_METRICS_RETENTION_HOURS", DefaultMetricsRetentionHours)),
		// 攻击源留存：与设备状态同一条清理循环（见 cmd/baidi-control）。
		AttackRetentionDays: clampAttackRetention(envInt("BAIDI_ATTACK_RETENTION_DAYS", DefaultAttackRetentionDays)),
	}
}

// DefaultAttackRetentionDays 攻击源统计默认留存 30 天。
const DefaultAttackRetentionDays = 30

// MinAttackRetentionDays 留存下限：低于 2 天的话概览的 24h 窗口在跨日清理后会缺口。
const MinAttackRetentionDays = 2

// clampAttackRetention 把攻击源留存夹到合法区间（非正数不代表"关掉清理"）。
func clampAttackRetention(d int) int {
	if d < MinAttackRetentionDays {
		return DefaultAttackRetentionDays
	}
	return d
}

// envInt 读整数环境变量（解析失败取默认）。
func envInt(k string, def int) int {
	if v, ok := os.LookupEnv(k); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

// envBool 读布尔环境变量（1/true/yes/on 为真，0/false/no/off 为假，其余取默认）。
func envBool(k string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// clampMetricsRetention 把设备状态留存夹到合法区间。
// 非正数（含把 BAIDI_METRICS_RETENTION_HOURS 设成 0 想"关掉清理"的写法）落回默认值，
// 而不是关闭清理——理由见 Config.MetricsRetentionHours。
func clampMetricsRetention(h int) int {
	if h < MinMetricsRetentionHours {
		return DefaultMetricsRetentionHours
	}
	return h
}

// clampDiskPct 把审计磁盘水位上限钳进 [1,95]；<=0 视为不启用（回 0）。
// 上限 95 是防呆：填 100 等于永不触发（那就别配），填 0 以下已由 <=0 归零。
func clampDiskPct(v int) int {
	switch {
	case v <= 0:
		return 0
	case v > 95:
		return 95
	default:
		return v
	}
}
