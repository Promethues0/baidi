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
	JWTKnockKeyPath    string        // 敲门令牌 Ed25519 私钥 PEM；其 .pub 是唯一分发给网关的验证材料
	AcceptHS256        bool          // 是否接受存量 HS256 令牌（阶段4 起默认 false；=1 为过渡逃生舱）
	PKIDir             string        // 内部 CA 目录（签发网关 mTLS 客户端证书）；空=禁用 mTLS
	MTLSAddr           string        // 网关接口的 mTLS 监听地址（如 127.0.0.1:8092）；空=不监听
	GwPlaintextCompat  bool          // 明文口是否仍挂网关接口（阶段4 起默认 false；=1 为过渡逃生舱）
	AuditRetentionDays int           // 审计日志留存天数（超期滚动清理并锚定防篡改链）；0=不清理
	// AlertInterval 业务告警周期评估间隔；<=0 关闭周期评估（只剩管理员手动「立即检测」）。
	AlertInterval time.Duration
	// AlertChainInterval 审计防篡改链自检间隔（全链重算比其余信号贵，单独节流）。
	// ★这条循环就是「防篡改链有人定期查」的执行方——链没人查，防篡改只是个说法。
	AlertChainInterval time.Duration
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
		// 业务告警：默认每分钟评估一轮，审计链自检每 15 分钟一次。
		AlertInterval:      envDuration("BAIDI_ALERT_INTERVAL", time.Minute),
		AlertChainInterval: envDuration("BAIDI_ALERT_CHAIN_INTERVAL", 15*time.Minute),
		// 审计外送：默认每 5s 投递一轮（够快到"刚发生的事很快就在 SIEM 里"，
		// 又不至于把一个空队列查成热点）。上界的唯一定义在 store，别在这里另抄一份。
		AuditForwardInterval: envDuration("BAIDI_AUDIT_FORWARD_INTERVAL", 5*time.Second),
		AuditForwardQueueMax: envInt("BAIDI_AUDIT_FORWARD_QUEUE_MAX", store.DefaultForwardQueueMax),
		// 设备状态留存：启动时 + 每小时清理超期采样点（见 store.PurgeExpiredGatewayMetrics）。
		MetricsRetentionHours: clampMetricsRetention(envInt("BAIDI_METRICS_RETENTION_HOURS", DefaultMetricsRetentionHours)),
	}
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
