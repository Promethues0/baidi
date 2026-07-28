// Package config 加载白帝控制中心的运行配置（环境变量优先，带合理默认）。
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
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
	Addr              string        // 监听地址，默认 :8090
	AllowOrigin       string        // CORS 允许来源（开发期 console），默认 *
	ShutdownTimeout   time.Duration // 优雅关闭超时
	Env               string        // dev / prod
	DBPath            string        // SQLite 数据库文件路径
	JWTSecret         string        // JWT 签名密钥（生产务必经 BAIDI_JWT_SECRET 注入）
	DownloadsDir      string        // 客户端安装包目录（manifest.json + 安装包）
	WebauthnRPID      string        // WebAuthn RP ID（可注册域名，如 vpn.example.com / localhost）
	WebauthnOrigins   string        // WebAuthn 允许来源，逗号分隔（如 https://vpn.example.com）
	JWTKeyPath        string        // Ed25519 签名私钥 PEM 路径（缺失则首启生成；公钥写同名 .pub 供分发）
	AcceptHS256       bool          // 迁移期是否接受存量 HS256 令牌（默认 true，收口后置 0）
	PKIDir            string        // 内部 CA 目录（签发网关 mTLS 客户端证书）；空=禁用 mTLS
	MTLSAddr          string        // 网关接口的 mTLS 监听地址（如 127.0.0.1:8092）；空=不监听
	GwPlaintextCompat bool          // 迁移期：明文口仍允许 JWT role=gateway 调网关接口（默认 true）
}

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
		// 迁移期默认接受存量 HS256 令牌：升级瞬间在线会话（8h TTL）与网关自签的
		// role=gateway 令牌都还是 HS256，一刀切会让管理台掉线 + 数据面断联。
		AcceptHS256: envBool("BAIDI_ACCEPT_HS256", true),
		// 网关机器身份走 mTLS：CA 目录默认启用（首启自动生成），监听地址默认关闭——
		// 开了才真正提供 mTLS 口，避免未配置证书的部署无谓占端口。
		PKIDir:            env("BAIDI_PKI_DIR", "pki"),
		MTLSAddr:          env("BAIDI_MTLS_ADDR", ""),
		GwPlaintextCompat: envBool("BAIDI_GW_PLAINTEXT_COMPAT", true),
	}
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
