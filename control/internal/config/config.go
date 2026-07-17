// Package config 加载白帝控制中心的运行配置（环境变量优先，带合理默认）。
package config

import (
	"os"
	"strconv"
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
	Addr            string        // 监听地址，默认 :8090
	AllowOrigin     string        // CORS 允许来源（开发期 console），默认 *
	ShutdownTimeout time.Duration // 优雅关闭超时
	Env             string        // dev / prod
	DBPath          string        // SQLite 数据库文件路径
	JWTSecret       string        // JWT 签名密钥（生产务必经 BAIDI_JWT_SECRET 注入）
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
	}
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
