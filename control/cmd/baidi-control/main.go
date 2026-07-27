// Command baidi-control 是白帝零信任访问控制系统的控制中心服务端（策略大脑 + 管理 API）。
// 白帝自有后端，独立于烛龙引擎。
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"baidi.dev/control/internal/api"
	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/config"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/webauthnx"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg := config.Load()
	// 生产环境拒绝用默认/空 JWT 密钥启动：密钥可猜则任何人都能伪造 admin 令牌。
	if config.InsecureProdSecret(cfg.Env, cfg.JWTSecret) {
		slog.Error("拒绝启动：BAIDI_ENV=prod 但 BAIDI_JWT_SECRET 未设置或仍为默认值，请注入强随机密钥")
		os.Exit(1)
	}
	st, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		slog.Error("open sqlite failed", "path", cfg.DBPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()
	secret := []byte(cfg.JWTSecret)
	// 令牌签名切非对称：control 私钥签、数据面只持公钥。迁移期仍接受存量 HS256 令牌
	// （BAIDI_ACCEPT_HS256=0 收口）。公钥写在 <私钥路径>.pub，由 deploy 分发给网关。
	keys, err := auth.LoadOrCreateKeys(cfg.JWTKeyPath, secret, cfg.AcceptHS256)
	if err != nil {
		slog.Error("载入/生成 JWT 签名密钥失败", "path", cfg.JWTKeyPath, "err", err)
		os.Exit(1)
	}
	slog.Info("令牌签名：Ed25519", "kid", keys.Kid(), "pubkey", cfg.JWTKeyPath+".pub", "acceptHS256", cfg.AcceptHS256)
	if cfg.AcceptHS256 {
		slog.Warn("⚠ 迁移窗口开启：仍接受存量 HS256 共享密钥令牌；存量会话过期后请置 BAIDI_ACCEPT_HS256=0")
	}
	// WebAuthn RP：RP ID 必须是可注册域名或 localhost（浏览器不允许裸 IP），
	// 未配置即禁用 passkey，登录回落 legacy 演示验证码路径。
	rp, err2 := webauthnx.New(cfg.WebauthnRPID, cfg.WebauthnOrigins, "白帝零信任")
	if err2 != nil {
		slog.Error("WebAuthn 配置无效", "rpid", cfg.WebauthnRPID, "origins", cfg.WebauthnOrigins, "err", err2)
		os.Exit(1)
	}
	if rp == nil {
		slog.Warn("WebAuthn 未启用（BAIDI_WEBAUTHN_RPID/ORIGIN 未配置）：二次认证回落演示验证码路径；" +
			"生产请配置可注册域名——浏览器规范不允许裸 IP 作 RP ID")
	} else {
		slog.Info("WebAuthn 已启用", "rpid", cfg.WebauthnRPID, "origins", cfg.WebauthnOrigins)
	}
	srv := api.New(st, st, keys, cfg.Env, cfg.DownloadsDir, rp)

	handler := httpx.Chain(srv.Routes(),
		httpx.RequestID,
		httpx.CORS(cfg.AllowOrigin),
		httpx.BodyLimit(1<<20),            // 请求体上限 1 MiB
		auth.Middleware(keys, srv.IsOpen), // 校验 Bearer JWT（登录/健康/门户登录免认证）
		httpx.Logger,
		httpx.Recover,
	)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// 启动
	go func() {
		slog.Info("baidi-control starting", "addr", cfg.Addr, "env", cfg.Env, "version", api.Version)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	// 优雅关闭
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	slog.Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}
}
