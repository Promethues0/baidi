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
	srv := api.New(st, st, secret, cfg.Env, cfg.DownloadsDir)

	handler := httpx.Chain(srv.Routes(),
		httpx.RequestID,
		httpx.CORS(cfg.AllowOrigin),
		httpx.BodyLimit(1<<20),              // 请求体上限 1 MiB
		auth.Middleware(secret, srv.IsOpen), // 校验 Bearer JWT（登录/健康/门户登录免认证）
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
