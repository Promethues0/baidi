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
	"baidi.dev/control/internal/pki"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/webauthnx"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	// 部署期离线签发网关身份材料（-issue-gateway-cert）：处理完即退出，不起服务。
	if runBootstrap() {
		return
	}

	cfg := config.Load()
	// 生产拒绝用默认/空 HS256 密钥启动——但仅当迁移逃生舱开着时该密钥才有意义。
	// 收口后（BAIDI_ACCEPT_HS256=false，默认）令牌全由 Ed25519 私钥签发，
	// BAIDI_JWT_SECRET 不再参与任何鉴权，自然也不必强求它非默认。
	if cfg.AcceptHS256 && config.InsecureProdSecret(cfg.Env, cfg.JWTSecret) {
		slog.Error("拒绝启动：BAIDI_ACCEPT_HS256=1 且 BAIDI_ENV=prod，但 BAIDI_JWT_SECRET 未设置或仍为默认值")
		os.Exit(1)
	}
	st, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		slog.Error("open sqlite failed", "path", cfg.DBPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()
	// 把留存天数注入展示层：审计页/诊断页显示的就是下面 purge 循环真正消费的这一份，
	// 不是种子编的 180，也不是 store 里再读一遍环境变量的副本。
	st.SetAuditRetentionDays(cfg.AuditRetentionDays)
	// 审计留存轮转：启动时清一次 + 每 24h 清一次超期行。
	// 清理段末的链锚点由 PurgeExpiredAudit 落 audit_meta，防篡改链不因轮转断裂。
	if cfg.AuditRetentionDays > 0 {
		purge := func() {
			n, perr := st.PurgeExpiredAudit(context.Background(), cfg.AuditRetentionDays)
			if perr != nil {
				slog.Error("审计留存轮转失败", "err", perr)
			} else if n > 0 {
				slog.Info("审计留存轮转完成", "deleted", n, "retentionDays", cfg.AuditRetentionDays)
			}
		}
		purge()
		go func() {
			t := time.NewTicker(24 * time.Hour)
			defer t.Stop()
			for range t.C {
				purge()
			}
		}()
	}
	secret := []byte(cfg.JWTSecret)
	// 令牌签名切非对称：control 私钥签、数据面只持公钥。迁移期仍接受存量 HS256 令牌
	// （BAIDI_ACCEPT_HS256=0 收口）。公钥写在 <私钥路径>.pub，由 deploy 分发给网关。
	keys, err := auth.LoadOrCreateKeys(cfg.JWTKeyPath, cfg.JWTKnockKeyPath, secret, cfg.AcceptHS256)
	if err != nil {
		slog.Error("载入/生成 JWT 签名密钥失败", "path", cfg.JWTKeyPath, "err", err)
		os.Exit(1)
	}
	slog.Info("令牌签名：Ed25519 按用途分密钥",
		"sessKid", keys.SessKid(), "knockKid", keys.KnockKid(),
		"分发给网关的公钥", cfg.JWTKnockKeyPath+".pub", "acceptHS256", cfg.AcceptHS256)
	if cfg.AcceptHS256 {
		slog.Warn("⚠ 逃生舱开启（BAIDI_ACCEPT_HS256=1）：仍接受存量 HS256 共享密钥令牌，" +
			"任何持该密钥者可伪造任意角色；存量 8h 会话过期后请立即关回")
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
	// 内部 CA：签发网关 mTLS 客户端证书（机器身份与用户身份在密码学上分家）
	ca, cerr := pki.LoadOrCreate(cfg.PKIDir)
	if cerr != nil {
		slog.Error("内部 CA 初始化失败", "dir", cfg.PKIDir, "err", cerr)
		os.Exit(1)
	}
	slog.Info("内部 CA 就绪", "dir", cfg.PKIDir)
	srv := api.New(st, st, keys, cfg.Env, cfg.DownloadsDir, rp, ca, cfg.GwPlaintextCompat)
	if cfg.GwPlaintextCompat {
		slog.Warn("⚠ 逃生舱开启（BAIDI_GW_PLAINTEXT_COMPAT=1）：/api/v1/gateways/* 仍挂在明文口，" +
			"可用 JWT role=gateway 调用；全部网关切到 mTLS 后请立即关回")
	}

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

	// 网关接口的 mTLS 监听（独立端口，只挂 /api/v1/gateways/*）：
	// 身份在传输层完成，且与人机接口分到两个端口——admin 令牌再也调不到网关接口。
	if cfg.MTLSAddr != "" {
		srvCert, serr := pki.ServerCertFor(ca, cfg.MTLSAddr)
		if serr != nil {
			slog.Error("mTLS 服务端证书签发失败", "err", serr)
			os.Exit(1)
		}
		mtlsSrv := &http.Server{
			Addr: cfg.MTLSAddr, Handler: srv.MTLSHandler(),
			TLSConfig: srv.MTLSConfig(ca, srvCert), ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			slog.Info("网关 mTLS 监听（仅 /api/v1/gateways/*）", "addr", cfg.MTLSAddr)
			if err := mtlsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("mTLS 监听失败", "err", err)
				os.Exit(1)
			}
		}()
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
	// ★排在 Shutdown 之后：先停止接新请求，再把队列里在途的安全事件通知发完。
	// 反过来的话，Shutdown 期间那批请求新产生的通知会直接落进一个已关闭的队列——
	// 恰恰是"关服务前最后那几条告警"最需要送到。
	srv.Close()
}
