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
	"strings"
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
	// ★审计留存轮转已搬到 srv 之后（srv.StartAuditPurgeLoop）：按磁盘水位的那一半
	// 要**落审计**，而写审计的能力在 Server 上。
	// 业务告警留存轮转：启动清一次 + 每 24h 清一次**已处置**的超期行。
	//
	// ★没有它这张表就只增不减：多条规则的触发条件是长期成立的（网关持续离线、
	// 应用长期未关联资源、过期 JIT 授予全系统没有回收动作），处置一条、条件仍在，
	// 冷却期后又是一条。pending 刻意不清——按时间删待办等于让没人管的问题自己消失。
	{
		purgeAlerts := func() {
			n, perr := st.PurgeExpiredAlerts(context.Background(), cfg.AlertRetentionDays)
			if perr != nil {
				slog.Error("业务告警留存轮转失败", "err", perr)
			} else if n > 0 {
				slog.Info("业务告警留存轮转完成", "deleted", n, "retentionDays", cfg.AlertRetentionDays)
			}
		}
		purgeAlerts()
		go func() {
			t := time.NewTicker(24 * time.Hour)
			defer t.Stop()
			for range t.C {
				purgeAlerts()
			}
		}()
	}
	// 审计外送的队列上界注入：入队时判丢弃用的就是这一份，外送页显示的也是它
	// （与 SetAuditRetentionDays 同一条纪律——展示值必须来自真正在用的那份）。
	st.SetAuditForwardQueueMax(cfg.AuditForwardQueueMax)
	// 设备状态时序留存轮转：启动清一次 + 每小时清一次（复用审计留存那条循环的形状）。
	//
	// ★节奏比审计的 24h 紧，因为写入率高三个数量级：每网关 15s 一条，24h 的松弛
	// 就是每台网关多留 5760 行。也没有「关闭清理」这一档——cfg 侧已把非法值夹回默认 72，
	// 清理失败只记日志不退出（观测数据的清理挡不住主业务）。
	{
		purgeMetrics := func() {
			n, perr := st.PurgeExpiredGatewayMetrics(context.Background(), cfg.MetricsRetentionHours)
			if perr != nil {
				slog.Error("设备状态留存轮转失败", "err", perr)
			} else if n > 0 {
				slog.Info("设备状态留存轮转完成", "deleted", n, "retentionHours", cfg.MetricsRetentionHours)
			}
			// 攻击源小时桶搭同一班清理车（写入率低得多，但同样没有"不清理"这一档）。
			before := time.Now().Add(-time.Duration(cfg.AttackRetentionDays) * 24 * time.Hour).Unix()
			if an, aerr := st.PurgeAttackSources(context.Background(), before); aerr != nil {
				slog.Error("攻击源留存轮转失败", "err", aerr)
			} else if an > 0 {
				slog.Info("攻击源留存轮转完成", "deleted", an, "retentionDays", cfg.AttackRetentionDays)
			}
		}
		purgeMetrics()
		go func() {
			t := time.NewTicker(time.Hour)
			defer t.Stop()
			for range t.C {
				purgeMetrics()
			}
		}()
	}
	secret := []byte(cfg.JWTSecret)
	// 令牌签名切非对称：control 私钥签、数据面只持公钥。迁移期仍接受存量 HS256 令牌
	// （BAIDI_ACCEPT_HS256=0 收口）。公钥写在 <私钥路径>.pub，由 deploy 分发给网关。
	keys, err := auth.LoadOrCreateKeys(cfg.JWTKeyPath, cfg.JWTKnockKeyPath, cfg.JWTWebKeyPath, secret, cfg.AcceptHS256)
	if err != nil {
		slog.Error("载入/生成 JWT 签名密钥失败", "path", cfg.JWTKeyPath, "err", err)
		os.Exit(1)
	}
	slog.Info("令牌签名：Ed25519 按用途分密钥",
		"sessKid", keys.SessKid(), "knockKid", keys.KnockKid(), "webKid", keys.WebKid(),
		"分发给网关的公钥", cfg.JWTKnockKeyPath+".pub（敲门）/"+cfg.JWTWebKeyPath+".pub（七层 Web 代理）",
		"acceptHS256", cfg.AcceptHS256)
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
	// 设备状态页的时间窗要按留存期截断，展示值必须来自**上面那条清理循环真正消费的
	// 那一份**配置（与 SetAuditRetentionDays 同一条纪律）：再读一遍环境变量的副本
	// 会在两者不一致时让页面承诺一段其实早被删掉的历史。
	srv.SetMetricsRetentionHours(cfg.MetricsRetentionHours)
	srv.SetAuthTimeouts(cfg.ExtAuthTimeout, cfg.LDAPConnectTimeout, cfg.LDAPRequestTimeout)
	// ★外部认证预算是这次唯一可能误伤真实部署的旋钮：配小了，慢但可用的目录会被判成
	// 「认证源不可用」，而那条路径**不计入锁定**——用户重试也永远进不去，且审计里
	// 只说「认证源不可用」，看不出是被自己的预算切断的（耗时已一并写进审计正文）。
	// 生效值必须看得见。
	switch {
	case cfg.ExtAuthTimeout <= 0:
		slog.Warn("⚠ 外部认证预算已关闭（BAIDI_EXTAUTH_TIMEOUT<=0）：一次口令登录最坏可挂到" +
			"数十秒（LDAP 的连接/请求超时是逐请求的，一次认证要走两次拨号 + StartTLS + " +
			"服务账号 bind + search + 用户 bind）。这是逃生舱，正常部署请留默认值")
	case cfg.ExtAuthTimeout < 3*time.Second:
		slog.Warn("⚠ 外部认证预算偏紧，慢但可用的目录可能被判成「认证源不可用」（该路径不计入锁定，"+
			"用户重试也进不去）；PRD 的 3s 是 P95 验收目标而不是容错阈值",
			"预算", cfg.ExtAuthTimeout.String())
	default:
		slog.Info("外部认证超时", "预算", cfg.ExtAuthTimeout.String(),
			"LDAP连接", cfg.LDAPConnectTimeout.String(), "LDAP请求", cfg.LDAPRequestTimeout.String())
	}
	if cfg.GwPlaintextCompat {
		slog.Warn("⚠ 逃生舱开启（BAIDI_GW_PLAINTEXT_COMPAT=1）：/api/v1/gateways/* 仍挂在明文口，" +
			"可用 JWT role=gateway 调用；全部网关切到 mTLS 后请立即关回")
	}

	// 业务告警周期评估（PRD ch5 FR-MON-21~25）：网关离线 / JIT 授予到期 /
	// 应用未关联资源 / 爆破锁定 / 终端判 block / 审计链自检，逐条读真实信号。
	// ★审计链那一条尤其要有人定期跑——防篡改链没人查，等于只是个说法。
	alertCtx, stopAlerts := context.WithCancel(context.Background())
	defer stopAlerts()
	srv.StartAlertLoop(alertCtx, cfg.AlertInterval, cfg.AlertChainInterval)

	// 审计日志外送投递循环（PRD ch16 + ch21.6）：把 audit_forward_queue 里的记录
	// 送到 syslog / SIEM，成功才出队、失败退避重试。
	// ★与告警循环共用 alertCtx 的取消信号（关服时一起停）；在途的那一批发完即止，
	// 没发完的留在队列里，下次启动继续——这正是持久化队列存在的意义。
	srv.StartAuditForwardLoop(alertCtx, cfg.AuditForwardInterval)
	// 审计留存轮转（PRD FR-AUDIT-10）：按保留天数 + 按磁盘水位，启动清一次 + 每 24h 一次。
	// 清理段末的链锚点由 store 侧共用实现落 audit_meta，防篡改链不因轮转断裂。
	srv.StartAuditPurgeLoop(alertCtx, cfg.AuditRetentionDays, cfg.AuditMaxDiskPercent)
	srv.StartExternalRecheckLoop(alertCtx, cfg.ExtRecheckInterval)

	// ★CORS 默认 "*"：任意网页都能对本控制面发跨源请求。API 认证走 Bearer 而非
	// Cookie，跨站页面读不到已认证响应，真实暴露面只有免认证端点——但其中包含登录，
	// 即「任意网页可把访客浏览器变成登录爆破节点」，而 nginx 那三条 20r/m 限流是按
	// 源 IP 的，分布式来源正好绕开（账号维度的 lockout 仍挡得住）。
	//
	// 默认值没有跟着收紧，是因为客户端 webview 的 origin 逐平台不同、且我们只实测过
	// 一个平台：漏掉一个 = 那个平台升级即全员连不上。收紧要显式配置 + 逐平台实测。
	// 沉默的坏默认改不掉，至少不让它沉默。
	if strings.TrimSpace(cfg.AllowOrigin) == "*" {
		slog.Warn("⚠ CORS 允许任意来源（BAIDI_CORS_ORIGIN=*）：任意网页可对本控制面发跨源请求，" +
			"包括从访客浏览器发起登录尝试（分布式来源绕过 nginx 的 IP 维度限流）。" +
			"建议改为白名单（逗号分隔），需覆盖在用客户端的 webview 来源：" +
			"控制台部署域名 / tauri://localhost（桌面 mac·Linux） / http://tauri.localhost（桌面 Windows） / " +
			"https://appassets.local（安卓）——改前请逐平台实测，漏掉一个该平台即连不上控制面")
	} else {
		slog.Info("CORS 白名单生效", "origins", cfg.AllowOrigin)
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
	stopAlerts() // 先停告警评估循环：关服期间没必要再起新一轮全链重算

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
