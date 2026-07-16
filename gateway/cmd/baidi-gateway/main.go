// Command baidi-gateway 是白帝安全代理网关（数据面）：SPA 单包授权 + SSL 隧道代理。
// 默认对未授权者隐身；持有效 JWT 敲门后才放行并代理到后端业务。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	"baidi.dev/gateway/internal/cplane"
	"baidi.dev/gateway/internal/darkfw"
	"baidi.dev/gateway/internal/gmcert"
	"baidi.dev/gateway/internal/proxy"
	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/spa"
)

func main() {
	spaAddr := flag.String("spa", env("BAIDI_GW_SPA", ":18201"), "SPA 敲门 UDP 监听地址")
	proxyAddr := flag.String("proxy", env("BAIDI_GW_PROXY", ":18443"), "TLS 隧道代理监听地址")
	backend := flag.String("backend", env("BAIDI_GW_BACKEND", "127.0.0.1:9999"), "后端业务 host:port")
	secret := flag.String("secret", env("BAIDI_JWT_SECRET", "baidi-dev-secret-change-me"), "JWT 密钥（须与 baidi-control 一致）")
	ttl := flag.Duration("ttl", 30*time.Second, "SPA 放行窗口")
	gm := flag.Bool("gm", false, "隧道用国密 TLCP（SM2 双证书 + SM3/SM4），否则通用 TLS")
	certDir := flag.String("certdir", env("BAIDI_GW_CERTDIR", "certs"), "国密证书目录（持久化 CA 签发的双证书；首启自动生成）")
	pf := flag.Bool("pf", false, "内核态隐身：SPA 放行落到 macOS pf 表 baidi_allowed（默认 DROP，需 root + 已加载 anchor）")
	resources := flag.String("resources", env("BAIDI_GW_RESOURCES", ""), "资源注册表 JSON 路径（按目的多资源路由；空=仅默认后端）")
	control := flag.String("control", env("BAIDI_GW_CONTROL", ""), "baidi-control 地址；设了则向控制面注册并周期拉取资源策略（动态，优先于静态 -resources）")
	gwid := flag.String("gwid", env("BAIDI_GW_ID", "gw-1"), "本网关 id（控制面注册标识）")
	poll := flag.Duration("poll", 15*time.Second, "控制面策略轮询/心跳间隔")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if *secret == "" {
		log.Fatal("拒绝启动：BAIDI_JWT_SECRET 为空（数据面授权依赖它校验 SPA 敲门身份）")
	}
	if *secret == "baidi-dev-secret-change-me" {
		slog.Warn("⚠ 正在使用开发默认 JWT 密钥，生产务必经 BAIDI_JWT_SECRET 配置独立密钥（须与 baidi-control 一致）")
	}
	slog.Info("baidi-gateway 启动", "spa", *spaAddr, "proxy", *proxyAddr, "backend", *backend, "ttl", ttl.String())

	al := spa.NewAllowlist()

	reg := resource.New(*backend)
	if *resources != "" {
		if err := reg.LoadFile(*resources); err != nil {
			log.Fatalf("加载资源注册表失败: %v", err)
		}
		slog.Info("资源注册表已加载", "file", *resources, "count", reg.Count())
	}

	// 控制面对接：注册自身 + 周期拉取资源授权策略（动态替代静态 resources.json）
	if *control != "" {
		started := time.Now()
		// 真实活性上报：已授权源数（SPA 放行表）+ 活跃隧道数（代理）+ 运行秒数 + 活跃会话（在线用户来源）
		report := func() (int, int, int64, []cplane.Session) {
			ss := al.Sessions()
			out := make([]cplane.Session, 0, len(ss))
			for _, s := range ss {
				out = append(out, cplane.Session{IP: s.IP, User: s.User, Role: s.Role, Since: s.Since.Unix()})
			}
			return al.ActiveCount(), proxy.Active(), int64(time.Since(started).Seconds()), out
		}
		// 应用控制面下发的强制下线撤销名单：封禁敲门 + 撤销放行窗口 + 切断活跃隧道。
		// 处置幂等由本地 applied[user]=until 自管，而非依赖 DenyUser 返回值——后者在网关
		// 本地时钟快于控制面时会把 until 判过期而返回 false，若据此 continue 会连撤窗/断隧道
		// 一并跳过（安全动作静默失效）。这里无论 until 是否"已过期"都执行一次撤窗+断隧道。
		applied := map[string]int64{}
		applyRevoked := func(revoked []cplane.Revoked) {
			for _, rv := range revoked {
				if applied[rv.User] >= rv.Until {
					continue // 该账号该封禁窗口已处置过
				}
				applied[rv.User] = rv.Until
				until := time.Unix(rv.Until, 0)
				al.DenyUser(rv.User, until) // 封禁后续敲门（时钟正常时生效）
				ips := al.RevokeUser(rv.User)
				n := proxy.KillUser(rv.User)
				slog.Warn("强制下线执行：封禁敲门 + 撤销放行 + 切断隧道",
					"user", rv.User, "revoked_ips", ips, "killed_tunnels", n,
					"until", until.Format("15:04:05"))
				if *pf {
					for _, ip := range ips {
						// 与 TTL reaper 同款防误删：该 IP 若已被其他账号重新敲门放行则跳过
						if _, _, ok := al.Allowed(ip); ok {
							continue
						}
						if err := darkfw.DenyIP(ip); err == nil {
							slog.Info("pf 放行回收（强制下线）", "ip", ip)
						}
					}
				}
			}
		}
		cp := cplane.New(*control, *gwid, *proxyAddr, *spaAddr, []byte(*secret))
		if err := cp.Register(report()); err != nil {
			slog.Warn("控制面注册失败（继续轮询重试）", "err", err.Error())
		}
		if rs, rv, err := cp.Policy(); err != nil {
			slog.Warn("首次拉取策略失败，暂用本地默认/静态策略", "err", err.Error())
		} else {
			reg.Replace(rs)
			applyRevoked(rv)
			slog.Info("控制面策略已拉取", "control", *control, "count", reg.Count())
		}
		go func() {
			t := time.NewTicker(*poll)
			defer t.Stop()
			for range t.C {
				_ = cp.Register(report()) // 心跳 + 上报真实活性指标与活跃会话
				if rs, rv, err := cp.Policy(); err == nil {
					reg.Replace(rs)
					applyRevoked(rv)
				} else {
					slog.Warn("轮询拉策略失败（保留上次策略）", "err", err.Error())
				}
			}
		}()
		slog.Info("控制面对接：注册 + 周期拉策略", "gwid", *gwid, "interval", poll.String())
	}

	if *pf {
		if !darkfw.Available() {
			log.Fatal("-pf 需要内核防火墙后端：Linux 的 nft 或 macOS 的 pfctl，均未找到")
		}
		_ = darkfw.Flush() // 启动归零，确保默认隐身
		al.OnAllow = func(ip, user string) {
			if err := darkfw.AllowIP(ip); err == nil {
				slog.Info("pf 放行写入", "ip", ip, "user", user, "table", darkfw.Table)
			}
		}
		go func() { // TTL 到期回收 pf 放行规则
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for range t.C {
				for _, ip := range al.Reap() {
					// 回收前再确认：若该 IP 已被重新敲门放行，别让陈旧 Deny 误删内核放行规则
					if _, _, ok := al.Allowed(ip); ok {
						continue
					}
					if err := darkfw.DenyIP(ip); err == nil {
						slog.Info("pf 放行回收（TTL 到期）", "ip", ip)
					}
				}
			}
		}()
		slog.Info("内核态隐身：默认 DROP + 动态放行集合", "backend", darkfw.Backend(), "set", darkfw.Table)
	}

	go func() {
		if err := spa.Serve(*spaAddr, []byte(*secret), *ttl, al); err != nil {
			log.Fatalf("SPA 监听失败: %v", err)
		}
	}()

	if *gm {
		certs, err := gmcert.EnsureGateway(*certDir)
		if err != nil {
			log.Fatalf("生成/加载国密双证书失败: %v", err)
		}
		slog.Info("隧道加密：国密 TLCP（持久化 CA 签发的 SM2 双证书）", "certdir", *certDir)
		if err := proxy.ServeTLCP(*proxyAddr, certs, reg, al); err != nil {
			log.Fatalf("TLCP 代理监听失败: %v", err)
		}
		return
	}
	slog.Info("隧道加密：通用 TLS（自签）")
	if err := proxy.Serve(*proxyAddr, mustSelfSigned(), reg, al); err != nil {
		log.Fatalf("代理监听失败: %v", err)
	}
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

// mustSelfSigned 生成启动期自签 TLS 证书（生产换国密 TLCP / 正式证书）。
func mustSelfSigned() tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "baidi-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"baidi-gateway", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}
