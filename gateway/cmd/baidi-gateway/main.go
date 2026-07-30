// Command baidi-gateway 是白帝安全代理网关（数据面）：SPA 单包授权 + SSL 隧道代理。
// 默认对未授权者隐身；持有效 JWT 敲门后才放行并代理到后端业务。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"log"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"

	"baidi.dev/gateway/internal/auth"
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
	secret := flag.String("secret", env("BAIDI_JWT_SECRET", ""), "旧 HS256 共享密钥（仅 -accept-hs256=true 的过渡逃生舱用；收口后留空即可）")
	ttl := flag.Duration("ttl", 30*time.Second, "SPA 放行窗口")
	gm := flag.Bool("gm", false, "隧道用国密 TLCP（SM2 双证书 + SM3/SM4），否则通用 TLS")
	certDir := flag.String("certdir", env("BAIDI_GW_CERTDIR", "certs"), "国密证书目录（持久化 CA 签发的双证书；首启自动生成）")
	pf := flag.Bool("pf", false, "内核态隐身：SPA 放行落到 macOS pf 表 baidi_allowed（默认 DROP，需 root + 已加载 anchor）")
	resources := flag.String("resources", env("BAIDI_GW_RESOURCES", ""), "资源注册表 JSON 路径（按目的多资源路由；空=仅默认后端）")
	control := flag.String("control", env("BAIDI_GW_CONTROL", ""), "baidi-control 地址；设了则向控制面注册并周期拉取资源策略（动态，优先于静态 -resources）")
	gwid := flag.String("gwid", env("BAIDI_GW_ID", "gw-1"), "本网关 id（控制面注册标识）")
	poll := flag.Duration("poll", 15*time.Second, "控制面策略轮询/心跳间隔")
	mtlsCert := flag.String("mtls-cert", env("BAIDI_GW_MTLS_CERT", ""), "控制面签发的网关客户端证书 PEM（mTLS 机器身份）")
	mtlsKey := flag.String("mtls-key", env("BAIDI_GW_MTLS_KEY", ""), "网关客户端私钥 PEM")
	mtlsCA := flag.String("mtls-ca", env("BAIDI_GW_MTLS_CA", ""), "控制面内部 CA 公证书 PEM（校验 mTLS 服务端）")
	strictKnock := flag.Bool("strict-knock", envBool("BAIDI_GW_KNOCK_STRICT", true),
		"严格敲门：只接受 control /knock-token 签发的短时效一次性令牌（use=knock）；"+
			"关闭则兼容长效会话令牌直接敲门——那会绕过封禁/账号状态/终端合规三道闸，仅限过渡")
	knockMaxTTL := flag.Duration("knock-max-ttl", 5*time.Minute,
		"敲门令牌寿命上界（纵深防御；须 ≥ control 的 knockTTL）")
	jwtPub := flag.String("jwt-pubkey", env("BAIDI_GW_JWT_PUBKEY", ""),
		"control 的**敲门**公钥 PEM 路径（部署期分发的 <knock 私钥>.pub），逗号分隔可装多把供轮换。"+
			"只装 knock 公钥即可——会话令牌用另一把密钥签，其 kid 在本地查不到，从密码学上就敲不开门")
	acceptHS256 := flag.Bool("accept-hs256", envBool("BAIDI_GW_ACCEPT_HS256", false),
		"是否接受旧的 HS256 共享密钥令牌（阶段4 起默认 false）；=true 为过渡逃生舱，会让持共享密钥者可伪造令牌")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	// 收口后网关不再持有任何共享密钥：令牌验证只靠 control 的敲门公钥。
	// 仅当显式打开 HS256 逃生舱时才需要 -secret。
	if *acceptHS256 && *secret == "" {
		log.Fatal("拒绝启动：-accept-hs256=true 需同时提供 -secret（旧共享密钥）")
	}
	if *secret != "" && !*acceptHS256 {
		slog.Warn("已忽略 -secret：HS256 兼容已关闭，网关只用 control 公钥验证令牌")
	}
	if !*strictKnock {
		slog.Warn("⚠ 严格敲门已关闭：长效会话令牌可直接敲门，绕过强制下线/账号禁用/终端合规三道闸，仅限过渡期")
	}
	verifier, err := auth.NewVerifier(*jwtPub, []byte(*secret), *acceptHS256)
	if err != nil {
		log.Fatalf("载入令牌验证材料失败: %v", err)
	}
	if !verifier.HasPublicKey() {
		slog.Warn("⚠ 未配置 control 公钥（-jwt-pubkey）：无法校验 EdDSA 令牌，" +
			"只能吃 HS256 存量令牌；请分发 control 的 <knock 私钥>.pub")
	}
	slog.Info("baidi-gateway 启动", "spa", *spaAddr, "proxy", *proxyAddr, "backend", *backend,
		"ttl", ttl.String(), "strictKnock", *strictKnock,
		"公钥数", verifier.PublicKeyCount(), "acceptHS256", verifier.AcceptsLegacy())

	al := spa.NewAllowlist()

	reg := resource.New(*backend)
	if *resources != "" {
		if err := reg.LoadFile(*resources); err != nil {
			log.Fatalf("加载资源注册表失败: %v", err)
		}
		slog.Info("资源注册表已加载", "file", *resources, "count", reg.Count())
	}

	// ── 隧道服务端凭据提前就绪 ──
	// 证书必须在**控制面注册之前**准备好，因为它的指纹要随注册心跳一起上报：网关的隧道证书
	// 是启动期自签的（国密路径是本地 CA 签的），没有公共 CA 可供客户端校验，客户端此前只能
	// InsecureSkipVerify——隧道加密但不认证，中间人可无声接管。改由控制面（真正的信任根）
	// 把指纹转发给客户端做证书钉扎。此前证书在 main 末尾才生成，注册时根本无从上报。
	var tlsCert tls.Certificate
	var tlcpCerts []tlcp.Certificate
	var tunnelFP string
	if *gm {
		tlcpCerts, err = gmcert.EnsureGateway(*certDir)
		if err != nil {
			log.Fatalf("生成/加载国密双证书失败: %v", err)
		}
		// TLCP 双证书中握手出示给客户端校验身份的是**签名证书**（EnsureGateway 返回的 [0]），
		// 加密证书只参与密钥交换——钉扎必须钉签名证书，否则客户端永远比对不上。
		if len(tlcpCerts) > 0 && len(tlcpCerts[0].Certificate) > 0 {
			tunnelFP = certFingerprint(tlcpCerts[0].Certificate[0])
		}
	} else {
		tlsCert = mustSelfSigned()
		tunnelFP = certFingerprint(tlsCert.Certificate[0])
	}
	slog.Info("隧道服务端证书就绪（指纹随注册下发给客户端做钉扎）", "gm", *gm, "fp", tunnelFP)

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
		// 机器身份只有 mTLS 客户端证书一条路：网关在代码层已无签发能力（阶段 4 删了 auth.Sign），
		// 没有证书就无从证明自己是网关——早失败好过起来后静默调不通。
		if *mtlsCert == "" || *mtlsKey == "" || *mtlsCA == "" {
			log.Fatal("拒绝启动：配了 -control 就必须同时配 -mtls-cert/-mtls-key/-mtls-ca。" +
				"用 admin 调 POST /api/v1/pki/gateway-certs 取证（响应含 certPem/keyPem/caPem）")
		}
		cp, cerr := cplane.NewMTLS(*control, *gwid, *proxyAddr, *spaAddr, *mtlsCert, *mtlsKey, *mtlsCA)
		if cerr != nil {
			log.Fatalf("mTLS 控制面客户端初始化失败: %v", cerr)
		}
		slog.Info("控制面身份：mTLS 客户端证书", "cert", *mtlsCert)
		cp.SetTunnelFP(tunnelFP) // 隧道证书指纹随后续每次注册心跳上报，供客户端钉扎
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
		if err := spa.Serve(*spaAddr, verifier, *ttl, al, *strictKnock, *knockMaxTTL); err != nil {
			log.Fatalf("SPA 监听失败: %v", err)
		}
	}()

	// 证书已在上文备妥（指纹须先于注册上报），这里只负责监听。
	if *gm {
		slog.Info("隧道加密：国密 TLCP（持久化 CA 签发的 SM2 双证书）", "certdir", *certDir)
		if err := proxy.ServeTLCP(*proxyAddr, tlcpCerts, reg, al); err != nil {
			log.Fatalf("TLCP 代理监听失败: %v", err)
		}
		return
	}
	slog.Info("隧道加密：通用 TLS（自签）")
	if err := proxy.Serve(*proxyAddr, tlsCert, reg, al); err != nil {
		log.Fatalf("代理监听失败: %v", err)
	}
}

// certFingerprint 计算证书 DER 的 SHA-256 指纹（小写 hex）。
// 与客户端 dataplane 的钉扎比对口径必须完全一致：都对**叶子证书的 DER 原文**取 SHA-256，
// 不含 PEM 头尾、不做 base64——换任一环节都会算出不同值而永远比对失败。
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
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
