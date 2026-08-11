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
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"

	"baidi.dev/gateway/internal/auth"
	"baidi.dev/gateway/internal/cplane"
	"baidi.dev/gateway/internal/darkfw"
	"baidi.dev/gateway/internal/gmcert"
	"baidi.dev/gateway/internal/natfw"
	"baidi.dev/gateway/internal/proxy"
	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/spa"
	"baidi.dev/gateway/internal/sysstat"
	"baidi.dev/gateway/internal/webproxy"
)

// version 网关版本号，编译期注入：go build -ldflags "-X main.version=v0.x.y"。
// 随 mTLS 心跳上报控制面（deploy/build.sh 已接线），未注入时如实报 "dev"。
var version = "dev"

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
	statDisk := flag.String("stat-disk", env("BAIDI_GW_STAT_DISK", "/"),
		"设备状态里量哪个挂载点的磁盘水位（随心跳上报控制面；采不到的指标报「不可判定」而非 0）")
	natOn := flag.Bool("nat", envBool("BAIDI_GW_NAT", false),
		"启用地址转换（PRD 第 18 章）：把控制面下发的 SNAT/DNAT 策略灌进内核 nft/pf。需 root。"+
			"★启用后命中 NAT 的流量绕过 SPA 隐身，且网关以路由设备形态工作")
	natDry := flag.Bool("nat-dryrun", false,
		"只生成 NAT 规则集并打印，不灌内核（无 root 时核对规则用）")
	// ── 七层 Web 代理（PRD 8.3.3，B/S 免客户端接入）──
	// 默认关闭：它是一个**入站攻击面**，且与 SPA 隐身天然互斥（见下方启动告警）。
	webAddr := flag.String("web", env("BAIDI_GW_WEB", ""),
		"七层 Web 代理监听地址（如 :18444）；空=不开启。★该端口必须对浏览器可达，"+
			"不受 SPA 隐身保护——开启即等于在网关上公开一个入站 HTTP 面")
	webPub := flag.String("web-jwt-pubkey", env("BAIDI_GW_WEB_JWT_PUBKEY", ""),
		"control 的**Web 票据**公钥 PEM 路径（部署期分发的 <web 私钥>.pub），逗号分隔可装多把供轮换。"+
			"与敲门公钥分开装：拿错路径的票据在对面连签名都验不过")
	webCert := flag.String("web-cert", env("BAIDI_GW_WEB_CERT", ""),
		"七层监听的 TLS 证书 PEM；与 -web-key 同时给则直接跑 HTTPS，否则明文（须前置 nginx 终结 TLS）")
	webKey := flag.String("web-key", env("BAIDI_GW_WEB_KEY", ""), "七层监听的 TLS 私钥 PEM")
	webSessTTL := flag.Duration("web-session-ttl", 15*time.Minute,
		"七层会话 Cookie 寿命（不做滑动续期；到期回门户重新点开应用）")
	webTicketTTL := flag.Duration("web-ticket-max-ttl", 2*time.Minute,
		"Web 访问票据寿命上界（纵深防御；须 ≥ control 的 webTicketTTL=60s）")
	webMaxBody := flag.Int64("web-max-body", 64<<20, "七层代理单次响应体上界（字节）")
	webTrusted := flag.String("web-trusted-proxies", env("BAIDI_GW_WEB_TRUSTED_PROXIES", ""),
		"七层的可信前置代理网段（逗号分隔，单 IP 或 CIDR，如 127.0.0.1,10.0.0.0/8）。"+
			"★只有来自这些网段的请求，其 X-Forwarded-For/-Proto/-Host 才被采信；"+
			"不配的话前置 nginx 拓扑下后端看到的客户端 IP 恒为 nginx 自己，且 X-Forwarded-Proto 恒 http")
	webExtHost := flag.String("web-external-host", env("BAIDI_GW_WEB_EXTERNAL_HOST", ""),
		"七层对外主机名（如 oa.example.com:9443），下发给后端做 X-Forwarded-Host。"+
			"不配且对端不可信时**不下发**该头——Host 头是客户端可控的，当真实值转发即 Host header injection")
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
	// 七层 Web 代理的验证材料必须**另装一把**，且缺了就拒绝启动——起一个每张票都验不过
	// 的 L7 监听，只会让人以为"功能开了但业务连不上"，而真正的原因是没分发公钥。
	var webVerifier *auth.Verifier
	var webTrustedProxies []netip.Prefix
	if *webAddr != "" {
		webTrustedProxies, err = webproxy.ParseTrustedProxies(*webTrusted)
		if err != nil {
			log.Fatalf("拒绝启动：-web-trusted-proxies 解析失败（%v）。"+
				"一条写错的网段会静默退化成「谁都不可信」，与「配了但没生效」在日志里完全同形", err)
		}
		if *webPub == "" {
			log.Fatal("拒绝启动：开了 -web 就必须配 -web-jwt-pubkey（control 的 <BAIDI_JWT_WEB_KEY>.pub）。" +
				"它与敲门公钥是两把不同的密钥，不能互相顶替")
		}
		// ★这里刻意不传 legacy/acceptHS256：七层是本轮新增的入站面，没有任何存量令牌
		// 需要兼容，也就没有理由给它开 HS256 逃生舱。
		webVerifier, err = auth.NewVerifier(*webPub, nil, false)
		if err != nil {
			log.Fatalf("载入 Web 票据公钥失败: %v", err)
		}
		if (*webCert == "") != (*webKey == "") {
			log.Fatal("拒绝启动：-web-cert 与 -web-key 必须成对给出")
		}
		slog.Warn("⚠ 七层 Web 代理已开启：该端口对浏览器可达，**不受 SPA 隐身保护**。"+
			"它是一个入站攻击面，请只在需要 B/S 免客户端接入时开启，并置于 HTTPS 之后",
			"addr", *webAddr, "tls", *webCert != "")
		// 明文监听 + 没有可信代理 = 后端会永远收到 X-Forwarded-Proto: http，
		// 而文档推荐的部署恰恰是「明文 + 前置 nginx 终结 TLS」。这条在启动时说清楚，
		// 否则症状是「某些应用一点开就无限重定向」，没人会往 XFP 上想。
		if *webCert == "" && len(webTrustedProxies) == 0 {
			slog.Warn("⚠ 七层为明文监听且未配 -web-trusted-proxies：" +
				"后端看到的客户端 IP 会恒为前置代理自己、X-Forwarded-Proto 恒为 http。" +
				"前置 nginx 终结 TLS 的部署请把 nginx 的地址填进 -web-trusted-proxies")
		}
	}
	slog.Info("baidi-gateway 启动", "version", version, "spa", *spaAddr, "proxy", *proxyAddr, "backend", *backend,
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

	// ── 七层 Web 代理装配 ──
	// 与 L4 隧道**共用同一份资源注册表与放行表**，于是同一个资源在两条接入形态下的
	// 后端与授权完全一致，不存在第二套判定。
	//
	// ★装配必须排在控制面对接**之前**：强制下线的 L7 执行方（webSrv.KillUser）要被
	// applyRevoked 闭包捕获，而那个闭包在控制面块里当场就会被首轮策略调用。
	// 放在后面赋值就是一个数据竞争 + 首轮强制下线切不到 L7 连接。
	var webSrv *webproxy.Server
	if *webAddr != "" {
		sessKey, kerr := webproxy.NewSessionKey()
		if kerr != nil {
			log.Fatalf("生成 Web 会话签名密钥失败: %v", kerr)
		}
		webSrv, err = webproxy.New(webproxy.Config{
			Verifier: webVerifier, Registry: reg, Allow: al, SessionKey: sessKey,
			TicketMaxTTL: *webTicketTTL, SessionTTL: *webSessTTL, MaxBodyBytes: *webMaxBody,
			TLSTerminated:  *webCert != "" && *webKey != "",
			TrustedProxies: webTrustedProxies,
			ExternalHost:   *webExtHost,
			GatewayID:      *gwid,
		})
		if err != nil {
			log.Fatalf("七层 Web 代理装配失败: %v", err)
		}
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
		cp.SetVersion(version)   // 版本随心跳上报：控制面此前连网关跑的什么版本都不知道
		// 七层落点随心跳上报：控制面据此拼出浏览器该跳的入口 URL。没开就不上报，
		// 控制面于是能对门户如实回「本网关未开启七层 Web 代理」，而不是发一张跳不通的票。
		cp.SetWeb(*webAddr, *webCert != "" && *webKey != "")
		// 宿主机设备状态（PRD ch5 FR-MON-01）随心跳上报。采样源交给 cplane 在每次
		// Register 里调一次——CPU 与吞吐是差分指标，采样节奏必须与上报节奏一致。
		// 首次心跳里这两项必然缺席（还没有第二个采样点），控制面按不可判定落 NULL。
		cp.SetMetrics(sysstat.New(*statDisk).Sample)
		cp.SetIfaces(sysstat.Ifaces) // 网卡清单随心跳上报，供控制面配置地址转换时选接口
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
				// ★七层的已升级连接（WebSocket）也要切。少了这一条，回执里"切断 N 条隧道"
				// 只统计 L4，而一条 Web 终端的 WS 会继续搬运业务数据直到用户自己关标签页。
				nw := 0
				if webSrv != nil {
					nw = webSrv.KillUser(rv.User)
				}
				slog.Warn("强制下线执行：封禁敲门 + 撤销放行 + 切断隧道",
					"user", rv.User, "revoked_ips", ips, "killed_tunnels", n, "killed_web_conns", nw,
					"until", until.Format("15:04:05"))
				// 数据面回执：三元组动作**已执行完毕**才入队（措辞是已发生的事实，
				// 控制面原样落审计——「已下发」与「已生效」从此可区分）。
				webPart := ""
				if webSrv != nil {
					webPart = fmt.Sprintf("、切断 %d 条七层长连接", nw)
				}
				cp.QueueEvent("revoke-applied", fmt.Sprintf(
					"已撤销用户 %s 的放行窗口：封禁敲门至 %s、撤销放行 %d 个源IP、切断 %d 条隧道%s",
					rv.User, until.Format("15:04:05"), len(ips), n, webPart))
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
		// 替换资源策略并在资源数变化时入队回执（策略每 15s 全量重拉，逐条 diff 噪音大；
		// 资源数变化是「下发确已抵达数据面」最省的可观测信号）。
		applyPolicy := func(rs []resource.Resource) {
			before := reg.Count()
			reg.Replace(rs)
			if after := reg.Count(); after != before {
				cp.QueueEvent("policy-applied", fmt.Sprintf("资源授权策略已生效：资源数 %d→%d", before, after))
			}
		}
		// 地址转换（PRD 第 18 章）。规则由控制面策略编译而来，网关不做任何推导。
		//
		// ★排除项由**网关自己**填：控制面不知道本机隧道/敲门监听在哪个端口，
		// 而这两个端口上的流量若被 SNAT 改写源地址，回包就找不到发起方——
		// 症状是「配完 NAT 零信任就断了」，两件事之间没有任何线索。
		var natApp *natfw.Applier
		if *natOn || *natDry {
			natApp = natfw.New(natfw.Exempt{
				TunnelPort: portOf(*proxyAddr),
				SPAPort:    portOf(*spaAddr),
			})
			natApp.DryRun = *natDry
			if *natDry {
				slog.Warn("NAT 处于 dry-run：只生成规则集不灌内核")
			} else if !natApp.Available() {
				// 不静默退化：配了 -nat 却没有内核后端，规则一条都不会生效，
				// 而管理台上策略是「已启用」的——这正是最难自证的失效形态。
				log.Fatal("拒绝启动：-nat 需要内核防火墙后端（Linux 的 nft 或 macOS 的 pfctl），均未找到")
			} else {
				if err := natfw.EnableForwarding(); err != nil {
					// 转发关着的话规则全部正确但一个包都过不去，同样没有报错。
					slog.Error("打开内核 IP 转发失败：NAT 规则会全部正确但一个包都不通", "err", err.Error())
				}
				if on, known := natfw.ForwardingEnabled(); known && !on {
					slog.Error("内核 IP 转发仍处于关闭状态，NAT 不会生效")
				}
			}
			slog.Info("地址转换已启用", "backend", natApp.Backend(), "dryrun", *natDry,
				"exempt_tunnel", portOf(*proxyAddr), "exempt_spa", portOf(*spaAddr))
			defer natApp.Flush() //nolint:errcheck // 退出即清规则，别把 NAT 留在内核里
		}
		// applyNAT 把本轮下发的策略灌进内核。控制面**没下发** nat 字段（旧控制面）时
		// 保持现状不动——把「缺字段」读成「清空」会在升级控制面的瞬间抹掉生产 NAT 规则。
		applyNAT := func() {
			if natApp == nil {
				return
			}
			ps, present := cp.NATPolicies()
			if !present {
				return
			}
			changed, err := natApp.Apply(ps)
			if err != nil {
				slog.Error("地址转换规则灌入内核失败（保留上一版规则，下轮重试）", "err", err.Error())
				return
			}
			if changed {
				slog.Info("地址转换规则已更新", "policies", len(ps))
				cp.QueueEvent("nat-applied", fmt.Sprintf("地址转换规则已灌入内核：%d 条策略生效", len(ps)))
			}
		}
		if err := cp.Register(report()); err != nil {
			slog.Warn("控制面注册失败（继续轮询重试）", "err", err.Error())
		}
		if rs, rv, err := cp.Policy(); err != nil {
			slog.Warn("首次拉取策略失败，暂用本地默认/静态策略", "err", err.Error())
		} else {
			applyPolicy(rs)
			applyRevoked(rv)
			applyNAT()
			slog.Info("控制面策略已拉取", "control", *control, "count", reg.Count())
		}
		go func() {
			t := time.NewTicker(*poll)
			defer t.Stop()
			for range t.C {
				_ = cp.Register(report()) // 心跳 + 上报真实活性指标与活跃会话 + 捎带版本与数据面回执
				if rs, rv, err := cp.Policy(); err == nil {
					applyPolicy(rs)
					applyRevoked(rv)
					applyNAT()
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

	if webSrv != nil {
		go func() {
			if err := webSrv.Serve(*webAddr, *webCert, *webKey); err != nil {
				log.Fatalf("七层 Web 代理监听失败: %v", err)
			}
		}()
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

// portOf 从监听地址（":18443" / "0.0.0.0:18443"）里取端口号；取不到回 0。
// NAT 的排除规则要按端口写，而端口只有本进程知道（控制面不下发监听地址）。
func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return n
}
