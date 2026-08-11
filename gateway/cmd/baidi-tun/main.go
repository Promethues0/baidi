// Command baidi-tun 是白帝客户端数据面 CLI：用 TUN（macOS utun / Linux tun / Windows wintun）
// 真正接管系统流量进隧道。引擎在 internal/dataplane（与移动端 gomobile 库共享）。
// 需管理员/root（创建 TUN、配 IP/路由）。平台接口配置见 ifup_{darwin,linux,windows}.go。
// Windows 还需运行目录有 wintun.dll（https://www.wintun.net/）。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"golang.zx2c4.com/wireguard/tun"

	"baidi.dev/gateway/internal/dataplane"
	"baidi.dev/gateway/internal/gmcert"
)

const mtu = 1420

func main() {
	tunName := flag.String("tun", defaultTunName, "TUN 设备名（macOS 必须 utun*；Linux/Windows 任意如 baidi0）")
	tunIP := flag.String("ip", "10.99.0.2", "TUN 接口 IP")
	// 逗号分隔可传多个网段：真实业务地址往往散落在多个内网段（10.20.1.0/24 的 OA、
	// 10.30.5.0/24 的 Git…），只接管单个网段是「隧道通了但点开应用不走隧道」的根因。
	// 网段清单由控制面接入剖面下发（GET /api/v1/client/profile 的 routes），不该由用户手填。
	route := flag.String("route", "10.99.0.0/24", "引流进隧道的受保护网段，逗号分隔可多段（如 10.99.0.0/24,10.20.1.10/32）")
	spaAddr := flag.String("spa", "127.0.0.1:18201", "网关 SPA 敲门地址（单落点；有 -gateways 时被它取代）")
	proxyAddr := flag.String("proxy", "127.0.0.1:18443", "网关隧道代理地址（单落点；有 -gateways 时被它取代）")
	// 多落点（网关多活 + 故障转移）：清单由控制面接入剖面的 gateways 段下发，
	// **顺序即优先级**，客户端按序尝试、失败切下一个。一台网关挂掉不再等于全部终端断。
	// 与 -resmap/-dns-records 同一套写法（JSON 文件），由桌面客户端落盘后传入。
	gatewaysPath := flag.String("gateways", "", `网关落点清单 JSON 文件（控制面剖面下发，顺序即优先级）：`+
		`[{"id":"gw-a","spa":"h:18201","proxy":"h:18443","pin":"<hex>"}]；空=用 -spa/-proxy/-pin 单落点`)
	token := flag.String("token", "", "baidi-control 签发的 JWT")
	gm := flag.Bool("gm", false, "隧道用国密 TLCP，否则通用 TLS")
	caDir := flag.String("ca", "certs", "CA 证书目录（国密隧道校验网关证书链）")
	serverName := flag.String("servername", "baidi-gateway", "校验的服务器名（须在网关证书 SAN 内）")
	insecure := flag.Bool("insecure", false, "跳过证书校验（仅排障）")
	resmapPath := flag.String("resmap", "", "\"host:port\"→资源id 映射 JSON 文件（多资源路由；由控制面剖面生成，空=用 -resource 默认）")
	pin := flag.String("pin", "", "网关隧道证书 SHA-256 指纹（hex，控制面剖面下发）：对通用 TLS 隧道做证书钉扎；空=不认证网关身份")
	defaultRes := flag.String("resource", "", "默认资源 id（resmap 未命中时用；空=网关回退默认后端）")
	control := flag.String("control", "", "baidi-control 地址（必填）：换短时效一次性敲门令牌 + 定期保活续窗")
	reknock := flag.Duration("reknock", 15*time.Second, "敲门保活间隔（须 < 网关 SPA TTL；-control 模式生效）")
	// ── 隧道内 DNS（split-DNS）──
	// 只按域分流、不全局接管：全局接管会让所有 DNS 都走隧道，隧道一断全网解析全挂。
	// 三个参数都由控制面接入剖面的 dns 段下发，不该由用户手填。
	dnsListen := flag.String("dns-listen", "", "隧道内 DNS 解析器监听的 VIP（如 10.99.0.53，必须落在 -route 内）；空=不启用，域名类业务将不经隧道")
	dnsRecords := flag.String("dns-records", "", "\"FQDN\"→IP 记录表 JSON 文件（控制面剖面下发；配了 -dns-listen 才有意义）")
	dnsDomains := flag.String("dns-domains", "", "交给隧道内解析器的搜索域，逗号分隔（如 corp.internal）：只按域分流，不接管系统全局 DNS")
	device := flag.String("device", "", "终端硬件指纹（须与 posture 上报同一个值）：随敲门令牌上报，供控制面授信终端准入闸判定；空=不上报（严格模式下会被拒）")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	// 令牌优先取 -token；为空则回退 BAIDI_TOKEN 环境变量（避免出现在 ps 进程参数里泄露）。
	if *token == "" {
		*token = os.Getenv("BAIDI_TOKEN")
	}
	if *token == "" {
		log.Fatal("需 -token 或 BAIDI_TOKEN 环境变量（baidi-control 签发的 JWT）")
	}
	// 网关 strict 模式只接受 control 签发的 use=knock 短时效令牌，会话令牌敲不开门；
	// 没有 control 就无从取得，早失败好过起来后静默连不通。
	if *control == "" {
		log.Fatal("需 -control（baidi-control 地址）：敲门令牌的唯一合规来源")
	}

	// 国密隧道客户端配置：默认 CA 根校验，-insecure 仅排障
	tlcpCfg := &tlcp.Config{ServerName: *serverName}
	if *gm {
		if *insecure {
			tlcpCfg.InsecureSkipVerify = true
		} else {
			if *serverName == "" {
				log.Fatal("非 -insecure 模式必须指定非空 -servername（须命中网关证书 SAN）")
			}
			pool, err := gmcert.LoadCAPool(*caDir)
			if err != nil {
				log.Fatalf("加载 CA 失败（-ca 指目录或 -insecure 跳过）: %v", err)
			}
			tlcpCfg.RootCAs = pool
		}
	}

	// ── 网关落点清单 ──
	// 放在创建 TUN 之前解析：清单填错要在动系统状态之前失败。
	endpoints, err := loadGateways(*gatewaysPath, *spaAddr, *proxyAddr, *pin)
	if err != nil {
		log.Fatalf("网关落点清单不可用: %v", err)
	}
	if len(endpoints) == 1 {
		slog.Info("只有一个网关落点：无故障转移余量", "gateway", endpoints[0].ProxyAddr)
	} else {
		labels := make([]string, 0, len(endpoints))
		for _, e := range endpoints {
			labels = append(labels, e.Label()+"("+e.ProxyAddr+")")
		}
		slog.Info("网关落点清单已装载（顺序即优先级，由控制面剖面下发）",
			"count", len(endpoints), "order", strings.Join(labels, " → "))
	}

	resmap := map[string]string{}
	if *resmapPath != "" {
		b, err := os.ReadFile(*resmapPath)
		if err != nil {
			log.Fatalf("读取 resmap 失败: %v", err)
		}
		if err := json.Unmarshal(b, &resmap); err != nil {
			log.Fatalf("解析 resmap 失败: %v", err)
		}
	}

	// ── 隧道内 DNS 参数校验 ──
	// 全部放在创建 TUN **之前**：一个配置笔误不该先把接口建起来、把路由改一半，
	// 更不该起来之后才发现「隧道正常但域名全解析不了」——那行报错早被日志刷走了。
	dnsIP := strings.TrimSpace(*dnsListen)
	domains, err := splitDomains(*dnsDomains)
	if err != nil {
		log.Fatalf("-dns-domains 非法: %v", err)
	}
	records := map[string]string{}
	if *dnsRecords != "" {
		b, rerr := os.ReadFile(*dnsRecords)
		if rerr != nil {
			log.Fatalf("读取 DNS 记录表失败: %v", rerr)
		}
		m, perr := parseDNSRecords(b)
		if perr != nil {
			log.Fatalf("解析 DNS 记录表 %s 失败: %v", *dnsRecords, perr)
		}
		records = m
	}
	routes := splitRoutes(*route)
	if len(routes) == 0 {
		log.Fatal("需至少一个 -route 网段：没有网段就没有流量会进隧道（接得上但什么也访问不了）")
	}
	if dnsIP != "" {
		ip := net.ParseIP(dnsIP)
		if ip == nil || ip.To4() == nil {
			log.Fatalf("-dns-listen %q 不是合法 IPv4 字面量", *dnsListen)
		}
		// ★ 解析器 VIP 必须落在被接管的网段内，否则查询包压根不会进 utun，解析器永远
		// 收不到东西——症状是「解析超时」而不是「解析到错误地址」，排查时极易怀疑到
		// 解析器实现上去，其实是路由少了一条。这条闸把它变成启动即失败。
		if !routesCover(routes, ip) {
			log.Fatalf("-dns-listen %s 不在任何 -route 网段内（%v）：查询包不会进隧道，解析器收不到任何请求。"+
				"解析器 VIP 应由控制面剖面随 routes 一并下发", dnsIP, routes)
		}
		if len(records) == 0 {
			slog.Warn("隧道内 DNS 已启用但记录表为空：任何域名都会被回 REFUSED（控制面剖面的 dns.records 是空的？）")
		}
		if len(domains) == 0 {
			slog.Warn("隧道内 DNS 已启用但未指定 -dns-domains：系统不会把任何查询发给它，解析器形同虚设")
		}
	} else if len(domains) > 0 || len(records) > 0 {
		slog.Warn("未配置 -dns-listen，-dns-domains/-dns-records 不生效：域名类业务将走系统 DNS + 默认出口（直连内网，且没有任何提示）")
	}

	// ① 创建 utun（需 root）② 配 IP + 把受保护网段路由进 TUN（需 root，平台实现）
	dev, err := tun.CreateTUN(*tunName, mtu)
	if err != nil {
		log.Fatalf("创建 TUN 失败（需 root：sudo）: %v", err)
	}
	name, _ := dev.Name()
	slog.Info("TUN 已创建", "dev", name, "mtu", mtu)
	if err := ifup(name, *tunIP, routes); err != nil {
		log.Fatalf("配置 TUN 失败: %v", err)
	}
	slog.Info("受保护网段已引流进 TUN（系统流量接管）", "routes", routes, "via", name)

	// ③ 系统解析器按域分流：把 domains 的查询指向隧道内解析器。
	//
	// 这一步失败按致命处理：没有它，隧道起来了、解析器也在跑，但系统根本不会把查询
	// 发过来——用户看到的是「已接入」而域名类应用全部直连内网（或干脆连不上），
	// 且没有任何报错。本项目最迷惑人的失败形态就是这种「无报错的静默失效」，宁可起不来。
	// applySplitDNS 在返回错误前已把本次写过的部分回滚干净，故此处不必再清理。
	defer runDNSCleanup() // 幂等；正常返回路径的兜底（异常路径见下面的 fatal/信号处理）
	// ★残留清扫**无条件**先跑一次，不能只在本次启用 split-DNS 时跑。
	// 上一轮被 SIGKILL/断电杀掉留下的 /etc/resolver 文件（Windows 上是跨重启存活的
	// NRPT 注册表规则）指向一个已消失的 VIP；若此后控制面停用了 dns 段、或用户权限
	// 收窄使剖面不再下发搜索域，那些残留就再无回收点——该域名在这台机器上永久解析
	// 失败，而新一次接入一切显示正常、没有任何日志线索。
	sweepStaleDNSConfig()
	if dnsIP != "" && len(domains) > 0 {
		cleanup, derr := applySplitDNS(name, dnsIP, domains)
		if derr != nil {
			log.Fatalf("配置系统解析器失败（已回滚）: %v", derr)
		}
		setDNSCleanup(cleanup)
		slog.Info("系统解析器已按域分流（其余域名照旧走原出口）", "domains", domains, "server", dnsIP, "records", len(records))
	}

	// ★ 信号路径的清理：Tauri 侧断开用的是 `kill <pid>`（SIGTERM），托盘退出同理。
	// 收不到清理的话，/etc/resolver（或 NRPT 规则）会把该域名指向一个已经不存在的 VIP，
	// 症状是「断开客户端后这个域名永久解析失败」，用户根本不会联想到是客户端留下的。
	// 注意 SIGKILL 拦不住——那种残留只能靠下次启动时的扫描回收（见 resolver_*.go）。
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	var stopping atomic.Bool
	go func() {
		s := <-sigc
		slog.Warn("收到退出信号：先收回系统解析器配置，再停数据面", "signal", s.String())
		stopping.Store(true) // 必须先置位：否则 Run 返回的 "file already closed" 会被当成故障
		runDNSCleanup()
		_ = dev.Close() // 打断 dataplane.Run 的 pumpInbound → Run 返回 → main 正常退出
		// 兜底硬退：清理已经做完，若数据面因故没能退出，也不要留一个 root 进程常驻。
		time.AfterFunc(5*time.Second, func() { os.Exit(1) })
	}()

	// ④ 跑共享数据面引擎（阻塞）
	cfg := &dataplane.Config{
		Endpoints: endpoints, Token: *token, Control: *control,
		Gm: *gm, TLCPConfig: tlcpCfg, Resmap: resmap, DefaultRes: *defaultRes,
		Reknock: *reknock, MTU: mtu,
		DNSListen: dnsIP, DNSRecords: records,
		Device: *device,
	}
	if err := dataplane.Run(dev, cfg); err != nil {
		// ★ log.Fatalf 不跑 defer——这里必须显式清理，否则「数据面异常退出」会顺带
		// 留下一份指向死 VIP 的系统解析配置，把一次接入失败放大成持续性的域名故障。
		runDNSCleanup()
		// 用户主动断开时，Run 返回的是我们自己关掉 dev 造成的 "file already closed"。
		// 按故障打日志会让客户端 UI 在一次正常断开后显示一条莫须有的错误
		// （tunnel.ts 按「失败/退出」等关键词从日志里提取最近故障），故区别对待。
		if stopping.Load() {
			slog.Info("数据面已停止（收到退出信号，系统解析器配置已收回）")
			return
		}
		log.Fatalf("数据面退出: %v", err)
	}
}

// routesCover 判断 ip 是否落在任一受接管网段内。routes 已由 splitRoutes 校验过合法性，
// 这里解析失败直接跳过（不可能发生，也不值得为它改变调用方的错误处理形状）。
func routesCover(routes []string, ip net.IP) bool {
	for _, r := range routes {
		if _, ipnet, err := net.ParseCIDR(r); err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// splitRoutes 解析逗号分隔的网段清单，去空白与空项。
// 顺带做 CIDR 合法性校验：一条非法网段会让 `route add` 失败并中断整个接口配置，
// 与其在配路由的一半才炸，不如在创建 TUN 前就报出是哪一条不合法。
func splitRoutes(s string) []string {
	var out []string
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(r); err != nil {
			log.Fatalf("-route 中的网段 %q 不是合法 CIDR: %v", r, err)
		}
		out = append(out, r)
	}
	return out
}
