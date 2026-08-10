// 客户端「接入剖面」（access profile）下发。
//
// ★这是补齐整条数据链路的关键一环。在此之前，客户端只知道「网关在哪」，却不知道
// 「哪些地址该进隧道」「进了隧道该报哪个资源 id」——于是 baidi-tun 只能接管一个手填的
// 网段（默认 10.99.0.0/24），而真实业务地址（10.20.1.10:8080）根本不在其中：
// 隧道明明建起来了，用户点开应用却完全不走隧道。客户端「连上了但没用」的根因就在这里。
//
// 剖面把控制面独有的三份知识一次性下发给客户端，让客户端不必、也不允许自己猜：
//
//	① 网关落点     —— 从在线网关注册信息取真实 spa/proxy 地址（不再让用户手填）
//	② 路由表       —— 需要被 utun 接管的网段（VIP 段 + 每个后端 /32）
//	③ 资源映射表   —— "host:port → 资源 id"，即 baidi-tun 的 -resmap
//	④ 分离式 DNS   —— 隧道内解析器 VIP + 分流域 + "FQDN → VIP" 记录表
//
// ★④ 补的是同一个洞的另一半。在此之前，剖面只按 **IP** 组织路由：管理员配一个
// `oa.corp.internal:8080` 的应用，客户端排不出 /32 路由、也无从接管，流量按默认出口
// 直连内网，**没有任何报错**——隧道显示"已接入"，业务却走了明文旁路。企业里业务系统
// 几乎都靠域名访问，所以域名后端不接管等于这条链路对大多数场景根本不成立。
// 补法见 buildDNSPlan：域名后端同样拿 VIP，控制面把「域名 → VIP」直接下发给终端解析器，
// 于是域名访问收敛到既有的「VIP → CONNECT <资源id>」路径，授权与审计口径丝毫不变。
//
// 安全姿态：剖面里**只**包含调用者当前有权访问的资源（含有效期内的 JIT 授予）。
// 无权资源不进 resmap，客户端从路由层就不会接管它——但这只是**纵深**，不是判定权：
// 真正的授权闸始终在网关侧 resource.Authorize（数据面拿到 id 后仍会重新鉴权）。
// 剖面泄露也不能提权，因为它只是「路由提示」，不是凭据。
package api

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// 客户端虚拟网段（VIP）默认值。VIP 是控制面给每个受控资源分配的**稳定本地别名**：
// 客户端既可以直接访问业务真实地址（透明模式，像传统 VPN），也可以访问 VIP
// （真实拓扑不下发到终端，更贴合零信任的最小知悉）。两者在 resmap 里指向同一资源 id。
const (
	defaultVIPCidr = "10.99.0.0/24"
	defaultTunIP   = "10.99.0.2"
	// vipFirstHost 是 VIP 分配的起始主机号。.1 留给网段网关语义、.2 是 utun 自身地址，
	// 故从 .11 起分配，给未来的保留地址留出余量。
	vipFirstHost = 11
	// vipResolverHost 是隧道内 DNS 解析器占用的主机号（取 53 = DNS 端口号，运维一眼能认出来）。
	//
	// ★它必须从资源 VIP 的分配区间里**挖掉**：资源 VIP 是 vipFirstHost 起连续递增的，
	// 不挖的话第 43 个资源（11+42=53）会和解析器抢同一个地址。症状是「某一个应用死活
	// 连不上」，而具体是哪个应用取决于资源 id 的字典序——归因难度极高。
	// 挖除**无条件**执行（哪怕本次没有任何域名后端、DNS 段是空的），否则「新增一个域名
	// 应用」会让 40 多个资源的 VIP 集体后移一位，用户存的书签与 SSH 配置全部失效。
	vipResolverHost = 53
	// vipLastHost 是 VIP 分配的末位主机号。/24 里 .255 是广播地址，故止于 .254。
	vipLastHost = 254
)

// ClientProfile 是下发给终端客户端的接入剖面。字段全部为「客户端照做即可」的成品，
// 不需要终端做任何策略推导——推导权留在控制面，终端只是执行器。
type ClientProfile struct {
	GeneratedAt string            `json:"generatedAt"`
	User        string            `json:"user"`
	Gateway     ProfileGateway    `json:"gateway"`
	VIPCidr     string            `json:"vipCidr"` // VIP 网段
	TunIP       string            `json:"tunIp"`   // utun 接口自身地址
	Routes      []string          `json:"routes"`  // 需接管进隧道的网段（CIDR）
	Apps        []ProfileApp      `json:"apps"`
	Resmap      map[string]string `json:"resmap"` // "host:port" → 资源 id（即 baidi-tun 的 -resmap）
	DNS         ProfileDNS        `json:"dns"`    // 隧道内分离式 DNS；Server 为空 = 无域名后端，客户端不必起解析器
	Warnings    []string          `json:"warnings,omitempty"`
}

// ProfileDNS 客户端分离式 DNS（split-DNS）配置。
type ProfileDNS struct {
	// Server 隧道内解析器的 VIP（如 10.99.0.53）。它本身也必须在 routes 里。
	Server string `json:"server"`
	// Domains 需要交给隧道内解析器的搜索域（如 ["corp.internal"]）。
	// ★只按域分流、不全局接管：全局接管会让所有 DNS 走隧道，隧道一断全网解析全挂。
	Domains []string `json:"domains"`
	// Records FQDN（小写、不带尾点）→ VIP。客户端解析器据此直接作答。
	Records map[string]string `json:"records"`
}

// ProfileGateway 网关落点。取自网关自身的 mTLS 注册上报，而非管理员在终端手填——
// 手填地址是"客户端连不通"的经典来源，也让网关迁移必须挨个改终端。
type ProfileGateway struct {
	Host      string `json:"host"`
	SPAPort   string `json:"spaPort"`
	ProxyPort string `json:"proxyPort"`
	// TunnelPin 是网关隧道 TLS 证书的 SHA-256 指纹（hex）。网关证书是启动期自签的，
	// 没有公共 CA 可依赖，客户端此前只能 InsecureSkipVerify——隧道加密但不认证，
	// 中间人可无声接管。指纹由**控制面**下发（信任根是控制面，不是连接本身），
	// 客户端据此做证书钉扎，把"加密"补成"加密 + 认证"。空=网关未上报，客户端应告警。
	TunnelPin string `json:"tunnelPin"`
	// Online 网关是否在心跳新鲜期内。false 表示以下地址是回退配置（环境变量兜底），
	// 客户端仍可尝试接入，但应把"网关离线"显著提示给用户，而不是让接入静默失败。
	Online bool `json:"online"`
}

// ProfileApp 一个应用在客户端侧的完整落点。
type ProfileApp struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Mode string `json:"mode"` // tunnel | web | global
	// Sensitivity 资源敏感度（low | normal | high），取自 store.Resource.Sensitivity。
	// ★不再由 `app.Category == "finance"` 派生：那条硬编码只认财务一个分类，
	// 管理员新建的任何高敏资源都会被当成普通资源，风险降权对它形同虚设。
	Sensitivity string `json:"sensitivity"`
	ResourceID  string `json:"resourceId"`
	Backend     string `json:"backend"` // 业务真实 host:port（透明访问用）
	VIP         string `json:"vip"`     // 控制面分配的虚拟 IP
	Port        int    `json:"port"`
	// URL 是「点开即用」的地址。web 模式给 http(s)://，其余给 host:port 供用户自行连接
	// （SSH/数据库等）。客户端 Apps 页直接用它，不再是弹 toast 的假动作。
	URL string `json:"url"`
	// Accessible 当前是否可直接访问。false 有两种成因，客户端提示语不同：
	//   - 无权限：需走 JIT 自助申请审批；
	//   - Degraded=true：终端不合规被降权，申请审批也没用，得先修好终端。
	Accessible bool `json:"accessible"`
	// Degraded 该资源此刻**因终端风险降权**而不可访问（而非因为没授权）。
	//
	// ★把两种"不可访问"分开，是因为用户的下一步动作完全不同：区分不了的话，
	// 一个被降权的用户会一遍遍提交必然无效的访问申请（降权否决优先于 JIT 授予），
	// 而审批人那边看到的是一张看不出问题的正常申请单。
	Degraded bool `json:"degraded,omitempty"`
}

// handleClientProfile 下发接入剖面（GET /api/v1/client/profile，需登录）。
func (s *Server) handleClientProfile(w http.ResponseWriter, r *http.Request) {
	// 与门户同一道闸：只认 admin/user 会话，拒 gateway 身份与 WebAuthn 中间票据(role=mfa)。
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	apps, err := s.store.Apps(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load apps")
		return
	}
	resources, err := s.store.Resources(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load resources")
		return
	}
	prof := s.buildProfile(r.Context(), normUser(c.Name), c.Role, apps, resources)
	httpx.JSON(w, http.StatusOK, prof)
}

// buildProfile 组装剖面。抽成纯函数（除 store 读取外无副作用）以便单元测试覆盖
// VIP 分配的确定性、越权资源的排除、以及 routes 去重。
func (s *Server) buildProfile(ctx context.Context, user, role string, apps store.AppBundle, resources []store.Resource) ClientProfile {
	byRes := make(map[string]store.Resource, len(resources))
	for _, res := range resources {
		byRes[res.ID] = res
	}

	// 组织/用户组主体的展开索引。★与 handleGatewayPolicy 用的是同一个 store 方法、
	// 同一份展开实现：剖面里「有没有这条路由」与网关侧「放不放行」必须同真同假。
	subjects := s.subjectIndex(ctx)

	// 有效期内的 JIT 授予：把高敏资源临时翻回可访问。读失败按「无授予」处理（fail-closed）。
	granted := map[string]bool{}
	if gs, err := s.store.ActiveGrantsFor(ctx, user); err == nil {
		for _, g := range gs {
			granted[g.ResourceID] = true
		}
	}

	// 终端风险降权：本人是否处于 degrade 档。判据与网关下发那份同源
	// （都是"跨设备取最差"的 posture 判定），只是这里只关心调用者自己。
	degraded, degradeReason := s.degradeStateOf(ctx, user)

	// ── VIP 分配必须确定性 ──
	// 同一用户重复拉剖面、以及不同终端拉同一资源，都必须得到同一个 VIP：否则客户端每次
	// 重连 VIP 都变，用户存的书签、SSH 配置全部失效。故按资源 id 字典序稳定分配，
	// 而不是按 map 迭代序或应用列表顺序（两者都不稳定）。
	resIDs := make([]string, 0, len(resources))
	for id := range byRes {
		resIDs = append(resIDs, id)
	}
	vipCidr := envOr("BAIDI_CLIENT_VIP_CIDR", defaultVIPCidr)
	base, warn := vipBase(vipCidr)
	var warnings []string
	if warn != "" {
		warnings = append(warnings, warn)
		vipCidr = defaultVIPCidr
		base, _ = vipBase(defaultVIPCidr)
	}
	vipOf := assignVIPs(resIDs, base)
	if len(vipOf) < len(resIDs) {
		warnings = append(warnings, fmt.Sprintf("VIP 号段 %s 已分配满（可用 %d 个，资源 %d 个），部分资源只能用真实地址访问",
			vipCidr, vipLastHost-vipFirstHost, len(resIDs)))
	}
	resolverVIP := offsetIP(base, vipResolverHost)

	// routes 用 set 去重：多个应用常落在同一后端主机（如 OA 与工单同机不同端口），
	// 重复下发 /32 会让 `route add` 第二次报「已存在」而中断接口配置。
	routeSet := map[string]bool{vipCidr: true}
	resmap := map[string]string{}
	out := make([]ProfileApp, 0, len(apps.Apps))
	// 域名形式后端的登记单，主循环只收集、循环后统一定序处理（见 buildDNSPlan）：
	// 同一个域名可能被多个资源用不同端口引用，「这条 A 记录归谁的 VIP」必须一次性裁决，
	// 边遍历边定会依赖 apps 的迭代顺序，而那个顺序是不稳定的。
	var domainBackends []domainBackend
	// 被降权摘掉的应用名，用于组装那条"让用户知道为什么"的告警。
	var degradedApps []string

	for _, a := range apps.Apps {
		if a.Status != "running" {
			continue // 已停用的应用不进剖面，免得终端接管一个必然连不通的地址
		}
		// global 模式（如 *.cnki.net 全网资源）没有确定的内网落点，不参与隧道路由。
		// 这类应用靠系统默认出口直连，剖面里给出但不写 resmap/route。
		if a.Mode == "global" {
			// 没有受控资源就没有敏感度可言（也不经隧道、不受降权约束）：如实标 normal。
			out = append(out, ProfileApp{
				ID: a.ID, Name: a.Name, Mode: a.Mode, Sensitivity: store.SensitivityNormal,
				Backend: a.Addr, URL: a.Addr, Accessible: true,
			})
			continue
		}
		res, hasRes := byRes[a.ResourceID]
		if !hasRes {
			// 应用未桥接到受控资源 → 网关无法按 id 查后端，隧道内报不出目标。
			// 这类应用是配置缺口，明确告警而不是静默漏掉（此前正是这类缺口被忽略）。
			warnings = append(warnings, fmt.Sprintf("应用「%s」未关联受控资源，无法经隧道访问（请在资源策略页补齐 resourceId）", a.Name))
			continue
		}
		// ── 可访问性判定：必须与网关侧完全同构 ──
		// 网关的权威闸是 resource.Authorize(静态 ACL + DenyUsers)，而控制面在下发网关策略时
		// 会把**组织/用户组展开出的账号**与**有效期内的 JIT 授予**一并并入 AllowUsers、
		// 把**被降权账号**写进高敏资源的 DenyUsers（见 handleGatewayPolicy → expandForGateway）。
		// 所以这里的判定也必须是「(静态 ACL ∪ 组织/组展开 ∪ 有效 JIT 授予) ∧ ¬降权否决」
		// ——少算任何一项的后果都是「策略/审批明明生效了，剖面里却没有该资源的 VIP 与路由」，
		// 多算则是「剖面排了路由、网关那边照拒」，两个方向都毫无报错。判定只有 accessibleFor 一处。
		hasGrant := granted[res.ID]
		accessible := accessibleFor(user, role, res, subjects, hasGrant, degraded)
		sens := res.Sensitivity
		degradeHit := degraded && res.HighSensitivity()
		if degradeHit {
			degradedApps = append(degradedApps, a.Name)
		}

		host, portStr, err := net.SplitHostPort(res.Backend)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("资源「%s」后端地址非法（%s），已跳过", res.Name, res.Backend))
			continue
		}
		port, _ := strconv.Atoi(portStr)
		vip := vipOf[res.ID]
		// 后端是 IP 字面量还是域名，决定了客户端用哪条路接管它：
		// IP → 直接下发 /32 路由；域名 → 走隧道内 DNS，把名字解析到 VIP。
		ipLit := net.ParseIP(host)
		isIPv4 := ipLit != nil && ipLit.To4() != nil
		fqdn := normFQDN(host)

		if accessible {
			// VIP 一侧恒登记：用户访问 10.99.0.14:8080 即命中该资源，且不暴露内网拓扑。
			resmap[net.JoinHostPort(vip, portStr)] = res.ID
			routeSet[vip+"/32"] = true

			switch {
			case isIPv4:
				// 真实后端一侧也登记（透明模式，兼容既有书签/配置）——两条路径在网关侧
				// 收敛到同一个 CONNECT <id>，鉴权与审计口径完全一致。
				// 强行给域名加 /32 路由会失败并中断整个接口配置，故只对 IP 字面量下发。
				resmap[res.Backend] = res.ID
				routeSet[host+"/32"] = true
			case validDNSName(fqdn):
				// ★域名后端**刻意不**登记 "域名:端口" 这一侧的 resmap 键，这个不对称是有意的：
				// resmap 是客户端按「连接的目的地址」反查资源 id 用的，而目的地址永远是一个 IP
				// ——客户端拿不到（也不该拿到）业务的真实 IP，"oa.corp.internal:8080" 这个键
				// 永远不可能被命中。登记它只会让人误以为透明模式对域名也生效，从而掩盖真正的
				// 接管路径（DNS 解析到 VIP → 命中 VIP 侧的键）。
				domainBackends = append(domainBackends, domainBackend{
					fqdn: fqdn, resID: res.ID, resName: res.Name, port: portStr, vip: vip,
				})
			case ipLit != nil:
				// IPv6 字面量后端：整条客户端数据面目前是 IPv4 单栈（VIP 段是 /24、
				// 隧道内解析器也只答 A 记录），接管不了。单独报出来，别让它掉进
				// 下面那条"不是合法域名"的分支——那句话对着一个 IPv6 地址完全对不上号。
				warnings = append(warnings, fmt.Sprintf("资源「%s」的后端是 IPv6 地址（%s），客户端数据面当前为 IPv4 单栈，无法接管", res.Name, host))
			default:
				// 通配符（*.cnki.net）之类的写法不是合法域名，装进解析器也永远答不出来。
				// 显式告警而不是静默丢弃——静默的结果是管理台配得好好的、客户端就是连不上。
				warnings = append(warnings, fmt.Sprintf("资源「%s」的后端主机名 %q 不是合法域名（通配符/非法字符无法在隧道内解析），已跳过 DNS 登记", res.Name, host))
			}
		}
		// 不可访问的资源仍作为磁贴下发（客户端显示「申请权限」入口），但**不进** resmap
		// 与 routes，也不进 DNS 记录：终端不接管它的流量，网关也不会收到该资源的 CONNECT。
		// 可见性与可达性在此刻意分离——看得见不等于连得上。

		// 域名后端的「点开即用」地址用**域名**而不是 VIP：VIP 拼出来的 URL 会让基于
		// Host 头/SNI 的虚拟主机路由与 TLS 证书校验失败，现象是隧道通了、页面却 404 或
		// 证书告警；SSH 同理（known_hosts 认的是域名）。名字已由隧道内解析器指向 VIP，
		// 用域名既正确又不多暴露什么——真实后端地址本来就在 Backend 字段里。
		urlHost := vip
		if ipLit == nil { // 只有真域名才换，IP 字面量（含 IPv6）一律沿用 VIP
			urlHost = fqdn
		}
		out = append(out, ProfileApp{
			ID: a.ID, Name: a.Name, Mode: a.Mode, Sensitivity: sens,
			ResourceID: res.ID, Backend: res.Backend, VIP: vip, Port: port,
			URL: appURL(a.Mode, urlHost, port), Accessible: accessible, Degraded: degradeHit,
		})
	}

	// ── 隧道内分离式 DNS ──
	// 记录表定完才知道每个域名最终落在哪个 VIP 上，故 resmap 还要再补一批「承载 VIP:端口」
	// 的键（同名多端口的场景下，它们和资源自身的 VIP 不是同一个，见 buildDNSPlan）。
	dnsPlan, dnsResmap, dnsWarns := buildDNSPlan(resolverVIP, domainBackends)
	for k, v := range dnsResmap {
		resmap[k] = v
	}
	warnings = append(warnings, dnsWarns...)
	if dnsPlan.Server != "" {
		// ★解析器 VIP 必须自己也在 routes 里。虽然它落在 vipCidr 内、名义上已被覆盖，
		// 但这条 /32 是防线：一旦运维把 BAIDI_CLIENT_VIP_CIDR 收窄到不含 .53，
		// 查询就会按默认路由送出隧道石沉大海，症状是「配了 DNS 却全部超时」——
		// 不是解析错误、不是拒绝，是纯粹的没有回音，最容易怀疑到解析器实现头上。
		routeSet[dnsPlan.Server+"/32"] = true
	}

	routes := make([]string, 0, len(routeSet))
	for r := range routeSet {
		routes = append(routes, r)
	}
	sort.Strings(routes) // 稳定顺序：便于客户端 diff 出「路由表变了」并按需重配接口

	gw, gwWarn := s.profileGateway()
	if gwWarn != "" {
		warnings = append(warnings, gwWarn)
	}
	// ★降权告警**排在最前**：客户端「应用」页只 toast 第一条 warning，而"我为什么打不开
	// 财务系统"是此刻用户最需要的答案，优先级高于任何配置缺口提示。
	// 降权而用户不知情，就会退化成「明明有权限却打不开」——本项目反复警告的那种迷惑失败形态。
	if w := degradeWarning(degradedApps, degradeReason); w != "" {
		warnings = append([]string{w}, warnings...)
	}
	return ClientProfile{
		GeneratedAt: time.Now().Format(time.RFC3339),
		User:        user,
		Gateway:     gw,
		VIPCidr:     vipCidr,
		TunIP:       envOr("BAIDI_CLIENT_TUN_IP", defaultTunIP),
		Routes:      routes,
		Apps:        out,
		Resmap:      resmap,
		DNS:         dnsPlan,
		Warnings:    warnings,
	}
}

// degradeStateOf 判断某账号此刻是否处于风险降权档，并给出可读原因。
//
// 判据是「跨设备取最差」的 posture 判定（store.PostureVerdict），与下发网关的降权名单
// （store.PostureUsersByDisposal，"任一设备命中"）是同一条口径的两种取法：
// 最差判定为 degrade ⟺ 有设备判 degrade 且没有设备判 block。block 用户走的是撤销名单
// 那条全断路径，不需要（也不该）在这里再被算成降权——那会让"已被阻断"显示成"已降权"。
//
// 读失败按「未降权」处理，理由见 (*Server).degradedUsers 的说明：降权是收缩动作，
// 读不到时宁可短暂不收缩，也不能凭空把用户的高敏资源关掉。
func (s *Server) degradeStateOf(ctx context.Context, user string) (bool, string) {
	rep, ok, err := s.store.PostureVerdict(ctx, user)
	if err != nil {
		slog.Error("终端降权判定读取失败，本次剖面按「未降权」下发", "账号", user, "err", err.Error())
		return false, ""
	}
	if !ok || rep.Verdict != store.DisposalDegrade {
		return false, ""
	}
	return true, strings.Join(rep.Reasons, "、")
}

// degradeWarning 组装下发给终端的降权告警文案。
// 只在**确实有资源被摘掉**时才出现：一个降级用户如果本来就没有任何高敏资源的权限，
// 告诉他"高敏资源已暂停"只会制造困惑（他从来也没有过）。
//
// ★恢复那句话必须把两半说清，不能只写「自动恢复」：
//   - 网关那半确实自动——降权名单每轮现算，下一次策略轮询（≤30s）里就没有他了；
//   - 客户端那半不自动——baidi-tun 的路由/DNS 记录在 tunnel_start 那一刻定死
//     （见 clients/desktop/src/lib/tunnel.ts 的 startedOpts），剖面刷新不会重配
//     已建接口。降权期间接入的隧道里根本没有高敏资源的 VIP /32 与 DNS 记录，
//     恢复合规后用户看到的是「已接入、提示已恢复、财务系统还是打不开」。
//     只说自动恢复，等于把这条最难查的失败形态写成了预期行为。
func degradeWarning(apps []string, reason string) string {
	if len(apps) == 0 {
		return ""
	}
	names := strings.Join(apps, "、")
	if len(apps) > 3 {
		names = strings.Join(apps[:3], "、") + fmt.Sprintf(" 等 %d 项", len(apps))
	}
	if reason == "" {
		reason = "终端环境检查未通过"
	}
	return fmt.Sprintf("因终端合规降级：%s 等高敏资源已暂停访问（普通资源不受影响，隧道未断开），原因：%s。"+
		"修复终端问题并重新上报后，网关侧下一轮（30s 内）自动恢复放行；若隧道是在降级期间建立的，"+
		"还需断开后重新接入——隧道路由在拉起那一刻定死，不重连拿不回这些资源的路由", names, reason)
}

// assignVIPs 给每个资源 id 分配一个 VIP 主机号。
//
// ★主机号由**资源 id 的哈希**决定，而不是它在排序列表里的下标。
// 下标法看似确定（同一集合两次调用结果一致），但只要管理员增删任何一个资源，
// 字典序在其后的全部资源 VIP 就集体位移一格：用户存进 SSH 配置的 10.99.0.11
// 要么连不通（resmap 里那个键没了），要么更糟——被相邻资源接住，端口恰好也相同时
// 静默连到**另一个业务系统**上。这正是 vipResolverHost 无条件挖除要防的失败形态，
// 而增删资源比新增域名应用常见得多。
//
// 哈希撞号时按 id 字典序先到先得、后到者线性探测下一个空号。这一步仍依赖集合内容，
// 但影响面从「其后的全部资源」缩到「恰好撞号的那一个」。
func assignVIPs(ids []string, base [4]byte) map[string]string {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)

	span := vipLastHost - vipFirstHost + 1
	used := make(map[int]bool, len(sorted))
	out := make(map[string]string, len(sorted))
	for _, id := range sorted {
		sum := sha256.Sum256([]byte(id))
		start := int(binary.BigEndian.Uint32(sum[:4]) % uint32(span))
		for i := 0; i < span; i++ {
			h := vipFirstHost + (start+i)%span
			if h == vipResolverHost || used[h] {
				continue // 解析器的号无条件挖除，见 vipResolverHost 注释
			}
			used[h] = true
			out[id] = offsetIP(base, h)
			break
		}
		// 号段被占满时该资源没有 VIP：resmap 仍登记真实后端地址，
		// 只是「点开即用」的 VIP 形态不可用。调用方据此给告警。
	}
	return out
}

// domainBackend 一条域名形式的后端登记（只有**可访问**的资源才会进来）。
type domainBackend struct {
	fqdn    string // 已规范化：小写、无尾点
	resID   string
	resName string
	port    string
	vip     string // 该资源自身的 VIP
}

// buildDNSPlan 由域名后端清单推导出下发给终端的 DNS 段，并返回需要补进 resmap 的键
// 与告警。无域名后端时返回空 Server——客户端据此完全不启用解析器，也就不会去动系统
// DNS 配置（少改一处系统状态，就少一处退出时要清理的东西）。
func buildDNSPlan(server string, items []domainBackend) (ProfileDNS, map[string]string, []string) {
	plan := ProfileDNS{Domains: []string{}, Records: map[string]string{}}
	if len(items) == 0 {
		return plan, nil, nil
	}

	// ★定序是硬要求。同一个域名被多个资源引用时（`git.corp.internal:22` 与
	// `git.corp.internal:8443` 是很常见的一对），A 记录只能指向一个 VIP，"谁赢"若取决于
	// 应用列表的迭代顺序，同一份配置在不同次调用间就会给出不同的解析结果：用户重连一次
	// 就有一个应用换了地址。按 (域名, 资源 id) 排序 → 字典序最小的资源恒定拿到承载权。
	sorted := append([]domainBackend(nil), items...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].fqdn != sorted[j].fqdn {
			return sorted[i].fqdn < sorted[j].fqdn
		}
		return sorted[i].resID < sorted[j].resID
	})

	extra := map[string]string{}   // 补进 resmap 的「承载 VIP:端口 → 资源 id」
	owner := map[string]string{}   // "域名|端口" → 资源 id，用于查重
	domainSet := map[string]bool{} // 待下发的分流域
	var warns []string

	for _, it := range sorted {
		vip, seen := plan.Records[it.fqdn]
		if !seen {
			vip = it.vip // 首个（字典序最小）资源的 VIP 承载这个名字
			plan.Records[it.fqdn] = vip
			if d := searchDomainFor(it.fqdn); d != "" {
				domainSet[d] = true
			}
		}
		key := it.fqdn + "|" + it.port
		if prev, dup := owner[key]; dup {
			// 两个资源的后端**完全相同**（同名同端口）：域名访问只有一个目的地，
			// 必然只命中其中之一。这是配置重复，不报出来就是一个资源永远访问不到。
			warns = append(warns, fmt.Sprintf("资源「%s」与「%s」的后端完全相同（%s:%s），经域名访问只会命中前者，请合并或改用不同端口", prev, it.resName, it.fqdn, it.port))
			continue
		}
		owner[key] = it.resName
		// 把本资源的端口挂到**承载 VIP** 上：域名解析到承载 VIP 后，靠端口区分是哪个资源。
		// 资源自身 VIP 的那条键由主循环登记，两条并存（两种访问姿态都通）。
		extra[net.JoinHostPort(vip, it.port)] = it.resID
	}

	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	sort.Strings(domains) // 稳定顺序：客户端据此 diff 出「该重配哪些 /etc/resolver 文件」
	plan.Domains = pruneSubDomains(domains)
	plan.Server = server
	return plan, extra, warns
}

// searchDomainFor 从域名后端推导出交给隧道内解析器的分流域。
//
// ★绝不能把公共后缀当分流域下发。`shop.example.com` 若推出 `com`，用户**整个互联网的
// DNS** 都会被劫进隧道，而我们的解析器对未知名字一律 REFUSED（刻意不做递归转发）——
// 结果是接入隧道后全网域名解析崩掉，且断开隧道前无法自愈。
//
// 保守判断：父域至少两级、且不在已知公共后缀清单里，才敢按域分流；否则退回只分流
// 这一个 FQDN 自己。退回而不是放弃，是因为放弃的后果同样是静默的：记录下发了，但操作
// 系统压根不会把这个名字问到我们这里，表现为「配了 DNS 记录却不生效」。
func searchDomainFor(fqdn string) string {
	if fqdn == "" {
		return ""
	}
	labels := strings.Split(fqdn, ".")
	if len(labels) >= 3 { // 父域 = 去掉首标签后仍有 ≥2 级
		if parent := strings.Join(labels[1:], "."); !publicSuffixes[parent] {
			return parent
		}
	}
	return fqdn
}

// publicSuffixes 一份**保守**的多级公共后缀清单。单级 TLD（com/cn/net…）已由
// searchDomainFor 的「父域至少两级」规则挡掉，这里只需要补上 `com.cn` / `co.uk`
// 这类两级注册后缀——它们看起来"有两级"，却同样是全网共享的注册后缀，
// 拿它做分流域等于把整个 .com.cn 劫进隧道。
//
// 刻意不引 golang.org/x/net/publicsuffix：完整 PSL 每年都变、要跟着升级依赖，
// 而这里只需要挡住误配，清单外的漏网之鱼最坏结果是多分流了一个二级域（可由管理员改
// 后端域名规避），远不如引入一个需要长期维护的数据集划算。
var publicSuffixes = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true, "ac.cn": true,
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true,
	"com.hk": true, "org.hk": true, "com.tw": true, "org.tw": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true,
	"com.br": true, "com.sg": true, "com.my": true, "co.kr": true, "co.in": true,
	"co.za": true, "com.mx": true, "com.ar": true, "com.tr": true, "co.th": true,
}

// pruneSubDomains 去掉被更宽的分流域覆盖的子域：同时下发 `corp.internal` 与
// `x.corp.internal` 时后者纯属冗余（两者指向同一个解析器），只会多写一个
// /etc/resolver 文件——也就多一个退出时要清理、清理漏了就永久污染系统解析的对象。
func pruneSubDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		covered := false
		for _, p := range in {
			if p != d && strings.HasSuffix(d, "."+p) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, d)
		}
	}
	return out
}

// normFQDN 规范化 DNS 名字：去空白、转小写、去尾点。
//
// ★两侧口径必须一致。DNS 名字大小写不敏感、线上表示还带尾点，管理员在控制台填的可能是
// `OA.corp.internal.`，客户端查上来的是 `oa.corp.internal`——不统一规范化就会出现
// 「明明配了却解析不到」，而日志里两个名字看起来一模一样（只差大小写/尾点），极难发现。
func normFQDN(s string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), "."))
}

// validDNSName 判断规范化后的名字是否是可解析的域名（而不是 `*.cnki.net` 这类通配写法）。
// 通配符资源没有确定的落点，装进解析器只会得到一条永远答不出来的死记录。
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, lb := range strings.Split(s, ".") {
		if lb == "" || len(lb) > 63 || lb[0] == '-' || lb[len(lb)-1] == '-' {
			return false
		}
		for i := 0; i < len(lb); i++ {
			c := lb[i]
			// 下划线不是合法主机名字符，但 AD/内网命名里很常见，放行以免误伤。
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// profileGateway 选取要下发的网关落点：优先取心跳最新鲜的在线网关（网关自己上报的
// 真实地址），全部离线才回退环境变量。回退时带出告警，让「连不上」有明确归因。
func (s *Server) profileGateway() (ProfileGateway, string) {
	const fresh = 90 * time.Second // 网关心跳间隔远小于此；超出即视为掉线

	s.mu.Lock()
	var best GatewayInfo
	var bestFP string
	for id, g := range s.gateways {
		if g.LastSeen > best.LastSeen {
			best, bestFP = g, s.gwTunnelFP[id]
		}
	}
	s.mu.Unlock()

	online := best.ID != "" && time.Since(time.Unix(best.LastSeen, 0)) < fresh
	if online {
		spaHost, spaPort := splitHostPortLoose(best.SPA)
		_, proxyPort := splitHostPortLoose(best.Proxy)
		// 网关上报的可能是 0.0.0.0/:port 这类监听地址，对客户端没有意义。
		// 这种情况回退到环境变量里配置的对外可达主机名。
		if spaHost == "" || spaHost == "0.0.0.0" || spaHost == "::" {
			spaHost = envOr("BAIDI_CLIENT_GW_HOST", "127.0.0.1")
		}
		return ProfileGateway{
			Host: spaHost, SPAPort: orDefault(spaPort, "18201"), ProxyPort: orDefault(proxyPort, "18443"),
			TunnelPin: bestFP, Online: true,
		}, pinWarning(bestFP)
	}
	return ProfileGateway{
		Host:      envOr("BAIDI_CLIENT_GW_HOST", "127.0.0.1"),
		SPAPort:   envOr("BAIDI_CLIENT_GW_SPA_PORT", "18201"),
		ProxyPort: envOr("BAIDI_CLIENT_GW_PROXY_PORT", "18443"),
		Online:    false,
	}, "没有网关在线上报，已回退到默认落点配置；若接入失败请先确认网关已注册到控制面"
}

// pinWarning 网关未上报隧道证书指纹时给出告警——客户端将无法钉扎证书，
// 隧道退化为「加密但不认证」。这是必须被看见的降级，不能静默。
func pinWarning(fp string) string {
	if fp == "" {
		return "网关未上报隧道证书指纹，客户端无法校验网关身份（隧道加密但不认证）；请升级网关版本"
	}
	return ""
}

// authorizeRes 移到 subjects.go：它现在要吃组织/用户组的展开索引，
// 与「下发给网关那份」共处一个文件，改一处时另一处就在眼前。

func containsFold(ss []string, v string) bool {
	for _, s := range ss {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

// appURL 给「点开即用」的地址：web 模式直接是可点的 URL（443 走 https），
// tunnel 模式（SSH/DB）给 host:port 让用户拷进自己的客户端。
// host 对 IP 后端是 VIP、对域名后端是域名本身（理由见调用处）。
func appURL(mode, host string, port int) string {
	if mode == "web" {
		if port == 443 {
			return fmt.Sprintf("https://%s", host)
		}
		return fmt.Sprintf("http://%s:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// vipBase 解析 VIP 网段，返回其网络地址的四字节形式。非法或非 IPv4 时返回告警文案，
// 调用方回退默认网段——绝不能因为一个配置笔误就让所有客户端拿不到剖面。
func vipBase(cidr string) ([4]byte, string) {
	var b [4]byte
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ipnet.IP.To4() == nil {
		return b, fmt.Sprintf("BAIDI_CLIENT_VIP_CIDR=%q 非法，已回退 %s", cidr, defaultVIPCidr)
	}
	copy(b[:], ipnet.IP.To4())
	return b, ""
}

// offsetIP 在网段基址上偏移 n 得到主机地址（仅支持 /24 及更大的常见私网段偏移范围）。
func offsetIP(base [4]byte, n int) string {
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v += uint32(n)
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}

// splitHostPortLoose 宽松拆分 host:port；拆不开时把整串当 host 返回，端口留空由调用方兜底。
func splitHostPortLoose(s string) (string, string) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return strings.TrimSpace(s), ""
	}
	return h, p
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
