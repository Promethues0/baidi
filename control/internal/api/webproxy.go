// 七层 Web 代理（PRD 8.3.3 / FR-INTRO-09/12，B/S 免客户端接入）的**控制面这一半**。
//
// 数据面那一半在 gateway/internal/webproxy。分工与敲门完全同构：
//
//	控制面  鉴权 → 签一张短时效一次性票据（use=web + jti + res + 60s）
//	数据面  验票（只持 web 公钥）→ 换成本机会话 Cookie → 逐请求重新鉴权 → 反代
//
// ★票据是**入场凭据**，不是授权结论：网关拿到它之后仍会用自己那份资源注册表
// （控制面每 15s 下发、含算好的 DenyUsers）逐请求重新鉴权。所以强制下线、
// 风险降权、JIT 到期都在一个轮询周期内自然生效，不必等票据或 Cookie 过期。
//
// ★可访问性判定必须与 buildProfile / handleGatewayPolicy **同一处**：都调 accessibleFor。
// 三个出口口径分叉的症状在本项目里出现过不止一次，且两个方向都很难查
// （门户点得开、网关照拒；或者门户不给点、其实有权限）。
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// webTicketTTL Web 访问票据有效期。与敲门令牌同款纪律——短到只够完成一次跳转。
// 网关侧另有 -web-ticket-max-ttl 上界兜底（纵深），改这里须同步那里。
const webTicketTTL = 60 * time.Second

// webEntryPath 网关 L7 的换票入口路径。★必须与 gateway/internal/webproxy 的
// entryPath 逐字一致：对不上的话票据发出去了、浏览器跳过去是 404，而两侧日志都正常。
const webEntryPath = "/__baidi/enter"

// handleWebTicket 门户点开一个 Web 应用时签发访问票据（POST /api/v1/portal/web-ticket）。
//
// 请求 {"appId":"a1"}；响应 {"url":"<入口 URL>","expiresIn":60,"resourceId":"oa"}。
func (s *Server) handleWebTicket(w http.ResponseWriter, r *http.Request) {
	// 与门户同一道闸：只认 admin/user 会话，拒 gateway 身份与 WebAuthn 半程票据。
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var body struct {
		AppID string `json:"appId"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil ||
		strings.TrimSpace(body.AppID) == "" {
		httpx.Error(w, http.StatusBadRequest, "appId 必填")
		return
	}
	account := normUser(c.Name)
	// ★三道账号闸与敲门令牌**共用同一段代码**（entryGates）。另起一套的话，
	// 「强制下线/账号禁用/终端不合规」在两条接入形态上迟早给出不同答案，
	// 而管理台只会显示其中一条路的状态。
	if !s.entryGates(w, r, c.Name, "Web 访问票据") {
		return
	}

	app, res, err := s.resolveWebApp(r, body.AppID)
	if err != nil {
		var he httpErr
		if errors.As(err, &he) {
			httpx.Error(w, he.code, he.msg)
			return
		}
		httpx.Error(w, http.StatusInternalServerError, "failed to resolve web app")
		return
	}

	// ── 授权判定：与剖面、网关策略下发同一入口 ──
	subjects := s.subjectIndex(r.Context())
	hasGrant := false
	if gs, gerr := s.store.ActiveGrantsFor(r.Context(), account); gerr == nil {
		for _, g := range gs {
			if g.ResourceID == res.ID {
				hasGrant = true
			}
		}
	}
	degraded, reason := s.degradeStateOf(r.Context(), account)
	if !accessibleFor(account, c.Role, res, subjects, hasGrant, degraded) {
		msg := "你当前对该应用没有访问权限"
		if degraded && res.HighSensitivity() {
			// 「被降权」与「没授权」的下一步动作完全不同，必须分开说——混为一谈
			// 会让用户反复提交必然无效的访问申请（降权否决压过 JIT 授予）。
			msg = "终端环境不合规，高敏应用已暂停访问（申请审批在此状态下无效）：" + reason
		}
		s.audit(r, "security", "拒发 Web 访问票据："+account+" 对应用「"+app.Name+"」无访问授权", "deny")
		httpx.Error(w, http.StatusForbidden, msg)
		return
	}

	base, gwID, err := s.webEntryBase(res)
	if err != nil {
		// ★如实回「网关没开七层」/「入口地址推导不出可达值」而不是给一个连不上的地址：
		// 后者会让管理员去查浏览器、查网络、查证书，而真正要做的只是给网关加 -web、
		// 或在网关页登记一下对外接入地址。
		httpx.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	tok := s.keys.Sign(auth.Claims{
		Sub: c.Sub, Role: c.Role, Name: account,
		Jti: auth.RandJTI(), Use: auth.UseWeb, Res: res.ID,
		// ★票据钉到具体网关（入口是由某台在线网关的登记地址或自报落点算出来时才填）：
		// 数据面的一次性去重是每台网关自己的内存，不带网关维度的话，同一张票在
		// 每台装了 web 公钥的网关上都能各换一次会话。走 webEntry / 环境变量覆盖时
		// 控制面确实不知道票会落到哪台，留空并在边界文档里说清。
		Gw: gwID,
	}, webTicketTTL)
	// 审计记的是**已发生的事实**：票签出去了。能不能真访问由网关逐请求判，
	// 所以这里不写"已放行访问"。「一次性」是数据面 jti 去重（webproxy.Server.ticketUsed）
	// 的语义，两侧措辞必须同真同假。
	s.audit(r, "access", fmt.Sprintf("签发 Web 访问票据：%s → 应用「%s」(资源 %s，%ds 内有效、一次性、%s)",
		account, app.Name, res.ID, int(webTicketTTL.Seconds()), gatewayBindNote(gwID)), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"url":        base + webEntryPath + "?t=" + url.QueryEscape(tok),
		"expiresIn":  int(webTicketTTL.Seconds()),
		"resourceId": res.ID,
	})
}

// httpErr 让 resolveWebApp 把"该回哪个状态码"带出来，而不是在里面直接写响应。
type httpErr struct {
	code int
	msg  string
}

func (e httpErr) Error() string { return e.msg }

// resolveWebApp 把 appId 解析成 (应用, 受控资源)，并校验它确实是一个可经七层访问的 Web 应用。
func (s *Server) resolveWebApp(r *http.Request, appID string) (store.App, store.Resource, error) {
	bundle, err := s.store.Apps(r.Context())
	if err != nil {
		return store.App{}, store.Resource{}, err
	}
	var app store.App
	for _, a := range bundle.Apps {
		if a.ID == appID {
			app = a
			break
		}
	}
	switch {
	case app.ID == "":
		return app, store.Resource{}, httpErr{http.StatusNotFound, "应用不存在"}
	case app.Status != "running":
		return app, store.Resource{}, httpErr{http.StatusConflict, "该应用已停用"}
	case app.Mode != "web":
		// tunnel / global 模式没有七层载体：前者要客户端隧道，后者压根不经白帝。
		return app, store.Resource{}, httpErr{http.StatusBadRequest,
			"该应用不是 Web 发布模式，无法经浏览器访问（请使用桌面客户端）"}
	case app.ResourceID == "":
		return app, store.Resource{}, httpErr{http.StatusConflict,
			"该应用未关联受控资源，无法访问（请在发布向导里补齐关联资源）"}
	}
	resources, err := s.store.Resources(r.Context())
	if err != nil {
		return app, store.Resource{}, err
	}
	for _, res := range resources {
		if res.ID == app.ResourceID {
			// ★资源 id 会被拼进 /app/<id>/ 路径与 Cookie 的 Path 属性，
			// 两侧用**同一条**规则校验（webproxy.ValidResourceID）。当面拒绝而不是
			// 签一张网关必然拒收的票——后者的症状是"点了没反应"。
			if !validWebResourceID(res.ID) {
				return app, res, httpErr{http.StatusConflict,
					"资源 id " + res.ID + " 含七层路径不支持的字符（只允许字母数字与 -_.），请改 id 后重试"}
			}
			return app, res, nil
		}
	}
	return app, store.Resource{}, httpErr{http.StatusConflict, "应用关联的受控资源已不存在"}
}

// webEntryBase 算出浏览器该跳的入口基址（形如 https://gw.example:18444，不带路径）。
//
// 取值优先级：
//  1. 该资源自己的 WebEntry 覆盖（管理员为这个应用配的专属域名）；
//  2. BAIDI_WEB_ENTRY_BASE（整站统一的对外入口，通常是前置 nginx 的地址）；
//  3. 在线且开了七层的网关上，**管理员登记的对外接入地址**（网关页那两栏，与客户端
//     剖面同一处取数 gatewayAccessMap）——**只登记了一栏时**才用它；
//  4. 该网关**自报的**七层监听地址里的 host（空/通配时退 SPA 监听的 host，再退
//     BAIDI_CLIENT_GW_HOST）。
//
// ★第 3 档是后补的。改造前直接从 2 跳到 4，而参考部署（install-remote.sh）的网关是
// `-spa :18201` + `BAIDI_GW_WEB=127.0.0.1:18444`（回环监听、前置 nginx 终结 HTTPS）：
// 第 4 档算出 http://127.0.0.1:18444，票据 URL 把浏览器指向**用户自己的机器**，
// 而 webProxyStatus 照报 ready、门户「访问」按钮亮着、控制台零报错——正是 CLAUDE.md
// 点名的「配置齐全却零报错不生效」形态。管理员在网关页登记的接入地址此前只喂给了
// 客户端剖面，七层这条路对它视而不见。
//
// ★第 3/4 档推导出来的 host 若是回环 / 通配 / 空（webHostUnroutable），**如实报错**
// 而不是发一张指向 127.0.0.1 的票：webProxyStatus 与 handleWebTicket 都经这一个函数，
// 门户按钮置灰的原因与取票被拒的原因是同一句话。第 1/2 档是管理员的显式配置，不受此判
// （本机 e2e 正是靠 BAIDI_WEB_ENTRY_BASE=http://127.0.0.1:… 跑起来的）。
//
// ★**两栏都登记且不是同一个值时，第 3 档判不出来**——如实报错，不猜。网关页那两栏
// （局域网/互联网访问地址）是 PRD FR-SCEN-17 要求分开填的，剖面把两个都下发给终端、由
// 数据面逐落点试拨，而浏览器只会收到**一个** 302：控制面无从知道此刻这位用户在内网还是
// 外网。第一版写死"内网栏优先"，于是「网关通配监听 + 两栏都登记 + 未配统一入口」这套
// 完全合法的配置下，外网用户在门户看到「访问」按钮亮着、点下去跳到内网主机名、浏览器
// 一直转圈，而控制面审计记着「签发 Web 访问票据」、网关侧连一个请求都没收到——与本轮
// 消灭的「指向 127.0.0.1 的票」是同一种形态，只是错得更隐蔽（对一半用户是通的）。
// 出路有三条，拒绝文案里逐条写出：配 BAIDI_WEB_ENTRY_BASE / 配资源级 webEntry /
// 两栏填同一个内外网统一的域名（FR-SCEN-09 的分区 DNS，剖面注释里也是这个解）。
//
// ★网关自报的七层监听 host **显式绑回环**（`-web 127.0.0.1:18444`）时，第 3 档也**不成立**：
// 登记地址 gw.example.com:18444 上没有任何东西在听，「登记 host + 自报端口」只对
// 通配监听（`:18444` / `0.0.0.0:18444`）成立。这不是不可判定——控制面手里就有 gw.Web，
// 两种形态在报文里分得开。第一版只判「登记地址存在与否」，于是参考部署的管理员为了
// 让 C/S 客户端连得上去网关页登记了接入地址之后，七层立刻报就绪、签出一张浏览器
// 必然连不上的票——与本函数要消灭的形态是同一种，只是往后挪了一步。回环绑定的唯一
// 正确出路是前置 nginx（BAIDI_WEB_ENTRY_BASE / 资源级 webEntry），拒绝文案就说这一条，
// **不能**说「请登记接入地址」——照那个补救去做仍然不通。
//
// 四档都拿不到就报错——绝不猜一个地址出来。
//
// 第二个返回值是**票据该绑到哪台网关**（走第 3/4 档时才有值）：前两档覆盖下票会经过
// 一个前置入口，可能落到任意一台网关上，写一个猜的值只会让正常访问被拒。
func (s *Server) webEntryBase(res store.Resource) (string, string, error) {
	if v := strings.TrimSpace(res.WebEntry); v != "" {
		return strings.TrimRight(v, "/"), "", nil
	}
	if v := strings.TrimSpace(envOr("BAIDI_WEB_ENTRY_BASE", "")); v != "" {
		return strings.TrimRight(v, "/"), "", nil
	}
	gw, online, anyOnline := s.freshestWebGateway()
	if !online {
		if anyOnline {
			// ★区分「一台网关都没有」与「网关在线但都没开七层」：后者照着前者的提示
			// 去查网关有没有启动，会白花很多时间。
			return "", "", errors.New("在线网关都未开启七层 Web 代理（需给 baidi-gateway 加 -web 监听并分发 Web 票据公钥）；" +
				"也可配置 BAIDI_WEB_ENTRY_BASE 指向前置入口")
		}
		return "", "", errors.New("没有网关在线，无法经浏览器访问（请先确认网关已注册到控制面）")
	}
	reportedHost, port := splitHostPortLoose(gw.Web)
	// 第 3 档：管理员登记的对外接入地址。与剖面 profileGateways 同一张表、同一个取数函数，
	// 别在这里另查一遍库——两处判据分叉的症状是「客户端连得上、浏览器打不开」或反过来。
	//
	// ★读库失败**不是**「未登记」：剖面那条路 fail-open 退回自报地址是对的（客户端至少还
	// 能试），但这里退回第 4 档会把 503 文案写成「请在网关页登记对外接入地址」——责任推给
	// 管理员，而他登记过、再登记一遍也不会好。读不到就说读不到，把原因带出来。
	accessMap, err := s.gatewayAccessMapErr()
	if err != nil {
		// ★用户面只给固定一句：这个 note 会随 /portal/apps 下发给**任何登录用户**，
		// 而 err 是 store 层原文（SQLite 报错会带库文件路径、锁状态等内部细节）。
		// 与 api 包对 store 失败一律固定文案是同一条纪律；真实原因进服务端日志。
		slog.Error("七层入口：网关接入地址读取失败", "gateway", gw.ID, "err", err.Error())
		return "", "", errors.New(webEntryUnresolvedPrefix + "网关接入地址读取失败（原因见控制面服务端日志）")
	}
	access := accessMap[gw.ID]
	switch store.ClassifyHost(reportedHost) {
	case store.HostLoopback:
		// ★显式绑回环：登记地址与自报端口组合不出一个有人监听的地址，别往下走第 3/4 档。
		// 这一判必须排在第 3 档**之前**——排在后面就是第一版的形态：登记了就报就绪。
		registered := ""
		if access.Configured() {
			registered = fmt.Sprintf("，登记地址 %s 上并没有该端口的服务", accessHostsNote(access))
		}
		return "", "", fmt.Errorf("%s网关 %s 的七层只监听回环 %s%s；经前置 nginx 终结 HTTPS 的部署请配置 "+
			"BAIDI_WEB_ENTRY_BASE（或资源级 webEntry）指向前置入口，或把 -web 改成对外可达的监听地址",
			webEntryUnresolvedPrefix, gw.ID, strings.TrimSpace(gw.Web), registered)
	case store.HostMalformed:
		// 形似 IP 的非标准写法（`-web 127.1:18444` / `[::1%lo0]:18444`）：控制面判不出它
		// 绑在哪，而它多半正是回环。**判不出来就不组合登记地址**——猜错的那一半正好是
		// 上面那条已经修过的静默失效（登记地址报就绪、票签出去、网关上什么都没在听）。
		return "", "", fmt.Errorf("%s网关 %s 自报的七层监听地址 %s 的主机部分不是标准写法，"+
			"控制面判不出它绑在哪个地址上（%q 这类短写会被系统按 inet_aton 展开）；"+
			"请把 -web 写成标准的 host:port，或配置 BAIDI_WEB_ENTRY_BASE（或资源级 webEntry）指向前置入口",
			webEntryUnresolvedPrefix, gw.ID, strings.TrimSpace(gw.Web), reportedHost)
	}
	host, source := "", ""
	if access.Configured() {
		lan, wan := strings.TrimSpace(access.LANHost), strings.TrimSpace(access.WANHost)
		if lan != "" && wan != "" && !strings.EqualFold(lan, wan) {
			// ★两栏都登记 = 内外网各有一个入口，而浏览器只会收到一个 302：判不出来就说判不出来。
			// 取内网栏（第一版的做法）对外网用户是一张必然打不开的票，且门户按钮照亮。
			return "", "", fmt.Errorf("%s网关 %s 的局域网与互联网访问地址都已登记（%s / %s），"+
				"而浏览器入口只能是其中一个——控制面无从知道访问者此刻在哪一侧（客户端隧道会两个都试，浏览器不会）。"+
				"请配置 BAIDI_WEB_ENTRY_BASE 或该资源的 webEntry 指定七层对外入口；"+
				"若内外网可用同一个域名（分区 DNS），把两栏填成同一个值即可",
				webEntryUnresolvedPrefix, gw.ID, lan, wan)
		}
		host, source = orDefault(lan, wan), "管理员登记的接入地址"
	} else {
		// 第 4 档：网关自报的监听地址。":18444" / "0.0.0.0:18444" 这类通配对浏览器没有意义，
		// 回退到与客户端剖面同一个对外主机名配置，口径一致。
		host, source = reportedHost, "网关自报的七层监听地址 "+strings.TrimSpace(gw.Web)
		if webHostUnroutable(host) {
			host, _ = splitHostPortLoose(gw.SPA)
			source = "网关自报的 SPA 监听地址 " + strings.TrimSpace(gw.SPA)
		}
		if webHostUnroutable(host) {
			host, source = envOr("BAIDI_CLIENT_GW_HOST", "127.0.0.1"), "全局兜底 BAIDI_CLIENT_GW_HOST"
		}
	}
	if webHostUnroutable(host) {
		// ★宁可不发票，也不发一张浏览器打不开的票。文案第一句固定（门户与取票共用），
		// 括号里说清此刻算出来的是什么、从哪来——否则管理员无从知道该去改哪一项。
		return "", "", fmt.Errorf("%s（网关 %s 当前只能推导出 %q，来源：%s；浏览器到不了回环/通配地址，"+
			"形似 IP 的非标准写法控制面也判不出它指向哪里）",
			webEntryUnresolvedMsg, gw.ID, host, source)
	}
	scheme := "http"
	if gw.WebTLS {
		scheme = "https"
	}
	return scheme + "://" + webURLHost(host, port), gw.ID, nil
}

// webURLHost 把 host[:port] 拼成能放进 URL 的 authority：IPv6 字面量必须加方括号。
//
// ★管理员登记 fd00::1 这样的 IPv6 接入地址（NormalizeAccessHost 收 IP 字面量，不区分 v4/v6），
// 改造前直接 host+":"+port 拼出 http://fd00::1:18444——浏览器把它解析成 host=fd00、
// port=":1:18444"，跳转直接失败，而票据照签、门户按钮照亮、控制面零报错。
// port 非空走 net.JoinHostPort（它自己会包括号）；port 为空时按「含冒号即 IPv6」包括号
// （主机名与 IPv4 里不可能出现冒号——带端口的写法在 NormalizeAccessHost 入口就被拒了）。
func webURLHost(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

// webEntryUnresolvedPrefix 七层入口地址推导不出可达值时的固定开头。
// 门户磁贴置灰的 note 与取票 503 的正文都以它开头；冒号之后是**按形态给的**补救路径——
// 推导值是回环/通配时是「登记接入地址或配 BAIDI_WEB_ENTRY_BASE」（webEntryUnresolvedMsg），
// 网关显式绑回环时只有「配前置入口」这一条（登记接入地址救不了它，不能照抄前一句）。
const webEntryUnresolvedPrefix = "七层入口地址无法确定："

// webEntryUnresolvedMsg 第 3/4 档推导出回环/通配/空时的整句：两条补救路径都真能救。
const webEntryUnresolvedMsg = webEntryUnresolvedPrefix + "请在网关页登记对外接入地址，或配置 BAIDI_WEB_ENTRY_BASE"

// accessHostsNote 把登记的两栏拼成一句人话（两栏都有就都写出来）。
// 只登记一栏时写那一栏——拒绝文案里说"登记地址 X"，X 必须真是管理员填过的值。
func accessHostsNote(a store.GatewayAccess) string {
	lan, wan := strings.TrimSpace(a.LANHost), strings.TrimSpace(a.WANHost)
	switch {
	case lan != "" && wan != "" && !strings.EqualFold(lan, wan):
		return lan + " / " + wan
	case lan != "":
		return lan
	default:
		return wan
	}
}

// ★网关自报的七层监听 host 走的是 webEntryBase 里那个 store.ClassifyHost 三路 switch，
// 不再另包一个 webListenLoopback 判据：那里要区分「是回环」（必然不通，文案点名回环）与
// 「判不出来」（非标准写法，文案点名写法），而 webHostUnroutable 把两者合成一个 bool。
// 与 webHostUnroutable 的分工不变：`:18444` / `0.0.0.0:18444` 是「所有接口都听」，登记的
// 对外地址 + 自报端口确实可达，**不能**当成不可达；`127.0.0.1:18444` 是「只有本机能到」，
// 任何对外地址都到不了那个端口。两者走的分支相反，判据必须分开。

// webHostUnroutable 判一个推导出来的入口主机名是否**必然**到不了浏览器（或判不出来）：
// 空 / 通配（0.0.0.0、::）/ 回环（127.x、::1、localhost）/ 形似 IP 的非标准写法。
//
// 这是 webEntryBase 第 3/4 档的唯一判据，webProxyStatus 与 handleWebTicket 都经它。
// 只判「必然不通」的形态，不判「可能不通」（内网 IP 对外网浏览器也不通，但控制面无从知道
// 浏览器在哪一侧——那条边界写在 docs/ARCHITECTURE.md 第七节七层小节，与「两栏都登记就
// 报判不出来」是同一件事的两半：一栏时只能用它，两栏时不许挑）。
func webHostUnroutable(host string) bool { return store.IsUnroutableHost(host) }

// gatewayBindNote 审计里描述这张票绑没绑网关（措辞只说已发生的事实）。
func gatewayBindNote(gwID string) string {
	if gwID == "" {
		return "经统一入口下发、未绑定具体网关"
	}
	return "绑定网关 " + gwID
}

// freshestWebGateway 取**开了七层**且心跳最新鲜的在线网关。
// 第三个返回值报告"有没有任何网关在线"，供调用方区分两种失败原因。
//
// ★候选必须先按 Web != "" 过滤。此前只按 LastSeen 取最大再判有没有开七层，于是
// 混合版本集群（gw-a 加了 -web、gw-b 还没升级）里，谁的心跳更新鲜每 15s 翻一次，
// 门户的 Web 磁贴与取票接口就有大约一半的请求回 503「网关未开启七层」——
// 管理员照着报错去给"网关"加 -web，却发现明明已经加了。
//
// ★平局按 id 字典序而不是 map 遍历序：LastSeen 是 Unix**秒**、心跳周期 15s，
// 两台网关启动时间相差不到 1s 时会持续落在同一秒，入口主机名于是在两台之间随机跳。
//
// 在线判据与网关页/客户端剖面共用 gatewayFresh。B/S 路径**没有故障转移**
// （浏览器只会收到一个 302），这条边界写在 docs/ARCHITECTURE.md 第七节。
func (s *Server) freshestWebGateway() (best GatewayInfo, ok bool, anyOnline bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.gateways {
		if !gatewayFresh(g.LastSeen, now) {
			continue
		}
		anyOnline = true
		if strings.TrimSpace(g.Web) == "" {
			continue
		}
		switch {
		case best.ID == "", g.LastSeen > best.LastSeen,
			g.LastSeen == best.LastSeen && g.ID < best.ID:
			best = g
		}
	}
	return best, best.ID != "", anyOnline
}

// webProxyStatus 门户用的一句话状态：七层入口此刻能不能用、不能用是为什么。
//
// ★它不是装饰：Web 磁贴的「访问」按钮要不要给点、点不动时该说什么，都靠它。
// 没有它的话，用户点下去只会拿到一个 503，而 503 的文案在弹窗里一闪而过。
func (s *Server) webProxyStatus() (bool, string) {
	if _, _, err := s.webEntryBase(store.Resource{}); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// validateWebEntry 校验对外入口基址覆盖：必须是 http(s):// + 主机[:端口]，不带路径/查询。
//
// ★带路径的话拼出来的入口 URL 会变成 https://x/base/__baidi/enter，而网关的
// 路由表里只有 /__baidi/enter——票发出去、浏览器跳过去 404，两侧日志都正常。
func validateWebEntry(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return errors.New("对外访问入口不是合法 URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("对外访问入口须以 http:// 或 https:// 开头")
	}
	if u.Host == "" {
		return errors.New("对外访问入口缺主机名")
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("对外访问入口只能填到主机[:端口]，不要带路径或查询串")
	}
	return nil
}

// validateBackend 校验受控资源的后端拨号目标必须是 host:port。
//
// ★为什么非拦不可：backend 是**网关唯一的拨号目标**（resource.Resource 里数据面只读这一个
// 字段）。写成裸地址 "10.91.0.1" 落库后，接口回 200、资源列表看起来完全正常，而：
//   - 客户端剖面会静默丢弃它（appAccessState 里那条 SplitHostPort 分支）；
//   - 网关拿到也拨不出去。
//
// 管理员配了一条"存在但对谁都不生效"的资源，全程零报错——正是本项目反复消灭的静默失效。
// 控制台在「选了地址对象、没选服务对象」时就会写出这种裸地址。
//
// ★判据与读侧**同一个** net.SplitHostPort：两处各写一套迟早会出现"入口放行、剖面丢弃"
// 或反过来。读侧兜底保留不动——存量库里可能已有裸地址的行，入口只能挡新写入，
// 绝不能让旧行读不出来（那会把一次校验收紧变成一次数据不可见）。
func validateBackend(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("后端地址不能为空")
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		// 措辞要说得出**正确形态**：笼统的"格式不对"会让人反复换写法试
		// （同 IPSec peer 拒收 FQDN 那条的教训，wave8 行动 17）。
		return fmt.Errorf("后端地址 %q 不是 host:port 形式——必须带端口，如 10.20.1.10:8080 或 oa.corp.internal:443（IPv6 写 [::1]:8080）", v)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("后端地址 %q 缺主机名", v)
	}
	if err := validateBackendHost(host); err != nil {
		return fmt.Errorf("后端地址 %q 的主机部分不合法：%w", v, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("后端地址 %q 的端口不合法（须为 1~65535 的数字）", v)
	}
	return nil
}

// validateBackendHost 主机部分必须是**单个**可拨号的目标：一个 IP，或一个具体主机名。
//
// ★这一半此前是缺的：`net.SplitHostPort` 只负责把最后一个冒号后面的东西切出来，
// 它对主机部分**什么都不检查**。于是这些全都 200 OK 落库过（实测）：
//
//	10.0.0.0/24:443          ← 网段
//	10.1.1.1-10.1.1.99:80    ← 地址范围
//	*.corp.internal:443      ← 泛域名
//
// 而对象库把 CIDR / 地址范围 / 通配域名都当**一等对象**提供并做成了种子，资源编辑器
// 还会拿选中的对象自动回填 backend——照着页面上给的选项点两下，就能存出一条网关
// 永远拨不出去的资源。三种形态的失败方式完全一样：接口回 200、列表正常、
// 剖面里有它、客户端点开就是连不上，两侧日志都不报错。
// 这正是 wave8 记的「入口比实现宽」：校验层放行执行层必然拒绝的值，
// 而拒绝发生在很久以后、很远的地方。
//
// 拒绝要**说得出正确形态**（同 IPSec peer 拒收 FQDN 那条的教训）：
// 笼统的"格式不对"会让管理员反复换写法试，而三种写法一种都不会成。
func validateBackendHost(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		return nil // 字面 IP（IPv6 已由 SplitHostPort 去掉方括号）
	}
	switch {
	case strings.Contains(host, "/"):
		return errors.New("看起来是一个网段（CIDR）。受控资源的后端必须是**单台**主机的拨号目标，" +
			"网关按它 net.Dial，拨不了网段。对象库里的网段对象用于地址匹配，不能直接当发布目标——" +
			"请填具体主机，如 10.20.1.10:8080")
	case strings.Contains(host, "*") || strings.Contains(host, "?"):
		return errors.New("看起来是一个泛域名。白帝**不做泛域名代理**（见 docs/ARCHITECTURE.md 第七节），" +
			"请为每个具体主机名各发布一条资源，如 oa.corp.internal:443")
	case strings.Contains(host, "-") && strings.Count(host, ".") >= 6:
		// 形如 10.1.1.1-10.1.1.99：两个点分四段被连字符连起来
		return errors.New("看起来是一个地址范围。受控资源的后端必须是单台主机，" +
			"请填其中一个具体地址，如 10.1.1.1:80")
	}
	// 其余按主机名校验：标签由字母/数字/连字符组成，不以连字符开头或结尾。
	if len(host) > 253 {
		return errors.New("主机名过长（超过 253 字符）")
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("主机名的分段 %q 为空或超过 63 字符", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("主机名的分段 %q 不能以连字符开头或结尾", label)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("主机名含非法字符 %q——只允许字母、数字、连字符与下划线", string(c))
			}
		}
	}
	return nil
}

// validWebResourceID 资源 id 能否安全用作七层的 URL 路径段与 Cookie Path。
//
// ★这是 gateway/internal/webproxy.ValidResourceID 的**同构副本**：control 与 gateway
// 是两个独立 Go module，不能互相 import（与 Claims 两份手抄是同一情形）。
// 规则改了必须两边同时改——不一致的方向都很难查：这边宽那边严 = 票签得出来、
// 浏览器跳过去被网关拒；这边严那边宽 = 管理员被无谓地拦住。
func validWebResourceID(id string) bool {
	if id == "" || len(id) > 64 || id == "." || id == ".." {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}
