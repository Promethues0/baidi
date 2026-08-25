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
		// ★如实回「网关没开七层」而不是给一个连不上的地址：后者会让管理员
		// 去查浏览器、查网络、查证书，而真正要做的只是给网关加 -web。
		httpx.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	tok := s.keys.Sign(auth.Claims{
		Sub: c.Sub, Role: c.Role, Name: account,
		Jti: auth.RandJTI(), Use: auth.UseWeb, Res: res.ID,
		// ★票据钉到具体网关（入口是由某台在线网关自报落点算出来时才填）：
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
//  3. 心跳最新鲜的在线网关**自报的**七层落点。
//
// 三条都拿不到就报错——绝不猜一个地址出来。
//
// 第二个返回值是**票据该绑到哪台网关**（只有走第 3 条时才有值）：前两条覆盖下票会经过
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
	host, port := splitHostPortLoose(gw.Web)
	// 网关上报的常是 ":18444" / "0.0.0.0:18444" 这类监听地址，对浏览器没有意义：
	// 回退到与客户端剖面同一个对外主机名配置，口径一致。
	if host == "" || host == "0.0.0.0" || host == "::" {
		spaHost, _ := splitHostPortLoose(gw.SPA)
		host = spaHost
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = envOr("BAIDI_CLIENT_GW_HOST", "127.0.0.1")
	}
	scheme := "http"
	if gw.WebTLS {
		scheme = "https"
	}
	if port == "" {
		return scheme + "://" + host, gw.ID, nil
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port), gw.ID, nil
}

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
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("后端地址 %q 的端口不合法（须为 1~65535 的数字）", v)
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
