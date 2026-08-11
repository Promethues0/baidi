package webproxy

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// inboundHopHeaders 进站必须**剥掉**的来源声明类头。
//
// ★PRD 8.3 要求把真实客户端 IP 透传给后端（XFF），但**信任进站的 XFF 等于让任何人
// 伪造来源 IP**：后端的风控、审计、按 IP 的 ACL 会一起被骗，而且骗过之后日志里
// 看起来完全正常。正确做法只有一条——先无条件剥干净，再按 net.Conn 的真实对端重写。
// 这与控制面 clientIP 那道 BAIDI_TRUSTED_PROXIES 信任边界是同一条纪律。
var inboundHopHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Real-Ip",
	"Forwarded",
	// 白帝自己注入的标识头同样要剥：否则外部可以自称"我是网关转发来的"。
	"X-Baidi-User",
	"X-Baidi-Resource",
}

// StripInboundHops 删掉全部来源声明类头（大小写不敏感，含重复出现的多值）。
func StripInboundHops(h http.Header) {
	for _, k := range inboundHopHeaders {
		h.Del(k)
	}
}

// Peer 一次请求的**真实来源**，由 ResolvePeer 按可信代理策略算出。
// 三个字段各自都有"宁可不给，也不给一个假的"的口径。
type Peer struct {
	IP    string // 客户端 IP：可信代理链之外的第一跳；无可信代理时就是 net.Conn 对端
	Proto string // http | https
	Host  string // 对外主机名；**空 = 不下发 X-Forwarded-Host**
}

// ResolvePeer 判定「客户端到底是谁、从什么协议进来、对外主机名是什么」。
//
// ★这是 StripInboundHops 的另一半，此前只做了「剥」：文档推荐的部署形态就是
// 把七层绑在 127.0.0.1 由前置 nginx 终结 HTTPS，那种拓扑下 net.Conn 的对端恒为
// 回环地址，于是所有用户到达后端时的 XFF 都是 127.0.0.1——PRD 8.3 要的真实客户端 IP
// 100% 失效，而不少内网应用把 127.0.0.1 当免认证的本机来源。所以必须有一份
// **显式配置的**可信代理白名单（-web-trusted-proxies），与控制面 clientIP 那道
// BAIDI_TRUSTED_PROXIES 完全同构：
//
//	对端在白名单内 → 采信它转发来的 XFF / X-Forwarded-Proto / X-Forwarded-Host；
//	对端不在白名单 → 一律按 net.Conn 重写，且**不下发 X-Forwarded-Host**。
//
// ★为什么不在白名单内就不下发 X-Forwarded-Host：那个值此前取自 r.Host，
// 而 Host 头是客户端完全可控的（网关的 mux 不按 host 路由，任何 Host 都进得来）。
// 把它当"真实值"下发给后端就是经典的 Host header injection——后端据它拼出的
// 找回密码链接会指向攻击者的域名。没有可信来源时就不给，后端会退回用 Host 头
// （SetURL 已把它改成后端自己的地址），Location 改写反而更准。
// 需要固定对外主机名的部署显式配 -web-external-host。
func ResolvePeer(r *http.Request, trusted []netip.Prefix, tlsTerminated bool, externalHost string) Peer {
	connIP := hostOf(r.RemoteAddr)
	p := Peer{IP: connIP, Proto: "http", Host: strings.TrimSpace(externalHost)}
	if tlsTerminated {
		p.Proto = "https"
	}
	if !IPTrusted(connIP, trusted) {
		return p
	}
	// ── 以下均取自可信代理转发的头（此时它们尚未被 StripInboundHops 剥掉）──
	if ip := leftmostUntrusted(r.Header.Values("X-Forwarded-For"), trusted); ip != "" {
		p.IP = ip
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))) {
	case "https":
		p.Proto = "https"
	case "http":
		p.Proto = "http"
	}
	if p.Host == "" {
		if h := validForwardedHost(r.Header.Get("X-Forwarded-Host")); h != "" {
			p.Host = h
		}
	}
	return p
}

// IPTrusted 报告某个 IP 是否落在可信代理网段里。解析不了的地址一律不可信。
func IPTrusted(ip string, trusted []netip.Prefix) bool {
	if len(trusted) == 0 {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, pfx := range trusted {
		if pfx.Contains(a) {
			return true
		}
	}
	return false
}

// leftmostUntrusted 从 XFF 链**右往左**走，返回第一个不在可信代理白名单里的地址。
//
// 右往左是唯一正确的方向：链的左半段是客户端可以随便写的（`X-Forwarded-For: 1.2.3.4`
// 发过来，nginx 会把真实对端追加在右边）。取最左边那个等于直接采信伪造值。
// 整条链都是可信代理时返回空（调用方保留 net.Conn 对端）。
func leftmostUntrusted(values []string, trusted []netip.Prefix) string {
	var chain []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				chain = append(chain, part)
			}
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		hop := strings.Trim(chain[i], "[]")
		if h, _, err := net.SplitHostPort(chain[i]); err == nil {
			hop = h
		}
		if _, err := netip.ParseAddr(hop); err != nil {
			return "" // 链里混进了不是 IP 的东西：整条链都不可信
		}
		if !IPTrusted(hop, trusted) {
			return hop
		}
	}
	return ""
}

// validForwardedHost 校验可信代理转发来的对外主机名（只取第一个，且必须是 host[:port]）。
func validForwardedHost(v string) string {
	v, _, _ = strings.Cut(v, ",")
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 253 {
		return ""
	}
	if strings.ContainsAny(v, " \t/?#@\\\"'") {
		return ""
	}
	return v
}

// SetForwarded 按 ResolvePeer 算出的**真实来源**重写来源信息。
// p.IP 只能来自 net.Conn 的对端或可信代理转发的链，绝不能取自不可信来源的请求头。
func SetForwarded(h http.Header, p Peer, user, res string) {
	h.Set("X-Forwarded-For", p.IP)
	h.Set("X-Real-Ip", p.IP)
	h.Set("X-Forwarded-Proto", p.Proto)
	if p.Host != "" {
		h.Set("X-Forwarded-Host", p.Host)
	}
	// 后端常用它做 SSO 免登；值来自网关验过的会话，不是浏览器自称。
	h.Set("X-Baidi-User", user)
	h.Set("X-Baidi-Resource", res)
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// ParseTrustedProxies 解析可信代理白名单（逗号分隔，单个 IP 或 CIDR）。
// 解析不了就报错让进程拒绝启动——一条写错的网段会静默退化成"谁都不可信"，
// 而那与"配了但没生效"在日志里完全同形。
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			pfx, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err
			}
			out = append(out, pfx.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// RewriteLocation 改写后端 3xx 的 Location 头，使跳转仍落在本应用的路径前缀内。
//
// ★内网应用极常发绝对跳转（`http://10.20.1.10:8080/login`）。不改写的话浏览器会被
// 甩到一个**内网地址**上：用户看到的是一次莫名其妙的超时，而网关日志里这次请求
// 完全正常（它确实按后端说的做了）。归因难度极高，故这是七层代理的必做项。
//
// 三种形态：
//   - 绝对 URL 且 host 就是后端 → 换成 prefix + 原路径；
//   - 绝对 URL 但指向别处（如 SSO 到 https://idp.example.com）→ **原样保留**，
//     那是后端有意要用户离开，替它改写反而会把外部登录流程打断；
//   - 根相对（/login）→ 加上前缀。相对（./x）不动，浏览器按当前目录解析本就正确。
func RewriteLocation(loc, backendHost, prefix string) string {
	if loc == "" {
		return loc
	}
	if strings.HasPrefix(loc, "//") {
		return loc // 协议相对的外部地址，同"指向别处"处理
	}
	if strings.HasPrefix(loc, "/") {
		return joinPrefix(prefix, loc)
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" {
		return loc // 解析不了 / 相对路径：不动（改坏一个能用的跳转比不改更糟）
	}
	if !strings.EqualFold(u.Host, backendHost) {
		return loc
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := joinPrefix(prefix, path)
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

// joinPrefix 把根相对路径挂到应用前缀下（prefix 恒以 / 收尾）。
func joinPrefix(prefix, path string) string {
	return strings.TrimSuffix(prefix, "/") + path
}

// RewriteSetCookiePath 把后端 Set-Cookie 的 Path 收进本应用前缀，并去掉 Domain。
//
// ★不改的话是一个**跨应用泄露**：后端普遍下发 `Path=/`，浏览器随后会把 A 应用的
// 会话 Cookie 一并送给 B 应用的后端（两者在浏览器眼里同源，只是路径不同）。
// Domain 同理——后端写的是它自己的内网域，留着只会让 Cookie 被浏览器整条丢弃，
// 表现为"登录成功后立刻又跳回登录页"这种最难查的形态。
//
// ★`__Host-` 前缀的 Cookie 必须改名（见 hostPrefixAlias）：RFC 6265bis 要求带该前缀的
// Cookie 必须 Path=/ 且无 Domain，我们一改 Path 浏览器就**整条静默丢弃**——症状正是
// 这段注释自己说要避免的"登录成功后立刻又跳回登录页"，而两侧日志一切正常。
// 不改 Path 也不行：Path=/ 的 Cookie 会被浏览器送给同源下的**每一个**应用，
// 那正是本函数存在的理由。所以只剩改名一条路，出站请求那侧再改回来（见 SanitizeOutboundCookies）。
func RewriteSetCookiePath(sc, prefix string) string {
	parts := strings.Split(sc, ";")
	out := make([]string, 0, len(parts)+1)
	hasPath := false
	for i, p := range parts {
		if i == 0 { // name=value：只在命中 __Host- 前缀时改名，其余原样
			out = append(out, renameHostPrefixed(p))
			continue
		}
		attr := strings.TrimSpace(p)
		lower := strings.ToLower(attr)
		switch {
		case lower == "path" || strings.HasPrefix(lower, "path="):
			hasPath = true
			out = append(out, " Path="+prefix)
		case lower == "domain" || strings.HasPrefix(lower, "domain="):
			// 丢弃：宿主域由网关决定，后端说了不算。
		case lower == "secure":
			// 保留原样（下面统一按前缀补 Path 即可）。
			out = append(out, p)
		default:
			out = append(out, p)
		}
	}
	if !hasPath {
		out = append(out, " Path="+prefix)
	}
	return strings.Join(out, ";")
}

// hostPrefixAlias 后端 `__Host-xxx` Cookie 在浏览器侧的替身名。
//
// 选一个业务上不可能撞车、且**不带任何浏览器语义前缀**的名字：改名的目的就是让它
// 摆脱 `__Host-` 的 Path=/ 硬约束，换成 `__Secure-` 之类只会换一种约束。
const hostPrefixAlias = "bdhostpfx-"

// cookieHostPrefix RFC 6265bis 的 __Host- 前缀。
const cookieHostPrefix = "__Host-"

// renameHostPrefixed 把 `__Host-x=v` 改成 `bdhostpfx-x=v`（其余原样返回）。
func renameHostPrefixed(nameValue string) string {
	lead := nameValue[:len(nameValue)-len(strings.TrimLeft(nameValue, " \t"))]
	nv := nameValue[len(lead):]
	if !strings.HasPrefix(nv, cookieHostPrefix) {
		return nameValue
	}
	return lead + hostPrefixAlias + strings.TrimPrefix(nv, cookieHostPrefix)
}

// SanitizeOutboundCookies 处理转发给后端的 Cookie 头，做两件事：
//
//	① **摘掉网关自己的会话 Cookie**。Cookie 不在 Go 的 hop-by-hop 剔除表里
//	   （只有 Connection/Proxy-*/Te/Trailer/Transfer-Encoding/Upgrade/Keep-Alive），
//	   不摘的话每个被保护应用（连同它的访问日志、APM、第三方 SDK）都白拿一张
//	   该用户在本资源上有效 15 分钟的网关会话凭据。HttpOnly 挡的是业务应用的 XSS，
//	   挡不住我们主动送过去。
//	② 把 `bdhostpfx-x` 改回后端认识的 `__Host-x`（见 RewriteSetCookiePath）。
func SanitizeOutboundCookies(h http.Header) {
	raw := h.Values("Cookie")
	if len(raw) == 0 {
		return
	}
	var keep []string
	for _, line := range raw {
		for _, pair := range strings.Split(line, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name, val, hasVal := strings.Cut(pair, "=")
			switch {
			case name == CookieName:
				continue // 网关自己的会话凭据，后端无权知道
			case hasVal && strings.HasPrefix(name, hostPrefixAlias):
				keep = append(keep, cookieHostPrefix+strings.TrimPrefix(name, hostPrefixAlias)+"="+val)
			default:
				keep = append(keep, pair)
			}
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}

// TargetFromReferer 处理**根相对静态资源**：浏览器按 `/static/app.css` 请求时，
// 该路径不在任何应用前缀下，直接 404 会让绝大多数内网应用在代理下"页面能开、样式全丢"。
//
// 用 Referer 推断它属于哪个应用，回一个 302 把它送进正确的前缀。
//
// ★安全性：这里**只产生一个同源重定向**，不读、不写、不放行任何数据——重定向后的
// 请求仍要过 Cookie 与逐请求鉴权那两道闸。Referer 是浏览器可控的，但攻击者本来就能
// 直接输入那个前缀路径，能力没有任何增加。
//
// 这也是本实现**不做 HTML 正文改写**的补偿：正文改写要解析并重写 HTML/CSS/JS
// 里的每一个绝对链接，是个无底洞（见文件头与 docs/ARCHITECTURE.md 的边界说明）。
func TargetFromReferer(referer, reqPath, reqQuery string) (string, bool) {
	if referer == "" || !strings.HasPrefix(reqPath, "/") {
		return "", false
	}
	if strings.HasPrefix(reqPath, "/app/") || strings.HasPrefix(reqPath, entryPath) {
		return "", false // 已在前缀内 / 入口端点自己，不参与
	}
	u, err := url.Parse(referer)
	if err != nil {
		return "", false
	}
	res, _, ok := SplitAppPath(u.Path)
	if !ok {
		return "", false
	}
	out := joinPrefix(AppPrefix(res), reqPath)
	if reqQuery != "" {
		out += "?" + reqQuery
	}
	return out, true
}
