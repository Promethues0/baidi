package webproxy

import (
	"net/http"
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

// SetForwarded 按**真实对端**重写来源信息。clientIP 必须来自 net.Conn 的
// RemoteAddr，绝不能取自任何请求头。
func SetForwarded(h http.Header, clientIP, host, proto, user, res string) {
	h.Set("X-Forwarded-For", clientIP)
	h.Set("X-Real-Ip", clientIP)
	h.Set("X-Forwarded-Host", host)
	h.Set("X-Forwarded-Proto", proto)
	// 后端常用它做 SSO 免登；值来自网关验过的会话，不是浏览器自称。
	h.Set("X-Baidi-User", user)
	h.Set("X-Baidi-Resource", res)
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
func RewriteSetCookiePath(sc, prefix string) string {
	parts := strings.Split(sc, ";")
	out := make([]string, 0, len(parts)+1)
	hasPath := false
	for i, p := range parts {
		if i == 0 { // name=value 原样
			out = append(out, p)
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
