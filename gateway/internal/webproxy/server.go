package webproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"baidi.dev/gateway/internal/auth"
	"baidi.dev/gateway/internal/knock"
	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/secevent"
	"baidi.dev/gateway/internal/spa"
)

// entryPath 票据换会话的入口端点。带 __ 前缀是为了不与任何业务路径撞车。
const entryPath = "/__baidi/enter"

// Config 七层 Web 代理的装配参数。
type Config struct {
	// Verifier 只装**控制面的 Web 票据公钥**（-web-jwt-pubkey）。
	// 装成敲门公钥的话，L7 与敲门两条路径的密码学隔离就没了。
	Verifier *auth.Verifier
	// Registry 与 L4 隧道**共用同一份**资源注册表：同一个资源在两条接入形态下
	// 的后端与授权完全一致，不存在第二套判定。
	Registry *resource.Registry
	// Allow 复用 SPA 放行表里的**账号封禁**部分（控制面下发的强制下线名单）。
	// 放行窗口那半与浏览器无关（浏览器不敲门），这里只读封禁。
	Allow *spa.Allowlist
	// SessionKey 本机 Cookie 签名密钥（启动期随机，见 NewSessionKey）。
	SessionKey []byte
	// TicketMaxTTL 票据寿命上界（纵深防御，须 ≥ 控制面的 webTicketTTL）。
	TicketMaxTTL time.Duration
	// SessionTTL 会话 Cookie 寿命。**刻意不做滑动续期**：续期会让一个活跃浏览器
	// 的会话无限延长，而账号禁用/锁定这类状态并不经数据面撤销通道下发
	// （那条通道只表达"强制下线"），Cookie 越长这段空窗就越长。
	SessionTTL time.Duration
	// MaxBodyBytes 单次响应体上界；<=0 用默认值。
	MaxBodyBytes int64
	// TLSTerminated 本监听自身是否已是 HTTPS。仅用于把 X-Forwarded-Proto 报对，
	// **不影响** Cookie 的 Secure 属性——那一条恒为真，没有关掉的开关。
	//
	// ★它只表达"网关自己在跑 HTTPS"。前置 nginx 终结 TLS 的推荐部署里本字段为 false，
	// 真实协议由可信代理转发的 X-Forwarded-Proto 决定（见 TrustedProxies）——
	// 少了那一半，后端会永远看到 proto=http，一个开了 HTTPS 强制跳转的后端会与
	// Location 改写咬成无限重定向，而每一跳在网关日志里都正常。
	TLSTerminated bool
	// TrustedProxies 可信前置代理网段（-web-trusted-proxies）。**只有**来自这些网段的
	// 请求，其 X-Forwarded-For / -Proto / -Host 才被采信；其余一律先剥后按 net.Conn 重写。
	// 空 = 谁都不可信（直连暴露时的正确默认）。
	TrustedProxies []netip.Prefix
	// ExternalHost 对外主机名（如 oa.example.com:9443）。配了就恒以它下发
	// X-Forwarded-Host；不配且对端不可信时**一个字节都不下发**（客户端可控的
	// Host 头不是"真实值"）。
	ExternalHost string
	// GatewayID 本网关 id（= mTLS 证书 CN）。票据里的 gw 与它不符即拒。
	GatewayID string
	// UpgradeRecheck 已升级连接（WebSocket）的授权复查间隔；<=0 用默认值。
	// 它是逐请求鉴权在长连接上的等价物，见 upgraded.go。
	UpgradeRecheck time.Duration
	// SecEvents 安全事件上报器（nil 安全）：每种拒绝除本机日志外，经节流上报
	// 控制面留痕（心跳捎带落审计 + 攻击源统计）。★L7 端口不受 SPA 隐身保护，
	// 是全系统唯一直接暴露的 HTTP 面——谁在打它此前只有本机日志知道。
	SecEvents *secevent.Reporter
}

const (
	defaultSessionTTL   = 15 * time.Minute
	defaultTicketMaxTTL = 2 * time.Minute
	defaultMaxBody      = 64 << 20 // 64 MiB
)

// Server 七层 Web 代理。
type Server struct {
	cfg   Config
	proxy *httputil.ReverseProxy
	// tickets 访问票据的 jti 去重缓存——「一次性票据」这四个字的**唯一执行方**。
	// 它此前不存在：控制面审计、文档、门户提示、前端注释四处都写着"60s 内一次性"，
	// 而网关只检查了 jti 非空，同一张票在 60s 内可无限次换出全新的 15 分钟会话。
	// 票据整串会出现在浏览器地址栏/历史与前置 nginx 的 access.log 里，拿到即可重放。
	tickets *knock.Cache
	// upgraded 已升级连接（WebSocket）的台账，见 upgraded.go。
	upgraded *upgradeTracker
}

// ctxKey 把已解析的目标资源从 handler 传给 ReverseProxy.Rewrite。
type ctxKey struct{}

// connCtxKey 把 net.Conn 从 http.Server 传进 handler：101 之后连接被劫持，
// 想再终止它只能靠这个引用（见 upgraded.go）。
type connCtxKey struct{}

type routed struct {
	res    resource.Resource
	user   string
	prefix string
	peer   Peer
}

// New 装配代理。校验必备材料——缺一样就拒绝构造，绝不起一个"看起来在跑、
// 实际每个请求都 500"的监听。
func New(cfg Config) (*Server, error) {
	if cfg.Verifier == nil || !cfg.Verifier.HasPublicKey() {
		return nil, errors.New("七层 Web 代理必须装载控制面的 Web 票据公钥（-web-jwt-pubkey）")
	}
	if cfg.Registry == nil {
		return nil, errors.New("七层 Web 代理缺资源注册表")
	}
	if cfg.Allow == nil {
		return nil, errors.New("七层 Web 代理缺 SPA 放行表（强制下线名单来源）")
	}
	if len(cfg.SessionKey) < 32 {
		return nil, errors.New("会话签名密钥长度不足 32 字节")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.TicketMaxTTL <= 0 {
		cfg.TicketMaxTTL = defaultTicketMaxTTL
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBody
	}
	if cfg.UpgradeRecheck <= 0 {
		cfg.UpgradeRecheck = defaultUpgradeRecheck
	}
	s := &Server{cfg: cfg, tickets: knock.NewCache(), upgraded: newUpgradeTracker()}
	s.proxy = &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		ModifyResponse: s.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("L7 后端不可达", "path", r.URL.Path, "err", err.Error())
			writeNotice(w, http.StatusBadGateway, "后端不可达", "业务系统没有响应，请联系管理员确认后端状态。")
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       60 * time.Second,
			MaxIdleConnsPerHost:   16,
			// ★内网 HTTPS 后端不校验证书，这是 L7 相对 L4 隧道的一处**安全性下降**，
			// 必须说清而不是藏着：L4 隧道里 TLS 是浏览器与业务端到端的，网关看不到明文；
			// L7 把 TLS 终结在网关，而内网应用普遍自签、白帝也没有内网 CA 可依赖。
			// 不做"假装校验"（那会让所有内网 HTTPS 应用直接不可用），也不留开关。
			// 边界写在 docs/ARCHITECTURE.md 第七节。
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 见上
		},
	}
	return s, nil
}

// ConnContext 必须装到承载 Handler() 的 http.Server 上（Serve 已自带）。
//
// ★它把 net.Conn 放进请求上下文：101 升级之后这条连接被劫持、不再产生任何请求，
// 想在强制下线/降权时终止它，只剩这一个引用可用（见 upgraded.go）。装不上的话
// handleAny 会**拒绝**协议升级——放行一条谁也切不断的连接比拒绝它更糟。
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connCtxKey{}, c)
}

// Handler 返回 L7 路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(entryPath, s.handleEnter)
	mux.HandleFunc("/", s.handleAny)
	return mux
}

// Serve 起监听。certFile/keyFile 非空时直接跑 HTTPS，否则明文（须由前置
// nginx 终结 TLS——会话 Cookie 恒带 Secure，浏览器在纯 HTTP 下根本不会保存它）。
func (s *Server) Serve(addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ConnContext:       ConnContext,
		// 刻意不设 WriteTimeout：它会把大文件下载与 WebSocket 长连接一刀切断，
		// 而超时该由上面 Transport 的 ResponseHeaderTimeout 承担。
	}
	if certFile != "" && keyFile != "" {
		slog.Info("七层 Web 代理监听（HTTPS）", "addr", addr, "sessionTTL", s.cfg.SessionTTL.String())
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	slog.Info("七层 Web 代理监听（明文，须由前置 HTTPS 终结）", "addr", addr,
		"sessionTTL", s.cfg.SessionTTL.String())
	return srv.ListenAndServe()
}

// handleEnter 票据换会话：验票 → 下发绑定 (账号,资源) 的 Cookie → 302 进应用。
func (s *Server) handleEnter(w http.ResponseWriter, r *http.Request) {
	ip := s.peerOf(r).IP
	c, err := VerifyTicket(s.cfg.Verifier, r.URL.Query().Get("t"), s.cfg.TicketMaxTTL, s.cfg.GatewayID)
	if err != nil {
		slog.Warn("L7 入口拒绝（票据无效）", "src", ip, "err", err.Error())
		s.cfg.SecEvents.Report("web-ticket", ip, "L7 入口拒绝（票据无效）")
		writeNotice(w, http.StatusUnauthorized, "访问票据无效",
			"票据已过期或不属于本网关。请回到应用门户重新点击该应用。")
		return
	}
	// ★一次性：同一个 jti 只换一次会话。放在签名与语义校验**之后**、建会话**之前**，
	// 与 spa.checkKnock 那侧的 cache.Seen("j:"+jti) 同构。
	// 少了这一步，"60s 内一次性"就只是四处文案里的说法：票据整串会进浏览器历史、
	// 也会被前置 nginx 的 access_log 原样记下，任何读到它的人都能在 60s 内换出
	// 一张属于受害者、寿命 15 分钟的会话 Cookie，且想换几张换几张。
	if s.ticketUsed(c) {
		slog.Warn("L7 入口拒绝（一次性票据已用，重放被拒）", "src", ip, "user", c.Name,
			"resource", c.Res, "jti", c.Jti)
		s.cfg.SecEvents.Report("web-ticket-replay", ip, "L7 入口拒绝（一次性票据重放被拒，账号 "+c.Name+"）")
		writeNotice(w, http.StatusUnauthorized, "访问票据已被使用",
			"每张票据只能换取一次会话（防止票据从地址栏或代理日志里被重放）。请回到应用门户重新点击该应用。")
		return
	}
	// 强制下线：控制面下发的封禁名单在这里同样生效——否则"已下线"的账号
	// 换条 L7 路径照样进得来，而管理台显示他已被切断。
	if s.cfg.Allow.UserDenied(c.Name) {
		slog.Warn("L7 入口拒绝（账号在强制下线封禁期内）", "src", ip, "user", c.Name)
		s.cfg.SecEvents.Report("web-entry-banned", ip, "L7 入口拒绝（账号 "+c.Name+" 在强制下线封禁期内）")
		writeNotice(w, http.StatusForbidden, "已被强制下线", "账号处于封禁期内，暂时无法接入。")
		return
	}
	// 建会话前先按当前策略鉴一次权：票据是控制面 60s 前签的，这 60s 里策略可能已变。
	res, ok := s.cfg.Registry.Lookup(c.Res)
	if !ok {
		slog.Warn("L7 入口拒绝（资源未下发到本网关）", "src", ip, "user", c.Name, "resource", c.Res)
		s.cfg.SecEvents.Report("web-res-missing", ip, "L7 入口拒绝（资源 "+c.Res+" 未下发到本网关，账号 "+c.Name+"）")
		writeNotice(w, http.StatusNotFound, "资源不存在", "该应用未下发到本网关，请联系管理员。")
		return
	}
	if !s.cfg.Registry.Authorize(c.Name, c.Role, res) {
		slog.Warn("L7 入口拒绝（无资源授权）", "src", ip, "user", c.Name, "role", c.Role, "resource", c.Res)
		s.cfg.SecEvents.Report("web-entry-authz", ip, "L7 入口拒绝（账号 "+c.Name+" 无资源 "+c.Res+" 授权）")
		writeNotice(w, http.StatusForbidden, "无访问授权", "你当前对该应用没有访问权限。")
		return
	}
	sess := Session{User: c.Name, Role: c.Role, Res: c.Res, Exp: time.Now().Add(s.cfg.SessionTTL).Unix()}
	prefix := AppPrefix(c.Res)
	http.SetCookie(w, &http.Cookie{
		Name:  CookieName,
		Value: Seal(s.cfg.SessionKey, sess),
		Path:  prefix, // ★路径限定：浏览器不会把它送给另一个应用
		// 三条属性都没有关掉的开关：
		//   HttpOnly —— 脚本读不到（业务应用的一个 XSS 就能偷走它）；
		//   Secure   —— 只走 HTTPS（明文暴露 L7 时浏览器会拒绝保存，那是**正确**的响亮失败）；
		//   SameSite —— Lax 顶住跨站表单 POST，同时不破坏从门户点过来的顶层跳转。
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})
	slog.Info("L7 会话已建立", "src", ip, "user", c.Name, "resource", c.Res, "ttl", s.cfg.SessionTTL.String())
	http.Redirect(w, r, prefix, http.StatusFound)
}

// ticketUsed 报告这张票是否已经换过会话（换过=true，拒绝）；未换过则记下。
//
// 去重窗按票据**实际剩余寿命**取，并以 TicketMaxTTL 封顶：票只有 60s，
// 固定一个大窗口只会让每张用过的票在内存里多躺很久，把入口变成一个可被
// 大量伪造 jti 撑爆的内存面（同 spa 那侧改掉固定 10min 上界的理由）。
func (s *Server) ticketUsed(c auth.Claims) bool {
	ttl := time.Until(time.Unix(c.Exp, 0)) + ticketDedupSkew
	if max := s.cfg.TicketMaxTTL + ticketDedupSkew; ttl > max {
		ttl = max
	}
	if ttl <= 0 {
		// 已经过期的票走不到这里（checkTicket/Verify 先拒），真到了就当已用——
		// 这个方向上 fail-closed 不会误伤任何一次正常访问。
		return true
	}
	return s.tickets.Seen("w:"+c.Jti, ttl)
}

// ticketDedupSkew 去重窗相对票据寿命的余量，容忍两端时钟偏差。
const ticketDedupSkew = 30 * time.Second

// peerOf 解析本次请求的真实来源（可信代理白名单在这里生效）。
func (s *Server) peerOf(r *http.Request) Peer {
	return ResolvePeer(r, s.cfg.TrustedProxies, s.cfg.TLSTerminated, s.cfg.ExternalHost)
}

// KillUser 切断某账号在七层上的全部已升级连接（WebSocket），返回条数。
//
// ★强制下线的 L7 执行方，与 L4 的 proxy.KillUser 成对。少了它，管理台显示"已切断"、
// 回执写着"切断 N 条隧道"，而那条 WS 仍在网关里双向搬运业务数据。
func (s *Server) KillUser(user string) int {
	n := s.upgraded.killUser(user)
	if n > 0 {
		slog.Warn("L7 强制下线执行：切断已升级连接", "user", user, "conns", n)
	}
	return n
}

// UpgradedCount 当前存活的已升级连接数（供日志/自检）。
func (s *Server) UpgradedCount() int { return s.upgraded.count() }

// handleAny 应用路径 + 根相对静态资源兜底。
func (s *Server) handleAny(w http.ResponseWriter, r *http.Request) {
	if to, ok := TargetFromReferer(r.Header.Get("Referer"), r.URL.Path, r.URL.RawQuery); ok {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	resID, rest, ok := SplitAppPath(r.URL.Path)
	if !ok {
		writeNotice(w, http.StatusNotFound, "无此地址", "请从应用门户进入受保护业务。")
		return
	}
	peer := s.peerOf(r)
	ip := peer.IP
	ck, err := r.Cookie(CookieName)
	if err != nil {
		// ★这句话必须具体。Secure Cookie 在明文 HTTP 下会被浏览器直接丢弃，
		// 症状是"点进去又被弹回门户"，而任何一侧日志都看不出异常。
		writeNotice(w, http.StatusUnauthorized, "会话不存在",
			"请回到应用门户重新点击该应用。若本页是通过 http:// 打开的，"+
				"浏览器不会保存带 Secure 属性的会话 Cookie——七层入口必须经 HTTPS 暴露。")
		return
	}
	sess, err := Open(s.cfg.SessionKey, ck.Value)
	if err != nil {
		slog.Warn("L7 拒绝（会话 Cookie 无效）", "src", ip, "resource", resID, "err", err.Error())
		s.cfg.SecEvents.Report("web-cookie", ip, "L7 拒绝（会话 Cookie 无效，资源 "+resID+"）")
		writeNotice(w, http.StatusUnauthorized, "会话已失效", "请回到应用门户重新点击该应用。")
		return
	}
	// ★服务端复核绑定：浏览器的 Path 规则挡的是"正常浏览器"，手工构造请求不受它约束。
	if sess.Res != resID {
		slog.Warn("L7 拒绝（Cookie 绑定的资源与请求路径不符——疑似跨应用复用）",
			"src", ip, "user", sess.User, "cookieRes", sess.Res, "pathRes", resID)
		s.cfg.SecEvents.Report("web-cookie-cross", ip, "L7 拒绝（Cookie 跨应用复用被拒，账号 "+sess.User+"）")
		writeNotice(w, http.StatusForbidden, "会话与应用不匹配",
			"该会话绑定的是另一个应用，不能用来访问本应用。")
		return
	}
	// ★同源发起方核对（纵深，不是隔离）。上面那道挡的是"拿 A 的 Cookie 开 B"，
	// 挡不住"在 A 的页面里用 B 自己的 Cookie 发请求"——所有应用共用网关这一个浏览器源，
	// A 的页面里一句 fetch('/app/b/…',{credentials:'same-origin'}) 是**同源**请求，
	// 浏览器会按 Path 规则把 B 那张 Cookie 一并送出，服务端所有判定也都对 B 成立。
	// 这里按 Referer / Sec-Fetch-Site 拦掉直白的那一种。
	//
	// **它不构成隔离**：Referer 可以被发起方用 referrerPolicy 抑制，Sec-Fetch-* 是浏览器
	// 自愿加的。真正的应用间隔离只有"每个应用一个独立域名"（资源的 webEntry 覆盖）。
	// 这条边界写在 docs/ARCHITECTURE.md 第七节，别再说"一个应用的会话凭据不能访问其它应用"。
	if from, cross := CrossAppOrigin(r.Header.Get("Referer"), resID,
		r.Header.Get("Sec-Fetch-Mode"), r.Header.Get("Sec-Fetch-Dest")); cross {
		slog.Warn("L7 拒绝（跨应用发起的同源请求）", "src", ip, "user", sess.User,
			"fromRes", from, "pathRes", resID)
		s.cfg.SecEvents.Report("web-cross-origin", ip, "L7 拒绝（跨应用发起的同源请求，账号 "+sess.User+"）")
		writeNotice(w, http.StatusForbidden, "跨应用请求已拒绝",
			"这个请求是从另一个应用的页面发起的。若确属正常业务，请给该应用配置专属访问域名。")
		return
	}
	// ── 逐请求重新鉴权（本设计的核心）──
	// 强制下线、风险降权（DenyUsers）、JIT 到期都会在下一次策略轮询后从这里生效。
	if s.cfg.Allow.UserDenied(sess.User) {
		slog.Warn("L7 拒绝（账号在强制下线封禁期内）", "src", ip, "user", sess.User)
		s.cfg.SecEvents.Report("web-banned", ip, "L7 拒绝（账号 "+sess.User+" 在强制下线封禁期内，会话已终止）")
		writeNotice(w, http.StatusForbidden, "已被强制下线", "账号处于封禁期内，会话已终止。")
		return
	}
	res, found := s.cfg.Registry.Lookup(resID)
	if !found {
		writeNotice(w, http.StatusNotFound, "资源不存在", "该应用已下架或未下发到本网关。")
		return
	}
	if !s.cfg.Registry.Authorize(sess.User, sess.Role, res) {
		slog.Warn("L7 拒绝（逐请求鉴权未通过）", "src", ip, "user", sess.User, "role", sess.Role, "resource", resID)
		s.cfg.SecEvents.Report("web-authz", ip, "L7 拒绝（账号 "+sess.User+" 对资源 "+resID+" 的逐请求鉴权未通过）")
		writeNotice(w, http.StatusForbidden, "访问已被收回",
			"你对该应用的访问权限已变更（可能是授权调整、终端降级或临时授予到期）。")
		return
	}

	// 交给反代：路径去掉 /app/<id> 前缀，其余原样。
	rr := r.Clone(context.WithValue(r.Context(), ctxKey{},
		routed{res: res, user: sess.User, prefix: AppPrefix(resID), peer: peer}))
	rr.URL.Path = rest

	// 协议升级（WebSocket）：101 之后这条连接不再产生任何请求，逐请求鉴权那道闸
	// 到此为止。登记进台账 + 起一个守护协程周期复查，让强制下线/降权/JIT 到期
	// 在这类长连接上同样有执行方（见 upgraded.go）。
	if isUpgradeRequest(r.Header.Get("Connection"), r.Header.Get("Upgrade")) {
		if c, ok := r.Context().Value(connCtxKey{}).(net.Conn); ok && c != nil {
			uc := s.upgraded.add(sess.User, resID, c)
			defer s.upgraded.remove(uc) // ServeHTTP 在被劫持连接读写结束前不会返回
			go s.guardUpgraded(uc, sess)
		} else {
			// 拿不到底层连接就**不放行升级**：放行等于制造一条谁也切不断的连接，
			// 而那正是本段代码要消灭的东西（判不了 ≠ 安全）。
			slog.Warn("L7 拒绝协议升级（拿不到底层连接，无法纳入可切断台账）",
				"src", ip, "user", sess.User, "resource", resID)
			writeNotice(w, http.StatusForbidden, "该连接不被支持",
				"网关无法把这条长连接纳入可切断台账，因此不予建立。")
			return
		}
	}
	s.proxy.ServeHTTP(w, rr)
}

// guardUpgraded 已升级连接的守护：周期复查授权 + 寿命上界，任一不过即切断。
//
// 判据与 handleAny 逐请求那段**同源**（UserDenied / Lookup / Authorize），
// 只是把"下一个请求"换成"下一个滴答"——两处分叉的话，长连接会成为唯一一条
// 撤权撤不掉的路径，而管理台与审计都显示已经撤掉了。
func (s *Server) guardUpgraded(uc *upgradedConn, sess Session) {
	t := time.NewTicker(s.cfg.UpgradeRecheck)
	defer t.Stop()
	// 寿命上界 = 会话 Cookie 的剩余寿命。连接不该比签发它的凭据活得久。
	deadline := time.Unix(sess.Exp, 0)
	for {
		select {
		case <-uc.done:
			return
		case now := <-t.C:
			reason := ""
			switch {
			case !now.Before(deadline):
				reason = "会话 Cookie 已到期（长连接不做滑动续期）"
			case s.cfg.Allow.UserDenied(sess.User):
				reason = "账号被强制下线"
			default:
				res, found := s.cfg.Registry.Lookup(uc.res)
				if !found {
					reason = "资源已下架或不再下发到本网关"
				} else if !s.cfg.Registry.Authorize(sess.User, sess.Role, res) {
					reason = "访问授权已收回（授权调整 / 终端降级 / 临时授予到期）"
				}
			}
			if reason == "" {
				continue
			}
			slog.Warn("L7 切断已升级连接（周期复查未通过）",
				"user", sess.User, "resource", uc.res, "reason", reason)
			_ = uc.conn.Close()
			return
		}
	}
}

// CrossAppOrigin 判断一个请求是否由**另一个应用的页面**发起（纯函数，便于单测）。
// 返回发起方资源 id 与是否跨应用。Referer 缺席/不可解析/不在 /app/ 下时不判跨应用——
// 直接导航与从门户点过来都没有本站 Referer，按跨应用拦掉会把正常访问全拦死。
//
// ★**顶层导航放行**：用户在 A 应用的页面里点一个指向 B 应用的链接是完全正常的业务，
// 拦掉它就是把一个能用的系统改坏。判据取 Sec-Fetch-Mode/Dest 而不是 Referer 的形状——
// 这两个头是**浏览器加的、页面脚本改不了**（fetch/XHR 的禁止修改头），
// 所以攻击者没法把一次带凭据的后台读取伪装成一次导航；而它们缺席时（老浏览器、
// curl）走保守分支：仍按跨应用拒。
func CrossAppOrigin(referer, resID, fetchMode, fetchDest string) (string, bool) {
	if strings.TrimSpace(referer) == "" {
		return "", false
	}
	if strings.EqualFold(fetchMode, "navigate") && strings.EqualFold(fetchDest, "document") {
		return "", false
	}
	u, err := url.Parse(referer)
	if err != nil {
		return "", false
	}
	from, _, ok := SplitAppPath(u.Path)
	if !ok || from == resID {
		return "", false
	}
	return from, true
}

// rewrite 组装出站请求：定后端、剥来源头、按真实对端重写。
func (s *Server) rewrite(pr *httputil.ProxyRequest) {
	rt, _ := pr.In.Context().Value(ctxKey{}).(routed)
	target := &url.URL{Scheme: rt.res.DialScheme(), Host: rt.res.Backend}
	// SetURL 同时把出站 Host 头改成后端 host——内网应用认的是自己的域名/地址，
	// 把浏览器看到的网关地址透传过去只会撞上后端的虚拟主机路由。
	pr.SetURL(target)
	pr.Out.URL.Path = pr.In.URL.Path
	pr.Out.URL.RawPath = pr.In.URL.RawPath

	// ★先剥后写，顺序不能反：剥的是浏览器自称的来源，写的是 ResolvePeer 算出的真实来源
	// （无可信代理时 = net.Conn 对端；有可信代理时 = 它转发的链上第一个不可信地址）。
	StripInboundHops(pr.Out.Header)
	SetForwarded(pr.Out.Header, rt.peer, rt.user, rt.res.ID)
	// 网关自己的会话 Cookie 不转发给后端；后端认识的 __Host- 前缀改回去。
	SanitizeOutboundCookies(pr.Out.Header)
}

// modifyResponse 改写跳转与 Cookie 作用域，并给响应体加上界。
func (s *Server) modifyResponse(resp *http.Response) error {
	rt, _ := resp.Request.Context().Value(ctxKey{}).(routed)
	if rt.prefix == "" {
		return nil
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		resp.Header.Set("Location", RewriteLocation(loc, rt.res.Backend, rt.prefix))
	}
	if scs := resp.Header.Values("Set-Cookie"); len(scs) > 0 {
		out := make([]string, 0, len(scs))
		for _, sc := range scs {
			out = append(out, RewriteSetCookiePath(sc, rt.prefix))
		}
		resp.Header.Del("Set-Cookie")
		for _, sc := range out {
			resp.Header.Add("Set-Cookie", sc)
		}
	}
	// 响应体上界。★对 101（WebSocket 升级）与 SSE 不设限：那两种是长连接流，
	// 按字节数掐断等于把功能做坏，而它们本来就不是"一份响应体"。
	if resp.StatusCode == http.StatusSwitchingProtocols ||
		strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return nil
	}
	resp.Body = &cappedBody{ReadCloser: resp.Body, left: s.cfg.MaxBodyBytes, limit: s.cfg.MaxBodyBytes}
	return nil
}

// cappedBody 超过上界即报错（而不是静默截断——截断出来的半个 JSON/半张图片
// 在业务侧表现成各种离奇的解析错误，谁也不会想到是代理干的）。
type cappedBody struct {
	io.ReadCloser
	left  int64
	limit int64
}

// Read 判据是「读完之后还想再要」，不是「读完之后正好归零」。
//
// ★这个差一很要命且极难归因：一个长度**恰好等于**上界的响应体，最后一次 Read 把
// left 减到 0，而 io.Copy 必然还要再调一次 Read 去拿 io.EOF——照旧写法那一次会
// 返回"超过上界"，于是一次并没有超限的正常下载在最后一刻失败，网关日志还振振有词。
// 多读 1 字节来判定：读到了才是真超限。
func (c *cappedBody) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, fmt.Errorf("响应体超过七层代理上界 %d 字节", c.limit)
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1] // 多给 1 字节的余地：读满它才说明确实超了
	}
	n, err := c.ReadCloser.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return 0, fmt.Errorf("响应体超过七层代理上界 %d 字节", c.limit)
	}
	return n, err
}

// writeNotice 回一个极简说明页。刻意不透露后端地址、资源清单等拓扑信息。
func writeNotice(w http.ResponseWriter, code int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title>`+
		`<div style="font:14px/1.7 system-ui,sans-serif;max-width:520px;margin:15vh auto;padding:0 20px">`+
		`<h2 style="font-size:18px;margin:0 0 10px">%s</h2><p style="color:#4e5969;margin:0">%s</p></div>`,
		title, title, detail)
}
