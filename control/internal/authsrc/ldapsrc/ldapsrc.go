// Package ldapsrc 用 LDAP / Active Directory 做口令认证，实现 authsrc.PasswordAuthenticator。
//
// # 为什么这里用库、而 IKEv2 我们自研
//
// 本仓库对 IKEv2/ESP 选择了从头自研（gateway/internal/ipsec/），那是因为它是
// **白帝↔白帝**的协议：两端都归我们，互通性风险为零，自研换来的是完全可控的实现。
// LDAP 恰好相反——它的**全部价值**就在于能连上**别人的** Active Directory。
// 自研一套 BER 编解码器在这里没有任何收益，只会把"能不能互通"变成一个新的、
// 且只有在客户现场才暴露的风险（对面可能是 AD、OpenLDAP、389-ds，各有方言与扩展）。
// 所以协议层直接用 github.com/go-ldap/ldap/v3，本包只负责**认证流程与安全语义**。
//
// # 认证流程
//
//	① 服务账号 bind（拿搜索权限）
//	② 按过滤器模板 search 定位用户条目（用户名经 RFC 4515 转义）
//	③ 用**用户自己的 entryDN + 用户输入的口令**再 bind 一次 —— 这一步才是认证
//	④ 回填 authsrc.Identity（Subject = entryDN）
//
// ★第③步必须用目录返回的 DN，而不是用模板拼 DN（`uid=%s,ou=people,...`）。
// 拼 DN 在 OU 分层的真实企业目录里几乎必然拼错，症状是"某些部门的人登不上"；
// 而且 DN 拼接有它自己的一套转义规则（RFC 4514，与过滤器的 4515 不同），
// 又是一处注入面。查出来再用，是唯一稳的做法。
//
// # 已知边界（别在这上面吹）
//
//   - 只做**简单 bind**（simple bind）。不支持 SASL / GSSAPI / Kerberos / NTLM。
//   - 不支持 referral 追踪：AD 多域林里对方回 referral 时我们直接当"没找到"。
//   - 组信息取 memberOf 属性，**不做嵌套组展开**（AD 的嵌套组要用
//     LDAP_MATCHING_RULE_IN_CHAIN 递归查，代价与语义都另说）。
//   - Subject 用 entryDN。它在用户改名/跨 OU 移动时会变；AD 的 objectGUID 才是
//     真正不变的标识。选 entryDN 是为了同时兼容非 AD 目录（objectGUID 是 AD 专有），
//     代价是：目录侧移动了对象，本地账号绑定需要重新建立。
//   - go-ldap v3.4.14 的拨号接口不吃 context，本包把 ctx 的 deadline 折算成
//     拨号/请求超时（见 dialTimeout），做不到"ctx 一取消立刻断开"。
package ldapsrc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"baidi.dev/control/internal/authsrc"
)

// TLSMode 传输层保护方式。
type TLSMode string

const (
	// TLSModeLDAPS 直接在 TLS 上跑 LDAP（默认端口 636）。首选。
	TLSModeLDAPS TLSMode = "ldaps"
	// TLSModeStartTLS 先明文连 389，再用 StartTLS 扩展操作升级。
	TLSModeStartTLS TLSMode = "starttls"
	// TLSModePlaintext 明文 LDAP。★逃生舱，仅限隔离网段里的联调。
	//
	// 简单 bind 会把**用户口令以明文**放进 LDAP 报文送上网线——不是哈希、不是挑战应答，
	// 就是明文。同网段任何一台机器抓包即得全员口令。选它必须是显式动作，且每次
	// 建 Provider 都会打 WARN（见 New）。
	TLSModePlaintext TLSMode = "plaintext"
)

const (
	// searchSizeLimit 定位用户时的搜索条数上限，固定为 2。
	//
	// ★为什么是 2 而不是 1：设成 1 的话，"过滤器写宽了匹配到多个人"和
	// "正好匹配到一个人"在返回结果上无法区分，我们会毫不知情地挑第一条去 bind——
	// 用户以为自己登录成了 A，实际认证的是 B，且**审计日志两侧都看起来正常**。
	// 取 2 是为了能"看见第二条"，看见就拒（见 lookup），把静默错配变成显式故障。
	searchSizeLimit = 2

	// maxUsernameLen 用户名长度上限。转义后最坏膨胀 3 倍，限一下免得有人拿
	// 兆字节级的用户名把目录服务器的过滤器编译器压垮（拒绝服务面，不是注入面）。
	maxUsernameLen = 256

	defaultConnectTimeout = 5 * time.Second
	defaultRequestTimeout = 10 * time.Second
)

// Config LDAP/AD 认证源配置。零值不可用，必须经 New 归一化与校验。
type Config struct {
	// Kind 决定方言默认值：authsrc.KindAD 走 AD 那套属性名，其余按通用 LDAP。
	// 只影响**默认值**——所有属性名都可以被下面的字段显式覆盖。
	Kind authsrc.Kind

	// ── 连接 ──
	Host string // 目录服务器主机名或 IP
	Port int    // 0 = 按 TLSMode 取默认（ldaps:636，其余:389）
	TLS  TLSMode

	// CACert 校验服务端证书用的 CA（PEM）。留空则用系统根证书池。
	//
	// ★填了就**只信这一把**（独立 pool，不并入系统池）。企业内网目录几乎都是
	// 私有 CA 签发的，只信私有 CA 比"系统池 + 私有 CA"更严：后者意味着任意一个
	// 公共 CA 误签一张你的目录服务器证书都能骗过校验。
	CACert string

	// InsecureSkipVerify 跳过服务端证书校验。★逃生舱，默认关。
	//
	// 打开等于把 TLS 降级成"只加密不认证"：中间人可以无声接管整条链路，
	// 而它拿到的是**用户明文口令**（简单 bind）。比明文 LDAP 更坏——明文至少
	// 一眼能看出没保护，这个看起来是有 TLS 的。开启会打 WARN。
	InsecureSkipVerify bool

	// ServerName 证书里应当出现的名字。留空取 Host。
	// 用 IP 连接但证书签的是主机名时，这里填主机名，比开 InsecureSkipVerify 正确得多。
	ServerName string

	// ── 服务账号（用于搜索定位用户，不是用来认证用户的）──
	BindDN       string
	BindPassword string

	// ── 目录结构 ──
	BaseDN string // 用户搜索的起点，如 OU=Users,DC=corp,DC=example
	// UserFilter 用户过滤器模板，必须含 {{username}} 占位符。
	// 留空按 Kind 取默认值（见 normalize）。
	UserFilter string

	UsernameAttr    string // 登录名属性：AD 用 sAMAccountName，通用 LDAP 用 uid
	DisplayNameAttr string // 显示名，默认 cn
	EmailAttr       string // 邮箱，默认 mail
	GroupAttr       string // 组成员，默认 memberOf

	// ── 超时 ──
	ConnectTimeout time.Duration // 默认 5s
	RequestTimeout time.Duration // 默认 10s

	// Logger 留空取 slog.Default()。抽成字段是为了让测试能断言"该打的 WARN 打了没"。
	Logger *slog.Logger
}

// Provider 一个已校验的 LDAP/AD 认证源。并发安全（每次认证自己拨号，不共享连接）。
//
// ★刻意不做连接池。池化的诱惑在于省一次 TLS 握手，但 LDAP 连接是**有状态**的
// （bind 之后整条连接就带着那个身份），复用一条刚被用户 bind 过的连接去做下一次
// 搜索，就是拿着上一个用户的权限查目录——这类越权在功能上完全无感，
// 只有在目录侧开了细粒度 ACL 时才会以"某些人搜不到某些人"的形式偶发暴露。
// 登录不是热路径，用完即弃换来的是"连接身份"这件事根本不存在。
type Provider struct {
	cfg Config
	tls *tls.Config
	log *slog.Logger
}

var _ authsrc.PasswordAuthenticator = (*Provider)(nil)

// New 归一化并校验配置，返回可用的 Provider。
// 配置缺失/非法一律返回包裹 authsrc.ErrNotConfigured 的错误——这是配置错误，
// 不是运行故障，控制台该把它显示成"这项没填对"而不是"目录连不上"。
func New(cfg Config) (*Provider, error) {
	c := cfg.normalize()
	lg := c.Logger

	if c.Host == "" {
		return nil, fmt.Errorf("ldapsrc: 未填写服务器地址: %w", authsrc.ErrNotConfigured)
	}
	if c.BaseDN == "" {
		return nil, fmt.Errorf("ldapsrc: 未填写 Base DN: %w", authsrc.ErrNotConfigured)
	}
	switch c.TLS {
	case TLSModeLDAPS, TLSModeStartTLS, TLSModePlaintext:
	default:
		return nil, fmt.Errorf("ldapsrc: 未知的传输方式 %q（应为 ldaps/starttls/plaintext）: %w", c.TLS, authsrc.ErrNotConfigured)
	}
	// ★服务账号有 DN 却没口令 = 一次"有 DN + 空口令"的 bind，多数目录会把它当**匿名 bind
	// 并返回成功**（RFC 4513 §5.1.2）。于是我们以为在用服务账号搜索，实际是匿名身份——
	// 症状是"部分用户查不到"（匿名可见的条目少），而日志里 bind 是成功的。
	// 想匿名搜索就把 BindDN 也留空（显式），不要靠空口令"顺便"变成匿名。
	if c.BindDN != "" && c.BindPassword == "" {
		return nil, fmt.Errorf("ldapsrc: 配置了服务账号 DN 但口令为空（空口令 bind 会被目录当作匿名，请填写口令；确需匿名搜索请把 DN 也留空）: %w", authsrc.ErrNotConfigured)
	}
	if !strings.Contains(c.UserFilter, usernamePlaceholder) {
		return nil, fmt.Errorf("ldapsrc: 用户过滤器 %q 缺少 %s 占位符: %w", c.UserFilter, usernamePlaceholder, authsrc.ErrNotConfigured)
	}
	// 拿一个不含特殊字符的样本把模板编译一遍：模板括号不配对之类的笔误，
	// 不在这里挡就要等到第一个用户登录时才炸，而那时看起来像"这个人登不上"。
	if _, err := ldap.CompileFilter(renderUserFilter(c.UserFilter, "probe")); err != nil {
		return nil, fmt.Errorf("ldapsrc: 用户过滤器 %q 语法非法: %v: %w", c.UserFilter, err, authsrc.ErrNotConfigured)
	}

	tc, err := c.buildTLS()
	if err != nil {
		return nil, err
	}

	// ── 降级项一律 WARN。这些都是"能跑但不安全"，静默通过等于把风险藏起来 ──
	if c.TLS == TLSModePlaintext {
		lg.Warn("LDAP 认证源使用明文连接：简单 bind 会把用户口令明文送上网络，同网段抓包即得全员口令；仅限隔离环境联调",
			"host", c.Host, "port", c.Port)
	}
	if c.InsecureSkipVerify {
		lg.Warn("LDAP 认证源跳过了服务端证书校验：TLS 退化为「加密但不认证」，中间人可无声接管并拿到用户明文口令",
			"host", c.Host, "port", c.Port)
	}
	if c.BindDN == "" {
		lg.Warn("LDAP 认证源未配置服务账号，将以匿名身份搜索用户；多数目录对匿名身份隐藏大部分条目，可能表现为「部分用户登不上」",
			"host", c.Host, "baseDN", c.BaseDN)
	}

	return &Provider{cfg: c, tls: tc, log: lg}, nil
}

// normalize 补默认值。不改调用方传入的 Config（值接收者）。
func (c Config) normalize() Config {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	c.Host = strings.TrimSpace(c.Host)
	c.BaseDN = strings.TrimSpace(c.BaseDN)
	c.BindDN = strings.TrimSpace(c.BindDN)
	c.UserFilter = strings.TrimSpace(c.UserFilter)
	c.ServerName = strings.TrimSpace(c.ServerName)

	if c.TLS == "" {
		// ★默认必须是 TLS。默认值决定了"没人特意配置时"的安全水位，
		// 而绝大多数部署就是不会特意配置。
		c.TLS = TLSModeLDAPS
	}
	if c.Port == 0 {
		if c.TLS == TLSModeLDAPS {
			c.Port = 636
		} else {
			c.Port = 389
		}
	}
	if c.ServerName == "" {
		c.ServerName = c.Host
	}

	// ── AD 方言 ──
	// AD 的登录名属性是 sAMAccountName（不是 uid，AD 默认 schema 里压根没有 uid），
	// 对象类是 user（不是 posixAccount/inetOrgPerson）。这两处照通用 LDAP 抄的话，
	// 症状是"连得上、服务账号也 bind 成功了，但所有人都查不到"。
	//
	// 默认过滤器同时接受 userPrincipalName：AD 用户习惯输入 alice@corp.example
	// 这种 UPN 形式，只认 sAMAccountName 会让他们必须记住"另一个"用户名。
	// 两个分支命中同一条目不会重复计数；万一命中了不同条目，说明目录里存在
	// 交叉命名，会被 lookup 的"命中多条即拒"挡下——那正是该拒的情形。
	//
	// ★刻意**不**在默认过滤器里加 `(!(userAccountControl:1.2.840.113556.1.4.803:=2))`
	// 这类"排除已禁用账号"的条件：加了之后被禁用的账号会表现成"用户不存在"，
	// 我们就再也拿不到 AD 回的 data 533，运维日志里也就没有"账号已被禁用"这句话了。
	// 让 AD 自己在 bind 阶段拒绝，我们才能把真实原因记下来。
	isAD := c.Kind == authsrc.KindAD
	if c.UserFilter == "" {
		if isAD {
			c.UserFilter = "(&(objectClass=user)(|(sAMAccountName=" + usernamePlaceholder + ")(userPrincipalName=" + usernamePlaceholder + ")))"
		} else {
			c.UserFilter = "(&(objectClass=person)(uid=" + usernamePlaceholder + "))"
		}
	}
	if c.UsernameAttr == "" {
		if isAD {
			c.UsernameAttr = "sAMAccountName"
		} else {
			c.UsernameAttr = "uid"
		}
	}
	if c.DisplayNameAttr == "" {
		c.DisplayNameAttr = "cn"
	}
	if c.EmailAttr == "" {
		c.EmailAttr = "mail"
	}
	if c.GroupAttr == "" {
		c.GroupAttr = "memberOf"
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = defaultConnectTimeout
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultRequestTimeout
	}
	return c
}

// buildTLS 组装 TLS 配置。明文模式返回 nil。
func (c Config) buildTLS() (*tls.Config, error) {
	if c.TLS == TLSModePlaintext {
		return nil, nil
	}
	tc := &tls.Config{
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // 逃生舱，New 里已 WARN
		MinVersion:         tls.VersionTLS12,
	}
	if pem := strings.TrimSpace(c.CACert); pem != "" {
		pool := x509.NewCertPool() // 独立池：只信这一把，理由见 Config.CACert
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, fmt.Errorf("ldapsrc: CA 证书不是合法 PEM: %w", authsrc.ErrNotConfigured)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

// ── 认证 ───────────────────────────────────────────────────────────────────

// Authenticate 实现 authsrc.PasswordAuthenticator。
func (p *Provider) Authenticate(ctx context.Context, username, password string) (authsrc.Identity, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return authsrc.Identity{}, fmt.Errorf("ldapsrc: 用户名为空: %w", authsrc.ErrInvalidCredentials)
	}
	if len(username) > maxUsernameLen {
		return authsrc.Identity{}, fmt.Errorf("ldapsrc: 用户名过长(%d 字节): %w", len(username), authsrc.ErrInvalidCredentials)
	}

	// ★★ 空口令必须在这里显式拒掉，这是 LDAP 最经典的认证绕过 ★★
	//
	// LDAP 简单 bind 里"有 DN + 零长度口令"在协议层被定义为**匿名 bind**
	// （RFC 4513 §5.1.1 unauthenticated bind），大量目录服务端会直接回 success。
	// 于是攻击者只要知道一个**真实存在的用户名**、口令留空，整条链路就会：
	// 搜到该用户 → 拿他的 DN 去 bind → 服务端回成功 → 我们签发他的会话。
	// 没有任何一层会报错，审计日志里是一次完全正常的"某某登录成功"。
	//
	// go-ldap 的 Conn.Bind 目前也带了同样的检查（SimpleBindRequest.AllowEmptyPassword
	// 默认 false），但**不能把安全性寄托在它身上**：那是库的客户端便利检查，
	// 换版本、换成 SimpleBind 手工构造请求、或将来改用别的库，它就没了。
	// 认证语义的闸门必须在我们自己的代码里，且有我们自己的用例守着。
	if password == "" {
		p.log.Warn("LDAP 认证收到空口令，已直接拒绝（空口令 bind 会被目录当作匿名并返回成功，属认证绕过）",
			"user", username, "host", p.cfg.Host)
		return authsrc.Identity{}, fmt.Errorf("ldapsrc: 口令为空: %w", authsrc.ErrInvalidCredentials)
	}

	// ① 服务账号连接：只用来搜索。
	conn, err := p.dial(ctx)
	if err != nil {
		return authsrc.Identity{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := p.bindService(conn); err != nil {
		return authsrc.Identity{}, err
	}

	// ② 定位用户条目。
	entry, err := p.lookup(conn, username)
	if err != nil {
		return authsrc.Identity{}, err
	}

	// ★ DN 为空还去 bind 是致命的：go-ldap 会发出一个"名字为空 + 口令非空"的
	// 简单 bind，这在 RFC 4513 里是未定义/应拒的形态，但确实有目录实现回成功——
	// 那就等于任何口令都能登录任何账号。目录不该回空 DN，回了就是异常，拒掉。
	if strings.TrimSpace(entry.DN) == "" {
		p.log.Error("LDAP 目录返回了空 DN 的条目，已拒绝认证（空 DN 去 bind 可能被服务端当作匿名/未认证 bind 并返回成功）",
			"user", username, "host", p.cfg.Host)
		return authsrc.Identity{}, fmt.Errorf("ldapsrc: 目录返回了空 DN: %w", authsrc.ErrSourceUnavailable)
	}

	// ③ 用用户自己的 DN + 口令再 bind 一次 —— 这一步才是真正的认证。
	//
	// ★用**另一条连接**，不在服务账号那条连接上 rebind。理由是 LDAP 连接的身份是
	// 有状态的：RFC 4511 §4.2.1 规定 bind **失败**会把连接置回匿名态。若在同一条
	// 连接上 rebind 失败后还继续用它做任何操作，那些操作就悄悄变成匿名身份执行了
	// （返回结果变少但不报错）。本流程眼下不会在 bind 之后再搜索，但把"连接身份"
	// 这个隐式状态彻底消除掉，比依赖"当前代码顺序恰好安全"要稳。
	userConn, err := p.dial(ctx)
	if err != nil {
		return authsrc.Identity{}, err
	}
	defer func() { _ = userConn.Close() }()
	if err := userConn.Bind(entry.DN, password); err != nil {
		return authsrc.Identity{}, p.classifyUserBind(err, username, entry.DN)
	}

	id := authsrc.Identity{
		Subject:     entry.DN,
		Username:    firstNonEmpty(entry.GetAttributeValue(p.cfg.UsernameAttr), username),
		DisplayName: entry.GetAttributeValue(p.cfg.DisplayNameAttr),
		Email:       entry.GetAttributeValue(p.cfg.EmailAttr),
		Groups:      entry.GetAttributeValues(p.cfg.GroupAttr),
	}
	return id.Normalized(), nil
}

// Probe 连通性自检：拨号 + 服务账号 bind + 确认 BaseDN 真实存在。**不校验任何用户凭据**。
func (p *Provider) Probe(ctx context.Context) error {
	conn, err := p.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := p.bindService(conn); err != nil {
		return err
	}

	// ★顺带验 BaseDN 是否存在。只验"能连上 + 服务账号能 bind"是不够的：
	// BaseDN 写错（少一级 OU、DC 顺序反了）时连接与 bind 都完全正常，
	// 但之后每一次用户搜索都返回 0 条 —— 对外表现为"**所有人**密码都不对"。
	// 这正是最该在"测试连接"按钮上就暴露的问题，放到用户登录时才发现代价太大。
	req := ldap.NewSearchRequest(
		p.cfg.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, p.timeLimitSeconds(), false,
		"(objectClass=*)",
		[]string{"1.1"}, // RFC 4511：1.1 = 一个属性都不要，只要 DN
		nil,
	)
	if _, err := conn.Search(req); err != nil {
		if isSizeLimit(err) {
			return nil // 服务端按 sizeLimit 截断，说明条目是在的
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return fmt.Errorf("ldapsrc: Base DN %q 在目录中不存在: %w", p.cfg.BaseDN, authsrc.ErrNotConfigured)
		}
		return fmt.Errorf("ldapsrc: 检查 Base DN %q 失败: %v: %w", p.cfg.BaseDN, err, authsrc.ErrSourceUnavailable)
	}
	return nil
}

// ── 内部步骤 ───────────────────────────────────────────────────────────────

// dial 建连（含 TLS/StartTLS）并设置请求超时。任何失败都归为 ErrSourceUnavailable。
func (p *Provider) dial(ctx context.Context) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ldapsrc: 上下文已取消: %v: %w", err, authsrc.ErrSourceUnavailable)
	}
	addr := net.JoinHostPort(p.cfg.Host, strconv.Itoa(p.cfg.Port))
	scheme := "ldap"
	if p.cfg.TLS == TLSModeLDAPS {
		scheme = "ldaps"
	}
	conn, err := ldap.DialURL(scheme+"://"+addr,
		ldap.DialWithDialer(&net.Dialer{Timeout: p.dialTimeout(ctx)}),
		ldap.DialWithTLSConfig(p.tls),
	)
	if err != nil {
		// ★这里必须是 ErrSourceUnavailable 而不是 ErrInvalidCredentials。
		// 混为一谈的症状：AD 挂了/证书过期了，全公司看到的却是"密码错误"，
		// 运维顺着"用户忘了密码"查，没人去看目录服务器。
		return nil, fmt.Errorf("ldapsrc: 连接 %s://%s 失败: %v: %w", scheme, addr, err, authsrc.ErrSourceUnavailable)
	}
	// ★超时必须设在 StartTLS **之前**。
	//
	// go-ldap 的 requestTimeout 初值是 0，而 0 的语义是"不挂任何定时器"——
	// StartTLS 是一次扩展操作，它内部等响应的那个 channel 接收在没有定时器时
	// 会**无限阻塞**，紧随其后的 TLS Handshake 同样没有 read deadline。
	// dialTimeout 只约束 TCP connect（go-ldap 不吃 ctx），管不到这一段。
	//
	// 于是目录进程卡死、或前面有会 ACK 的 tarpit 时，每次登录都会挂死一个
	// HTTP handler goroutine + 一个 fd + go-ldap 的两个内部协程，且**一条日志都没有**；
	// 用户看到的只是登录页转圈，反复重试就能把控制面的 fd 耗光。
	// LDAPS 路径不受影响（握手在 tls.DialWithDialer 里，由 Dialer.Timeout 覆盖）。
	conn.SetTimeout(p.cfg.RequestTimeout)
	if p.cfg.TLS == TLSModeStartTLS {
		if err := conn.StartTLS(p.tls); err != nil {
			_ = conn.Close()
			// StartTLS 失败绝不能"降级继续用明文"——那会把用户口令明文发出去。
			return nil, fmt.Errorf("ldapsrc: 与 %s 的 StartTLS 协商失败: %v: %w", addr, err, authsrc.ErrSourceUnavailable)
		}
	}
	return conn, nil
}

// dialTimeout 取「配置的连接超时」与「ctx 剩余时间」的较小值。
//
// ★不能直接把剩余时间塞进 net.Dialer.Timeout：Dialer.Timeout == 0 的语义是
// **没有超时**，而"ctx 已经过期"算出来恰好是 0 或负数。写反的后果不是快速失败，
// 是这次拨号永远不超时——一个本该毫秒级返回的错误变成挂死。故这里兜到 1ms。
func (p *Provider) dialTimeout(ctx context.Context) time.Duration {
	d := p.cfg.ConnectTimeout
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < d {
			d = left
		}
	}
	if d <= 0 {
		d = time.Millisecond
	}
	return d
}

// bindService 以服务账号 bind。BindDN 为空表示匿名搜索（New 里已 WARN）。
func (p *Provider) bindService(conn *ldap.Conn) error {
	if p.cfg.BindDN == "" {
		return nil
	}
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			// ★服务账号口令错/过期是**我们的**配置故障，绝不能回 ErrInvalidCredentials。
			// 回错了的症状：服务账号口令一到期，全公司同时"密码错误"，
			// 而每个人的密码其实都是对的。这类误导最贵。
			code, reason := decodeADBindFailure(err.Error())
			p.log.Error("LDAP 服务账号 bind 被拒绝（配置故障，不是用户口令问题）",
				"bindDN", p.cfg.BindDN, "host", p.cfg.Host, "adDataCode", code, "adReason", reason, "err", err)
			return fmt.Errorf("ldapsrc: 服务账号 %q bind 被拒绝（口令错误或已过期）: %w", p.cfg.BindDN, authsrc.ErrNotConfigured)
		}
		return fmt.Errorf("ldapsrc: 服务账号 bind 失败: %v: %w", err, authsrc.ErrSourceUnavailable)
	}
	return nil
}

// lookup 按过滤器定位唯一的用户条目。
func (p *Provider) lookup(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	filter := renderUserFilter(p.cfg.UserFilter, username)

	req := ldap.NewSearchRequest(
		p.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		searchSizeLimit, p.timeLimitSeconds(), false,
		filter,
		// 只取用得上的属性，不用 "*"。少传一点是次要的，主要是别把 userPassword /
		// unicodePwd 这类口令材料拉进本进程内存——拉进来就可能进日志、进 panic 栈。
		p.wantAttrs(),
		nil,
	)
	// ★客户端侧也强制一遍条数上限：sizeLimit 在协议里是**建议**，服务端可以无视，
	// 也可能被目录管理员的全局上限覆盖。只指望服务端守约，"匹配多条"这道闸就形同虚设。
	req.EnforceSizeLimit = true

	res, err := conn.Search(req)
	switch {
	case err == nil:
		// 正常路径
	case isSizeLimit(err):
		// 结果被截断 = 至少还有我们没看到的条目 → 唯一性无法确认，按"匹配多条"处理。
		return nil, p.errAmbiguous(username, filter, res)
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		// BaseDN 本身不存在。配置问题，不是"这个用户没有"。
		return nil, fmt.Errorf("ldapsrc: Base DN %q 在目录中不存在: %w", p.cfg.BaseDN, authsrc.ErrNotConfigured)
	default:
		return nil, fmt.Errorf("ldapsrc: 搜索用户失败: %v: %w", err, authsrc.ErrSourceUnavailable)
	}

	switch {
	case res == nil || len(res.Entries) == 0:
		// ★与"口令错误"合并成同一个对外错误，刻意不区分：区分开这个接口就成了
		// 用户名枚举器，攻击者能把整个目录的账号名捞干净（见 authsrc.ErrInvalidCredentials）。
		return nil, fmt.Errorf("ldapsrc: 用户 %q 在目录中不存在: %w", username, authsrc.ErrInvalidCredentials)
	case len(res.Entries) > 1:
		return nil, p.errAmbiguous(username, filter, res)
	}
	return res.Entries[0], nil
}

// errAmbiguous 过滤器命中多条时的统一出口。
//
// ★归为 ErrNotConfigured 而不是 ErrInvalidCredentials：命中多条的根因是过滤器写宽了
// 或目录里存在重名条目，都是**配置/数据**问题。若回"密码错误"，运维会去查这个用户，
// 而真正该改的是过滤器——这正是本包反复要避免的那种误导。
// 用户侧看到什么由 API 层决定；服务端日志里必须能一眼看出是哪几条 DN 撞了。
func (p *Provider) errAmbiguous(username, filter string, res *ldap.SearchResult) error {
	var dns []string
	if res != nil {
		for _, e := range res.Entries {
			dns = append(dns, e.DN)
		}
	}
	p.log.Error("LDAP 用户过滤器命中多个条目，已拒绝认证（挑其中一条去 bind 会让用户以为登录成了 A、实际认证的是 B）",
		"user", username, "filter", filter, "baseDN", p.cfg.BaseDN, "matched", dns)
	return fmt.Errorf("ldapsrc: 用户 %q 在 %q 下命中多个条目(%v)，请收窄用户过滤器: %w",
		username, p.cfg.BaseDN, dns, authsrc.ErrNotConfigured)
}

// classifyUserBind 把用户 bind 的失败分成"凭据错"与"源不可用"。
func (p *Provider) classifyUserBind(err error, username, dn string) error {
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		// AD 把"账号禁用/锁定/口令过期"全塞进 49 号码的诊断串里（见 adcode.go）。
		// 对用户仍回统一文案，但服务端日志必须留下解出来的原因，
		// 否则运维会对着一个被禁用的账号查"他是不是记错密码了"。
		if code, reason := decodeADBindFailure(err.Error()); code != "" {
			p.log.Warn("LDAP/AD 用户 bind 被拒绝",
				"user", username, "dn", dn, "adDataCode", code,
				"adReason", firstNonEmpty(reason, "未收录的 AD 子状态码，请按该十六进制码查 AD 文档"))
		}
		return fmt.Errorf("ldapsrc: 用户 %q bind 被拒绝: %w", username, authsrc.ErrInvalidCredentials)
	}
	// 49 之外的一律当源故障：目录忙、连接被切、TLS 出问题都会落在这里，
	// 把它们说成"密码错误"就是又一次把运维引向错误方向。
	return fmt.Errorf("ldapsrc: 用户 bind 失败: %v: %w", err, authsrc.ErrSourceUnavailable)
}

// wantAttrs 搜索时请求的属性清单（去重、去空）。
func (p *Provider) wantAttrs() []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range []string{p.cfg.UsernameAttr, p.cfg.DisplayNameAttr, p.cfg.EmailAttr, p.cfg.GroupAttr} {
		a = strings.TrimSpace(a)
		if a == "" || seen[strings.ToLower(a)] {
			continue
		}
		seen[strings.ToLower(a)] = true
		out = append(out, a)
	}
	return out
}

// timeLimitSeconds 把请求超时折算成协议里的 timeLimit（秒，整数）。
// 至少 1 秒：LDAP 里 timeLimit=0 的语义是"不限时"，向下取整到 0 会把
// 一个 800ms 的超时配置变成"永不超时"，与 dialTimeout 里那个坑同源。
func (p *Provider) timeLimitSeconds() int {
	s := int(p.cfg.RequestTimeout / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}

// isSizeLimit 判断错误是否为"结果被条数上限截断"。两种来源都要认：
// go-ldap 客户端自己截断（ErrSizeLimitExceeded），以及服务端回 4 号结果码。
func isSizeLimit(err error) bool {
	return errors.Is(err, ldap.ErrSizeLimitExceeded) || ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
