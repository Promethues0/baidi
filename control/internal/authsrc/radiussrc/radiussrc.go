// Package radiussrc 用 RADIUS（RFC 2865）做口令认证，实现 authsrc.PasswordAuthenticator。
//
// # 为什么这里用库、而 IKEv2 我们自研
//
// 与 ldapsrc 同一条分界：RADIUS 的全部价值在于能连上**别人的**认证服务器
// （FreeRADIUS、Cisco ISE、动态口令厂商的 RADIUS 前置……）。自研一套报文编解码只会把
// "能不能互通"变成新的风险，所以协议层直接用 layeh.com/radius，本包只负责
// **认证流程与安全语义**（错误分层、Subject 设计、Message-Authenticator）。
//
// # Subject 设计——正面回答 SCOPE 里那条「明拒」理由
//
// 本项目此前把 RADIUS 列为明拒，理由是：「RADIUS 没有稳定 Subject → 绑定只能退回
// 按用户名 → 外部目录里新建一个同名 admin 即可冒充本地管理员」。这句话的**前半句是对的**
// （RADIUS 应答里确实没有 entryDN / sub 那样的权威标识），**后半句的推导不成立**——
// 它假设"按用户名绑定"会绑到本地账号上，而本仓的账号映射机制早已把这条路堵死：
//
//   - Subject 对 RADIUS 定义为 `radius:<认证源 id>:<User-Name>`（见 Subject()），其中
//     User-Name 是**实际发给服务器认证的那个字符串**（只去首尾空白，**不改大小写**）。
//     它在**该源内**稳定（同一个人以同一写法两次登录得到同一个 Subject），且绑定表主键是
//     (source_id, subject)——另一条 RADIUS 源里同名的 alice 是另一个身份，互不串号。
//     ★绑定键必须等于被认证方真正认过的字符串：此前 Subject 按小写归一而 User-Name
//     保持原样，对大小写敏感的 RADIUS 后端（FreeRADIUS 接 files/SQL 后端的默认姿态），
//     "Alice" 与 "alice" 是**两个各有口令的账号**，却会被白帝绑成同一个 Subject——
//     后登者直接继承先登者的授权 / JIT 授予 / 封禁状态，且审计里是一次正常登录。
//     代价是「同一人换大小写登录会建出两个账号」——这比「两个人合并成一个」便宜得多，
//     且在用户目录页上看得见。部署建议：服务器侧不区分大小写的部署（接 AD 的 FreeRADIUS
//     等），请在 RADIUS 侧把 User-Name 规范化（如 `rewrite_user_name` / unlang 里 tolower），
//     白帝这边刻意不替它做这件事。
//   - 外部账号 `role` 恒 user、`pass_hash` 恒空（store.BindExternalUser）：RADIUS 服务器
//     说"alice 通过了"，白帝这边落的是一个**普通外部用户**，没有任何本地口令能登录它。
//   - 与本地账号撞名时**不复用**那个本地账号，而是加来源后缀 `alice@<源 id>`
//     （BindExternalUser 的撞名分支，且加了后缀还继续查重）。RADIUS 侧建一个叫 admin 的
//     用户，登进来的是 `admin@<源 id>`，不是本地 admin。
//   - 把它提升为管理员会被 `api.guardLocalCredentialForAdmin` 拒绝（外部账号无本地口令，
//     提上去也登不进管理台，故入口直接收口）。即便管理员按补救路径（先重置本地口令）
//     提了权，管理员账号也**不能经任何外部认证源换取会话**——门户口令路径、OIDC 回调、
//     **OIDC 交接票据换会话**三处共用一个闸（`api.externalSessionCredential`）：RADIUS
//     服务器说"这个 admin 通过了"，换不到那个已提权账号的会话。第三处不是重复：交接票据
//     里的 Role 是**签发那一刻的快照**，60s 窗口内把某人改派成 admin 的话，只在前两处判
//     就等于给那张票开了个洞——所以换会话时按重读的 users 行**再判一次**。
//
// 于是 RADIUS 服务器的管理者能造出的最多是**这个源的普通外部身份**——这恰恰是他本来
// 就有权造的东西（他管着那台服务器）。"冒充本地管理员"那条路在 Subject 之外的三道
// 机制上各断了一次。**「没有稳定 Subject」真正的代价**只剩一条：目录侧把 alice 改名成
// alice2，白帝这边会把她当成新人重建一个号（与 ldapsrc 里 entryDN 随改名/移动而变
// 是同一种代价）。这是可接受的、可解释的运维事实，不是安全漏洞。
//
// # 认证流程
//
//	① 组 Access-Request：User-Name + NAS-Identifier + （PAP）User-Password
//	   或（CHAP）CHAP-Challenge + CHAP-Password，**一律附 Message-Authenticator**
//	   （RFC 5080 §2.2.2 建议；FreeRADIUS 3.2.5+ 为缓解 Blast-RADIUS 可以配成必需）
//	② 发送并等待应答；按剩余预算重发（RADIUS 是 UDP，无应答就是超时）。Retries 缺席 =
//	   默认 1（共发两次）；**显式 0 = 只发一次**，此时库的重发计时器一并关掉（见 exchange）
//	③ 应答的 Response Authenticator 由库校验（MD5）；本包**要求**应答另带合法的
//	   Message-Authenticator（HMAC-MD5）——Blast-RADIUS（CVE-2024-3596）攻破的正是
//	   只有 MD5 的那一层，缺席与校验不过一律判源不可用（见 exchange 与下方「应答侧
//	   Message-Authenticator 是必需的」）
//	④ Access-Accept → 回填 authsrc.Identity；Access-Reject → ErrInvalidCredentials；
//	   其余（超时 / 网络 / 密钥不匹配 / 应答缺 MA / Access-Challenge）→ ErrSourceUnavailable
//
// # 应答侧 Message-Authenticator 是必需的（Blast-RADIUS）
//
// 请求侧**无条件**附 Message-Authenticator，应答侧此前的判据是「带了才校验」——
// 那等于不校验：能改报文的攻击者（Blast-RADIUS 的前提就是他在链路上）只要把伪造应答里的
// Message-Authenticator 属性**删掉**，"带了"为假，整道 HMAC 校验被跳过，只剩 MD5 的
// Response Authenticator，而那层正是 CVE-2024-3596 攻破的对象。**要不要验，不能由被攻击的
// 那条链路上的攻击者决定。**
//
// 所以默认**要求**：应答不带该属性 = 源不可用（错误文案同时列出两种可能——被剥离，或
// 服务器本就不回）。确实不回该属性的老设备有一个**显式**逃生舱
// Config.AllowMissingResponseMessageAuthenticator（落库键 allowMissingResponseMessageAuthenticator，
// 默认 false = 要求；零值即安全那一侧），打开时保存回执与「测试连接」结论当面说明放弃了哪一层保护。
// **逃生舱只放宽"缺席"，不放宽"带了但校验不过"**——后者是确定的篡改/密钥不匹配，任何配置下都拒。
//
// # 错误分层（与 ldapsrc 逐字同款，别在这上面松）
//
// Access-Reject 是**唯一**映射到 ErrInvalidCredentials 的结果——它计入爆破锁定、
// 对用户回「用户名或密码错误」。超时、UDP 端口不可达、共享密钥不对（应答校验失败）
// 都是 ErrSourceUnavailable：**不计入锁定、不回"密码错误"**。回错了的症状与 LDAP
// 服务账号口令过期那条一样贵——共享密钥一换，全公司同时"密码错误"，而每个人的密码
// 都是对的。
//
// ★共享密钥不匹配在真实服务器上经常表现成**超时**而不是"应答校验失败"：FreeRADIUS
// 对 Message-Authenticator 校验不过的请求是**静默丢弃**（日志里一句 "Shared secret is
// incorrect"，不回任何报文）；对未登记的 NAS 客户端同样静默丢弃。所以超时那条错误
// 文案必须把这两种可能都列出来，"测试连接"才有指导下一步的价值。
//
// # 已知边界（别在这上面吹）
//
//   - 只做 PAP 与 CHAP（RFC 1994 变体）。**不做 EAP**（EAP-TLS / PEAP / EAP-TTLS），
//     不做 MS-CHAPv2。CHAP 要求服务器侧持有明文口令，接 AD 后端的 FreeRADIUS 通常
//     只放行 PAP——选 CHAP 前先确认服务端。
//   - **不做 Access-Challenge 多轮应答**（动态令牌"再输一次 next token"那种交互）；
//     收到 Challenge 归为源不可用并写明原因。
//   - **不做「RADIUS 作为二次认证令牌」**：控制台认证策略里那个「Radius 动态令牌」是
//     二次认证方式（authpolicy.SecondaryMethods 里仍冻结），与本包的「RADIUS 作为
//     口令认证源」是两件事。
//   - RADIUS 应答里没有邮箱、显示名——Identity.Email 恒空。**准入闸的邮箱域白名单
//     对 RADIUS 源恒 fail-closed**，API 层在保存时拒绝为 RADIUS 源配置 allowedDomains。
//   - 组只能从 Class / Filter-Id / Reply-Message 三个标准属性之一映射（由服务端策略
//     写入），不做厂商私有属性（VSA）。**单次登录最多考察前 maxGroupValues（32）个值、
//     每个 ≤ maxGroupValueLen（128）字节，超出的丢弃并节流记日志**——把 Class 用作逐会话
//     标识的服务器（Cisco ISE 的 `CACS:<session>…`、FreeRADIUS 的会话状态 Class）每次登录
//     都回一个新值，不设上限就是让对面决定我们这边建多少行。同一条理由，API 层**绝不从
//     这些值自动新建用户组**：它们只用于准入闸（allowedGroups 比对）与「已存在的用户组」
//     的成员同步（见 api.radiusSyncableGroups）。★**LDAP / OIDC 的组同步是另一条路**
//     （memberOf / groups claim，DN 维度、无条数上限，仍会自动建组），本波刻意没动它——
//     别把这条收口读成"组同步已统一"。
//   - **应答侧 Message-Authenticator 默认必需**（见上一节）。打开逃生舱
//     AllowMissingResponseMessageAuthenticator 之后，该源的应答完整性就只剩 MD5 的
//     Response Authenticator——Blast-RADIUS 攻破的正是它，别把打开逃生舱的部署说成
//     "已缓解 CVE-2024-3596"。本包**不做** RADIUS/TLS（RadSec），那才是根治。
//   - 无账号状态回验（协议里没有"按用户查状态"的通道；与 OIDC 同一条边界）。
//   - **未与 FreeRADIUS / 商用 RADIUS 设备实机互通验证**：所有往返都是对进程内的
//     layeh 服务端。报文编解码是库的，Message-Authenticator 的取舍是按 RFC 写的。
//   - 明文传输：RADIUS 只用 MD5 混淆 User-Password（RFC 2865 §5.2），CHAP 只保护口令
//     本身；RADIUS/TLS（RadSec，RFC 6614）本波不做。请把服务器放在受控网段。
package radiussrc

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"

	"baidi.dev/control/internal/authsrc"
)

// Protocol 口令在报文里的携带方式。
type Protocol string

const (
	// ProtocolPAP User-Password 属性（RFC 2865 §5.2，MD5 混淆）。默认；互通面最广。
	ProtocolPAP Protocol = "pap"
	// ProtocolCHAP CHAP-Challenge + CHAP-Password（RFC 2865 §5.3）。口令不上网线，
	// 但服务端必须持有明文口令才能验。
	ProtocolCHAP Protocol = "chap"
)

// GroupAttr 组信息从应答的哪个标准属性映射。空 = 不映射组。
type GroupAttr string

const (
	GroupAttrNone         GroupAttr = ""
	GroupAttrClass        GroupAttr = "class"         // Class（25）：多数服务端用它回传角色/组
	GroupAttrFilterID     GroupAttr = "filter-id"     // Filter-Id（11）
	GroupAttrReplyMessage GroupAttr = "reply-message" // Reply-Message（18）：少见，但有些动态口令厂商这么回
)

// 探测方法（ProbeReport.Method 的取值），控制台据此说清"是哪一种可达"。
const (
	ProbeMethodStatusServer  = "status-server"  // RFC 5997
	ProbeMethodAccessRequest = "access-request" // 服务器不支持 Status-Server 时的回退
)

const (
	defaultPort          = 1812
	defaultTimeout       = 3 * time.Second
	defaultRetries       = 1
	defaultNASIdentifier = "baidi-control"

	// maxUsernameLen RADIUS 属性值上限是 253 字节（Length 一字节减去头）。
	maxUsernameLen = 253
	// maxRetries 重发上限。UDP 重发是给丢包留的，不是给"再等等看"留的。
	maxRetries = 5

	// maxGroupValues 单次登录最多考察的组属性值个数（按报文顺序取前 N 个）；
	// maxGroupValueLen 单个组值的字节上限。两者都是**被判定方自报数据的入口上限**：
	// 组值来自对面服务器，没有上限就是让对面决定我们这边的内存与表规模。
	maxGroupValues   = 32
	maxGroupValueLen = 128
	// groupDropLogEvery 组值被丢弃时的日志节流周期：一台每次都回 40 个 Class 的服务器
	// 在高峰期每秒都会触发，逐条记等于把日志变成它的回显。
	groupDropLogEvery = time.Minute
	// missingMALogEvery 「逃生舱放行了不带 Message-Authenticator 的应答」的日志节流周期。
	// 同一条理由：它在每次登录的热路径上。
	missingMALogEvery = time.Minute
)

// Config RADIUS 认证源配置。零值不可用，必须经 New 归一化与校验。
type Config struct {
	// SourceID 认证源 id，Subject 的第二段。**必填**——没有它 Subject 就退化成
	// 跨源共享的裸用户名，两条 RADIUS 源里的 alice 会被绑成同一个人。
	SourceID string

	Host string
	Port int // 0 = 1812
	// Secret NAS 与服务器的共享密钥。**必填**；由 API 层从 auth_source_secrets 解密后传入，
	// 与 LDAP bind 口令同一条只写不读的路径。
	Secret string

	// NASIdentifier 报文里的 NAS-Identifier（RFC 2865 要求 NAS-IP-Address 与
	// NAS-Identifier 至少一个）。服务端常据此挑策略。默认 "baidi-control"。
	NASIdentifier string

	Protocol  Protocol  // 默认 pap
	GroupAttr GroupAttr // 默认不映射

	// Timeout 单次等待应答的时间；Retries 重发次数。总预算 = Timeout × (Retries+1)，
	// 且**永远不超过 ctx 的剩余预算**（对齐 BAIDI_EXTAUTH_TIMEOUT 那套 8s 外部认证预算）。
	Timeout time.Duration // 默认 3s
	Retries int           // 默认 1（共发两次）；显式 0 = 只发一次不重发；<0 = 取默认（API 层用它表示"配置里缺席"）

	// AllowMissingResponseMessageAuthenticator 逃生舱：允许应答**不带**
	// Message-Authenticator（RFC 2869 §5.14）。
	//
	// ★**零值 false = 要求带**，安全那一侧就是零值——存量库里没有这个键、旧调用方
	// 没填这个字段时，得到的都是收紧的姿态。反过来写（RequireXxx bool）的话，
	// 升级那一刻所有既有配置的零值都是"不要求"，而两边都不报错。
	//
	// 打开等于放弃 Blast-RADIUS（CVE-2024-3596）缓解里唯一还站得住的那层 HMAC，
	// 只剩已被攻破的 MD5 Response Authenticator。只给确实不回该属性的老设备用，
	// 且保存回执与「测试连接」结论必须当面说明（见 Provider.waiverNote）。
	// **它只放宽"缺席"**：带了却校验不过在任何配置下都拒。
	AllowMissingResponseMessageAuthenticator bool

	// Logger 留空取 slog.Default()。
	Logger *slog.Logger
}

// Provider 一个已校验的 RADIUS 认证源。并发安全（每次认证各自拨一个 UDP 套接字）。
type Provider struct {
	cfg  Config
	addr string
	log  *slog.Logger

	// groupDrop 组值丢弃日志的节流状态（见 groupsFrom）。
	groupDrop logThrottle
	// maWaived 「逃生舱放行了一份不带 Message-Authenticator 的应答」日志的节流状态。
	// 与组值同一条理由：它在登录热路径上，逐条记等于把日志变成对面的回显。
	maWaived logThrottle
}

// logThrottle 「每 d 最多记一条」的日志节流器。零值可用。
// 节流的只是**日志**，被节流的行为本身照常发生。
type logThrottle struct {
	mu sync.Mutex
	at time.Time
}

func (t *logThrottle) allow(d time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if !t.at.IsZero() && now.Sub(t.at) < d {
		return false
	}
	t.at = now
	return true
}

var _ authsrc.PasswordAuthenticator = (*Provider)(nil)
var _ authsrc.DetailedProber = (*Provider)(nil)

// errNoResponse 预算内没收到任何应答。与 ErrSourceUnavailable **同时**挂在错误链上：
// 外层只关心"源不可用"，Probe 的回退逻辑要分得出"是超时还是密钥不对"。
var errNoResponse = errors.New("radiussrc: 无应答")

// Subject 计算 RADIUS 身份的权威标识：`radius:<源 id>:<User-Name>`。
//
// username 必须是**实际发给服务器认证的那个 User-Name**：只去首尾空白（Authenticate
// 发出去之前也只做了这一步），**不改大小写**。绑定键必须等于被认证方真正认过的字符串——
// 对大小写敏感的 RADIUS 后端，"Alice" 与 "alice" 是两个各有口令的账号，按小写归一
// 会把两个人绑成一个 Subject，后登者继承先登者的授权/JIT/封禁。反过来的代价（同一人
// 换大小写登录建出两个账号）便宜且可见。**刻意与 authsrc.Identity.Normalized 的
// Username 小写口径不同**：Username 是展示/建号用的账号名，Subject 是身份绑定键。
// 前缀 `radius:` 让它与 entryDN / OIDC sub 在形态上分得开（审计里一眼能看出来源类型）。
func Subject(sourceID, username string) string {
	return "radius:" + strings.TrimSpace(sourceID) + ":" + strings.TrimSpace(username)
}

// New 归一化并校验配置。配置缺失/非法一律返回包裹 authsrc.ErrNotConfigured 的错误。
func New(cfg Config) (*Provider, error) {
	c := cfg.normalize()
	if c.SourceID == "" {
		return nil, fmt.Errorf("radiussrc: 缺少认证源 id（Subject 依赖它隔离不同源）: %w", authsrc.ErrNotConfigured)
	}
	if c.Host == "" {
		return nil, fmt.Errorf("radiussrc: 未填写服务器地址: %w", authsrc.ErrNotConfigured)
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, fmt.Errorf("radiussrc: 端口 %d 超出 1~65535: %w", c.Port, authsrc.ErrNotConfigured)
	}
	if c.Secret == "" {
		return nil, fmt.Errorf("radiussrc: 未配置共享密钥（请在「凭据」里填写 RADIUS shared secret）: %w", authsrc.ErrNotConfigured)
	}
	switch c.Protocol {
	case ProtocolPAP, ProtocolCHAP:
	default:
		return nil, fmt.Errorf("radiussrc: 未知的口令协议 %q（应为 pap/chap）: %w", c.Protocol, authsrc.ErrNotConfigured)
	}
	switch c.GroupAttr {
	case GroupAttrNone, GroupAttrClass, GroupAttrFilterID, GroupAttrReplyMessage:
	default:
		return nil, fmt.Errorf("radiussrc: 未知的组属性 %q（应为 class/filter-id/reply-message 或留空）: %w", c.GroupAttr, authsrc.ErrNotConfigured)
	}
	if c.Retries > maxRetries {
		return nil, fmt.Errorf("radiussrc: 重发次数 %d 超出上限 %d: %w", c.Retries, maxRetries, authsrc.ErrNotConfigured)
	}
	if len(c.NASIdentifier) > maxUsernameLen {
		return nil, fmt.Errorf("radiussrc: NAS-Identifier 过长: %w", authsrc.ErrNotConfigured)
	}
	return &Provider{
		cfg:  c,
		addr: net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		log:  c.Logger,
	}, nil
}

// normalize 补默认值。不改调用方传入的 Config（值接收者）。
func (c Config) normalize() Config {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	c.SourceID = strings.TrimSpace(c.SourceID)
	c.Host = strings.TrimSpace(c.Host)
	c.NASIdentifier = strings.TrimSpace(c.NASIdentifier)
	c.Protocol = Protocol(strings.ToLower(strings.TrimSpace(string(c.Protocol))))
	c.GroupAttr = GroupAttr(strings.ToLower(strings.TrimSpace(string(c.GroupAttr))))
	if c.Port == 0 {
		c.Port = defaultPort
	}
	if c.NASIdentifier == "" {
		c.NASIdentifier = defaultNASIdentifier
	}
	if c.Protocol == "" {
		c.Protocol = ProtocolPAP
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.Retries < 0 {
		c.Retries = defaultRetries
	}
	return c
}

// ── 认证 ───────────────────────────────────────────────────────────────────

// Authenticate 实现 authsrc.PasswordAuthenticator。
func (p *Provider) Authenticate(ctx context.Context, username, password string) (authsrc.Identity, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return authsrc.Identity{}, fmt.Errorf("radiussrc: 用户名为空: %w", authsrc.ErrInvalidCredentials)
	}
	if len(username) > maxUsernameLen {
		return authsrc.Identity{}, fmt.Errorf("radiussrc: 用户名过长(%d 字节): %w", len(username), authsrc.ErrInvalidCredentials)
	}
	// ★空口令在这里显式拒掉（与 ldapsrc 同一条纪律）。有些 RADIUS 后端对空口令的账号
	// （刚建号、或"仅凭用户名放行"的策略）会回 Accept——认证语义的闸门必须在我们自己
	// 的代码里，不能寄托在对面的配置上。
	if password == "" {
		p.log.Warn("RADIUS 认证收到空口令，已直接拒绝", "user", username, "host", p.cfg.Host)
		return authsrc.Identity{}, fmt.Errorf("radiussrc: 口令为空: %w", authsrc.ErrInvalidCredentials)
	}

	pkt := radius.New(radius.CodeAccessRequest, []byte(p.cfg.Secret))
	if err := rfc2865.UserName_SetString(pkt, username); err != nil {
		return authsrc.Identity{}, fmt.Errorf("radiussrc: 组 User-Name 失败: %v: %w", err, authsrc.ErrInvalidCredentials)
	}
	if err := rfc2865.NASIdentifier_SetString(pkt, p.cfg.NASIdentifier); err != nil {
		return authsrc.Identity{}, fmt.Errorf("radiussrc: 组 NAS-Identifier 失败: %v: %w", err, authsrc.ErrNotConfigured)
	}
	switch p.cfg.Protocol {
	case ProtocolCHAP:
		if err := setCHAP(pkt, password); err != nil {
			return authsrc.Identity{}, fmt.Errorf("radiussrc: 组 CHAP 失败: %v: %w", err, authsrc.ErrSourceUnavailable)
		}
	default:
		// User-Password 在 Encode 时按 RFC 2865 §5.2 用 secret + Request Authenticator 混淆。
		if err := rfc2865.UserPassword_SetString(pkt, password); err != nil {
			// 口令超过 128 字节等属性层限制：这是用户输入的问题，按凭据错处理。
			return authsrc.Identity{}, fmt.Errorf("radiussrc: 组 User-Password 失败: %v: %w", err, authsrc.ErrInvalidCredentials)
		}
	}
	if err := signMessageAuthenticator(pkt); err != nil {
		return authsrc.Identity{}, fmt.Errorf("radiussrc: 组 Message-Authenticator 失败: %v: %w", err, authsrc.ErrSourceUnavailable)
	}

	resp, err := p.exchange(ctx, pkt)
	if err != nil {
		return authsrc.Identity{}, err
	}
	switch resp.Code {
	case radius.CodeAccessAccept:
		id := authsrc.Identity{
			Subject:  Subject(p.cfg.SourceID, username),
			Username: username,
			Groups:   p.groupsFrom(resp),
		}
		return id.Normalized(), nil
	case radius.CodeAccessReject:
		// ★唯一映射到"凭据错"的分支。Reply-Message 只进日志，不回给用户——
		// 服务端的拒绝原因（"账号不存在"/"口令错"）回给用户就是用户名枚举接口。
		if msgs, _ := rfc2865.ReplyMessage_GetStrings(resp); len(msgs) > 0 {
			p.log.Info("RADIUS Access-Reject", "user", username, "host", p.cfg.Host, "replyMessage", strings.Join(msgs, " | "))
		}
		return authsrc.Identity{}, fmt.Errorf("radiussrc: 服务器回 Access-Reject: %w", authsrc.ErrInvalidCredentials)
	case radius.CodeAccessChallenge:
		// 多轮挑战应答（动态令牌"再输一次"）本包不做。它**不是**凭据错：口令可能是对的，
		// 只是服务端还想再问一句。归为源不可用——不计锁定，并把原因说清楚。
		return authsrc.Identity{}, fmt.Errorf("radiussrc: 服务器要求多轮挑战应答（Access-Challenge），白帝 RADIUS 源只做单轮 PAP/CHAP: %w", authsrc.ErrSourceUnavailable)
	}
	return authsrc.Identity{}, fmt.Errorf("radiussrc: 服务器回了意外的报文类型 %s: %w", resp.Code, authsrc.ErrSourceUnavailable)
}

// exchange 发送并等待应答，把库的错误翻成本包的分层语义。
//
// 预算 = min(ctx 剩余, Timeout × (Retries+1))。Client.Retry = Timeout 让库按周期重发，
// 直到预算耗尽——RADIUS 是 UDP，"重发"与"超时"是同一件事的两面。
func (p *Provider) exchange(ctx context.Context, pkt *radius.Packet) (*radius.Packet, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("radiussrc: 上下文已取消: %v: %w", err, authsrc.ErrSourceUnavailable)
	}
	budget := p.cfg.Timeout * time.Duration(p.cfg.Retries+1)
	ctx, cancel := context.WithTimeout(ctx, budget) // 若 ctx 自己的 deadline 更早，以更早的为准
	defer cancel()

	start := time.Now()
	resp, err := p.newClient().Exchange(ctx, pkt, p.addr)
	if err != nil {
		return nil, p.classifyExchangeErr(err, time.Since(start))
	}
	// 库已校验 Response Authenticator（MD5）。这里校验 Message-Authenticator（HMAC-MD5）：
	// Blast-RADIUS 伪造的正是只有 MD5 那层的应答，所以**缺席也要拒**——否则攻击者
	// 把这个属性删掉就能把这道校验整个跳过（判据由被攻击链路上的攻击者说了算 = 不设防）。
	present, ok := verifyResponseMessageAuthenticator(resp, pkt.Authenticator, pkt.Secret)
	switch {
	case present && !ok:
		// 带了但对不上：确定的篡改或密钥不匹配。**逃生舱不放宽这一条**。
		return nil, fmt.Errorf("radiussrc: 应答的 Message-Authenticator 校验失败（共享密钥不匹配，或报文在途中被改）: %w", authsrc.ErrSourceUnavailable)
	case !present && !p.cfg.AllowMissingResponseMessageAuthenticator:
		return nil, fmt.Errorf("radiussrc: 服务器 %s 的应答没有携带 Message-Authenticator（RFC 2869 §5.14），已拒绝。"+
			"两种可能：① 应答在链路上被中间人剥离或伪造——Blast-RADIUS（CVE-2024-3596）攻破的正是应答里剩下的那层 MD5 Response Authenticator；"+
			"② 该服务器（或其配置）本就不在应答里带这个属性（老设备常见）。"+
			"确认是后者时，可在该认证源上打开「允许应答不带 Message-Authenticator」"+
			"（allowMissingResponseMessageAuthenticator）——那等于放弃 HMAC 这层保护，只剩已被攻破的 MD5: %w",
			p.addr, authsrc.ErrSourceUnavailable)
	case !present:
		if p.maWaived.allow(missingMALogEvery) {
			p.log.Warn("逃生舱放行了一份不带 Message-Authenticator 的 RADIUS 应答：该源已放弃 Blast-RADIUS（CVE-2024-3596）缓解，应答完整性只剩 MD5",
				"host", p.cfg.Host, "code", resp.Code.String(), "日志节流", missingMALogEvery.String())
		}
	}
	return resp, nil
}

// newClient 构造这次交换用的 radius.Client。
//
// ★抽成函数是为了让「Retries=0 只发一次」**可断言**：端到端数服务端收到几份报文这件事在
// Retries=0 时是**间歇性**的——预算恰好等于 Timeout×1，库里的重发计时器与 ctx 截止**同时**
// 触发，select 二选一随机，删掉下面那行 `client.Retry = 0` 也只有约一半的跑次会红
// （两次采样：复审员 2/6、本次 3/6）。而「显式 retries=0 只发一份」被 CLAUDE.md、ARCHITECTURE 第七节与
// 本包注释三处当成事实写着，守卫必须是确定的：TestNewClientRetryTimer 直接断 Retry 字段。
func (p *Provider) newClient() *radius.Client {
	client := &radius.Client{
		Retry: p.cfg.Timeout,
		// ★=1：第一份校验不过的应答就立刻报错。共享密钥不匹配时服务器（若不校验
		// Message-Authenticator）会回一份用它的密钥签的 Reject，我们验不过——
		// 这就是结论了，再等下去只会把"密钥不对"拖成"超时"，两种故障混成一种。
		MaxPacketErrors: 1,
		Dialer:          net.Dialer{Timeout: p.cfg.Timeout},
	}
	if p.cfg.Retries == 0 {
		// Retries=0 = 只发一次：必须把库的重发计时器**关掉**（Retry=0），不能靠预算到期去拦——
		// 计时器在 Timeout 那一刻与 ctx 截止**同时**触发，库里 select 二选一是随机的，
		// 大约一半概率会在退出前多发一份。管理员选了「重发 0 次」，发出去 2 份就是没兑现。
		client.Retry = 0
	}
	return client
}

// waiverNote 逃生舱开着时给「测试连接」结论加的一句当面告警。resp 是这次探测收到的应答
// （可为 nil）——**开着** 与 **这次真的用上了** 是两回事，两种情况的下一步动作相反：
// 服务器其实带了 MA 就该把它关掉，真没带则关掉会让该源整个不可用。
func (p *Provider) waiverNote(resp *radius.Packet) string {
	if !p.cfg.AllowMissingResponseMessageAuthenticator {
		return ""
	}
	const head = "。⚠ 该源已打开「允许应答不带 Message-Authenticator」：不带该属性的应答会被接受，" +
		"Blast-RADIUS（CVE-2024-3596）攻破的 MD5 Response Authenticator 就是此时唯一的应答完整性保护"
	if resp != nil && rfc2869.MessageAuthenticator_Get(resp) != nil {
		return head + "。但这次应答其实带了合法的 Message-Authenticator——建议关掉这个开关，恢复那层保护"
	}
	return head + "。这次应答确实没带该属性：关掉开关会让该源不可用，请先在服务端开启应答侧 Message-Authenticator"
}

// classifyExchangeErr 把一次交换失败归到 ErrSourceUnavailable，并写清最可能的原因。
//
// ★这里**没有任何分支**通向 ErrInvalidCredentials。凭据对不对只有 Access-Reject 说了算。
func (p *Provider) classifyExchangeErr(err error, spent time.Duration) error {
	var nonAuth *radius.NonAuthenticResponseError
	switch {
	case errors.As(err, &nonAuth):
		return fmt.Errorf("radiussrc: 服务器 %s 的应答校验失败（Response Authenticator 不匹配）：两端的共享密钥不一致: %w",
			p.addr, authsrc.ErrSourceUnavailable)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("radiussrc: %s 在 %dms 内无应答（最多重发 %d 次）。可能：主机/端口不通或 UDP 被防火墙丢弃；"+
			"服务器未把本机登记为 NAS 客户端；或共享密钥不匹配——多数 RADIUS 服务器对这两种情况**静默丢包**而不回错误: %w: %w",
			p.addr, spent.Milliseconds(), p.cfg.Retries, errNoResponse, authsrc.ErrSourceUnavailable)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("radiussrc: 等待 %s 应答时上下文被取消: %w", p.addr, authsrc.ErrSourceUnavailable)
	}
	var ne net.Error
	if errors.As(err, &ne) || errors.As(err, new(*net.OpError)) {
		// UDP 上的 ICMP 端口不可达会以读错误的形式冒出来：这是"确定不通"，比超时更明确。
		return fmt.Errorf("radiussrc: 与 %s 通信失败: %v: %w", p.addr, err, authsrc.ErrSourceUnavailable)
	}
	return fmt.Errorf("radiussrc: 与 %s 交换报文失败: %v: %w", p.addr, err, authsrc.ErrSourceUnavailable)
}

// groupsFrom 按配置的属性把应答里的值映射成组名。非 UTF-8 的值（二进制 Class）跳过并 WARN。
//
// ★入口上限（见包注释「已知边界」）：只考察报文里**前 maxGroupValues 个**值，单个值超过
// maxGroupValueLen 字节的丢弃。超出部分不是"截断后保留"而是**整个丢掉**——截断会造出一个
// 服务器从没回过的组名，而它可能恰好撞上白名单里某个真组。丢弃按 groupDropLogEvery 节流记日志。
func (p *Provider) groupsFrom(resp *radius.Packet) []string {
	var raw []string
	switch p.cfg.GroupAttr {
	case GroupAttrClass:
		raw, _ = rfc2865.Class_GetStrings(resp)
	case GroupAttrFilterID:
		raw, _ = rfc2865.FilterID_GetStrings(resp)
	case GroupAttrReplyMessage:
		raw, _ = rfc2865.ReplyMessage_GetStrings(resp)
	default:
		return nil
	}
	droppedCount, droppedLong := 0, 0
	if len(raw) > maxGroupValues {
		droppedCount = len(raw) - maxGroupValues
		raw = raw[:maxGroupValues]
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		if len(v) > maxGroupValueLen {
			droppedLong++
			continue
		}
		if !utf8.ValidString(v) {
			p.log.Warn("RADIUS 组属性值不是合法 UTF-8（可能是二进制 Class），已跳过",
				"attr", string(p.cfg.GroupAttr), "hex", hex.EncodeToString([]byte(v)))
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if droppedCount > 0 || droppedLong > 0 {
		p.logGroupDrop(droppedCount, droppedLong)
	}
	return out
}

// logGroupDrop 节流记一条"组值被丢弃"的告警：同一 Provider 每 groupDropLogEvery 最多一条。
// 丢弃本身不节流（每次登录都照丢），节流的只是日志。
func (p *Provider) logGroupDrop(overCount, overLen int) {
	if !p.groupDrop.allow(groupDropLogEvery) {
		return
	}
	p.log.Warn("RADIUS 组属性值超出入口上限，已丢弃（服务器可能把该属性用作逐会话标识，而非组）",
		"host", p.cfg.Host, "attr", string(p.cfg.GroupAttr),
		"超出个数上限被丢弃", overCount, "超出长度上限被丢弃", overLen,
		"个数上限", maxGroupValues, "长度上限字节", maxGroupValueLen,
		"日志节流", groupDropLogEvery.String())
}

// ── 探测 ───────────────────────────────────────────────────────────────────

// Probe 实现 authsrc.PasswordAuthenticator：连通性自检。**不校验任何用户凭据**。
func (p *Provider) Probe(ctx context.Context) error {
	_, err := p.ProbeDetail(ctx)
	return err
}

// ProbeDetail 实现 authsrc.DetailedProber：优先 Status-Server（RFC 5997），
// 服务器不应答时退到一次刻意的 Access-Request。
//
// ★两种结果必须分得开：Status-Server 的 Access-Accept 与回退路径的 Access-Reject 都是
// "可达且密钥匹配"，但后者会在服务器日志里留下一条失败登录，管理员该知道那条是我们打的。
// 只有**两种探测都超时**才判不可达。
func (p *Provider) ProbeDetail(ctx context.Context) (authsrc.ProbeReport, error) {
	// ① Status-Server：必须带 Message-Authenticator（RFC 5997 §2），否则服务器直接丢。
	st := radius.New(radius.CodeStatusServer, []byte(p.cfg.Secret))
	if err := rfc2865.NASIdentifier_SetString(st, p.cfg.NASIdentifier); err != nil {
		return authsrc.ProbeReport{}, fmt.Errorf("radiussrc: 组 NAS-Identifier 失败: %v: %w", err, authsrc.ErrNotConfigured)
	}
	if err := signMessageAuthenticator(st); err != nil {
		return authsrc.ProbeReport{}, fmt.Errorf("radiussrc: 组 Message-Authenticator 失败: %v: %w", err, authsrc.ErrSourceUnavailable)
	}
	resp, err := p.exchange(ctx, st)
	switch {
	case err == nil:
		// RFC 5997：认证口对 Status-Server 回 Access-Accept。回别的也说明它活着且密钥对。
		detail := "Status-Server（RFC 5997）应答 " + resp.Code.String() + "：服务器可达、共享密钥匹配" + p.waiverNote(resp)
		return authsrc.ProbeReport{Method: ProbeMethodStatusServer, Detail: detail}, nil
	case !errors.Is(err, errNoResponse):
		// 密钥不匹配 / 端口不可达 / ctx 取消：结论已经有了，回退再打一次只会得到同样的答案。
		return authsrc.ProbeReport{Method: ProbeMethodStatusServer}, err
	}

	// ② 回退：一次探测用 Access-Request（随机账号 + 随机口令）。
	// 期望的"好结果"是 Access-Reject——它证明服务器活着且密钥对（Reject 也是签过的）。
	probeUser := "baidi-probe-" + randHex(4)
	ar := radius.New(radius.CodeAccessRequest, []byte(p.cfg.Secret))
	if err := rfc2865.UserName_SetString(ar, probeUser); err != nil {
		return authsrc.ProbeReport{}, fmt.Errorf("radiussrc: 组探测 User-Name 失败: %v: %w", err, authsrc.ErrSourceUnavailable)
	}
	if err := rfc2865.NASIdentifier_SetString(ar, p.cfg.NASIdentifier); err != nil {
		return authsrc.ProbeReport{}, fmt.Errorf("radiussrc: 组 NAS-Identifier 失败: %v: %w", err, authsrc.ErrNotConfigured)
	}
	if err := rfc2865.UserPassword_SetString(ar, randHex(16)); err != nil {
		return authsrc.ProbeReport{}, fmt.Errorf("radiussrc: 组探测 User-Password 失败: %v: %w", err, authsrc.ErrSourceUnavailable)
	}
	if err := signMessageAuthenticator(ar); err != nil {
		return authsrc.ProbeReport{}, fmt.Errorf("radiussrc: 组 Message-Authenticator 失败: %v: %w", err, authsrc.ErrSourceUnavailable)
	}
	resp, err = p.exchange(ctx, ar)
	if err != nil {
		if errors.Is(err, errNoResponse) {
			return authsrc.ProbeReport{Method: ProbeMethodAccessRequest},
				fmt.Errorf("radiussrc: %s 对 Status-Server 与探测用 Access-Request 均无应答。可能：主机/端口不通或 UDP 被防火墙丢弃；"+
					"服务器未把本机（NAS-Identifier=%s）登记为客户端；或共享密钥不匹配——多数 RADIUS 服务器对这两种情况静默丢包而不回错误: %w: %w",
					p.addr, p.cfg.NASIdentifier, errNoResponse, authsrc.ErrSourceUnavailable)
		}
		return authsrc.ProbeReport{Method: ProbeMethodAccessRequest}, err
	}
	base := "服务器不支持 Status-Server（RFC 5997，无应答），已改用一次探测用 Access-Request（随机账号 " + probeUser + "）："
	switch resp.Code {
	case radius.CodeAccessReject:
		return authsrc.ProbeReport{Method: ProbeMethodAccessRequest,
			Detail: base + "收到 Access-Reject，服务器可达、共享密钥匹配。该次探测会在 RADIUS 服务器日志里留下一条失败登录" + p.waiverNote(resp)}, nil
	case radius.CodeAccessAccept:
		// 随机账号被放行不是"连接正常"——那台服务器可能对任何人放行。绿灯会替它背书，故判失败并点名。
		return authsrc.ProbeReport{Method: ProbeMethodAccessRequest},
			fmt.Errorf("radiussrc: 探测用随机账号 %s 竟被 Access-Accept 放行：服务器可能对任意账号放行，请先检查服务端策略再启用此源", probeUser)
	case radius.CodeAccessChallenge:
		return authsrc.ProbeReport{Method: ProbeMethodAccessRequest,
			Detail: base + "收到 Access-Challenge，服务器可达、共享密钥匹配；但它要求多轮挑战应答，白帝 RADIUS 源只做单轮 PAP/CHAP，该源的用户可能登录不了" + p.waiverNote(resp)}, nil
	}
	return authsrc.ProbeReport{Method: ProbeMethodAccessRequest,
		Detail: base + "收到 " + resp.Code.String() + "，服务器可达、共享密钥匹配" + p.waiverNote(resp)}, nil
}

// ── 报文工具 ─────────────────────────────────────────────────────────────────

// setCHAP 组 CHAP-Challenge + CHAP-Password（RFC 2865 §5.3 / RFC 1994）：
// CHAP-Password = ident(1) || MD5(ident || password || challenge)。
// 显式带 CHAP-Challenge 属性而不是复用 Request Authenticator——两种写法都合规，
// 显式的那种对所有实现都成立。
func setCHAP(pkt *radius.Packet, password string) error {
	var ident [1]byte
	if _, err := rand.Read(ident[:]); err != nil {
		return err
	}
	chal := make([]byte, 16)
	if _, err := rand.Read(chal); err != nil {
		return err
	}
	h := md5.New()
	h.Write(ident[:])
	h.Write([]byte(password))
	h.Write(chal)
	chapPw := append(ident[:], h.Sum(nil)...)
	if err := rfc2865.CHAPChallenge_Set(pkt, chal); err != nil {
		return err
	}
	return rfc2865.CHAPPassword_Set(pkt, chapPw)
}

// signMessageAuthenticator 给请求附 Message-Authenticator（RFC 2869 §5.14）：
// HMAC-MD5(secret, 整个报文，其中 Message-Authenticator 字段先置 16 个零)。
// Access-Request / Status-Server 的 Authenticator 字段原样参与（Encode 对这两类不改它）。
func signMessageAuthenticator(pkt *radius.Packet) error {
	if err := rfc2869.MessageAuthenticator_Set(pkt, make([]byte, 16)); err != nil {
		return err
	}
	wire, err := pkt.MarshalBinary()
	if err != nil {
		return err
	}
	mac := hmac.New(md5.New, pkt.Secret)
	mac.Write(wire)
	// Set 原地替换同长度的值，属性顺序不变，故上面算 HMAC 时的布局与发出去的一致。
	return rfc2869.MessageAuthenticator_Set(pkt, mac.Sum(nil))
}

// verifyResponseMessageAuthenticator 校验应答里的 Message-Authenticator（若有）。
// 应答的 HMAC 按 RFC 2869 §5.14 以**请求的** Authenticator 填在 Authenticator 字段上计算。
// 返回 (是否带了该属性, 校验是否通过)。
func verifyResponseMessageAuthenticator(resp *radius.Packet, reqAuth [16]byte, secret []byte) (present, ok bool) {
	got := rfc2869.MessageAuthenticator_Get(resp)
	if got == nil {
		return false, false
	}
	if len(got) != 16 {
		return true, false
	}
	// 深拷贝属性切片：Attributes.Set 会就地搬移元素，直接借原切片会把 resp 改坏。
	clone := *resp
	clone.Attributes = make(radius.Attributes, len(resp.Attributes))
	copy(clone.Attributes, resp.Attributes)
	if err := rfc2869.MessageAuthenticator_Set(&clone, make([]byte, 16)); err != nil {
		return true, false
	}
	clone.Authenticator = reqAuth
	wire, err := clone.MarshalBinary()
	if err != nil {
		return true, false
	}
	mac := hmac.New(md5.New, secret)
	mac.Write(wire)
	return true, hmac.Equal(mac.Sum(nil), got)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}
