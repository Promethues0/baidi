package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// ── SMTP 邮件通道 ──

// SMTPTLSMode 传输加密方式。
type SMTPTLSMode string

const (
	// SMTPTLSStartTLS 先明文连 587/25，再用 STARTTLS 升级。企业内最常见。
	SMTPTLSStartTLS SMTPTLSMode = "starttls"
	// SMTPTLSImplicit 整条连接直接 TLS（465，历史上叫 SMTPS）。
	SMTPTLSImplicit SMTPTLSMode = "implicit"
	// SMTPTLSPlaintext 明文 SMTP。★逃生舱：仅限内网那种"只在本机中继、不出网"的 MTA。
	//
	// 选它意味着邮件正文（里面写着哪个账号在被爆破、哪台终端不合规）以明文过网线。
	// 每次构造都会打 WARN，且**此模式下一律不允许发送认证凭据**（见 Send）。
	SMTPTLSPlaintext SMTPTLSMode = "plaintext"
)

// SMTPAuthMode 认证方式。
type SMTPAuthMode string

const (
	// SMTPAuthNone 匿名（内网中继常见：按来源 IP 放行，不做 SMTP AUTH）。
	SMTPAuthNone SMTPAuthMode = "none"
	// SMTPAuthPlain AUTH PLAIN（RFC 4616）。
	SMTPAuthPlain SMTPAuthMode = "plain"
	// SMTPAuthLogin AUTH LOGIN（无 RFC 的事实标准，Exchange/部分国产邮件网关只认它）。
	// 标准库没有实现，见本文件末尾的 loginAuth。
	SMTPAuthLogin SMTPAuthMode = "login"
)

// SMTPConfig 邮件通道配置。零值不可用，必须经 NewSMTP 校验。
type SMTPConfig struct {
	Host string
	Port int // 0 = 按 TLS 模式取默认（implicit:465，其余:587）
	TLS  SMTPTLSMode

	// ServerName 证书里应当出现的名字。留空取 Host。
	// 用 IP 连接但证书签的是主机名时填这里，比开 InsecureSkipVerify 正确得多。
	ServerName string
	// CACert 校验服务端证书用的 CA（PEM）。留空用系统根证书池；
	// 填了就**只信这一把**（与 ldapsrc 同一条推理：内网 MTA 多是私有 CA 签的，
	// "系统池 ∪ 私有 CA" 反而更宽——任一公共 CA 误签一张你的 MTA 证书都能骗过校验）。
	CACert string
	// InsecureSkipVerify 跳过服务端证书校验。★逃生舱，默认关，开启打 WARN。
	InsecureSkipVerify bool

	Auth     SMTPAuthMode
	Username string
	Password string

	// From 发件人地址（信封发件人与 From 头共用）。
	From string
	// FromName 发件人显示名，可空。
	FromName string

	Timeout time.Duration // 整个 SMTP 会话的上界，默认 15s

	// Logger 留空取 slog.Default()。抽成字段是为了让测试能断言"该打的 WARN 打了没"。
	Logger *slog.Logger
}

// SMTPChannel 一条已校验的邮件通道。并发安全（每次发送自己拨号，不共享连接）。
//
// ★刻意不做连接池：SMTP 连接是有状态的（AUTH 之后整条连接带着那个身份），
// 而发告警不是热路径。用完即弃换来的是"连接身份"这件事根本不存在。
type SMTPChannel struct {
	cfg SMTPConfig
	tls *tls.Config
	log *slog.Logger
}

var _ Channel = (*SMTPChannel)(nil)

const defaultSMTPTimeout = 15 * time.Second

// NewSMTP 归一化并校验配置。配置错误返回包裹 ErrNotConfigured 的错误——
// 控制台该把它显示成"这项没填对"而不是"邮件服务器连不上"。
func NewSMTP(cfg SMTPConfig) (*SMTPChannel, error) {
	c := cfg
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	c.Host = strings.TrimSpace(c.Host)
	c.ServerName = strings.TrimSpace(c.ServerName)
	c.From = strings.TrimSpace(c.From)
	c.FromName = strings.TrimSpace(c.FromName)
	c.Username = strings.TrimSpace(c.Username)
	if c.TLS == "" {
		c.TLS = SMTPTLSStartTLS
	}
	if c.Auth == "" {
		c.Auth = SMTPAuthNone
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultSMTPTimeout
	}
	if c.Port == 0 {
		if c.TLS == SMTPTLSImplicit {
			c.Port = 465
		} else {
			c.Port = 587
		}
	}

	if c.Host == "" {
		return nil, fmt.Errorf("smtp: 未填写服务器地址: %w", ErrNotConfigured)
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, fmt.Errorf("smtp: 端口 %d 非法: %w", c.Port, ErrNotConfigured)
	}
	switch c.TLS {
	case SMTPTLSStartTLS, SMTPTLSImplicit, SMTPTLSPlaintext:
	default:
		return nil, fmt.Errorf("smtp: 未知的传输方式 %q（应为 starttls/implicit/plaintext）: %w", c.TLS, ErrNotConfigured)
	}
	switch c.Auth {
	case SMTPAuthNone, SMTPAuthPlain, SMTPAuthLogin:
	default:
		return nil, fmt.Errorf("smtp: 未知的认证方式 %q（应为 none/plain/login）: %w", c.Auth, ErrNotConfigured)
	}
	if c.Auth != SMTPAuthNone {
		if c.Username == "" || c.Password == "" {
			// ★空口令不当匿名用。SMTP 的 AUTH PLAIN 带空口令多半直接被拒（不像 LDAP 会
			// 静默退化成匿名），但真正的问题在于**意图**：管理员以为配了认证。
			// 想匿名就显式选 none。
			return nil, fmt.Errorf("smtp: 认证方式为 %s 但账号或口令为空（确需匿名请把认证方式选 none）: %w", c.Auth, ErrNotConfigured)
		}
		if c.TLS == SMTPTLSPlaintext {
			// ★配置期就拒，不等到发送时才发现。明文连接上做 AUTH = 把 SMTP 账号口令
			// 明文送上网线，与 ldapsrc 里"StartTLS 失败绝不降级"是同一条纪律的另一面。
			return nil, fmt.Errorf("smtp: 明文传输下不允许配置 SMTP 认证（口令会明文过网线）；"+
				"请改用 starttls/implicit，或把认证方式选 none: %w", ErrNotConfigured)
		}
	}
	if c.From == "" {
		return nil, fmt.Errorf("smtp: 未填写发件人地址: %w", ErrNotConfigured)
	}
	if hasCRLF(c.From) || hasCRLF(c.FromName) {
		return nil, fmt.Errorf("smtp: 发件人含换行符（邮件头注入）: %w", ErrNotConfigured)
	}

	tc, err := c.buildTLS()
	if err != nil {
		return nil, err
	}
	if c.TLS == SMTPTLSPlaintext {
		c.Logger.Warn("邮件通道使用明文 SMTP：告警正文（含账号名与不合规原因）会明文过网线，仅限本机/隔离网段中继",
			"host", c.Host, "port", c.Port)
	}
	if c.InsecureSkipVerify {
		c.Logger.Warn("邮件通道跳过了服务端证书校验：TLS 退化为「加密但不认证」，中间人可无声接管并读走全部告警内容",
			"host", c.Host, "port", c.Port)
	}
	return &SMTPChannel{cfg: c, tls: tc, log: c.Logger}, nil
}

func (c SMTPConfig) buildTLS() (*tls.Config, error) {
	name := c.ServerName
	if name == "" {
		name = c.Host
	}
	tc := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // 逃生舱，默认关且打 WARN
	if pem := strings.TrimSpace(c.CACert); pem != "" {
		pool, err := certPoolFromPEM(pem)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

// Addr 返回该通道实际拨号的地址（展示/诊断用，不含任何凭据）。
func (p *SMTPChannel) Addr() string { return net.JoinHostPort(p.cfg.Host, fmt.Sprint(p.cfg.Port)) }

// Send 发一封邮件。整个会话受 Timeout 与 ctx 双重约束。
//
// ★纪律：STARTTLS 失败**绝不降级明文**。降级的后果不只是"这封告警被看见了"——
// AUTH 会跟着明文发出去，SMTP 账号一旦泄露就是一个能以本组织名义发信的身份。
// 这与 ldapsrc.dial 是同一条纪律，测试也照抄那边的思路（对照组：服务端不支持
// STARTTLS 时必须报错，且服务端不得收到任何 MAIL/AUTH 命令）。
func (p *SMTPChannel) Send(ctx context.Context, to []string, subject, body string) error {
	rcpt := trimAll(to)
	if len(rcpt) == 0 {
		return ErrNoRecipients
	}
	for _, a := range rcpt {
		if hasCRLF(a) {
			return fmt.Errorf("smtp: 收件人 %q 含换行符（邮件头注入）: %w", a, ErrNotConfigured)
		}
	}

	deadline := time.Now().Add(p.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialer := &net.Dialer{Deadline: deadline}

	var conn net.Conn
	var err error
	if p.cfg.TLS == SMTPTLSImplicit {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: p.tls}).DialContext(ctx, "tcp", p.Addr())
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", p.Addr())
	}
	if err != nil {
		return fmt.Errorf("smtp: 连接 %s 失败: %v: %w", p.Addr(), err, ErrSendFailed)
	}
	defer conn.Close()
	// ★整条会话一个 deadline。不设的话，一台"接受连接后再也不回话"的 MTA
	// 会把这个 goroutine 永久挂住——派发是串行的，一次挂死等于后面所有告警都发不出去。
	_ = conn.SetDeadline(deadline)
	// ctx 取消时把连接踹掉（net/smtp 不接受 ctx）。
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	name := p.cfg.ServerName
	if name == "" {
		name = p.cfg.Host
	}
	cl, err := smtp.NewClient(conn, name)
	if err != nil {
		return fmt.Errorf("smtp: 握手失败: %v: %w", err, ErrSendFailed)
	}
	defer cl.Close()

	if p.cfg.TLS == SMTPTLSStartTLS {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			// ★这里就是不降级的执行点。返回错误而不是"那就明文发吧"。
			return fmt.Errorf("smtp: %s 未通告 STARTTLS 支持，拒绝以明文继续"+
				"（降级会把告警正文与 SMTP 账号口令明文送上网线）；确需明文请显式把传输方式改为 plaintext: %w",
				p.Addr(), ErrSendFailed)
		}
		if err := cl.StartTLS(p.tls); err != nil {
			return fmt.Errorf("smtp: STARTTLS 协商失败: %v（拒绝降级明文）: %w", err, ErrSendFailed)
		}
	}

	if p.cfg.Auth != SMTPAuthNone {
		if _, isTLS := cl.TLSConnectionState(); !isTLS {
			// 兜底：配置期已经拦过一次（plaintext + auth 直接拒绝构造），这里防的是
			// "以为握上了 TLS 其实没有"。net/smtp 的 PlainAuth 对 localhost 有豁免，
			// 不能把这道判断交给它。
			return fmt.Errorf("smtp: 连接未加密，拒绝发送 SMTP 认证凭据: %w", ErrSendFailed)
		}
		if ok, _ := cl.Extension("AUTH"); !ok {
			return fmt.Errorf("smtp: %s 未通告 AUTH 支持，但通道配置了 %s 认证: %w", p.Addr(), p.cfg.Auth, ErrSendFailed)
		}
		var a smtp.Auth
		switch p.cfg.Auth {
		case SMTPAuthPlain:
			a = smtp.PlainAuth("", p.cfg.Username, p.cfg.Password, name)
		case SMTPAuthLogin:
			a = &loginAuth{username: p.cfg.Username, password: p.cfg.Password}
		}
		if err := cl.Auth(a); err != nil {
			return fmt.Errorf("smtp: 认证失败: %v: %w", err, ErrSendFailed)
		}
	}

	if err := cl.Mail(p.cfg.From); err != nil {
		return fmt.Errorf("smtp: MAIL FROM 被拒: %v: %w", err, ErrSendFailed)
	}
	for _, a := range rcpt {
		if err := cl.Rcpt(a); err != nil {
			// ★一个收件人被拒即整条失败，不"部分成功"。
			// 部分成功会被记成 ok，而管理员再也不知道有人没收到。
			return fmt.Errorf("smtp: 收件人 %s 被拒: %v: %w", a, err, ErrSendFailed)
		}
	}
	wc, err := cl.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA 被拒: %v: %w", err, ErrSendFailed)
	}
	if _, err := wc.Write(p.buildMessage(rcpt, subject, body)); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp: 正文写入失败: %v: %w", err, ErrSendFailed)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp: 正文提交被拒: %v: %w", err, ErrSendFailed)
	}
	// QUIT 失败不算发送失败：邮件在 DATA 提交成功那一刻就已被 MTA 接管，
	// 这里报错只会让"其实发出去了"被记成失败，然后管理员反复重试造成重复告警。
	if err := cl.Quit(); err != nil {
		p.log.Warn("SMTP QUIT 未正常结束（邮件已被 MTA 接收，不影响本次发送）", "host", p.cfg.Host, "err", err.Error())
	}
	return nil
}

// buildMessage 组装 RFC 5322 报文（UTF-8 正文按 base64 传输编码）。
//
// 主题走 RFC 2047 编码：中文主题不编码会被多数 MTA 打成乱码或整封退信。
// 正文用 base64 而不是 8bit：不是所有 MTA 都通告 8BITMIME，
// 而告警正文必然含中文——这是"能不能看懂"而非"好不好看"的问题。
func (p *SMTPChannel) buildMessage(to []string, subject, body string) []byte {
	var b strings.Builder
	from := p.cfg.From
	if p.cfg.FromName != "" {
		from = mime.QEncoding.Encode("UTF-8", p.cfg.FromName) + " <" + p.cfg.From + ">"
	}
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + messageID() + "@baidi>\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return []byte(b.String())
}

func messageID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

// ── AUTH LOGIN ──

// loginAuth 实现 AUTH LOGIN。标准库只带 PLAIN/CRAM-MD5，而 Exchange 与不少国产
// 邮件网关只认 LOGIN——不实现它，"配好了却认证失败"会被误判成口令错。
//
// ★与标准库 plainAuth 同款的 TLS 闸：server.TLS 为假一律拒绝。
// LOGIN 把账号与口令分两回合 base64 发出去，base64 不是加密，明文链路上等同裸奔。
type loginAuth struct {
	username, password string
	step               int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("smtp: 拒绝在未加密连接上使用 AUTH LOGIN（base64 不是加密）")
	}
	return "LOGIN", nil, nil
}

// Next 按**回合序**应答，不解析服务端提示词。
//
// ★不按提示词匹配是刻意的：各家的提示不统一（"Username:" / "User Name" / 空串 /
// 本地化文案），按前缀猜一旦错位就会把**口令发到账号那一格**——服务端把口令当成用户名
// 记进日志，而现象只是"认证失败"。LOGIN 的回合序是固定的两问（先账号后口令），
// 照序回答对所有实现都成立。
func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	}
	return nil, errors.New("smtp: AUTH LOGIN 服务端索要了第三段凭据，协议异常，已中止")
}
