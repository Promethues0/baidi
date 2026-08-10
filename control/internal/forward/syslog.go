package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ── RFC 5424 syslog over TCP / TLS ──
//
// 报文结构（RFC 5424 §6）：
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ELEMENT...] BOM MSG
//
// 帧（RFC 6587）：TCP 上的 syslog 没有天然边界，必须自己定界。
//   - octet-counting：`<长度> <报文>`，RFC 6587 §3.4.1 推荐；rsyslog/syslog-ng 都认。
//   - non-transparent-framing：报文后跟一个 LF，rsyslog 的 imtcp 默认形态。
//
// 两种都实现是因为它们各自都有真实对端，而**猜错就是整段日志解析不出来**：
// 收集端按 LF 切分时收到 octet-counting 的报文，会把长度前缀当成消息内容的一部分。

// Framing TCP 上的帧方式。
type Framing string

const (
	// FramingOctet RFC 6587 §3.4.1 八位组计数（推荐：消息里出现换行也不会被切断）。
	FramingOctet Framing = "octet"
	// FramingLF RFC 6587 §3.4.2 非透明帧，以 LF 收尾（rsyslog imtcp 的默认形态）。
	FramingLF Framing = "lf"
)

// 默认端口：TLS 走 6514（RFC 5425 指定），明文 TCP 走 514。
const (
	defaultSyslogTLSPort   = 6514
	defaultSyslogPlainPort = 514
)

// defaultEnterpriseID SD-ID 的私有企业号后缀。
//
// ★RFC 5424 §7.2 要求自定义 SD-ID 形如 `name@<私有企业号>`。白帝**没有** IANA
// 分配的企业号，所以默认用 32473——那是 RFC 5612 明确保留给文档/示例的号段。
// 随手编一个别人的号才是错的（收集端按 SD-ID 分流时会把白帝的日志混进那家的桶里）。
// 有自己企业号的部署方在配置里填 enterpriseId 覆盖即可。
const defaultEnterpriseID = "32473"

// defaultFacility local0。syslog 的 facility 没有"应用日志"这一档，
// local0-7 是给本地应用留的惯例区间。
const defaultFacility = 16

const defaultSyslogTimeout = 10 * time.Second

// severity 取值（RFC 5424 §6.2.1）。
const (
	sevWarning = 4
	sevNotice  = 5
	sevInfo    = 6
)

// SyslogConfig syslog 出口配置。零值不可用，必须经 NewSyslog 校验。
type SyslogConfig struct {
	Host string
	Port int // 0 = 按 TLS 取默认（TLS:6514，明文:514）

	// TLS 是否启用 TLS（RFC 5425）。
	//
	// ★注意这里**没有** InsecureSkipVerify 之类的开关，是刻意的：
	// 外送内容是全量审计（谁在什么时候从哪个 IP 做了什么）。一个"临时跳过校验"
	// 的开关在生产上一定会被永久打开，而 TLS 一旦退化成"加密但不认证"，
	// 中间人可以无声接管整条审计流——且两端日志都完全正常。
	// 证书对不上时的正解是填 ServerName（IP 连接、证书签的是主机名）或
	// CACert（内网私有 CA 签发），两条路都在下面。
	TLS bool
	// ServerName 证书里应当出现的名字，留空取 Host。
	ServerName string
	// CACert 校验服务端证书用的 CA（PEM）。留空用系统根证书池；填了就只信这一把。
	CACert string

	Facility int     // 0 视为未填，取 local0(16)
	AppName  string  // 默认 baidi-control
	Hostname string  // 默认本机 hostname
	Framing  Framing // 默认 octet
	// EnterpriseID SD-ID 的私有企业号后缀，默认 32473（RFC 5612 文档号）。
	EnterpriseID string

	Timeout time.Duration // 一次批量投递（连接 + 写入）的上界，默认 10s

	Logger *slog.Logger
}

// SyslogForwarder 一条已校验的 syslog 出口。并发安全。
//
// ★每批投递自己拨号、发完即关，**刻意不持久化连接**：
// 常连要处理半开连接、对端重启、写超时后的状态残留，而这些状态出错的症状是
// "看起来在发、其实进了黑洞"。外送批次是分钟级的，重连的开销无关紧要，
// 换来的是"这一批到底发出去没有"每次都由一次完整的 TCP 生命周期回答。
type SyslogForwarder struct {
	cfg SyslogConfig
	tls *tls.Config
	log *slog.Logger
}

var _ Forwarder = (*SyslogForwarder)(nil)

// NewSyslog 归一化并校验配置。配置错误返回包裹 ErrNotConfigured 的错误。
func NewSyslog(cfg SyslogConfig) (*SyslogForwarder, error) {
	c := cfg
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	c.Host = strings.TrimSpace(c.Host)
	c.ServerName = strings.TrimSpace(c.ServerName)
	c.AppName = strings.TrimSpace(c.AppName)
	c.Hostname = strings.TrimSpace(c.Hostname)
	c.EnterpriseID = strings.TrimSpace(c.EnterpriseID)
	if c.Host == "" {
		return nil, fmt.Errorf("syslog: 未填写服务器地址: %w", ErrNotConfigured)
	}
	if c.Port == 0 {
		if c.TLS {
			c.Port = defaultSyslogTLSPort
		} else {
			c.Port = defaultSyslogPlainPort
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, fmt.Errorf("syslog: 端口 %d 非法: %w", c.Port, ErrNotConfigured)
	}
	if c.Facility == 0 {
		c.Facility = defaultFacility
	}
	if c.Facility < 0 || c.Facility > 23 {
		return nil, fmt.Errorf("syslog: facility %d 非法（应为 0-23）: %w", c.Facility, ErrNotConfigured)
	}
	if c.AppName == "" {
		c.AppName = "baidi-control"
	}
	if c.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			c.Hostname = h
		}
	}
	switch c.Framing {
	case "":
		c.Framing = FramingOctet
	case FramingOctet, FramingLF:
	default:
		return nil, fmt.Errorf("syslog: 未知的帧方式 %q（应为 octet/lf）: %w", c.Framing, ErrNotConfigured)
	}
	if c.EnterpriseID == "" {
		c.EnterpriseID = defaultEnterpriseID
	}
	// SD-ID 必须是 PRINTUSASCII 且不含 = SP ] "（RFC 5424 §6.3.2）。
	// 企业号来自管理员输入，脏值会拼出一条谁也解析不了的 SD——收集端多半整条丢弃。
	if strings.Trim(c.EnterpriseID, "0123456789.") != "" {
		return nil, fmt.Errorf("syslog: 企业号 %q 只能由数字与点组成: %w", c.EnterpriseID, ErrNotConfigured)
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultSyslogTimeout
	}

	var tc *tls.Config
	if c.TLS {
		name := c.ServerName
		if name == "" {
			name = c.Host
		}
		tc = &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}
		if pemStr := strings.TrimSpace(c.CACert); pemStr != "" {
			pool, err := certPoolFromPEM(pemStr)
			if err != nil {
				return nil, err
			}
			tc.RootCAs = pool
		}
	} else {
		// 明文 TCP 不是配置错误（同机 / 隔离网段的收集器很常见），但要留痕：
		// 审计正文里有账号名、源 IP 与管理动作，明文过网线等于把它们摊开。
		c.Logger.Warn("审计外送使用明文 TCP syslog：审计正文（账号 / 源 IP / 管理动作）会明文过网线，仅建议同机或隔离网段",
			"host", c.Host, "port", c.Port)
	}
	return &SyslogForwarder{cfg: c, tls: tc, log: c.Logger}, nil
}

// Target 返回拨号地址（展示用）。
func (p *SyslogForwarder) Target() string {
	scheme := "tcp"
	if p.cfg.TLS {
		scheme = "tls"
	}
	return scheme + "://" + net.JoinHostPort(p.cfg.Host, strconv.Itoa(p.cfg.Port))
}

// Send 拨号并把整批记录写出去。
//
// ★整批同一条连接、一次写完再关：分多次连接发同一批的话，中途失败就会留下
// "前半批已到、后半批未到"的局面，而队列只能整批重试 —— 于是 SIEM 侧看到重复的 seq。
func (p *SyslogForwarder) Send(ctx context.Context, batch []Record) error {
	if len(batch) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, r := range batch {
		buf.Write(p.frame(r))
	}

	cctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	addr := net.JoinHostPort(p.cfg.Host, strconv.Itoa(p.cfg.Port))
	d := &net.Dialer{}
	var conn net.Conn
	var err error
	if p.cfg.TLS {
		conn, err = (&tls.Dialer{NetDialer: d, Config: p.tls}).DialContext(cctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(cctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("syslog: 连接 %s 失败: %v: %w", addr, err, ErrSendFailed)
	}
	defer conn.Close()
	if dl, ok := cctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("syslog: 写入 %s 失败: %v: %w", addr, err, ErrSendFailed)
	}
	// ★必须显式 Close 并检查错误：TCP 写入成功只说明数据进了本机内核缓冲区。
	// 直接 defer 掉返回值的话，"对端在读到之前就 RST 了"这种情况会被记成成功，
	// 而那正是审计静默丢失的样子。
	if err := conn.Close(); err != nil {
		return fmt.Errorf("syslog: 关闭到 %s 的连接时报错（本批可能未被对端收下）: %v: %w", addr, err, ErrSendFailed)
	}
	return nil
}

// frame 把一条记录编成一个带帧的 RFC 5424 报文。
func (p *SyslogForwarder) frame(r Record) []byte {
	msg := p.message(r)
	switch p.cfg.Framing {
	case FramingLF:
		return append(msg, '\n')
	default:
		out := make([]byte, 0, len(msg)+8)
		out = append(out, strconv.Itoa(len(msg))...)
		out = append(out, ' ')
		return append(out, msg...)
	}
}

// message 组装 RFC 5424 报文体（不含帧）。
func (p *SyslogForwarder) message(r Record) []byte {
	pri := p.cfg.Facility*8 + severityOf(r)
	var b strings.Builder
	b.WriteByte('<')
	b.WriteString(strconv.Itoa(pri))
	b.WriteString(">1 ") // VERSION 恒为 1
	b.WriteString(syslogTime(r.Time))
	b.WriteByte(' ')
	b.WriteString(printASCII(p.cfg.Hostname, 255))
	b.WriteByte(' ')
	b.WriteString(printASCII(p.cfg.AppName, 48))
	b.WriteByte(' ')
	b.WriteString(printASCII(strconv.Itoa(os.Getpid()), 128))
	b.WriteByte(' ')
	// MSGID 用审计类别：收集端按它分流最自然（access/auth/admin/security/dataplane）。
	b.WriteString(printASCII(r.Category, 32))
	b.WriteByte(' ')

	// STRUCTURED-DATA：链的 seq/mac 在这里。
	//
	// ★这是整个外送功能的价值所在：外部 SIEM 拿着 seq + mac 可以独立发现
	// 「控制面那边的第 N 条与我收到的第 N 条对不上」。放进 MSG 正文里也能传，
	// 但 SD 是 RFC 定义的结构化位置，收集端能直接切成字段而不必正则去抠。
	b.WriteString("[baidi@")
	b.WriteString(p.cfg.EnterpriseID)
	for _, kv := range [][2]string{
		{"seq", strconv.FormatInt(r.Seq, 10)},
		{"mac", r.MAC},
		{"category", r.Category},
		{"actor", r.User},
		{"srcIp", r.SrcIP},
		{"verdict", r.Verdict},
	} {
		b.WriteByte(' ')
		b.WriteString(kv[0])
		b.WriteString(`="`)
		b.WriteString(sdEscape(kv[1]))
		b.WriteString(`"`)
	}
	b.WriteByte(']')

	// MSG：BOM 前缀声明 UTF-8（RFC 5424 §6.4）。审计事件文案是中文，
	// 不带 BOM 的话收集端按 RFC 只能当不透明字节串处理，界面上多半显示成乱码。
	b.WriteByte(' ')
	b.WriteString("\xEF\xBB\xBF")
	b.WriteString(truncRunes(oneLine(r.Event), 2048))
	return []byte(b.String())
}

// severityOf 由判定映射 syslog severity。
//
// 映射口径要固定且可解释——收集端的告警规则会直接吃这一格：
// 拒绝/失败 → warning（有人被挡住了，值得看）；二次认证 → notice；其余 → info。
// 刻意不用 error/critical：这些是**被审计对象的行为**，不是控制面自身故障。
func severityOf(r Record) int {
	switch r.Verdict {
	case "deny", "fail":
		return sevWarning
	case "mfa":
		return sevNotice
	default:
		return sevInfo
	}
}

// syslogTime 把审计的本地时间串（2006-01-02 15:04:05）转成 RFC 3339 带时区偏移。
//
// ★解析失败回 NILVALUE "-" 而不是 time.Now()：拿"现在"冒充记录时间，
// 会让 SIEM 侧看到一批时间戳全等于外送时刻的记录——比缺失更坏，因为它看起来是对的。
func syslogTime(ts string) string {
	t, err := time.ParseInLocation("2006-01-02 15:04:05", ts, time.Local)
	if err != nil {
		return "-"
	}
	return t.Format("2006-01-02T15:04:05.000000Z07:00")
}

// sdEscape 转义 SD-PARAM 取值里的 " \ ]（RFC 5424 §6.3.3），并压成单行。
// 不转义 ] 的话，事件文案里一个右方括号就能提前闭合 SD 元素，
// 后半截内容会被收集端当成 MSG——一条被悄悄截断的审计。
func sdEscape(v string) string {
	v = oneLine(v)
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return truncRunes(r.Replace(v), 512)
}

// printASCII 把 HEADER 字段收敛成 RFC 5424 允许的 PRINTUSASCII（33-126）并限长。
// 非法字符替成 '-'，空串回 NILVALUE "-"（HEADER 各格不允许为空）。
func printASCII(s string, max int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	var b strings.Builder
	for _, c := range []byte(s) {
		if c < 33 || c > 126 {
			b.WriteByte('-')
			continue
		}
		b.WriteByte(c)
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
	}
	return out
}
