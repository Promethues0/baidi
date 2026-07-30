// 隧道内 DNS 响应器：让「按域名访问业务系统」也能真正走进隧道。
//
// # 为什么必须有它
//
// 在此之前客户端**只按 IP 路由**：控制面给每个资源分配 VIP、下发 routes，utun 接管这些
// 网段。于是管理员配一个 `oa.corp.internal:8080` 的应用时，终端拿到的后端是域名而不是
// IP，既排不出 /32 路由、也无从接管——流量直连内网出口，**且没有任何报错**。
// 隧道显示"已接入"、应用打不开或走了明文旁路，是本项目最难排查的一类静默失效。
//
// 补法是：控制面在接入剖面里额外下发 `dns` 段（解析器 VIP + 搜索域 + FQDN→VIP 记录），
// 客户端在隧道内起一个**只会作答、不会转发**的迷你解析器，把域名直接解析到 VIP；
// VIP 已经在 routes 里，于是域名访问自然收敛到既有的「VIP → CONNECT <资源id>」路径，
// 授权与审计口径完全不变。
//
// # 明确不做（不是"还没做"，是刻意不做）
//
//   - **不做递归/转发**：未知域名一律 REFUSED，绝不向上游解析器转发。理由三条：
//     ① 转发会把内网查询（含主机名这类拓扑信息）泄露到隧道外；
//     ② 我们会变成一个开放解析器，是个免费的放大攻击反射点；
//     ③ 操作系统已按搜索域分流（macOS /etc/resolver、Linux systemd-resolved），
//     不属于我们的域名根本不会被问到——真收到了也说明分流配错了，静默转发只会掩盖它。
//   - 不支持 TCP/53、DNSSEC、EDNS0 扩容、CNAME/SRV/PTR、通配符、区域传送。
//   - 不引第三方 DNS 库：我们只消费 A/AAAA 查询这一个子集，几十行就够；
//     引库反而要额外审它的解析安全性（DNS 解析器历史上是内存安全漏洞的高发区）。
package dataplane

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
)

const (
	dnsPort      = 53
	dnsHeaderLen = 12 // ID(2) Flags(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
	// dnsMaxMsg 收包上限。传统 UDP DNS 是 512 字节，带 EDNS0 的客户端会宣称更大；
	// 放到 4096 只是为了不因为一个带 OPT 的大查询而读半截，我们自己的应答恒 < 512。
	dnsMaxMsg = 4096
	// dnsMaxName 编码后名字总长上限（RFC 1035 §2.3.4），含各标签长度前缀与末尾根标签。
	dnsMaxName = 255
	// dnsTTL 应答 TTL（秒）。刻意取短：授权变更/JIT 到期/VIP 重分配都要靠客户端重查生效，
	// TTL 太长会让"策略已改、终端还在用旧解析结果"持续很久，且用户完全无从察觉。
	dnsTTL = 30
	// dnsIdleTimeout 一个 UDP 会话（四元组）空闲多久后回收。
	dnsIdleTimeout = 10 * time.Second
)

// DNS 头部标志位与 RCODE。
const (
	dnsFlagQR = uint16(0x8000) // 1=应答
	dnsFlagAA = uint16(0x0400) // 权威应答
	dnsFlagRD = uint16(0x0100) // 期望递归（原样回显）

	dnsRcodeNoError  = uint16(0)
	dnsRcodeFormErr  = uint16(1)
	dnsRcodeNXDomain = uint16(3)
	dnsRcodeRefused  = uint16(5)
)

// 查询类型与类。
const (
	dnsTypeA    = uint16(1)
	dnsTypeAAAA = uint16(28)
	dnsClassIN  = uint16(1)
)

// dnsResponder 是一张只读的 FQDN → IPv4 静态表，外加一个极小的报文编解码器。
// 构造后不再变更，可被多个会话 goroutine 并发读取，无需加锁。
type dnsResponder struct {
	records map[string][4]byte
}

// newDNSResponder 由控制面下发的记录表构造响应器。
//
// ★键值都要规范化：DNS 名字大小写不敏感，线上表示还带尾点。管理员在控制台填的可能是
// `OA.corp.internal.`，而客户端查上来的是 `oa.corp.internal`——不统一规范化就会出现
// 「明明配了却解析不到」，且日志里两个名字看起来一模一样（只差大小写/尾点），极难发现。
//
// 非法记录（值不是 IPv4 字面量）跳过并显式告警：宁可少一条记录也不能让整张表装不上，
// 但绝不静默丢弃——静默丢弃就是又一个"配了没生效"。
func newDNSResponder(records map[string]string) *dnsResponder {
	d := &dnsResponder{records: make(map[string][4]byte, len(records))}
	for name, addr := range records {
		n := normalizeDNSName(name)
		if n == "" {
			slog.Warn("隧道内 DNS：忽略空域名记录", "addr", addr)
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(addr))
		if ip == nil || ip.To4() == nil {
			// 只答 A 记录，IPv6 值无处安放（AAAA 恒回空应答，见 answer 注释）。
			slog.Warn("隧道内 DNS：记录值不是 IPv4 字面量，已跳过", "name", n, "addr", addr)
			continue
		}
		var v4 [4]byte
		copy(v4[:], ip.To4())
		d.records[n] = v4
	}
	return d
}

// normalizeDNSName 统一成「小写、无尾点、去空白」的比较口径。
func normalizeDNSName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

// dnsQuestion 一条已解析的问题段。
type dnsQuestion struct {
	// raw 是线上原始 QNAME 字节（含各标签长度前缀与末尾 0）。应答必须原样回显问题段，
	// 包括大小写——不少解析器（含 glibc 的 0x20 编码探测）会逐字节比对来防投毒。
	raw    []byte
	name   string // 规范化后的名字，用于查表
	qtype  uint16
	qclass uint16
}

// dnsReply 一份待编码的应答。拆成结构体是为了让"哪些位怎么置"在一处看全，
// 而不是散落在若干个 append 里。
type dnsReply struct {
	id     uint16
	opcode uint16 // 必须原样回显查询的 OPCODE
	rd     bool   // RD 原样回显（我们不递归，但回显是规范要求）
	aa     bool   // 只有作答自己拥有的名字时才置权威位
	rcode  uint16
	q      *dnsQuestion // nil = 无法回显问题段（QDCOUNT≠1 或解析失败）
	a      *[4]byte     // nil = 0 条应答记录
}

// bytes 编码应答。
func (r dnsReply) bytes() []byte {
	flags := dnsFlagQR | (r.opcode&0xF)<<11 | (r.rcode & 0xF)
	if r.rd {
		flags |= dnsFlagRD
	}
	if r.aa {
		flags |= dnsFlagAA
	}
	var qd, an uint16
	if r.q != nil {
		qd = 1
	}
	if r.a != nil {
		an = 1
	}

	out := make([]byte, 0, 64)
	out = appendBE16(out, r.id)
	out = appendBE16(out, flags)
	out = appendBE16(out, qd)
	out = appendBE16(out, an)
	out = appendBE16(out, 0) // NSCOUNT
	// ARCOUNT 恒 0：查询里若带 EDNS0 的 OPT 记录，我们**不**回 OPT。按 RFC 6891 §7，
	// 应答不含 OPT 即表示"本服务器不支持 EDNS"，客户端会自行降级到 512 字节语义——
	// 我们的应答本来就远小于 512，没有扩容需求，少实现一段就少一份解析面。
	out = appendBE16(out, 0)

	if r.q != nil {
		out = append(out, r.q.raw...)
		out = appendBE16(out, r.q.qtype)
		out = appendBE16(out, r.q.qclass)
	}
	if r.a != nil {
		// 应答记录的 NAME 直接重写一遍原始 QNAME，而不用 0xC00C 压缩指针。
		// 压缩指针在应答里完全合法且更省字节，但我们在**查询**侧是拒绝指针的
		// （见 parseDNSQuestion），编解码两侧口径一致更省心；名字都很短，省这十几字节没意义。
		out = append(out, r.q.raw...)
		out = appendBE16(out, dnsTypeA)
		out = appendBE16(out, dnsClassIN)
		out = appendBE32(out, dnsTTL)
		out = appendBE16(out, 4) // RDLENGTH
		out = append(out, r.a[:]...)
	}
	return out
}

// answer 解析一条查询并给出应答字节。第二返回值 false 表示**不回包**。
//
// 判定顺序与理由：
//   - QR=1（这本身是个应答）→ 不回包。否则两个配置成互指的解析器会无限对轰。
//   - 报文过短/过长、名字非法 → FORMERR（能定位到"报文坏了"）。
//   - OPCODE≠QUERY、QDCOUNT≠1、CLASS≠IN、未命中、其它 QTYPE → REFUSED（"我不管这个名字"）。
//   - 命中 + QTYPE=A → 一条 A 记录。
//   - 命中 + QTYPE=AAAA → **NOERROR + 0 条应答**，见下方 ★。
//
// ★为什么未命中回 REFUSED 而不是 NXDOMAIN：NXDOMAIN 是**权威否定**，会被系统解析器
// 负缓存（且缓存对该名字的所有类型生效）。若某域名此刻还没进剖面（应用刚建好、审批刚过），
// 一次 NXDOMAIN 会让它在缓存期内持续解析失败，用户重试也没用。REFUSED 不会被负缓存。
func (d *dnsResponder) answer(msg []byte) ([]byte, bool) {
	if len(msg) < dnsHeaderLen {
		// 连 ID 都读不出来，回包也无法被对端匹配，直接丢弃。
		return nil, false
	}
	if len(msg) > dnsMaxMsg {
		return nil, false
	}
	flags := dnsBE16(msg[2:])
	if flags&dnsFlagQR != 0 {
		return nil, false // 应答不是查询：绝不回包，避免解析器互相对轰成环
	}
	rep := dnsReply{
		id:     dnsBE16(msg[0:]),
		opcode: (flags >> 11) & 0xF,
		rd:     flags&dnsFlagRD != 0,
	}

	// QDCOUNT≠1 一律 REFUSED：现实中没有任何客户端会在一个报文里问多个问题
	// （规范允许，但没有实现能正确处理"多问题多 RCODE"），支持它只是徒增解析面。
	if rep.opcode != 0 || dnsBE16(msg[4:]) != 1 {
		rep.rcode = dnsRcodeRefused
		return rep.bytes(), true
	}

	q, err := parseDNSQuestion(msg)
	if err != nil {
		slog.Debug("隧道内 DNS：查询报文非法", "err", err.Error())
		rep.rcode = dnsRcodeFormErr
		return rep.bytes(), true
	}
	rep.q = &q

	if q.qclass != dnsClassIN {
		rep.rcode = dnsRcodeRefused
		return rep.bytes(), true
	}
	v4, hit := d.records[q.name]
	if !hit {
		// 走到这里说明系统解析器把一个不属于我们的名字分流了过来，或者控制面漏配了记录。
		// 两者都值得留痕：这正是"应用配了域名却连不上"的第一现场。
		slog.Info("隧道内 DNS 未命中，回 REFUSED（不转发上游）", "name", q.name, "qtype", q.qtype)
		rep.rcode = dnsRcodeRefused
		return rep.bytes(), true
	}
	rep.aa = true // 名字是我们自己的，权威作答

	switch q.qtype {
	case dnsTypeA:
		rep.a = &v4
		return rep.bytes(), true
	case dnsTypeAAAA:
		// ★★ 经典陷阱：这里**必须**是 NOERROR + 0 条应答，绝不能是 NXDOMAIN。
		// NXDOMAIN 的语义是"这个名字根本不存在"，而不是"这个名字没有 IPv6 地址"。
		// 客户端（含 glibc getaddrinfo）会据此认定整个名字不存在，**连已经拿到的 A 记录
		// 也一并丢弃**，症状就是"明明配了 A 记录却解析失败"，且只在开了 IPv6 的机器上复现——
		// 同一份配置在同事机器上好好的，在你机器上就是不行，是最耗时间的一类 bug。
		// 正确姿态是 NODATA：RCODE=NOERROR、ANCOUNT=0、权威位置上。
		return rep.bytes(), true
	default:
		// CNAME/SRV/PTR/ANY 等：我们没有这些数据，也不代为查询。
		rep.aa = false
		rep.rcode = dnsRcodeRefused
		return rep.bytes(), true
	}
}

// parseDNSQuestion 从固定头之后解析**唯一**一条问题段。
//
// 防护点（每一条都对应一种真实的畸形包）：
//   - 标签长度 ≤63：由 b&0xC0 != 0 一并挡掉（64 起高两位必然非零）；
//   - 名字编码总长 ≤255；
//   - 每次前进都做边界检查，杜绝越界读；
//   - **压缩指针一律拒绝**：查询报文里根本不该出现指针（它前面没有可被指向的名字），
//     而一旦允许指针，就要处理"指针指向自己/互指成环"——这是 DNS 解析器的经典
//     拒绝服务面（解析进程原地打转，表现为客户端全部卡死而非报错）。直接拒绝最省事。
func parseDNSQuestion(msg []byte) (dnsQuestion, error) {
	var q dnsQuestion
	off := dnsHeaderLen
	start := off
	var labels []string
	encoded := 1 // 末尾根标签的那个 0 字节

	for {
		if off >= len(msg) {
			return q, errDNS("QNAME 在报文结束前未终止（报文被截断）")
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			return q, errDNS("查询里出现压缩指针，拒绝（防指针环导致的解析死循环）")
		}
		if l&0xC0 != 0 {
			// 0x40/0x80 是 RFC 2671/RFC 6891 时代的保留标签类型，无人使用。
			return q, errDNS("标签类型保留位非法")
		}
		// 到这里 l ∈ [1,63]，标签长度上限自动满足。
		off++
		if off+l > len(msg) {
			return q, errDNS("标签长度越过报文尾（报文被截断或长度字段被篡改）")
		}
		encoded += 1 + l
		if encoded > dnsMaxName {
			return q, errDNS("QNAME 编码总长超过 255 字节")
		}
		labels = append(labels, strings.ToLower(string(msg[off:off+l])))
		off += l
	}
	if off+4 > len(msg) {
		return q, errDNS("问题段缺少 QTYPE/QCLASS（报文被截断）")
	}
	q.raw = msg[start:off]
	q.name = strings.Join(labels, ".")
	q.qtype = dnsBE16(msg[off:])
	q.qclass = dnsBE16(msg[off+2:])
	return q, nil
}

// dnsErr 是本文件内部的解析错误类型，只承载一句中文原因（会进 Debug 日志）。
type dnsErr string

func (e dnsErr) Error() string { return string(e) }

func errDNS(s string) error { return dnsErr(s) }

// serveSession 处理一个 UDP 会话。gVisor 的 udp.Forwarder 按四元组交出一个连接式端点，
// 于是这里可以当成 net.Conn 用。
//
// ★不能"收一条就关"：glibc / systemd-resolved 会用**同一个源端口**并发发出 A 与 AAAA
// 两条查询。若答完第一条就关闭端点，第二条要么被丢、要么绕回 forwarder 重建端点——
// 前者让 getaddrinfo 一直等到超时重试，症状是"能解析，但每次都要卡好几秒"，
// 而且只在双栈机器上出现。所以这里保持会话，空闲 dnsIdleTimeout 后才回收。
func (d *dnsResponder) serveSession(c net.Conn) {
	defer c.Close()
	buf := make([]byte, dnsMaxMsg)
	for {
		if err := c.SetReadDeadline(time.Now().Add(dnsIdleTimeout)); err != nil {
			return
		}
		n, err := c.Read(buf)
		if err != nil {
			return // 空闲超时或端点关闭：正常回收路径
		}
		resp, ok := d.answer(buf[:n])
		if !ok {
			continue
		}
		if _, err := c.Write(resp); err != nil {
			slog.Debug("隧道内 DNS：应答写回失败", "err", err.Error())
			return
		}
	}
}

func dnsBE16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func appendBE16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

func appendBE32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// serveTCPSession 在 TCP 上作答（RFC 1035 §4.2.2：每条报文前加 2 字节大端长度前缀）。
//
// ★为什么必须实现，而不是让它落到隧道转发路径上：
// 解析器 VIP 会随 routes 一起被 utun 接管，于是**发往它 53 端口的 TCP 连接也会被接管**。
// 若不在这里短路，那条连接会掉进 tunnel()，被当成一次普通业务访问去 CONNECT 一个
// 根本不存在的资源 id——症状是「dig +tcp 挂住不返回」，而 UDP 查询一切正常。
// 这种「只有某一种查询方式会卡死」的故障极难归因。
//
// 正常情况下没人会走到这里：我们的应答恒 <512 字节且从不置 TC 位，客户端没有理由
// 重试 TCP。但 `dig +tcp`、以及被显式配成 TCP-only 的解析器确实会直接用 TCP。
func (d *dnsResponder) serveTCPSession(c net.Conn) {
	defer c.Close()
	buf := make([]byte, dnsMaxMsg)
	for {
		if err := c.SetReadDeadline(time.Now().Add(dnsIdleTimeout)); err != nil {
			return
		}
		// 长度前缀必须读满 2 字节：TCP 是字节流，一次 Read 可能只给到 1 字节。
		var lenBuf [2]byte
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return // 空闲超时 / 对端关闭：正常回收
		}
		n := int(dnsBE16(lenBuf[:]))
		if n == 0 || n > dnsMaxMsg {
			// 长度非法就直接断开，不要试图跳过 n 字节继续读——
			// 那等于让对端用一个假长度指挥我们空转。
			return
		}
		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			return
		}
		resp, ok := d.answer(buf[:n])
		if !ok {
			continue
		}
		out := make([]byte, 0, 2+len(resp))
		out = appendBE16(out, uint16(len(resp)))
		out = append(out, resp...)
		if _, err := c.Write(out); err != nil {
			slog.Debug("隧道内 DNS(TCP)：应答写回失败", "err", err.Error())
			return
		}
	}
}
