// Package cplane 是网关侧的控制面客户端：向 baidi-control 注册自身，并拉取资源授权策略。
//
// 机器身份走 mTLS 客户端证书（CA 身份迁移 阶段 2/4）：证书由控制面内部 CA 签发，
// 身份在传输层完成。此前是用共享密钥自签 role=gateway 令牌——而那把密钥同时能签
// role=admin，等于把控制面的签发能力放在被保护方手里。
//
// ★阶段 4 已删除自签回退：gateway/internal/auth 不再有 Sign 函数，
// 数据面在**代码层**不具备签发能力。要调控制面就必须持证书，没有第二条路。
package cplane

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"baidi.dev/gateway/internal/natfw"
	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/sysstat"
)

// Client 访问 baidi-control 的网关接口。
type Client struct {
	control    string
	gwID       string
	proxy, spa string
	// web 七层 Web 代理的监听地址（未开启则为空）与它自身是否已终结 TLS。
	// 控制面据此拼出浏览器该跳的入口 URL；不开启就连字段都不上报，
	// 控制面于是能如实回「本网关未开启七层 Web 代理」而不是给一个连不上的地址。
	web    string
	webTLS bool
	mtls   bool // 已装载客户端证书：身份走 TLS
	// tunnelFP 本网关隧道 TLS/TLCP 证书的 SHA-256 指纹（hex）。随注册心跳上报，
	// 由控制面转发给客户端做证书钉扎——网关证书自签，客户端没有别的途径确认对端身份。
	tunnelFP string
	// version 网关二进制版本号（编译期 -ldflags 注入，缺省 "dev"）。随心跳上报，
	// 补上「控制面连网关跑的是什么版本都不知道」的盲区。
	version string
	// events 数据面回执队列：网关把「控制面指令已实际生效」的事实攒在这里，
	// 随下次心跳带给控制面落审计——否则「已下发」与「已生效」全系统不可区分。
	events eventQueue
	// metrics 宿主机设备状态的采样函数（PRD ch5 FR-MON-01）。nil = 本进程不上报，
	// 心跳报文里连 metrics 字段都不会出现——控制面据此区分「旧网关不会报」与
	// 「新网关报了但一项都没采到」，后者是一个内容为 {} 的对象。
	//
	// ★用函数而不是快照值：CPU 与吞吐是差分指标，必须**每次心跳恰好采一次**。
	// 存快照会让采样节奏与心跳脱钩，速率的分母就不再是两次上报的真实间隔。
	metrics func() sysstat.Sample
	// ifaces 本机网卡枚举源（地址转换用）。nil = 不上报，报文里无该字段。
	ifaces func() []sysstat.Iface
	httpc  *http.Client

	// lastNAT/natPresent 上一次策略响应里的地址转换策略，以及控制面**是否下发了**该字段。
	// 两者分开存是必须的：nil（旧控制面不认识 NAT）与空数组（本网关无策略）
	// 在内核动作上完全相反——前者保持现状，后者清空规则。
	mu         sync.Mutex
	lastNAT    []natfw.Policy
	natPresent bool
}

// SetTunnelFP 设置随注册上报的隧道证书指纹。证书在监听前就已备妥，故可在首次 Register 前调用。
func (c *Client) SetTunnelFP(fp string) { c.tunnelFP = fp }

// SetVersion 设置随注册心跳上报的网关版本号。
func (c *Client) SetVersion(v string) { c.version = v }

// SetWeb 登记七层 Web 代理的监听地址（空=未开启，不上报该字段）。
func (c *Client) SetWeb(addr string, tlsOn bool) { c.web, c.webTLS = addr, tlsOn }

// SetMetrics 装上宿主机设备状态采样源；不调用即不上报（向后兼容：报文里无 metrics 字段）。
func (c *Client) SetMetrics(fn func() sysstat.Sample) { c.metrics = fn }

// SetIfaces 装上网卡枚举源；不调用即不上报。
func (c *Client) SetIfaces(fn func() []sysstat.Iface) { c.ifaces = fn }

// Event 一条数据面回执：网关报告某个控制面指令**已实际执行**的事实。
// 措辞必须是已发生的事（"已撤销/已生效"），控制面会原样落审计——谎报即审计失实。
type Event struct {
	TS     int64  `json:"ts"`     // 网关侧执行时刻（Unix 秒）
	Kind   string `json:"kind"`   // revoke-applied | policy-applied
	Detail string `json:"detail"` // 事实描述（中文，含关键参数）
}

// QueueEvent 把一条回执入队，随下次心跳带走；队列满时丢最旧（回执是尽力而为的
// 观测通道，不是执行通道——安全动作本身已在网关本地完成，丢回执不影响防护）。
func (c *Client) QueueEvent(kind, detail string) {
	c.events.push(Event{TS: time.Now().Unix(), Kind: kind, Detail: detail})
}

// DroppedEvents 返回因队列溢出被丢弃的回执累计条数（观测/测试用）。
func (c *Client) DroppedEvents() int { return c.events.droppedCount() }

// maxQueuedEvents 回执队列上界：控制面不可达时队列不无限膨胀。
// 64 条 ≈ 4 个轮询周期内的密集处置量，超出说明控制面已长时间失联，旧回执的价值递减。
const maxQueuedEvents = 64

// eventQueue 有界回执队列（零值可用）：满则丢最旧并计数。
//
// 每条入队回执带一个单调递增序号，ack 按**序号**而非条数清理。用条数会在
// 「发送期间恰好溢出」时丢掉从未发出的回执：队满时 push 从队首挤掉一条、队尾补一条，
// 长度不变，随后 ack(n) 按长度从队首砍 n 条就会把队尾那条新回执一并砍掉——它从未
// 被 snapshot 带走过，控制面永远收不到，且没有任何报错。按序号清理则天然免疫：
// ack 只删「序号 ≤ 本次带走的最后一条」的条目，新回执序号更大，永远留存。
// 今天 QueueEvent 只在轮询 goroutine 上调用（触发不了），但队列带锁且 QueueEvent 是
// 导出 API——将来任一后台 goroutine（如 pf 回收器）入队即中招，故按可并发的正确性写。
type eventQueue struct {
	mu      sync.Mutex
	buf     []queuedEvent
	nextSeq uint64
	dropped int
}

type queuedEvent struct {
	seq uint64
	ev  Event
}

func (q *eventQueue) push(e Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.buf) >= maxQueuedEvents {
		drop := len(q.buf) - maxQueuedEvents + 1
		q.buf = q.buf[drop:]
		q.dropped += drop
	}
	q.nextSeq++
	q.buf = append(q.buf, queuedEvent{seq: q.nextSeq, ev: e})
}

// snapshot 复制当前队列内容（不清空）并返回末条序号，供发送成功后 ack。
// 队列为空时返回的序号为 0，ack(0) 是空操作。
func (q *eventQueue) snapshot() ([]Event, uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.buf) == 0 {
		return nil, 0
	}
	out := make([]Event, len(q.buf))
	for i, qe := range q.buf {
		out[i] = qe.ev
	}
	return out, q.buf[len(q.buf)-1].seq
}

// ack 发送成功后移除序号 ≤ through 的条目；发送失败不调用，回执留队重试。
func (q *eventQueue) ack(through uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	keep := q.buf[:0]
	for _, qe := range q.buf {
		if qe.seq > through {
			keep = append(keep, qe)
		}
	}
	q.buf = keep
}

func (q *eventQueue) droppedCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// NewMTLS 构造走 mTLS 客户端证书的控制面客户端。
// certFile/keyFile 是控制面签发给本网关的证书与私钥，caFile 是内部 CA 公证书。
func NewMTLS(control, gwID, proxy, spa, certFile, keyFile, caFile string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("载入网关客户端证书失败: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("载入 CA 证书失败: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA 证书解析失败: " + caFile)
	}
	return &Client{
		control: strings.TrimRight(control, "/"),
		gwID:    gwID, proxy: proxy, spa: spa, mtls: true,
		httpc: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
			}},
		},
	}, nil
}

// UsesMTLS 报告是否以客户端证书作为机器身份（供启动日志暴露真实姿态）。
func (c *Client) UsesMTLS() bool { return c.mtls }

func (c *Client) do(method, path string, body []byte) (*http.Response, error) {
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.control+path, rd)
	if err != nil {
		return nil, err
	}
	// 身份由客户端证书承载：不附带任何 Bearer 令牌——网关不具备签发能力。
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpc.Do(req)
}

// Session 上报给控制面的一条活跃会话（真实在线用户来源）。
type Session struct {
	IP    string `json:"ip"`
	User  string `json:"user"`
	Role  string `json:"role"`
	Since int64  `json:"since"` // 首次敲门放行的 Unix 时刻
}

// Register 向控制面注册/心跳，同时上报真实活性指标与活跃会话：clients=放行窗口内已授权源数，
// tunnels=活跃隧道连接数，uptimeSec=网关运行秒数，sessions=当前活跃会话（供监控中心在线用户）。
// 心跳还捎带 version（编译期注入的网关版本）、events（数据面回执，发送成功即从队列清除；
// 失败留队随下次心跳重试）与 metrics（宿主机设备状态采样，未装采样源则整个字段缺席）。
// 旧控制面不认识这几个字段时按 JSON 语义直接忽略，不影响注册。
func (c *Client) Register(clients, tunnels int, uptimeSec int64, sessions []Session) error {
	evs, through := c.events.snapshot()
	payload := map[string]any{
		"id": c.gwID, "proxy": c.proxy, "spa": c.spa,
		"clients": clients, "tunnels": tunnels, "uptime": uptimeSec, "sessions": sessions,
		"tunnelFp": c.tunnelFP, // 供控制面转发给客户端做隧道证书钉扎
		"version":  c.version,
		"events":   evs,
		// now：网关此刻的本机时钟（Unix 秒），供控制面比对两侧时钟偏差。
		// ★为什么值得上报：敲门令牌是控制面按自己的钟签的短时效凭据（exp=签发+90s），
		// 而**验它的是网关的钟**。两侧漂过这个量，合法客户端的每一次敲门都会以
		// 「令牌过期」被拒——客户端没有错误可看（SPA 是单包无回应的），控制面日志一切正常，
		// 这正是本项目最忌讳的静默失效形态。控制面在收包时刻做减法并呈现/告警。
		"now": time.Now().Unix(),
	}
	// 七层 Web 代理落点：未开启就连键都不加。★不能上报空串——控制面区分
	// 「旧网关不认识这个字段」与「新网关明确说没开」没有意义，但**给一个空地址**
	// 会让入口 URL 拼成 http://host:/…，浏览器打开是一个莫名其妙的错误。
	if c.web != "" {
		payload["web"] = c.web
		payload["webTls"] = c.webTLS
	}
	// 设备状态：每次心跳采一次（差分指标的间隔 = 上报间隔）。采不到的单项由
	// Sample 的 omitempty 自然缺席，绝不补 0；整个采样源缺席时连 metrics 键都不加。
	if c.metrics != nil {
		payload["metrics"] = c.metrics()
	}
	// 网卡清单：地址转换选源/目的接口时只能从真实存在的卡里挑（见 sysstat.Ifaces 注释）。
	// 与 metrics 同款兼容策略——未装枚举源就连字段都不出现，旧控制面照常忽略。
	if c.ifaces != nil {
		payload["ifaces"] = c.ifaces()
	}
	body, _ := json.Marshal(payload)
	resp, err := c.do(http.MethodPost, "/api/v1/gateways/register", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control 注册返回 %d", resp.StatusCode)
	}
	c.events.ack(through) // 只清本次带走的那批：发送期间新入队的回执序号更大，留待下次心跳
	return nil
}

// resourceDTO 对应控制面返回的资源 JSON（camelCase）。
type resourceDTO struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Backend    string   `json:"backend"`
	AllowRoles []string `json:"allowRoles"`
	AllowUsers []string `json:"allowUsers"`
	// DenyUsers 控制面算好的否决名单（终端风险降权对高敏资源的收缩）。
	// 旧控制面不下发这个字段 → 空切片 → 行为与改造前逐字节一致（向后兼容）。
	DenyUsers []string `json:"denyUsers"`
	// WebScheme 七层代理拨后端用的协议（http|https）。空 = http（旧控制面即此形态）。
	WebScheme string `json:"webScheme"`
}

// Revoked 控制面下发的一条强制下线封禁（封禁期内拒绝敲门，并撤窗/切断该账号隧道）。
// 数据面执行只需 user + until；处置原因（reason）为运营敏感文本，按最小披露原则不下发网关。
type Revoked struct {
	User  string `json:"user"`
	Until int64  `json:"until"` // 封禁截止 Unix 秒
}

// Policy 拉取当前资源授权策略 + 强制下线撤销名单（旧控制面无 revoked 字段则为空，向后兼容）。
func (c *Client) Policy() ([]resource.Resource, []Revoked, error) {
	resp, err := c.do(http.MethodGet, "/api/v1/gateways/policy", nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("control 拉策略返回 %d", resp.StatusCode)
	}
	var r struct {
		Resources []resourceDTO  `json:"resources"`
		Revoked   []Revoked      `json:"revoked"`
		NAT       []natfw.Policy `json:"nat"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, nil, err
	}
	out := make([]resource.Resource, 0, len(r.Resources))
	for _, d := range r.Resources {
		out = append(out, resource.Resource{ID: d.ID, Backend: d.Backend,
			AllowRoles: d.AllowRoles, AllowUsers: d.AllowUsers, DenyUsers: d.DenyUsers,
			WebScheme: d.WebScheme})
	}
	// NAT 策略与资源策略同一次响应取回，单独暴露给调用方（main 决定灌不灌内核）。
	// ★旧控制面不带 nat 字段时这里是 nil，与「本网关无 NAT 策略」的空数组**语义不同**：
	// 前者应保持现状不动内核，后者应清空规则。故用 NATPresent 区分，别让缺字段
	// 被读成「把 NAT 全删掉」——那会在升级控制面的瞬间把生产 NAT 规则清空。
	c.mu.Lock()
	c.lastNAT, c.natPresent = r.NAT, r.NAT != nil
	c.mu.Unlock()
	return out, r.Revoked, nil
}

// NATPolicies 返回上一次 Policy() 取回的地址转换策略，以及控制面**是否下发了**该字段。
// present=false 表示对端是不认识 NAT 的旧控制面，调用方应保持内核规则现状。
func (c *Client) NATPolicies() (policies []natfw.Policy, present bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastNAT, c.natPresent
}
