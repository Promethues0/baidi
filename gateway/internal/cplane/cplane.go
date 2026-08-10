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

	"baidi.dev/gateway/internal/resource"
)

// Client 访问 baidi-control 的网关接口。
type Client struct {
	control    string
	gwID       string
	proxy, spa string
	mtls       bool // 已装载客户端证书：身份走 TLS
	// tunnelFP 本网关隧道 TLS/TLCP 证书的 SHA-256 指纹（hex）。随注册心跳上报，
	// 由控制面转发给客户端做证书钉扎——网关证书自签，客户端没有别的途径确认对端身份。
	tunnelFP string
	// version 网关二进制版本号（编译期 -ldflags 注入，缺省 "dev"）。随心跳上报，
	// 补上「控制面连网关跑的是什么版本都不知道」的盲区。
	version string
	// events 数据面回执队列：网关把「控制面指令已实际生效」的事实攒在这里，
	// 随下次心跳带给控制面落审计——否则「已下发」与「已生效」全系统不可区分。
	events eventQueue
	httpc  *http.Client
}

// SetTunnelFP 设置随注册上报的隧道证书指纹。证书在监听前就已备妥，故可在首次 Register 前调用。
func (c *Client) SetTunnelFP(fp string) { c.tunnelFP = fp }

// SetVersion 设置随注册心跳上报的网关版本号。
func (c *Client) SetVersion(v string) { c.version = v }

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
// 心跳还捎带 version（编译期注入的网关版本）与 events（数据面回执，发送成功即从队列清除；
// 失败留队随下次心跳重试）。旧控制面不认识这两个字段时按 JSON 语义直接忽略，不影响注册。
func (c *Client) Register(clients, tunnels int, uptimeSec int64, sessions []Session) error {
	evs, through := c.events.snapshot()
	body, _ := json.Marshal(map[string]any{
		"id": c.gwID, "proxy": c.proxy, "spa": c.spa,
		"clients": clients, "tunnels": tunnels, "uptime": uptimeSec, "sessions": sessions,
		"tunnelFp": c.tunnelFP, // 供控制面转发给客户端做隧道证书钉扎
		"version":  c.version,
		"events":   evs,
	})
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
		Resources []resourceDTO `json:"resources"`
		Revoked   []Revoked     `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, nil, err
	}
	out := make([]resource.Resource, 0, len(r.Resources))
	for _, d := range r.Resources {
		out = append(out, resource.Resource{ID: d.ID, Backend: d.Backend, AllowRoles: d.AllowRoles, AllowUsers: d.AllowUsers})
	}
	return out, r.Revoked, nil
}
