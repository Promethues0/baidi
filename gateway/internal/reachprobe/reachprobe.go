// Package reachprobe 网关→后端可达性拨测（wave7 行动 9：FR-SCEN-26）。
//
// 直接对症本项目历史上最迷惑的失败形态：「一切显示正常、点开应用才炸」——
// 资源发布了、隧道建起来了、授权也过了，唯独 backend 那台机器根本不通，
// 而这件事在用户点开之前没有任何一处能看见。拨测把它提前到部署/诊断期。
//
// ★拨测必须在网关做：控制面未必可达业务网段（典型部署里它只在管理网），
// 由它拨测会把"控制面到后端不通"误报成"后端不可达"。
//
// 姿态纪律：
//   - 低频 + 抖动：默认 60s 一轮 ±20%，逐资源串行、间隔 100ms——拨测是观测，
//     不该让几十个资源的并发 SYN 在内网监控上画出一台"扫描器"。
//   - TCP connect 即判：连上就 OK（顺手记耗时），拒绝/超时都算不可达并带原因。
//     不发任何应用层字节——探测不该在后端日志里留下半截协议噪声。
//   - 三态：新增资源在下一轮之前没有结果（缺席=未探测，绝不是"不可达"）；
//     已删除资源的结果随该轮消失。上报侧同款：旧网关连 reach 字段都不发。
package reachprobe

import (
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

// Result 一条资源的最近一次拨测结果。
type Result struct {
	ID string `json:"id"`
	OK bool   `json:"ok"`
	// MS 拨号耗时（毫秒，成功时有意义）。
	MS int `json:"ms"`
	// Err 失败原因（精简的一句，成功时为空）。
	Err string `json:"err,omitempty"`
	// TS 本次拨测时刻（Unix 秒）。控制面按它判新鲜度。
	TS int64 `json:"ts"`
}

// resourceView 拨测需要的最小资源投影。
type resourceView struct{ ID, Backend string }

// Prober 周期拨测器。
type Prober struct {
	list    func() []resourceView
	dial    func(addr string, timeout time.Duration) error // 可注入（测试）
	timeout time.Duration
	gap     time.Duration // 逐资源间隔

	mu   sync.Mutex
	last map[string]Result
}

// New 构造拨测器。listFn 通常包装 resource.Registry.List。
func New(listFn func() (ids, backends []string)) *Prober {
	p := &Prober{
		timeout: 3 * time.Second,
		gap:     100 * time.Millisecond,
		last:    map[string]Result{},
	}
	p.list = func() []resourceView {
		ids, backends := listFn()
		out := make([]resourceView, 0, len(ids))
		for i := range ids {
			if i < len(backends) && ids[i] != "" && backends[i] != "" {
				out = append(out, resourceView{ID: ids[i], Backend: backends[i]})
			}
		}
		return out
	}
	p.dial = func(addr string, timeout time.Duration) error {
		c, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return err
		}
		return c.Close()
	}
	return p
}

// RunOnce 跑一轮拨测并替换整份结果（已删除的资源自然消失，不留陈旧行）。
func (p *Prober) RunOnce() {
	views := p.list()
	fresh := make(map[string]Result, len(views))
	for i, v := range views {
		if i > 0 {
			time.Sleep(p.gap)
		}
		start := time.Now()
		err := p.dial(v.Backend, p.timeout)
		r := Result{ID: v.ID, TS: time.Now().Unix()}
		if err != nil {
			r.Err = trimErr(err.Error())
		} else {
			r.OK = true
			r.MS = int(time.Since(start).Milliseconds())
		}
		fresh[v.ID] = r
	}
	p.mu.Lock()
	p.last = fresh
	p.mu.Unlock()
}

// Snapshot 最近一轮的结果（按 id 排序，上报稳定）。
func (p *Prober) Snapshot() []Result {
	p.mu.Lock()
	out := make([]Result, 0, len(p.last))
	for _, r := range p.last {
		out = append(out, r)
	}
	p.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Start 启动周期拨测（进程生命期运行）。首轮立即跑：部署完第一次打开
// 诊断页就该有答案，而不是等一分钟。
func (p *Prober) Start(interval time.Duration) {
	go func() {
		p.RunOnce()
		for {
			// ±20% 抖动：多台网关同配置部署时不齐步拨测同一批后端。
			jitter := time.Duration(rand.Int63n(int64(interval) / 5 * 2)) // #nosec G404 观测抖动无需密码学随机
			time.Sleep(interval - interval/5 + jitter)
			p.RunOnce()
		}
	}()
}

// trimErr 把 net 错误里冗长的 "dial tcp 1.2.3.4:80: " 前缀截掉，留人能读的那半句。
func trimErr(s string) string {
	if i := lastColonSpace(s); i > 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

func lastColonSpace(s string) int {
	for i := len(s) - 2; i >= 0; i-- {
		if s[i] == ':' && s[i+1] == ' ' {
			return i
		}
	}
	return -1
}
