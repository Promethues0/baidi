package dataplane

// 客户端侧的网关落点故障转移（PRD FR-ARCH-03/04）。
//
// 在此之前数据面只认一个落点（Config.SpaAddr / ProxyAddr / TunnelPin 三件套）：
// 那台网关挂掉，这台终端就断，哪怕控制面明明还有别的网关在线。现在控制面经接入剖面
// 下发**有序的落点清单**（见 control 的 profileGateways），数据面按序尝试、失败切下一个。
//
// 三条纪律：
//
//	① **顺序由控制面定，数据面不重排**。终端没有任何做调度决策的材料（不知道谁负载低、
//	   不知道谁离自己近），自作主张排序就是拿一个假信号覆盖控制面算好的结论。
//	② **指纹逐落点**。每台网关的隧道证书都是自己启动期自签的，共用一份指纹会让
//	   故障转移在钉扎那一步必然失败，症状是「切过去就连不上」——极易被误判成
//	   第二台网关也坏了，把一次成功的容灾排查成一次双机故障。
//	③ **切换必须留痕**。当前用的是第几落点、为什么切，都要打进日志——桌面客户端的
//	   接入页正是从这些日志行里解析出接入态的。静默切换的后果是用户说"我明明连着
//	   但很慢"，而现场没有任何线索指向"你现在走的是异地那台备用网关"。

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// Endpoint 一个网关落点。字段与控制面剖面的 ProfileGateway 一一对应（除 online——
// 那是控制面视角的心跳新鲜度，只用来决定**顺序**，不该被终端拿去做"要不要试"的判断：
// 控制面看不到心跳与终端连不上它，是两个独立的事实，后者才是这里唯一关心的）。
type Endpoint struct {
	ID        string // 网关注册 id（= mTLS 证书 CN）；无 id 的回退落点为空串
	SPAAddr   string // SPA 敲门 host:port
	ProxyAddr string // 隧道代理 host:port
	Pin       string // 该网关隧道证书的 SHA-256 指纹（hex）；空 = 不钉扎（降级，会打 WARN）
}

// Label 人话标识，供日志与 UI 引用。
func (e Endpoint) Label() string {
	if e.ID == "" {
		return e.ProxyAddr
	}
	return e.ID
}

// endpoints 规整出本次运行要用的落点清单。
//
// 单落点三件套（SpaAddr/ProxyAddr/TunnelPin）是**旧调用方的兼容入口**：移动端绑定与
// 手工起的 baidi-tun 都还在用它，去掉的话它们会拿到一个空清单然后一条流都拨不出去。
func (c *Config) endpoints() []Endpoint {
	if len(c.Endpoints) > 0 {
		return c.Endpoints
	}
	return []Endpoint{{SPAAddr: c.SpaAddr, ProxyAddr: c.ProxyAddr, Pin: c.TunnelPin}}
}

// picker 落点选择器：记住"当前在用哪一个"以及"为什么是它"。
//
// 为什么要有状态：一次拨号失败之后，后续每条新流都应当直接去新落点，而不是每次都
// 先撞一遍那台已经死掉的网关（5s 拨号超时 × 每条流 = 用户眼里的"接入后什么都打不开"）。
type picker struct {
	mu     sync.Mutex
	eps    []Endpoint
	cur    int
	reason string // 当前落点的选用原因（首选 / 因何切换而来）
}

func newPicker(eps []Endpoint) *picker {
	return &picker{eps: eps, reason: "控制面剖面首选落点"}
}

// current 返回当前落点及其下标。
func (p *picker) current() (int, Endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cur, p.eps[p.cur]
}

// all 返回落点清单（只读快照；清单在进程生命周期内不变）。
func (p *picker) all() []Endpoint { return p.eps }

// promote 把第 i 个落点设为当前，并记下切换原因。已经是当前落点时返回 false。
func (p *picker) promote(i int, reason string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i == p.cur {
		return false
	}
	p.cur, p.reason = i, reason
	return true
}

// status 供日志/状态展示：第几个（1 起）、共几个、落点标识、隧道地址、选用原因。
func (p *picker) status() (idx, total int, label, addr, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.eps[p.cur]
	return p.cur + 1, len(p.eps), e.Label(), e.ProxyAddr, p.reason
}

// logCurrent 打一条**结构固定**的落点状态行。
//
// ★格式是与桌面客户端的契约：clients/desktop/src/lib/tunnel.ts 按
// `endpoint=<i>/<n>`、`id=`、`addr=`、`reason=` 四个键解析出「当前用的是第几落点、
// 为什么切」并显示在接入页。改键名要同步改那边的正则，否则接入页会静默退回
// "第 1 个落点"——而那正是切换之后最不该显示的信息（地址显示成已挂掉的那台、
// 指纹退回首选那台的，于是**未钉扎的运行中隧道被显示成已钉扎**）。
//
// 这条契约有守卫，光靠纪律拴不住：TestLogCurrent_KeysAreDesktopContract 把本函数的
// 真实输出落进 testdata/endpoint_log.txt，桌面侧 tunnel.test.ts 读**同一份文件**喂
// parseEndpoint。改了输出形制就把新的一行写回样本，并跑一遍
// `cd clients/desktop && npm test`——只更新样本而不改那边的正则，桌面侧当场红。
func (p *picker) logCurrent(msg string, warn bool) {
	idx, total, label, addr, reason := p.status()
	args := []any{
		"endpoint", fmt.Sprintf("%d/%d", idx, total),
		"id", label,
		"addr", addr,
		"reason", reason,
	}
	if warn {
		slog.Warn(msg, args...)
		return
	}
	slog.Info(msg, args...)
}

// validateEndpoints 装载期校验：一个填错的落点不该等到用户点开应用才暴露。
func validateEndpoints(eps []Endpoint) error {
	if len(eps) == 0 {
		return fmt.Errorf("网关落点清单为空：没有落点就没有隧道可拨（接得上但什么也访问不了）")
	}
	for i, e := range eps {
		if strings.TrimSpace(e.ProxyAddr) == "" {
			return fmt.Errorf("第 %d 个网关落点（%s）缺隧道地址", i+1, e.Label())
		}
		if strings.TrimSpace(e.SPAAddr) == "" {
			// 敲不了门就永远拨不通（网关对未敲门者隐身），这类落点留着只会
			// 让故障转移在它身上白白耗一轮拨号超时。
			return fmt.Errorf("第 %d 个网关落点（%s）缺 SPA 敲门地址：敲不了门就永远拨不通", i+1, e.Label())
		}
	}
	return nil
}
