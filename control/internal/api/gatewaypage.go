package api

// 网关与隐身页（GET /api/v1/gateway）的聚合视图。
//
// ★为什么整段搬到 api 层：这一页原本读 store.Memory 的 GatewayBundle 种子——
// 「华东出口 / 华南出口」两个区域、四台带负载百分比的主备节点，一个字节都不是真的。
// 网关的权威事实压根不在库里，而在 Server.gateways：经 mTLS 客户端证书注册的心跳
// 登记（谁在线、敲门口/隧道口在哪、几条隧道、什么版本）。所以这里不是"给种子补一份
// SQLite 实现"，而是把出口接到既有的那份真实登记上，与 GET /api/v1/gateways、
// diag 的 checkGateways/checkStealth **同源**。
//
// ★「区域」这一维被整个去掉了，只列真实网关。理由：白帝没有任何地方知道一台网关
// 在哪个区域——apps.node 里那列区域名从来没有消费方；把区域做成网关自报字段的话，
// 它既不可验证（网关自己填什么就是什么），又不参与路由/策略/调度的任何判定，
// 那就是又一个 config-only 维度。主/备角色与负载百分比同理删除：没有选主、没有
// 负载采集，画一根 81% 的进度条只会让人以为白帝在做流量调度。
//
// 保留下来的每一项都能在心跳报文里指出出处，没有出处的（是否真的对外隐身、
// 敲门校验是否正常）如实缺席，由页面说明"控制面不从外部实测端口可见性"。

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// GatewayPageBundle 网关与隐身页。
type GatewayPageBundle struct {
	Nodes []GatewayNodeView `json:"nodes"`
	// Total / Online 注册总数与心跳新鲜的台数（判据 = OnlineWindowSec）。
	Total  int `json:"total"`
	Online int `json:"online"`
	// OnlineWindowSec 判定"在线"的心跳窗口秒数。下发给前端是为了让页面能说清
	// "在线"二字的判据，而不是让人猜一个阈值。
	OnlineWindowSec int `json:"onlineWindowSec"`
	// KnockTokenTTLSec 控制面签发的敲门令牌有效期（真实常量 knockTTL）。
	// 它是这一页唯一一个来自控制面自身的事实，其余全部来自网关上报。
	KnockTokenTTLSec int `json:"knockTokenTtlSec"`
	// Sessions 全部在线网关上报的活跃会话总数（与在线用户页同源：gwSess）。
	Sessions int `json:"sessions"`
}

// GatewayNodeView 一台已注册网关的页面投影。字段与注册心跳一一对应。
type GatewayNodeView struct {
	ID       string `json:"id"`       // 网关注册 id（= mTLS 证书 CN）
	Proxy    string `json:"proxy"`    // 隧道监听（网关自报）
	SPA      string `json:"spa"`      // SPA 敲门监听（网关自报）
	Online   bool   `json:"online"`   // 心跳新鲜
	LastSeen int64  `json:"lastSeen"` // 最后一次心跳（Unix 秒）
	Uptime   int64  `json:"uptime"`   // 网关自报运行秒数
	Clients  int    `json:"clients"`  // 放行窗口内已授权源数
	Tunnels  int    `json:"tunnels"`  // 活跃隧道连接数
	Sessions int    `json:"sessions"` // 该网关上报的活跃会话条数
	Version  string `json:"version"`  // 二进制版本；旧网关不上报则为空串（前端显示 —）
	// SkewSec 该网关时钟相对控制面的偏差（秒，正=网关快）；null = 未上报（旧网关），
	// 页面必须显示"未上报"而不是 0——语义见 GatewayInfo.SkewSec。
	SkewSec *int64 `json:"skewSec"`
	// LANHost / WANHost 管理员登记的对外接入地址（PRD FR-SCEN-08/17，wave8 行动 4）。
	//
	// ★这是**客户端真正会去拨的地址**，与上面 Proxy/SPA 那两个网关自报的**监听地址**
	// 是两回事：网关默认监听 ':18201'（不带 host），无从知道自己在 NAT / 负载均衡
	// 后面对外是什么地址。两栏都空时剖面只能拿自报地址或全局兜底去猜，
	// 而猜错的症状是「控制台显示在线、客户端拨号超时」——故页面要能填、也要标出没填。
	LANHost string `json:"lanHost"`
	WANHost string `json:"wanHost"`
	// AccessConfigured 是否登记过至少一栏。false 时页面要显著提示（见上）。
	AccessConfigured bool `json:"accessConfigured"`
}

// handleGateway 返回网关与隐身页的聚合视图。
//
// 权限：与 GET /api/v1/gateways 同档——网关落点（敲门口/隧道口）与在线会话数
// 属于攻击者最想要的那部分拓扑信息，只给 admin，且角色现算（requireAdmin 内部
// 走 AdminRoleFor，不信令牌里的 role 快照）。
func (s *Server) handleGateway(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	now := time.Now()
	window := int64(gatewayOnlineWindow / time.Second)

	out := GatewayPageBundle{
		Nodes:            []GatewayNodeView{},
		OnlineWindowSec:  int(window),
		KnockTokenTTLSec: int(knockTTL.Seconds()),
	}
	access := s.gatewayAccessMap()
	s.mu.Lock()
	for id, g := range s.gateways {
		a := access[id]
		n := GatewayNodeView{
			LANHost: a.LANHost, WANHost: a.WANHost, AccessConfigured: a.Configured(),
			ID: id, Proxy: g.Proxy, SPA: g.SPA, LastSeen: g.LastSeen, Uptime: g.Uptime,
			Clients: g.Clients, Tunnels: g.Tunnels, Sessions: len(s.gwSess[id]), Version: g.Version,
			SkewSec: g.SkewSec,
		}
		n.Online = gatewayFresh(g.LastSeen, now)
		if n.Online {
			out.Online++
			// ★会话总数只统计在线网关：心跳超时的网关那份 sessions 是过期快照，
			// 计进来会让"在线用户"这个读数在网关掉线后仍然虚高。口径与
			// handleOnline 一致（那里同样跳过超窗网关）。
			out.Sessions += n.Sessions
		}
		out.Total++
		out.Nodes = append(out.Nodes, n)
	}
	s.mu.Unlock()
	// 确定性排序（在线优先、其次 id 字典序）：map 遍历顺序随机，
	// 每次刷新节点跳位会让人以为拓扑真的在变。
	sort.Slice(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Online != out.Nodes[j].Online {
			return out.Nodes[i].Online
		}
		return out.Nodes[i].ID < out.Nodes[j].ID
	})
	httpx.JSON(w, http.StatusOK, out)
}

// handleSetGatewayAccess 登记一台网关的对外接入地址（PermSystem，PRD FR-SCEN-08/17）。
//
// body {lanHost, wanHost}，两栏都可留空（都空 = 撤销登记）。
// 权限归 PermSystem 而不是 PermSecurity：接入地址是网络部署配置，与网关证书、
// 组网同属系统管理员职责；而且改错它等于让全体终端连不上，不该由第二个人能动。
func (s *Server) handleSetGatewayAccess(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	if s.gwAccess == nil {
		httpx.Error(w, http.StatusServiceUnavailable,
			"当前后端不支持登记网关接入地址（需要 SQLite 存储；纯内存演示栈无此能力）")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		httpx.Error(w, http.StatusBadRequest, "网关 id 不能为空")
		return
	}
	// ★必须是**已注册**的网关：给一个不存在的 id 登记地址，页面上什么也不会出现
	// （网关页只列注册过的），而管理员会以为自己配好了。这与 NAT 策略要求接口
	// 必须是实测枚举过的是同一条纪律。
	s.mu.Lock()
	_, known := s.gateways[id]
	s.mu.Unlock()
	if !known {
		httpx.Error(w, http.StatusNotFound,
			"网关「"+id+"」尚未注册到控制面（id 必须与网关 mTLS 证书 CN 逐字符一致）")
		return
	}
	var b struct {
		LANHost string `json:"lanHost"`
		WANHost string `json:"wanHost"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid payload")
		return
	}
	saved, err := s.gwAccess.SetGatewayAccess(r.Context(),
		store.GatewayAccess{GatewayID: id, LANHost: b.LANHost, WANHost: b.WANHost})
	if err != nil {
		if errors.Is(err, store.ErrBadAccessHost) {
			httpx.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.Error(w, http.StatusInternalServerError, "failed to save gateway access")
		return
	}
	// 审计：这条配置直接决定全体终端往哪拨号，改动必须留痕。
	desc := "撤销登记"
	if saved.Configured() {
		desc = "内网=" + orDefault(saved.LANHost, "—") + " 互联网=" + orDefault(saved.WANHost, "—")
	}
	s.audit(r, "policy", "设置网关「"+id+"」的对外接入地址："+desc, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "access": saved})
}
