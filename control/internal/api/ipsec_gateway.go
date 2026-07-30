package api

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── IPSec VPN 组网 · 数据面侧（只挂 mTLS 监听）──
//
// 三个端点构成 baidi-ipsec 与控制面之间的全部往来：
//
//	GET  /api/v1/gateways/ipsec              拉本机负责的站点配置（15s 一次）
//	GET  /api/v1/gateways/ipsec/{id}/psk     版本变化时单取一次密钥
//	POST /api/v1/gateways/ipsec/status       回报实测运行态（15s 全量覆写）
//
// ★为什么不搭 /api/v1/gateways/policy 的车（勘察阶段曾建议搭车）：
// CN 前缀分权之后，ipsec-* 证书**不允许**调 policy——搭车就自相矛盾。
// 一张只负责站点组网的证书没有理由能读走全量资源授权策略。
//
// ★为什么 PSK 单独一个端点而不是塞进站点配置：站点配置每 15s 拉一次，
// 密钥跟着重传就是每 15s 让它在网络上出现一次。改成「策略里只带 pskVersion、
// 本地版本落后才单取」之后，一把密钥一生只传输它被修改的那几次。

// ipsecGatewaySiteDTO 下发给网关的站点配置——**最小披露**。
//
// 刻意不含的东西，每一项都有理由：
//   - PSK 原文与指纹：走单独端点，且指纹对网关没有任何用途；
//   - localRef/remoteRef：对象库 id 是管理侧概念，网关拿了也不会用；
//   - status/rxBytes/txBytes/lastUp：运行态的权威在网关自己手里，
//     控制面回灌只会制造「网关照着控制面的旧快照汇报自己」的循环。
type ipsecGatewaySiteDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	GatewayID string `json:"gatewayId"`
	Enabled   bool   `json:"enabled"`

	Peer         string `json:"peer"`
	LocalSubnet  string `json:"localSubnet"`
	RemoteSubnet string `json:"remoteSubnet"`
	LocalID      string `json:"localId"`
	RemoteID     string `json:"remoteId"`

	// IKEVersion 必须下发。网关的装载期校验里有一道「非 IKEv2 一律拒绝」的闸，
	// 而这道闸只能靠这个字段触发——不下发的话字段恒为空，闸**永远不会响**，
	// 管理员在控制台选了 IKEv1 会被当成 IKEv2 静默处理。
	// 那正是本项目反复吃过亏的形态：界面上配了 A、实际跑了 B、全程无报错。
	IKEVersion string `json:"ikeVersion"`

	Auth     string           `json:"auth"`
	Suite    string           `json:"suite"`
	Phase1   store.IpsecPhase `json:"phase1"`
	Phase2   store.IpsecPhase `json:"phase2"`
	PFS      bool             `json:"pfs"`
	PqHybrid bool             `json:"pqHybrid"`

	// PSKVersion 网关据此判断本地缓存的密钥是否过期。
	// 0 表示这条站点还没配过 PSK——网关应当直接把它置 failed 并回报
	// 「未配置 PSK」，而不是拿空密钥去协商：空 PSK 是能协商成功的，
	// 那才是真事故（两端都以为自己在做认证，实际上谁都没有）。
	PSKVersion int `json:"pskVersion"`

	// PeerNATPort 对端 UDP 封装口；0 = 按对称假设（生产两端都是 4500）。
	PeerNATPort int `json:"peerNatPort"`
}

func toGatewaySiteDTO(s store.IpsecSite) ipsecGatewaySiteDTO {
	return ipsecGatewaySiteDTO{
		ID: s.ID, Name: s.Name, GatewayID: s.GatewayID, Enabled: s.Enabled,
		Peer: s.Peer, LocalSubnet: s.LocalSubnet, RemoteSubnet: s.RemoteSubnet,
		LocalID: s.LocalID, RemoteID: s.RemoteID,
		IKEVersion: s.IkeVersion,
		Auth:       s.Auth, Suite: s.Suite, Phase1: s.Phase1, Phase2: s.Phase2,
		PFS: s.Pfs, PqHybrid: s.PqHybrid, PSKVersion: s.PSKVersion,
		PeerNATPort: s.PeerNATPort,
	}
}

// handleGatewayIpsecSites 下发本网关负责的站点清单（mTLS，CN 必须是 ipsec-*）。
//
// ★按 CN 精确过滤是最小披露的执行点：多网关部署时，成都的 IPSec 网关不该知道
// 上海站点的对端公网地址与内网网段——那是一张现成的横向移动地图。
// 与 handleGatewayPolicy 的 revoked「不下发 reason」是同一条推理。
func (s *Server) handleGatewayIpsecSites(w http.ResponseWriter, r *http.Request) {
	is, ok := s.ipsecStore(w)
	if !ok {
		return
	}
	cn := GatewayCN(r.Context())
	sites, err := is.IpsecSitesForGateway(r.Context(), cn)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load ipsec sites")
		return
	}
	out := make([]ipsecGatewaySiteDTO, 0, len(sites))
	for _, st := range sites {
		out = append(out, toGatewaySiteDTO(st))
	}
	// 即使一条都没有也返回空数组而不是 404：网关侧「拉到空列表」与「拉取失败」
	// 必须可区分——前者要拆掉本地所有 SA（管理员确实删光了），
	// 后者要 fail-closed 保留上次配置。混在一起会让一次控制面抖动拆掉全部隧道。
	httpx.JSON(w, http.StatusOK, map[string]any{"sites": out})
}

// handleGatewayIpsecPSK 单取一条站点的 PSK 原文（mTLS，CN 必须是 ipsec-* 且拥有该站点）。
//
// 这是 PSK 原文在整个系统里唯一的出口。三道闸叠着：
//  1. 路由只挂在 mTLS 监听上——明文 :8090 上根本没有这个路径；
//  2. CN 前缀必须是 ipsec-（见 MTLSHandler），且证书指纹在白名单内未吊销；
//  3. 站点的 gateway_id 必须精确等于本次请求的 CN。
//
// ★第 3 条不能省。少了它，任意一张有效的 IPSec 网关证书就能把全部站点的 PSK
// 逐条取走——前两道闸只证明「你是一台我们签过的 IPSec 网关」，不证明
// 「这条站点归你」。
func (s *Server) handleGatewayIpsecPSK(w http.ResponseWriter, r *http.Request) {
	is, ok := s.ipsecStore(w)
	if !ok {
		return
	}
	cn := GatewayCN(r.Context())
	id := r.PathValue("id")

	sites, err := is.IpsecSitesForGateway(r.Context(), cn)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load ipsec sites")
		return
	}
	var site store.IpsecSite
	owned := false
	for _, st := range sites {
		if st.ID == id {
			site, owned = st, true
			break
		}
	}
	if !owned {
		// 404 而不是 403：不告诉调用方「这条站点存在但不归你」——
		// 站点 id 本身就是拓扑情报，存在性也不该泄露给不相干的网关。
		slog.Warn("IPSec 网关索取非本机站点的 PSK", "cn", cn, "site", id)
		httpx.Error(w, http.StatusNotFound, "站点不存在或不归本网关承载")
		return
	}
	sec, found, err := is.IpsecSecret(r.Context(), id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load ipsec secret")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "站点 "+id+" 尚未配置 PSK")
		return
	}
	box, err := secret.Default()
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "PSK 主密钥不可用："+err.Error())
		return
	}
	// AAD = site_id：若这行密文是从别的站点剪贴过来的，这里会直接失败而不是下发一把错密钥。
	psk, err := box.Open(id, sec.Nonce, sec.Cipher)
	if err != nil {
		slog.Error("IPSec PSK 解密失败", "site", id, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "PSK 解密失败（密文行可能已损坏或主密钥被替换）")
		return
	}
	// 审计让密钥流动可追溯。★频率天然很低（只有版本变化时网关才来取），
	// 不会淹没审计日志；真出现高频下发本身就是值得注意的异常。
	s.auditAs(r, cn, "security",
		"向网关 "+cn+" 下发站点 "+id+" 的 PSK（v"+strconv.Itoa(site.PSKVersion)+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		// base64 而不是裸字符串：PSK 是**字节串**，可能含任意字节。
		// ★口径必须与网关侧一致——AUTH 里 prf(PSK, "Key Pad for IKEv2") 的 key
		// 就是解码后的这段原文，不做任何再编码。两端编码不一致的症状是
		// 一句无头无尾的「认证失败」，与另外五种根因完全无法区分。
		"psk": base64.StdEncoding.EncodeToString(psk),
		// 版本取自 ipsec_sites（权威），不是密文行里的副本——
		// 网关拿它更新本地版本，两处不一致会造成「永远认为自己是旧的」或反之。
		"version": site.PSKVersion,
	})
}

// handleGatewayIpsecStatus 接收网关回报的实测运行态（mTLS，CN 必须是 ipsec-*）。
//
// ★body 里的 gatewayId 一律被忽略，全部行强制写成本次请求的 CN（store 层再兜一次）。
// 不这么做的话，一台配错 id（或被攻陷）的网关能把别的网关的站点全写成 failed，
// 界面上看起来像对端集体故障——一个纯粹的伪造运行态通道。
//
// ★不属于本网关的站点会被丢弃并在响应里给出计数，而不是静默忽略：
// 网关端配了一条控制面已经删掉/改派的站点时，它需要知道自己在白报。
func (s *Server) handleGatewayIpsecStatus(w http.ResponseWriter, r *http.Request) {
	is, ok := s.ipsecStore(w)
	if !ok {
		return
	}
	cn := GatewayCN(r.Context())
	var b struct {
		States []store.IpsecSAState `json:"states"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	sites, err := is.IpsecSitesForGateway(r.Context(), cn)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load ipsec sites")
		return
	}
	owned := make(map[string]bool, len(sites))
	for _, st := range sites {
		owned[st.ID] = true
	}
	now := time.Now().Unix()
	accepted := make([]store.IpsecSAState, 0, len(b.States))
	rejected := make([]string, 0)
	for _, st := range b.States {
		if !owned[st.SiteID] {
			rejected = append(rejected, st.SiteID)
			continue
		}
		st.GatewayID = cn
		if st.ReportedAt == 0 {
			st.ReportedAt = now // 由控制面盖时间戳：界面上的「最近更新 3s 前」不该依赖网关时钟
		}
		st.State = normalizeIpsecState(st.State)
		accepted = append(accepted, st)
	}
	// 全量覆写：本网关不再回报的站点行随之消失。这正是「站点被删了、
	// 界面上那条 up 的残影还挂着」的解药。
	if err := is.ReplaceIpsecSAStates(r.Context(), cn, accepted); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save ipsec sa states")
		return
	}
	if len(rejected) > 0 {
		slog.Warn("IPSec 网关回报了不归它承载的站点", "cn", cn, "sites", rejected)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "accepted": len(accepted), "rejected": rejected,
	})
}

// normalizeIpsecState 把回报的状态收敛到五态之一，未知值一律折成 failed。
//
// ★不能原样落库。库里出现一个界面不认识的状态字符串时，前端的状态灯会静默
// 不渲染——看起来像「这一行没有状态」，实际是网关报了个我们没定义的值。
// 折成 failed 至少是个显眼的、会被追查的结果。
func normalizeIpsecState(s string) string {
	switch s {
	case "down", "connecting", "up", "rekeying", "failed":
		return s
	case "":
		return "connecting" // 网关没填 = 还没有结论，不是故障
	default:
		return "failed"
	}
}
