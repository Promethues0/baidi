package cplane

// 本文件是 baidi-ipsec（站点组网守护进程）与控制面之间的**全部**往来，共三个端点：
//
//	GET  /api/v1/gateways/ipsec              拉本机负责的站点配置（15s 一轮）
//	GET  /api/v1/gateways/ipsec/{id}/psk     仅在 pskVersion 变化时单取一次密钥
//	POST /api/v1/gateways/ipsec/status       回报实测运行态（控制面全量覆写）
//
// 沿用 cplane.go 的既有姿态，三条都不打折：
//
//  1. **身份全在 mTLS 传输层**，请求不带任何 Bearer——网关在代码层就没有签发能力
//     （阶段 4 删除了 auth.Sign）。控制面按客户端证书 CN 认人，且 CN 必须以 `ipsec-`
//     开头才够得着这三个端点（见 control/internal/api/mtls.go 的 ipsecCNOnly）。
//  2. **PSK 不搭策略的车**。站点配置每 15s 拉一轮，密钥若跟着重传，就是每 15s 让它
//     在网络上出现一次；改成「策略只带版本号、本地落后才单取」之后，一把密钥一生
//     只传输它被修改的那几次。版本比对的逻辑在 cmd/baidi-ipsec/sync.go。
//  3. **新字段向后兼容**：DTO 里多出来的字段解码时被忽略，缺少的字段取零值。
//     ★零值必须是安全的那一侧——例如 IKEVersion 为空表示「控制面没下发」，
//     ipsec.ValidateWith 会跳过该项检查，而不是把空串当成「不是 IKEv2」拒掉。
//
// ★这里刻意**不**提供 Register：控制面的 accessCNet 明确拒绝 ipsec-* 证书调用
// /api/v1/gateways/register（一张只负责站点组网的证书不该出现在接入网关名册里）。
// 调它只会拿到 403，别为了"让它出现在监控中心"而绕。

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"baidi.dev/gateway/internal/ipsec"
)

// ErrIpsecPSKUnavailable 控制面明确表示「取不到这条站点的 PSK」（HTTP 404）。
//
// 两种情形共用它，因为控制面刻意不区分（站点存在性本身就是拓扑情报，
// 见 handleGatewayIpsecPSK 里回 404 而不是 403 的理由）：
//   - 该站点尚未配置 PSK；
//   - 该站点不归本网关承载（gateway_id 与本次证书 CN 不符）。
//
// ★调用方必须把它与「网络抖动取不到」区分开：前者重试一万次也没用，
// 该把站点置 failed 并把原因摆到控制台上；后者只需沿用本地缓存的密钥继续跑。
var ErrIpsecPSKUnavailable = errors.New("cplane: 控制面未下发该站点的 PSK（未配置，或该站点已不归本网关承载）")

// IpsecPhaseDTO 一相加密套件。三个字段是控制台的自由字符串，
// 网关侧由 ike.SpecFromPhase 映射成 Transform 码点，映射不出来就装载期拒绝。
type IpsecPhaseDTO struct {
	Enc  string `json:"enc"`
	Hash string `json:"hash"`
	DH   string `json:"dh"`
}

// IpsecSiteDTO 控制面下发的一条站点配置，字段与 control 的 ipsecGatewaySiteDTO 逐一对应。
//
// ★它不是 ipsec.SiteConfig，也不该被直接当成配置用：这里全是**字符串**，
// 地址/网段的解析、PSK 的填充、缺省值的补齐都在 cmd/baidi-ipsec/sync.go 完成。
// 分开的理由是解析失败必须变成"那一条站点 failed + 中文原因"，而不是
// 让一条写错网段的记录把整批同步搞砸（控制面数据错一条，其余站点不该跟着断）。
type IpsecSiteDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	GatewayID string `json:"gatewayId"`
	Enabled   bool   `json:"enabled"`

	Peer         string `json:"peer"`         // 对端 IKE 落点，端口可省（缺省 500）
	LocalSubnet  string `json:"localSubnet"`  // TSi
	RemoteSubnet string `json:"remoteSubnet"` // TSr
	LocalID      string `json:"localId"`      // IDi，须 FQDN 形态
	RemoteID     string `json:"remoteId"`     // IDr

	Auth   string        `json:"auth"`  // 本轮只支持 psk
	Suite  string        `json:"suite"` // standard | gm
	Phase1 IpsecPhaseDTO `json:"phase1"`
	Phase2 IpsecPhaseDTO `json:"phase2"`
	PFS    bool          `json:"pfs"`

	// PqHybrid / IKEVersion 是**本实现没有对应能力**的两个开关，
	// 收下来是为了当面拒绝而不是静默忽略（见 ipsec.ExtraOptions 的说明）：
	// 管理员在界面上打开了 PQ 混合、选了 IKEv1，网关若照常按 IKEv2 无 PQ 跑起来
	// 并显示 up，界面与实际就彻底脱节且一行报错都没有。
	//
	// ★IKEVersion 当前的控制面并不下发（gatewayIpsecSite 无此字段），
	// 解码后是空串，ValidateWith 据此跳过检查——这正是"新字段向后兼容"要的语义：
	// 缺字段 = 没意见，而不是"选了别的版本"。将来控制面补上即自动生效。
	PqHybrid   bool   `json:"pqHybrid"`
	IKEVersion string `json:"ikeVersion"`

	// PeerNATPort 对端 UDP 封装口；0 = 按对称假设取本端 -natt-port（生产两端都是 4500）。
	PeerNATPort int `json:"peerNatPort"`

	// PSKVersion 网关据此判断本地缓存的密钥是否过期。
	// 0 表示这条站点还没配过 PSK——此时**不要**拿空密钥去协商：空 PSK 两端一样能
	// 协商成功、界面一样显示 up，但认证强度为零。
	PSKVersion int `json:"pskVersion"`
}

// 响应体读取上限。控制面是本系统的信任根，这里限长不是防它作恶，
// 而是防一次配置事故（比如反代把一个 HTML 错误页贴过来）把网关的内存吃干净。
const (
	maxIpsecSitesBody  = 4 << 20 // 站点清单：几百条站点也远用不到 4MB
	maxIpsecPSKBody    = 64 << 10
	maxIpsecStatusBody = 256 << 10
)

// IpsecSites 拉本网关负责的站点配置。
//
// ★「拉到空列表」与「拉取失败」必须可区分，这是 fail-closed 的前提：
// 前者是管理员真的把站点删光了，要把本地 SA 全拆掉；后者是控制面抖动，
// 必须保留上一轮配置继续跑。所以成功时返回**非 nil 的空切片 + nil error**，
// 失败时返回 nil + error，调用方一律用 err 判断，别去看长度。
func (c *Client) IpsecSites() ([]IpsecSiteDTO, error) {
	resp, err := c.do(http.MethodGet, "/api/v1/gateways/ipsec", nil)
	if err != nil {
		return nil, fmt.Errorf("拉取 IPSec 站点配置失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取 IPSec 站点配置返回 %d：%s", resp.StatusCode, snippet(resp.Body))
	}
	var r struct {
		Sites []IpsecSiteDTO `json:"sites"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIpsecSitesBody)).Decode(&r); err != nil {
		return nil, fmt.Errorf("解析 IPSec 站点配置失败：%w", err)
	}
	if r.Sites == nil {
		r.Sites = []IpsecSiteDTO{}
	}
	return r.Sites, nil
}

// IpsecPSK 单取一条站点的 PSK 原文，返回密钥字节与控制面权威的版本号。
//
// ★返回的 version 取自 ipsec_sites（权威），可能与站点清单里那个不一致
// （两次请求之间管理员刚好改了密钥）。调用方应当以**这里返回的版本**记进缓存，
// 否则会陷入"永远认为自己是旧的"或反之——前者每轮重取密钥，后者永远用不上新密钥。
//
// 口径：控制面用 base64 传输，解码后的**原文字节**就是 AUTH 里
// prf(PSK, "Key Pad for IKEv2") 的 key，不做任何再编码。两端编码不一致的症状是
// 一句无头无尾的「认证失败」，与另外五种根因完全无法区分。
func (c *Client) IpsecPSK(siteID string) ([]byte, int, error) {
	if strings.TrimSpace(siteID) == "" {
		return nil, 0, errors.New("cplane: 取 PSK 时站点 id 为空")
	}
	// 站点 id 来自控制面，理论上干净；仍然转义——路径注入的代价是"取到别的站点的密钥"。
	path := "/api/v1/gateways/ipsec/" + url.PathEscape(siteID) + "/psk"
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("取站点 %s 的 PSK 失败：%w", siteID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, 0, fmt.Errorf("站点 %s：%w", siteID, ErrIpsecPSKUnavailable)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("取站点 %s 的 PSK 返回 %d：%s", siteID, resp.StatusCode, snippet(resp.Body))
	}
	var r struct {
		PSK     string `json:"psk"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIpsecPSKBody)).Decode(&r); err != nil {
		return nil, 0, fmt.Errorf("解析站点 %s 的 PSK 响应失败：%w", siteID, err)
	}
	psk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.PSK))
	if err != nil {
		return nil, 0, fmt.Errorf("站点 %s 的 PSK 不是合法 base64：%w（两端编码口径必须一致，"+
			"否则只会得到一句无头无尾的「认证失败」）", siteID, err)
	}
	// ★空 PSK 在这里就拦掉，不让它有机会走到状态机。
	// 空密钥两端一样能把 AUTH 算通、隧道一样建得起来、界面一样显示 up，
	// 只是这条隧道的认证强度为零——「配错了连不上」是小事故，「配错了连上了」才是真事故。
	if len(psk) == 0 {
		return nil, 0, fmt.Errorf("站点 %s 的 PSK 解码后为空：%w", siteID, ErrIpsecPSKUnavailable)
	}
	return psk, r.Version, nil
}

// ReportIpsecStatus 回报实测运行态，返回控制面**拒收**的站点 id。
//
// 拒收即「本网关报了一条不归它承载的站点」，控制面会丢弃这些行。把它返回而不是
// 咽下去，是因为这正是"网关端还留着一条控制面已删除/已改派的站点"的唯一信号——
// 静默丢弃的话，网关会一直白报，而管理员在界面上只会看到那条站点凭空消失。
//
// ★body 里的 gatewayId 会被控制面无条件改写成本次证书的 CN，这里照常填是为了
// 本地日志可读，不承担任何身份作用（能伪造运行态的通道必须只有一条：证书）。
func (c *Client) ReportIpsecStatus(states []ipsec.SiteState) ([]string, error) {
	if states == nil {
		// 全量覆写语义下 nil 与空列表等价（"本网关名下一条都没有"），
		// 但 JSON 里 null 与 [] 对某些解码器不等价，统一成 []。
		states = []ipsec.SiteState{}
	}
	body, err := json.Marshal(map[string]any{"states": states})
	if err != nil {
		return nil, fmt.Errorf("序列化 IPSec 运行态失败：%w", err)
	}
	resp, err := c.do(http.MethodPost, "/api/v1/gateways/ipsec/status", body)
	if err != nil {
		return nil, fmt.Errorf("回报 IPSec 运行态失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("回报 IPSec 运行态返回 %d：%s", resp.StatusCode, snippet(resp.Body))
	}
	var r struct {
		Rejected []string `json:"rejected"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIpsecStatusBody)).Decode(&r); err != nil {
		// 状态已经写进去了（控制面先落库再回响应），解析响应失败不该被当成回报失败——
		// 当成失败会让调用方重试，而重试一次全量覆写没有任何坏处也没有任何收益，
		// 只是把一条无害的解析问题放大成"回报通道坏了"。
		return nil, nil
	}
	return r.Rejected, nil
}

// snippet 取响应体开头的一小段用于错误信息。
//
// ★控制面的拒绝理由几乎都写在 body 里且写得很具体（例如 ipsecCNOnly 会告诉你
// 「本次 CN 是什么、期望前缀是什么」）。只报一个状态码等于把最有用的那句话扔了，
// 而 IPSec 的部署失败原因高度集中在"CN 前缀写错了"这一条上。
func snippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "（响应体为空）"
	}
	return strings.Join(strings.Fields(s), " ")
}
