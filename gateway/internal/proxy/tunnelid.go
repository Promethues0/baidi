package proxy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"baidi.dev/gateway/internal/auth"
)

// ── L4 隧道连接的自带身份（wave11 行动 3，PRD FR-INTRO-06 / FR-ARCH-02 / FR-AUDIT-05）──
//
// 被修的坏形态：隧道上**没有任何身份材料**。TLS/TLCP 两条监听都不设 ClientAuth，
// 前导只有 "CONNECT <资源id>"，敲门令牌只走 UDP 口。于是 proxy.handle 只能拿
// spa.Allowlist 按源 IP 反查身份，而那张表以源 IP 为唯一键、后敲门者整条覆盖 user。
// 门槛因此不是"持有白帝账号"而是"**共享源 IP**"：企业 NAT / CGNAT / 咖啡厅 / 酒店 /
// 同公网 IP 的云主机上，只要有人处在 30s 放行窗内，同出口任意主机直连隧道口即
// 继承其全部 AllowUsers、JIT 授予与风险降权结论，审计里还记着那个无辜者的账号。
//
// 修法照抄 B/S 那条已经验证过的链（控制面签票 → 数据面只持公钥验票），不发明新机制：
//
//	控制面  /knock-token 跑完五道闸之后，同一次调用附发 use=tunnel 短时效票据
//	客户端  挂在前导上："CONNECT <资源id> <票据>\n"
//	网关    -jwt-tunnel-pubkey 只装 tunnel 那把公钥 → 验签取身份
//	放行表  退回纯端口闸（Allowed(ip) 只回 ok），另加一道 AllowedFor(ip, 账号) 复核

// TunnelID 隧道身份的校验材料与姿态。零值（Verifier=nil, Strict=false）= 逃生舱姿态。
type TunnelID struct {
	// Verifier 只装 control 的 tunnel 公钥（<BAIDI_JWT_TUNNEL_KEY>.pub）。
	// nil 表示没有验票材料——严格模式下网关会拒绝启动，不会静默退回按源 IP 定身份。
	Verifier *auth.Verifier
	// Strict 默认 true。false 是逃生舱 BAIDI_GW_TUNNEL_ID_STRICT=0：允许不带票据的
	// 老客户端接入，身份退回按源 IP 猜。**每一条回落都留痕**（见 handle 的回落分支），
	// 否则这个开关会永久开着，而文档写着"已修"。
	Strict bool
	// MaxTTL 票据寿命上界（纵深；须 ≥ 控制面的 tunnelTicketTTL）。
	MaxTTL time.Duration
}

// maxTunnelTicketTTLCeiling 票据寿命的硬上界，用于兜住"上界没配/配成 0"。
// 与 webproxy 的 maxTicketTTLCeiling 同款：一个没有上界的纵深不是纵深。
const maxTunnelTicketTTLCeiling = 30 * time.Minute

// verifyTunnelTicket 验签 + 语义校验，返回票据自证的 (账号, 角色)。
func (id TunnelID) verifyTunnelTicket(raw string) (account, role string, err error) {
	if strings.TrimSpace(raw) == "" {
		return "", "", errors.New("缺少隧道身份票据")
	}
	if id.Verifier == nil {
		// 装配错误而不是客户端错误，文案要能直接指向修法。
		return "", "", errors.New("本网关未配置隧道票据公钥（-jwt-tunnel-pubkey），无法校验身份")
	}
	c, verr := id.Verifier.Verify(raw)
	if verr != nil {
		return "", "", fmt.Errorf("票据无效: %w", verr)
	}
	if cerr := checkTunnelTicket(c, id.MaxTTL); cerr != nil {
		return "", "", cerr
	}
	return c.Name, c.Role, nil
}

// checkTunnelTicket 票据语义校验（纯函数，便于无网络单测）。
func checkTunnelTicket(c auth.Claims, maxTTL time.Duration) error {
	if c.Use != auth.UseTunnel {
		return fmt.Errorf("非隧道身份票据（use=%q，需 %q）", c.Use, auth.UseTunnel)
	}
	// ★这张票**刻意不做一次性**（不校验 jti、不做去重缓存），与敲门令牌和 Web 票据
	// 在这一点上分道。理由不是"省事"，写下来是为了挡住下一个"照抄 web 票据"的人：
	//
	//	一次性意味着每条业务 TCP 流都要换一张新票，也就是每条流都要打一次控制面。
	//	隧道是**逐流**建连的（一个 IDE 拉一次 git 就是几十条），控制面从此进入每条
	//	业务连接的数据路径；再叠加严格敲门那条 fail-closed 纪律（控制面不可达超过
	//	30s 窗口自然关闭），控制面一抖动就不是"下一轮重试"而是**当场断流**。
	//	而一次性在这里换来的安全增量很小：票据只在客户端 ↔ 网关的 TLS/TLCP 隧道内
	//	出现（不像敲门令牌那样以 UDP 明文包沿链路广播到全部落点），能读到它的人
	//	已经在解密隧道内容了。真正的时效闸是那 30s 放行窗口 + AllowedFor 复核。
	//
	// 同理**不校验 Gw**：控制面不知道这张票会被拿去拨哪台落点（客户端每轮敲全部落点、
	// 拨得通哪台算哪台），绑定只会让故障转移在切换那一刻被自己挡住。web 票据能绑 gw
	// 是因为那条路的一次性去重需要网关维度，这条路没有一次性，也就没有那个前提。
	if maxTTL <= 0 || maxTTL > maxTunnelTicketTTLCeiling {
		maxTTL = maxTunnelTicketTTLCeiling
	}
	if c.Iat == 0 || time.Duration(c.Exp-c.Iat)*time.Second > maxTTL {
		return fmt.Errorf("票据寿命超上界（%ds > %s）", c.Exp-c.Iat, maxTTL)
	}
	// 与 control 的 requireUser、spa.checkKnock、webproxy.checkTicket 同一份角色白名单：
	// 网关机器身份（role=gateway）与 MFA 半程票据都不得成为一条隧道连接的身份。
	if c.Role != "admin" && c.Role != "user" {
		return fmt.Errorf("角色 %q 不得作为隧道身份", c.Role)
	}
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("票据缺账号（无法做资源鉴权）")
	}
	return nil
}
