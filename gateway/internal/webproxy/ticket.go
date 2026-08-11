// Package webproxy 是网关的**七层 Web 代理**（PRD 8.3.3 / FR-INTRO-09/12，B/S 免客户端接入）。
//
// 在此之前网关只有 L4 CONNECT 隧道：浏览器用户能登录门户、能看到应用磁贴，却无法
// 通过浏览器访问任何被保护业务——门户 openApp() 整个函数体就是一句 toast。
// 这是"页面存在≠功能存在"最典型的一例，也是产品对外宣称的两大接入形态之一。
//
// ── 浏览器怎么证明自己是谁 ──
//
// 浏览器做不了 SPA 敲门（那是带签名令牌的 UDP 包），所以这条路径另起一条入场流程，
// 但**纪律与敲门完全一致：签发权在控制面，数据面只验**。
//
//	门户登录（控制面）→ 用户点 Web 应用 → 控制面按资源鉴权后签发一张
//	**短时效一次性**票据（use=web + jti + res + ≤60s）→ 浏览器带票据跳到网关
//	/__baidi/enter → 网关用**控制面公钥**验票 → 换成网关本地会话 Cookie → 反代。
//
// ★网关没有、也不会有签发能力。Cookie 用网关启动期随机生成的本地 HMAC 密钥签，
// 那是**本机会话状态**（"这个浏览器刚才出示过一张有效票"），不是身份签发：
// 它出不了这台网关、换不到任何控制面凭据、也不能自证账号——控制面从不验它。
// gateway/internal/auth 至今没有 Sign 函数，这里也一个字节都不往那边加。
//
// ── 为什么每个请求都要重新鉴权 ──
//
// Cookie 只回答"这个浏览器是谁"，不回答"此刻他还能不能访问这个资源"。
// 后者每个请求都重查 resource.Registry（含控制面算好的 DenyUsers 否决名单），
// 于是强制下线 / 风险降权 / JIT 到期在**一个策略轮询周期内**自然生效，
// 而不必等 Cookie 过期。只在建会话时判一次的话，一张 15 分钟的 Cookie
// 就是一段谁也撤不掉的访问权。
package webproxy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"baidi.dev/gateway/internal/auth"
)

// maxTicketTTLCeiling 票据寿命的硬上界（纵深防御）：控制面签的是 60s，
// 这里再兜一道，免得控制面某天把 TTL 改大而数据面毫无感知。
const maxTicketTTLCeiling = 5 * time.Minute

// VerifyTicket 校验一张 L7 访问票据（签名已由 v 完成，这里只判语义）。
//
// ★用途闸方向与 spa.checkKnock 相反且必须成对存在：那边只收 use=knock，这边只收
// use=web。少了任一侧，一张票就能同时开两条入场路径——而两条路径的闸完全不同
// （敲门那条有终端合规/设备准入，这条没有）。
//
// gwID 是本网关自己的 id（-gwid）。票据带 gw 且不是自己时拒——见 Claims.Gw。
func VerifyTicket(v *auth.Verifier, raw string, maxTTL time.Duration, gwID string) (auth.Claims, error) {
	if strings.TrimSpace(raw) == "" {
		return auth.Claims{}, errors.New("缺少访问票据")
	}
	c, err := v.Verify(raw)
	if err != nil {
		return auth.Claims{}, fmt.Errorf("票据无效: %w", err)
	}
	if err := checkTicket(c, maxTTL, gwID); err != nil {
		return auth.Claims{}, err
	}
	return c, nil
}

// checkTicket 票据语义校验（纯函数，便于无网络单测）。
func checkTicket(c auth.Claims, maxTTL time.Duration, gwID string) error {
	if c.Use != auth.UseWeb {
		return fmt.Errorf("非 Web 访问票据（use=%q，需 %q）", c.Use, auth.UseWeb)
	}
	if c.Jti == "" {
		// jti 的消费方是 Server.ticketUsed 的去重缓存（handleEnter 里调）。
		// 这里只校验它存在——真正的一次性由那一处保证，两处缺一不可。
		return errors.New("票据缺 jti（一次性去重的依据）")
	}
	// 网关绑定：票据点名了别台网关就不是给我们的。去重缓存是本机内存，
	// 少了这一条，同一张票在每台装了 web 公钥的网关上都能各换出一次会话。
	if c.Gw != "" && gwID != "" && c.Gw != gwID {
		return fmt.Errorf("票据绑定的是网关 %q，本网关是 %q", c.Gw, gwID)
	}
	if strings.TrimSpace(c.Res) == "" {
		return errors.New("票据未绑定资源（缺 res）")
	}
	if !ValidResourceID(c.Res) {
		return fmt.Errorf("票据绑定的资源 id 非法: %q", c.Res)
	}
	if maxTTL <= 0 || maxTTL > maxTicketTTLCeiling {
		maxTTL = maxTicketTTLCeiling
	}
	if c.Iat == 0 || time.Duration(c.Exp-c.Iat)*time.Second > maxTTL {
		return fmt.Errorf("票据寿命超上界（%ds > %s）", c.Exp-c.Iat, maxTTL)
	}
	// 与 control 的 requireUser、spa.checkKnock 同一份角色白名单：
	// 网关机器身份与 WebAuthn 半程票据都不得换出 Web 会话。
	if c.Role != "admin" && c.Role != "user" {
		return fmt.Errorf("角色 %q 不得换取 Web 会话", c.Role)
	}
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("票据缺账号（无法逐请求鉴权）")
	}
	return nil
}

// ValidResourceID 资源 id 是否可安全用作 URL 路径段。
//
// ★这不是洁癖：资源 id 会被拼进 /app/<id>/ 前缀，也会被写进 Cookie 的 Path 属性。
// 带 `/`、`;`、空格的 id 会让 Path 属性被截断或串到别的前缀上，
// 从而把「一个应用的 Cookie 只能开一个应用」这条结构性隔离悄悄拆掉。
// 控制面签票前用同一条规则校验并当面报错，两侧口径必须一致。
func ValidResourceID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	// 不允许 "." / ".." 这类会被路径规范化吃掉的形态。
	return id != "." && id != ".."
}
