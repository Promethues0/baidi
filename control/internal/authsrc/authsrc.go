// Package authsrc 是外部认证源的接入层：把 LDAP/AD、OIDC 这类"别人家的身份系统"
// 收敛成两个接口，让登录链路不必知道对面到底是什么。
//
// # 为什么这一层要单独存在
//
// 白帝此前的登录只查本地 SQLite + bcrypt，而控制台的「认证源接入」页是一整页
// 内存种子——连「总部 AD 域 1160 用户」这个数字都是编的。企业落地时，身份的权威
// 几乎不可能在白帝自己的库里，所以这一层不是锦上添花，是能不能用的分界线。
//
// # 自研与不自研的分界
//
// 本项目对 IKEv2/ESP 选择了自研，因为那是**白帝↔白帝**的协议，两端都归我们；
// LDAP 恰恰相反——它的全部价值就在于能连上**别人的** Active Directory。
// 自研一个 BER 编解码器在这里没有任何收益，只会把「能不能互通」变成新的风险，
// 所以 LDAP 客户端直接用 go-ldap。OIDC 则是纯 HTTP+JWT，用标准库实现即可，
// 反倒是引库要额外审它的校验完整性（下面列的那些校验漏一条就是认证绕过）。
package authsrc

import (
	"context"
	"errors"
	"strings"
)

// Identity 一次成功认证之后，从认证源拿回来的身份。
type Identity struct {
	// Subject 是认证源侧的**权威标识**：OIDC 的 sub、LDAP 的 entryDN。
	//
	// ★账号映射必须以它为准，绝不能只按 Username 匹配。只按用户名匹配的话，
	// 谁能在外部目录里新建一个与本地管理员同名的账号，谁就能登录成管理员——
	// 而这个洞在日志里看起来完全正常（"admin 登录成功"）。
	Subject string

	// Username 登录名（LDAP 的 sAMAccountName/uid、OIDC 的 preferred_username）。
	// 只作展示与初次绑定时的候选，不作为身份判定依据。
	Username    string
	DisplayName string
	Email       string
	Groups      []string
}

// Normalized 返回规范化后的副本：账号与邮箱转小写去空白。
//
// ★与 spa/proxy 的 normUser 同一条推理：企业身份（sAMAccountName、邮箱）
// 大小写不敏感，不规范化就会出现「换个大小写重登即绕过强制下线」这类问题。
func (i Identity) Normalized() Identity {
	i.Username = strings.ToLower(strings.TrimSpace(i.Username))
	i.Email = strings.ToLower(strings.TrimSpace(i.Email))
	i.Subject = strings.TrimSpace(i.Subject)
	return i
}

// PasswordAuthenticator 用「账号 + 口令」直接认证的源（LDAP / AD）。
type PasswordAuthenticator interface {
	// Authenticate 校验凭据并返回身份。凭据错误返回包裹 ErrInvalidCredentials 的错误；
	// 源本身不可用（网络、TLS、配置）返回包裹 ErrSourceUnavailable 的错误。
	//
	// ★这两类必须可区分：口令错该记一次登录失败并原样告诉用户，
	// 源不可用则是运维故障，不该让用户以为自己密码记错了，也不该计入锁定计数。
	Authenticate(ctx context.Context, username, password string) (Identity, error)
	// Probe 连通性自检（控制台「测试连接」按钮的后端）。不校验任何用户凭据。
	Probe(ctx context.Context) error
}

// RedirectAuthenticator 需要把用户重定向到外部去完成登录的源（OIDC）。
type RedirectAuthenticator interface {
	// AuthURL 构造授权端点跳转地址。state 防 CSRF、nonce 防 ID Token 重放、
	// codeVerifier 用于 PKCE——三者都必须由调用方随机生成并与会话绑定。
	AuthURL(state, nonce, codeVerifier string) (string, error)
	// Exchange 用授权码换令牌并校验 ID Token，返回身份。
	// nonce 必须与 AuthURL 时用的一致：不比对就等于没有防重放。
	Exchange(ctx context.Context, code, codeVerifier, nonce string) (Identity, error)
	Probe(ctx context.Context) error
}

// 认证失败的两类根因。调用方必须区别对待，见 PasswordAuthenticator.Authenticate 的说明。
var (
	// ErrInvalidCredentials 账号或口令不对（也包括账号在目录里不存在）。
	//
	// ★刻意不区分「用户不存在」与「口令错误」：区分开就成了用户名枚举接口，
	// 攻击者能靠它把目录里的账号名捞干净。对外一律「用户名或密码错误」。
	ErrInvalidCredentials = errors.New("authsrc: 用户名或密码错误")
	// ErrSourceUnavailable 认证源不可用（网络不通、TLS 失败、配置错误、超时）。
	ErrSourceUnavailable = errors.New("authsrc: 认证源不可用")
	// ErrNotConfigured 该认证源缺少必要配置，属于配置错误而非运行故障。
	ErrNotConfigured = errors.New("authsrc: 认证源未配置完整")
)

// Kind 认证源类型。落库用字符串，便于以后加类型不动 schema。
type Kind string

const (
	KindLocal Kind = "local" // 本地目录（SQLite + bcrypt），永远存在且不可删
	KindLDAP  Kind = "ldap"  // 通用 LDAP
	KindAD    Kind = "ad"    // Active Directory（LDAP 的一种方言，见 ldap 包的差异说明）
	KindOIDC  Kind = "oidc"  // OpenID Connect
)

// Supported 报告某类型是否已真实实现。
//
// ★控制台上那些「RADIUS / 短信网关 / 商密证书」的磁贴是历史种子，背后什么都没有。
// 与其让它们看起来可选，不如在这里集中定义"什么是真的"，由 API 层据此把未实现的
// 类型明确拒掉——本项目反复吃亏的就是「界面上能选、后端静默不生效」。
func (k Kind) Supported() bool {
	switch k {
	case KindLocal, KindLDAP, KindAD, KindOIDC:
		return true
	}
	return false
}
