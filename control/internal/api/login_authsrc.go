package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/authsrc/ldapsrc"
	"baidi.dev/control/internal/authsrc/oidcsrc"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// 登录链路的认证源编排：本地目录优先，未命中再按优先级问外部源。
//
// # 这一层的全部安全语义都在注释里，改之前请读完
//
// 认证源接入最容易做出来的两个洞，都不在协议实现里，而在这一层的账号映射上：
//
//	① 按用户名而不是 subject 绑定 → 外部目录里新建一个叫 admin 的账号即可冒充本地管理员，
//	   而审计日志里是一次完全正常的「admin 登录成功」；
//	② 外部用户留着本地口令哈希 → 认证源被停用/删除后，那个账号退回成"某个本地口令也能登录"，
//	   而那个口令是谁设的、什么时候设的，没有人说得清。
//
// 两者的共同点是：**出问题时看起来一切正常**。所以下面每一处都写了症状。

// authSourceStore 是本文件需要的 store 能力。抽成小接口而不是直接用 *SQLiteStore，
// 是为了让登录编排能被单测覆盖（测试里塞一个假实现即可）。
type authSourceStore interface {
	AuthSources(ctx context.Context) ([]store.AuthSourceRec, error)
	AuthSourceSecret(ctx context.Context, id string) (store.AuthSourceSecret, bool, error)
	UserBySubject(ctx context.Context, sourceID, subject string) (store.Credential, bool, error)
	BindExternalUser(ctx context.Context, sourceID string, ext store.ExternalIdentity) (store.Credential, error)
}

// authSrcStore 取 store 的认证源能力；未实现（如纯 Memory）时返回 nil。
func (s *Server) authSrcStore() authSourceStore {
	if as, ok := s.store.(authSourceStore); ok {
		return as
	}
	return nil
}

// ldapConfigDTO / oidcConfigDTO 是落库 config JSON 的形状。
// 敏感项（bind 口令 / client_secret）**不在这里**——它们在 auth_source_secrets 表。
type ldapConfigDTO struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	TLSMode            string `json:"tlsMode"` // ldaps | starttls | plaintext
	CACert             string `json:"caCert"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	BindDN             string `json:"bindDn"`
	BaseDN             string `json:"baseDn"`
	UserFilter         string `json:"userFilter"`
	UsernameAttr       string `json:"usernameAttr"`
	DisplayNameAttr    string `json:"displayNameAttr"`
	EmailAttr          string `json:"emailAttr"`
	GroupAttr          string `json:"groupAttr"`
}

type oidcConfigDTO struct {
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"clientId"`
	RedirectURI string   `json:"redirectUri"`
	Scopes      []string `json:"scopes"`
}

// buildProvider 由一条落库配置构造出可用的认证源实现。
//
// ★凭据在这里、且只在这里被解密。整个控制面里能读到 bind 口令/client_secret 明文的
// 就这一个函数——与 IPSec PSK 同款收敛（见 ipsec_gateway.go 的推理）。
func (s *Server) buildProvider(ctx context.Context, rec store.AuthSourceRec) (any, error) {
	as := s.authSrcStore()
	if as == nil {
		return nil, fmt.Errorf("当前存储实现不支持认证源")
	}
	kind := authsrc.Kind(rec.Kind)
	if !kind.Supported() {
		// ★明确拒绝而不是静默跳过：控制台上那些 RADIUS/短信/证书磁贴是历史种子，
		// 后端从来没有实现过。静默跳过的症状是「配了一个 RADIUS 源，用户登录一直失败，
		// 日志里什么都没有」。
		return nil, fmt.Errorf("认证源类型 %q 本版本未实现", rec.Kind)
	}

	// 取凭据（可能没有：OIDC 的公共客户端、匿名 bind 的 LDAP）。
	var credential string
	if sec, ok, err := as.AuthSourceSecret(ctx, rec.ID); err != nil {
		return nil, err
	} else if ok {
		box, err := secret.Default()
		if err != nil {
			return nil, fmt.Errorf("凭据主密钥不可用：%w", err)
		}
		// AAD 绑认证源 id：把某一行密文剪贴到另一条源上会直接解不开，
		// 而不是安静地下发一把错凭据。
		plain, err := box.Open(rec.ID, sec.Nonce, sec.Cipher)
		if err != nil {
			return nil, fmt.Errorf("凭据解密失败（密文行损坏或主密钥被替换）：%w", err)
		}
		credential = string(plain)
	}

	switch kind {
	case authsrc.KindLDAP, authsrc.KindAD:
		var c ldapConfigDTO
		if err := json.Unmarshal([]byte(rec.Config), &c); err != nil {
			return nil, fmt.Errorf("LDAP 配置不是合法 JSON：%w", err)
		}
		return ldapsrc.New(ldapsrc.Config{
			Kind: kind, Host: c.Host, Port: c.Port,
			TLS:                ldapTLSMode(c.TLSMode),
			CACert:             c.CACert,
			InsecureSkipVerify: c.InsecureSkipVerify,
			BindDN:             c.BindDN, BindPassword: credential,
			BaseDN: c.BaseDN, UserFilter: c.UserFilter,
			UsernameAttr: c.UsernameAttr, DisplayNameAttr: c.DisplayNameAttr,
			EmailAttr: c.EmailAttr, GroupAttr: c.GroupAttr,
		})
	case authsrc.KindOIDC:
		var c oidcConfigDTO
		if err := json.Unmarshal([]byte(rec.Config), &c); err != nil {
			return nil, fmt.Errorf("OIDC 配置不是合法 JSON：%w", err)
		}
		return oidcsrc.New(oidcsrc.Config{
			Issuer: c.Issuer, ClientID: c.ClientID, ClientSecret: credential,
			RedirectURI: c.RedirectURI, Scopes: c.Scopes,
		})
	}
	return nil, fmt.Errorf("认证源类型 %q 无法构造", rec.Kind)
}

// authenticateExternal 依次问外部认证源，返回第一个认证成功的本地凭据。
//
// 返回 (凭据, 命中的源, 是否命中, 错误)。错误只在「所有源都不可用」这类
// 运维故障时非 nil——调用方据此区分「密码错」与「目录挂了」。
func (s *Server) authenticateExternal(ctx context.Context, username, password string) (store.Credential, string, string, bool, error) {
	as := s.authSrcStore()
	if as == nil {
		return store.Credential{}, "", "", false, nil
	}
	srcs, err := as.AuthSources(ctx)
	if err != nil {
		return store.Credential{}, "", "", false, err
	}

	// unavailable 记录「源本身出故障」的次数。★它与「凭据错」必须分开统计：
	// 只有当**没有任何源认出这个人、且至少有一个源是坏的**时，才该告诉调用方
	// "这是运维故障"。否则 AD 挂了会让所有本来就不存在的用户名也报"目录不可用"，
	// 反过来变成一个探测接口。
	var unavailable []string

	for _, rec := range srcs {
		if !rec.Enabled || authsrc.Kind(rec.Kind) == authsrc.KindLocal {
			continue
		}
		prov, err := s.buildProvider(ctx, rec)
		if err != nil {
			slog.Warn("认证源不可用（配置构造失败）", "源", rec.Name, "id", rec.ID, "err", err.Error())
			unavailable = append(unavailable, rec.Name)
			continue
		}
		pa, ok := prov.(authsrc.PasswordAuthenticator)
		if !ok {
			// OIDC 这类重定向式的源不参与口令登录——它有自己的入口。
			continue
		}
		id, err := pa.Authenticate(ctx, username, password)
		switch {
		case err == nil:
			cred, berr := as.BindExternalUser(ctx, rec.ID, store.ExternalIdentity{
				Subject: id.Subject, Username: id.Username,
				DisplayName: id.DisplayName, Email: id.Email, Groups: id.Groups,
			})
			if berr != nil {
				slog.Error("外部身份绑定失败", "源", rec.Name, "subject", id.Subject, "err", berr.Error())
				return store.Credential{}, rec.Name, rec.Kind, false, berr
			}
			// 第三个返回值是源的 kind（ldap/ad/oidc）：认证策略按用户目录分组，
			// 登录链路是唯一知道"这个人是被哪个目录认出来的"的地方。
			return cred, rec.Name, rec.Kind, true, nil
		case errors.Is(err, authsrc.ErrInvalidCredentials):
			// 这个源不认识他/口令不对：继续问下一个源。不记 unavailable。
			continue
		default:
			// ErrSourceUnavailable / ErrNotConfigured：运维故障。
			// ★不能当成"密码错误"回给用户——那会让运维去查用户而不是查目录。
			slog.Warn("认证源故障", "源", rec.Name, "id", rec.ID, "err", err.Error())
			unavailable = append(unavailable, rec.Name)
		}
	}

	if len(unavailable) > 0 {
		return store.Credential{}, "", "", false,
			fmt.Errorf("%w：%s", authsrc.ErrSourceUnavailable, strings.Join(unavailable, "、"))
	}
	return store.Credential{}, "", "", false, nil
}

func ldapTLSMode(s string) ldapsrc.TLSMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "starttls":
		return ldapsrc.TLSModeStartTLS
	case "plaintext", "none":
		return ldapsrc.TLSModePlaintext
	}
	return ldapsrc.TLSModeLDAPS // 零值即最安全的那一档
}
