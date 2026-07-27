// Package webauthnx 把白帝的 store 类型适配到 go-webauthn 库，并封装三个仪式的服务端半边。
//
// 为什么用库而不手写：attestation/CBOR/COSE 解码、签名校验、计数器克隆检测、UV/UP 位判定
// 是安全细节密集区，手写等于自建高危攻击面。库为纯 Go（CGO_ENABLED=0 可编译，已实测）。
//
// RP ID 必须是可注册域名或 localhost——浏览器规范不允许裸 IP 作 RP ID，
// 故 IP 演示站无法启用 WebAuthn，未配置时上层回落 legacy 演示路径。
package webauthnx

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"baidi.dev/control/internal/store"
)

// RP 一个已配置的 WebAuthn 依赖方（Relying Party）。RPID/Origins 为空即视为未启用。
type RP struct {
	w *webauthn.WebAuthn
}

// New 构造 RP。rpID 如 "vpn.example.com" 或 "localhost"；origins 逗号分隔的允许来源。
// 任一为空 → 返回 (nil, nil)，表示 WebAuthn 未启用（调用方回落 legacy 路径）。
func New(rpID, origins, displayName string) (*RP, error) {
	rpID = strings.TrimSpace(rpID)
	origins = strings.TrimSpace(origins)
	if rpID == "" || origins == "" {
		return nil, nil
	}
	var list []string
	for _, o := range strings.Split(origins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			list = append(list, o)
		}
	}
	if len(list) == 0 {
		return nil, nil
	}
	if displayName == "" {
		displayName = "白帝零信任"
	}
	w, err := webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: displayName, RPOrigins: list})
	if err != nil {
		return nil, err
	}
	return &RP{w: w}, nil
}

// user 把白帝账号 + 已注册凭据适配成 go-webauthn 要求的 webauthn.User。
type user struct {
	id    string // users.id（稳定主键，不用 account——改名会失联）
	name  string // 登录账号
	disp  string // 显示名
	creds []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *user) WebAuthnName() string                       { return u.name }
func (u *user) WebAuthnDisplayName() string                { return u.disp }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// NewUser 由账号信息与库中凭据构造 webauthn.User。
func NewUser(userID, account, display string, creds []store.WebauthnCredential) (webauthn.User, error) {
	u := &user{id: userID, name: account, disp: pick(display, account)}
	for _, c := range creds {
		wc, err := toWebauthnCredential(c)
		if err != nil {
			return nil, err
		}
		u.creds = append(u.creds, wc)
	}
	return u, nil
}

func toWebauthnCredential(c store.WebauthnCredential) (webauthn.Credential, error) {
	id, err := base64.RawURLEncoding.DecodeString(c.CredentialID)
	if err != nil {
		return webauthn.Credential{}, err
	}
	pub, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
	if err != nil {
		return webauthn.Credential{}, err
	}
	var aaguid []byte
	if c.AAGUID != "" {
		aaguid, _ = base64.RawURLEncoding.DecodeString(c.AAGUID)
	}
	var transports []protocol.AuthenticatorTransport
	if c.Transports != "" {
		var ts []string
		_ = json.Unmarshal([]byte(c.Transports), &ts)
		for _, t := range ts {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}
	return webauthn.Credential{
		ID: id, PublicKey: pub, Transport: transports,
		Authenticator: webauthn.Authenticator{AAGUID: aaguid, SignCount: c.SignCount},
	}, nil
}

// ── 注册仪式 ──

// BeginRegistration 生成 CreationOptions 与 SessionData（含 challenge）。
// excludeCredentials 由 u 的已注册凭据自动填充，防同一认证器重复注册。
func (r *RP) BeginRegistration(u webauthn.User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return r.w.BeginRegistration(u,
		webauthn.WithExclusions(credentialDescriptors(u.WebAuthnCredentials())),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
}

// FinishRegistration 校验 attestation（challenge/origin/RP ID/UP 位/公钥解析），返回可落库的凭据。
func (r *RP) FinishRegistration(u webauthn.User, sess webauthn.SessionData, req *http.Request) (store.WebauthnCredential, error) {
	c, err := r.w.FinishRegistration(u, sess, req)
	if err != nil {
		return store.WebauthnCredential{}, err
	}
	ts, _ := json.Marshal(transportStrings(c.Transport))
	return store.WebauthnCredential{
		CredentialID: base64.RawURLEncoding.EncodeToString(c.ID),
		PublicKey:    base64.RawURLEncoding.EncodeToString(c.PublicKey),
		SignCount:    c.Authenticator.SignCount,
		Transports:   string(ts),
		AAGUID:       base64.RawURLEncoding.EncodeToString(c.Authenticator.AAGUID),
	}, nil
}

// ── 登录断言仪式 ──

// BeginLogin 生成 RequestOptions 与 SessionData。allowCredentials 限定为该用户已注册凭据。
func (r *RP) BeginLogin(u webauthn.User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return r.w.BeginLogin(u)
}

// FinishLogin 校验断言（签名/challenge/origin/RP ID/UP 位），返回本次使用的凭据。
// 计数器单调性由上层 store.UpdateSignCount 判定（库对 signCount=0 的同步 passkey 不报错）。
func (r *RP) FinishLogin(u webauthn.User, sess webauthn.SessionData, req *http.Request) (credentialID string, newSignCount uint32, err error) {
	c, err := r.w.FinishLogin(u, sess, req)
	if err != nil {
		return "", 0, err
	}
	if c.Authenticator.CloneWarning {
		return "", 0, errors.New("认证器计数器异常，疑似凭据克隆")
	}
	return base64.RawURLEncoding.EncodeToString(c.ID), c.Authenticator.SignCount, nil
}

// ── 辅助 ──

// EncodeSession 把 SessionData 序列化以便落库（webauthn_challenges.session_data）。
func EncodeSession(s *webauthn.SessionData) (string, error) {
	b, err := json.Marshal(s)
	return string(b), err
}

// DecodeSession 从库中还原 SessionData。
func DecodeSession(raw string) (webauthn.SessionData, error) {
	var s webauthn.SessionData
	err := json.Unmarshal([]byte(raw), &s)
	return s, err
}

// ChallengeOf 取 SessionData 里的 challenge（库内已是 base64url 字符串），作为落库的单次消费键。
func ChallengeOf(s *webauthn.SessionData) string { return s.Challenge }

func credentialDescriptors(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.Descriptor())
	}
	return out
}

func transportStrings(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

func pick(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a
}
