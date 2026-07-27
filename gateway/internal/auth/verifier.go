package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

// ── 非对称验证（CA 身份迁移 阶段 1）──
//
// 网关只持 control 的**公钥**验证令牌，在密码学上不再具备签发能力。
// 此前两侧共用一把 HS256 密钥：网关机被攻陷即可自签 role=admin 令牌调控制面
// （现网 baidi-gateway.service 与 baidi-control.service 读同一个 baidi.env）。
//
// 公钥来自部署期分发的 PEM 文件（control 启动时写在 <私钥>.pub），
// 而不是任何在线端点——在线分发若自身是信任根就构成循环论证：
// 能抢答该端点者可下发自有公钥，为任意 Sub/Role 伪造令牌。

// Verifier 校验令牌：EdDSA 走 control 公钥；HS256 仅在迁移期走旧共享密钥。
type Verifier struct {
	pub          ed25519.PublicKey
	legacy       []byte
	acceptLegacy bool
}

// NewVerifier 构造校验器。pubPath 为空表示尚未分发公钥（只能验 HS256，迁移期形态）。
// legacy 为共享密钥，acceptLegacy=false 时彻底拒绝 HS256（迁移收口）。
func NewVerifier(pubPath string, legacy []byte, acceptLegacy bool) (*Verifier, error) {
	v := &Verifier{legacy: legacy, acceptLegacy: acceptLegacy}
	if strings.TrimSpace(pubPath) == "" {
		if !acceptLegacy {
			return nil, errors.New("未配置 control 公钥且已关闭 HS256 兼容：无可用的令牌验证材料")
		}
		return v, nil
	}
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("公钥 PEM 解析失败: " + pubPath)
	}
	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("公钥不是 Ed25519: " + pubPath)
	}
	v.pub = pub
	return v, nil
}

// HasPublicKey 报告是否已装载 control 公钥（供启动日志暴露真实姿态）。
func (v *Verifier) HasPublicKey() bool { return v.pub != nil }

// AcceptsLegacy 报告是否仍接受 HS256 存量令牌。
func (v *Verifier) AcceptsLegacy() bool { return v.acceptLegacy && len(v.legacy) > 0 }

// Verify 校验令牌签名与有效期。alg 白名单由 parseHeader 把守（阶段 0），
// 杜绝「把 alg 改成 HS256、拿公钥当 HMAC 密钥」的 alg-confusion。
func (v *Verifier) Verify(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("malformed token")
	}
	var allowed []string
	if v.pub != nil {
		allowed = append(allowed, "EdDSA")
	}
	if v.AcceptsLegacy() {
		allowed = append(allowed, "HS256")
	}
	h, err := parseHeader(parts[0], allowed...)
	if err != nil {
		return Claims{}, err
	}
	body := parts[0] + "." + parts[1]

	switch h.Alg {
	case "EdDSA":
		sig, err := b64.DecodeString(parts[2])
		if err != nil || !ed25519.Verify(v.pub, []byte(body), sig) {
			return Claims{}, errors.New("bad signature")
		}
	case "HS256":
		m := hmac.New(sha256.New, v.legacy)
		m.Write([]byte(body))
		if !hmac.Equal([]byte(b64.EncodeToString(m.Sum(nil))), []byte(parts[2])) {
			return Claims{}, errors.New("bad signature")
		}
	default:
		return Claims{}, errors.New("unexpected alg: " + h.Alg)
	}
	return decodeClaims(parts[1])
}
