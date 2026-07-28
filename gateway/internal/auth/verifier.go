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

// ── 非对称验证（CA 身份迁移 阶段 1 + 阶段 3）──
//
// 网关只持 control 的**公钥**验证令牌，在密码学上不再具备签发能力。
// 此前两侧共用一把 HS256 密钥：网关机被攻陷即可自签 role=admin 令牌调控制面
// （现网 baidi-gateway.service 与 baidi-control.service 读同一个 baidi.env）。
//
// 阶段 3 起按 kid 白名单验证：网关只安装 **knock 公钥**，会话令牌用另一把
// sess 密钥签，其 kid 在本地查不到 → 从密码学上就验不过。于是 spa.checkKnock 的
// use 语义闸退化为纵深防御，而不再是拦住会话令牌的唯一防线。
//
// 公钥来自部署期分发的 PEM 文件（control 启动时写在 <私钥>.pub），
// 而不是任何在线端点——在线分发若自身是信任根就构成循环论证：
// 能抢答该端点者可下发自有公钥，为任意 Sub/Role 伪造令牌。

// Verifier 校验令牌：EdDSA 按 kid 查已安装公钥；HS256 仅在迁移期走旧共享密钥。
type Verifier struct {
	pubs         map[string]ed25519.PublicKey // kid → 公钥（kid 由公钥自身哈希派生）
	legacy       []byte
	acceptLegacy bool
}

// kidOf 与 control 的 KidOf 同算法：SHA-256 前 8 字节 base64url。
// 两侧各自从公钥算出 kid，无需传递任何命名约定。
func kidOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64.EncodeToString(sum[:8])
}

// NewVerifier 构造校验器。pubPaths 为逗号分隔的公钥 PEM 路径（多把并存支持轮换：
// 轮换期同时装新旧两把，旧令牌自然过期后再摘掉旧的）。
// 为空表示尚未分发公钥（只能验 HS256，迁移期形态）。
func NewVerifier(pubPaths string, legacy []byte, acceptLegacy bool) (*Verifier, error) {
	v := &Verifier{pubs: map[string]ed25519.PublicKey{}, legacy: legacy, acceptLegacy: acceptLegacy}
	for _, p := range strings.Split(pubPaths, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pub, err := loadPub(p)
		if err != nil {
			return nil, err
		}
		v.pubs[kidOf(pub)] = pub
	}
	if len(v.pubs) == 0 && !acceptLegacy {
		return nil, errors.New("未配置 control 公钥且已关闭 HS256 兼容：无可用的令牌验证材料")
	}
	return v, nil
}

func loadPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("公钥 PEM 解析失败: " + path)
	}
	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("公钥不是 Ed25519: " + path)
	}
	return pub, nil
}

// PublicKeyCount 已安装的公钥数（供启动日志暴露真实姿态）。
func (v *Verifier) PublicKeyCount() int { return len(v.pubs) }

// HasPublicKey 报告是否已装载至少一把 control 公钥。
func (v *Verifier) HasPublicKey() bool { return len(v.pubs) > 0 }

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
	if len(v.pubs) > 0 {
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
		// ★kid 查不到即拒：网关只装 knock 公钥，会话令牌（sess 密钥签）到此为止。
		pub, ok := v.pubs[h.Kid]
		if !ok {
			return Claims{}, errors.New("unknown kid: " + h.Kid)
		}
		sig, err := b64.DecodeString(parts[2])
		if err != nil || !ed25519.Verify(pub, []byte(body), sig) {
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
