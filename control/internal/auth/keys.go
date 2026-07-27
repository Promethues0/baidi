package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── 非对称身份签名（CA 身份迁移 阶段 1）──
//
// 目标：control 持私钥签发全部人类身份令牌，数据面只持公钥、在密码学上不具备签发能力。
// 在此之前 control 与 gateway 共用一把 HS256 密钥，网关机被攻陷即可自签 role=admin 令牌
// （现网 baidi-control.service 与 baidi-gateway.service 读同一个 baidi.env）。
//
// 算法选 Ed25519（JWT alg=EdDSA）而非 ES256：stdlib crypto/ed25519、签名 64 字节定长、
// 无 k 值随机数灾难面，手写 JWT 只需把 HMAC 换成 ed25519.Sign/Verify。
//
// ★公钥分发用部署期文件（PublicPEM 写盘 → deploy 拷给网关），不用 JWKS 端点：
// JWKS 自身若是信任根就构成循环论证——能抢答该端点者可下发自有公钥，为任意
// Sub/Role 伪造令牌，比今天的共享密钥更糟（今天至少要先偷到 baidi.env）。

// Keys 持有签名私钥与验证材料。legacy 为迁移期的 HS256 密钥。
type Keys struct {
	priv         ed25519.PrivateKey
	pub          ed25519.PublicKey
	kid          string
	legacy       []byte // 迁移期：验证存量 HS256 令牌（8h 会话令牌未到期前仍在流通）
	acceptLegacy bool
}

// KidOf 由公钥算 kid（SHA-256 前 8 字节 base64url），用于多密钥并存与轮换。
func KidOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64.EncodeToString(sum[:8])
}

// LoadOrCreateKeys 从 path 载入 Ed25519 私钥 PEM；不存在则生成并原子落盘（0600）。
// 同时把公钥写到 path+".pub"（0644）供部署分发给网关。
//
// legacy/acceptLegacy 控制迁移期是否接受存量 HS256 令牌：
// 必须默认接受一个发布周期，否则升级瞬间所有在线会话（8h TTL）与网关自签的
// role=gateway 令牌全部 401——控制面与数据面同时断联。
func LoadOrCreateKeys(path string, legacy []byte, acceptLegacy bool) (*Keys, error) {
	priv, err := loadOrCreatePriv(path)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	k := &Keys{priv: priv, pub: pub, kid: KidOf(pub), legacy: legacy, acceptLegacy: acceptLegacy}
	// 公钥旁路落盘，deploy 据此分发给网关（网关的信任锚是这个文件，不是任何在线端点）
	if err := writeFile(path+".pub", k.PublicPEM(), 0o644); err != nil {
		return nil, fmt.Errorf("写公钥失败: %w", err)
	}
	return k, nil
}

// NewTestKeys 生成一次性内存密钥（测试用，不落盘）。
func NewTestKeys(legacy []byte, acceptLegacy bool) *Keys {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Keys{priv: priv, pub: pub, kid: KidOf(pub), legacy: legacy, acceptLegacy: acceptLegacy}
}

func (k *Keys) Kid() string               { return k.kid }
func (k *Keys) Public() ed25519.PublicKey { return k.pub }

// AcceptsLegacy 报告是否仍接受存量 HS256 令牌（迁移窗口未关闭）。供 /diag 暴露真实姿态。
func (k *Keys) AcceptsLegacy() bool { return k.acceptLegacy && len(k.legacy) > 0 }

// LegacyIs 报告迁移期的 HS256 密钥是否等于给定值（用于识别"仍在用默认开发密钥"）。
func (k *Keys) LegacyIs(s string) bool { return string(k.legacy) == s }

// PublicPEM 返回 PKIX 公钥 PEM（分发给网关做验证锚）。
func (k *Keys) PublicPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(k.pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Sign 用 Ed25519 私钥签发 JWT（alg=EdDSA，header 带 kid）；自动填充 Iat/Exp。
func (k *Keys) Sign(c Claims, ttl time.Duration) string {
	now := time.Now()
	c.Iat = now.Unix()
	c.Exp = now.Add(ttl).Unix()
	hj, _ := json.Marshal(header{Alg: "EdDSA", Typ: "JWT", Kid: k.kid})
	payload, _ := json.Marshal(c)
	body := b64.EncodeToString(hj) + "." + b64.EncodeToString(payload)
	sig := ed25519.Sign(k.priv, []byte(body))
	return body + "." + b64.EncodeToString(sig)
}

// Verify 校验令牌：EdDSA 走公钥；HS256 仅在迁移期（acceptLegacy）走旧共享密钥。
// alg 白名单由 parseHeader 把守（阶段 0），杜绝 alg-confusion。
func (k *Keys) Verify(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("malformed token")
	}
	allowed := []string{"EdDSA"}
	if k.acceptLegacy {
		allowed = append(allowed, "HS256")
	}
	h, err := parseHeader(parts[0], allowed...)
	if err != nil {
		return Claims{}, err
	}
	body := parts[0] + "." + parts[1]

	switch h.Alg {
	case "EdDSA":
		if h.Kid != "" && h.Kid != k.kid {
			return Claims{}, errors.New("unknown kid")
		}
		sig, err := b64.DecodeString(parts[2])
		if err != nil || !ed25519.Verify(k.pub, []byte(body), sig) {
			return Claims{}, errors.New("bad signature")
		}
	case "HS256":
		if !k.acceptLegacy || len(k.legacy) == 0 {
			return Claims{}, errors.New("legacy HS256 已停用")
		}
		if !hmacEqual(mac(k.legacy, body), parts[2]) {
			return Claims{}, errors.New("bad signature")
		}
	default:
		return Claims{}, errors.New("unexpected alg: " + h.Alg)
	}
	return decodeClaims(parts[1])
}

// ── 落盘辅助（原子写 + 严格权限，照 gmcert 的骨架）──

func loadOrCreatePriv(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("私钥 PEM 解析失败: " + path)
		}
		key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败: %w", err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("私钥不是 Ed25519：" + path)
		}
		return priv, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	buf := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := writeFile(path, buf, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// writeFile 原子写：先写同目录临时文件再 rename，避免读到半截文件。
func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
