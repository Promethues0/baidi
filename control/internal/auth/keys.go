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

// ── 非对称身份签名（CA 身份迁移 阶段 1 + 阶段 3）──
//
// 阶段 1：control 持私钥签发全部人类身份令牌，数据面只持公钥、不具备签发能力。
// 在此之前 control 与 gateway 共用一把 HS256 密钥，网关机被攻陷即可自签 role=admin
// （现网 baidi-control.service 与 baidi-gateway.service 读同一个 baidi.env）。
//
// 阶段 3：**按用途分成两把密钥**——sess 签会话令牌与 MFA 票据，knock 只签敲门令牌。
// 网关只安装 knock 公钥，于是 8h 会话令牌在网关侧**从密码学上**就验不过（kid 查不到），
// spa.checkKnock 的 use 语义闸从唯一防线退化为纵深：即便它被误改或绕过，
// 会话令牌依然敲不开门。信任模型变了，而不只是校验逻辑变了。
//
// 算法选 Ed25519（JWT alg=EdDSA）：stdlib crypto/ed25519、签名 64 字节定长、
// 无 k 值随机数灾难面，手写 JWT 只需把 HMAC 换成 ed25519.Sign/Verify。
//
// ★公钥分发用部署期文件（PublicPEM 写盘 → deploy 拷给网关），不用 JWKS 端点：
// JWKS 自身若是信任根就构成循环论证——能抢答该端点者可下发自有公钥，为任意
// Sub/Role 伪造令牌，比今天的共享密钥更糟（今天至少要先偷到 baidi.env）。

// keypair 一把签名密钥及其 kid。
type keypair struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

func (k keypair) publicPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(k.pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Keys 持有签发/验证材料。legacy 为迁移期的 HS256 密钥。
type Keys struct {
	sess         keypair // 会话令牌 + MFA 票据
	knock        keypair // 只签敲门令牌；其公钥是唯一分发给数据面的
	legacy       []byte
	acceptLegacy bool
}

// KidOf 由公钥算 kid（SHA-256 前 8 字节 base64url）。
// 刻意用纯哈希派生而非加 sess-/knock- 前缀：网关从 PEM 自行算出 kid 与令牌 header 比对，
// 无需知道任何命名约定——它装了哪把公钥就只认哪把，隔离靠密钥本身而非字符串规则。
func KidOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64.EncodeToString(sum[:8])
}

// LoadOrCreateKeys 载入/生成两把 Ed25519 私钥（0600 原子写），
// 并把各自公钥写到同名 .pub（0644）。knock 公钥即分发给网关的那份。
//
// legacy/acceptLegacy 控制迁移期是否接受存量 HS256 令牌：迁移期必须接受，
// 否则升级瞬间所有在线会话（8h TTL）与网关自签的 role=gateway 令牌全部 401。
func LoadOrCreateKeys(sessPath, knockPath string, legacy []byte, acceptLegacy bool) (*Keys, error) {
	sess, err := loadKeypair(sessPath)
	if err != nil {
		return nil, fmt.Errorf("会话签名密钥: %w", err)
	}
	knock, err := loadKeypair(knockPath)
	if err != nil {
		return nil, fmt.Errorf("敲门签名密钥: %w", err)
	}
	return &Keys{sess: sess, knock: knock, legacy: legacy, acceptLegacy: acceptLegacy}, nil
}

func loadKeypair(path string) (keypair, error) {
	priv, err := loadOrCreatePriv(path)
	if err != nil {
		return keypair{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	kp := keypair{priv: priv, pub: pub, kid: KidOf(pub)}
	if err := writeFile(path+".pub", kp.publicPEM(), 0o644); err != nil {
		return keypair{}, fmt.Errorf("写公钥失败: %w", err)
	}
	return kp, nil
}

// NewTestKeys 生成一次性内存密钥对（测试用，不落盘）。
func NewTestKeys(legacy []byte, acceptLegacy bool) *Keys {
	return &Keys{sess: genKeypair(), knock: genKeypair(), legacy: legacy, acceptLegacy: acceptLegacy}
}

func genKeypair() keypair {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return keypair{priv: priv, pub: pub, kid: KidOf(pub)}
}

func (k *Keys) SessKid() string  { return k.sess.kid }
func (k *Keys) KnockKid() string { return k.knock.kid }

// SessPublicPEM 会话签名公钥（control 自用/审计；**不分发给网关**）。
func (k *Keys) SessPublicPEM() []byte { return k.sess.publicPEM() }

// KnockPublicPEM 敲门签名公钥——这是唯一该分发给数据面的验证材料。
func (k *Keys) KnockPublicPEM() []byte { return k.knock.publicPEM() }

// AcceptsLegacy 报告是否仍接受存量 HS256 令牌（迁移窗口未关闭）。供 /diag 暴露真实姿态。
func (k *Keys) AcceptsLegacy() bool { return k.acceptLegacy && len(k.legacy) > 0 }

// LegacyIs 报告迁移期的 HS256 密钥是否等于给定值（用于识别"仍在用默认开发密钥"）。
func (k *Keys) LegacyIs(s string) bool { return string(k.legacy) == s }

// Sign 按令牌用途选密钥签发（alg=EdDSA，header 带 kid）；自动填充 Iat/Exp。
// Use=knock 走 knock 密钥，其余（会话令牌、MFA 票据）走 sess 密钥——
// 调用点无需关心选哪把，用途字段本身就是路由依据。
func (k *Keys) Sign(c Claims, ttl time.Duration) string {
	kp := k.sess
	if c.Use == UseKnock {
		kp = k.knock
	}
	now := time.Now()
	c.Iat = now.Unix()
	c.Exp = now.Add(ttl).Unix()
	hj, _ := json.Marshal(header{Alg: "EdDSA", Typ: "JWT", Kid: kp.kid})
	payload, _ := json.Marshal(c)
	body := b64.EncodeToString(hj) + "." + b64.EncodeToString(payload)
	return body + "." + b64.EncodeToString(ed25519.Sign(kp.priv, []byte(body)))
}

// byKid 按 kid 定位公钥（两把密钥并存，也为将来轮换留位）。
func (k *Keys) byKid(kid string) (ed25519.PublicKey, bool) {
	switch kid {
	case k.sess.kid:
		return k.sess.pub, true
	case k.knock.kid:
		return k.knock.pub, true
	}
	return nil, false
}

// Verify 校验令牌：EdDSA 按 kid 选公钥；HS256 仅在迁移期走旧共享密钥。
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
		pub, ok := k.byKid(h.Kid)
		if !ok {
			return Claims{}, errors.New("unknown kid: " + h.Kid)
		}
		sig, err := b64.DecodeString(parts[2])
		if err != nil || !ed25519.Verify(pub, []byte(body), sig) {
			return Claims{}, errors.New("bad signature")
		}
	case "HS256":
		if !k.AcceptsLegacy() {
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
