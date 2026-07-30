// Package secret 是控制面存放**对称密钥材料**的加密盒。
//
// 本轮只有一个使用者：IPSec 站点的预共享密钥（PSK）。它与 internal/auth 的两把
// Ed25519 签名私钥是完全不同的东西，别混着看：
//
//	auth 的密钥用来**证明身份**——私钥只在 control，泄露=可伪造任意令牌；
//	secret 的密钥用来**保护静态数据**——泄露只在拿到库文件后才有意义。
//
// 因此这里刻意不复用 auth 的密钥：一把密钥一个用途。共用会让「轮换 JWT 签名密钥」
// 这种例行操作顺带把全部 PSK 变成不可解密的乱码，而症状会是所有站点同时
// 「认证失败」——一个看起来像对端集体故障、实际是自己换了密钥的事故。
//
// ★落盘密钥的分发方式与 CLAUDE.md 里 JWT 公钥的口径一致：部署期文件，不做在线端点。
// 区别在于这把是对称密钥，**任何情况下都不下发给网关**——网关拿的是解密后的 PSK 原文，
// 且只经 mTLS 口、只拿自己那条站点的那一把。
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// KeyLen 主密钥长度（AES-256）。
const KeyLen = 32

// pemType 密钥文件的 PEM 块类型。用 PEM 而不是裸二进制/hex：
// 文件被误当文本打开时能一眼看出这是什么，也与项目里 jwt-ed25519.pem 的形制一致。
const pemType = "BAIDI IPSEC PSK KEY"

// DefaultKeyPathEnv 主密钥**文件路径**的环境变量名。
//
// ★存的是路径而不是密钥本身（不是 BAIDI_JWT_SECRET 那种直接放值的形式）：
// 环境变量会出现在 `ps e`、systemd 的 `systemctl show`、容器 inspect 与崩溃转储里；
// 文件可以 0600 且能被 systemd 的 ProtectSystem/ReadWritePaths 收紧。
const DefaultKeyPathEnv = "BAIDI_IPSEC_PSK_KEY"

// DefaultKeyPath 返回主密钥文件路径（未配置时与 SQLite 库同目录的相对默认值，
// 与 BAIDI_JWT_KEY 默认 "jwt-ed25519.pem" 同款惯例）。
func DefaultKeyPath() string {
	if p := os.Getenv(DefaultKeyPathEnv); p != "" {
		return p
	}
	return "ipsec-psk.key"
}

// Box 一把主密钥及其 AEAD。零值不可用，必须经 Open/NewFromKey 构造。
type Box struct {
	key  []byte
	aead cipher.AEAD
}

// Open 载入（不存在则生成）主密钥文件并构造加密盒。
//
// 首启自生成 + 0600 原子写，照抄 auth.loadOrCreatePriv 的成熟做法：
// 让「没配任何环境变量也能跑起来」与「生产上是一把真随机密钥」同时成立。
// 不这么做的替代方案是硬编码一个默认密钥，那等于没加密。
func Open(path string) (*Box, error) {
	key, err := loadOrCreateKey(path)
	if err != nil {
		return nil, err
	}
	return NewFromKey(key)
}

// NewFromKey 用给定的 32 字节主密钥构造加密盒（测试与自检用，不落盘）。
func NewFromKey(key []byte) (*Box, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("secret: 主密钥长度应为 %d 字节，实得 %d", KeyLen, len(key))
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Box{key: append([]byte(nil), key...), aead: aead}, nil
}

// Seal 加密一段密钥材料，返回 (nonce, 密文‖tag)。
//
// ★aad 必须是**这条记录的唯一标识**（本项目用 site_id）。不绑 AAD 的后果不是
// 理论风险：把 A 站点的密文行整行剪贴到 B 站点的行上，B 就用上了 A 的 PSK——
// 一次不需要任何密码学突破、只要能写库就能完成的密钥转移。绑上之后，
// 剪贴过去的行在解密时会直接 authentication failed，而不是悄悄生效。
//
// nonce 每次调用重新随机：GCM 的 nonce 复用会同时毁掉机密性与完整性，
// 而且不会报任何错。这里的写入频率极低（改一次 PSK 一次），12 字节随机
// 的碰撞概率可以忽略。
func (b *Box) Seal(aad string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if aad == "" {
		return nil, nil, errors.New("secret: AAD 不能为空（否则密文行可被跨记录剪贴复用）")
	}
	nonce = make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, b.aead.Seal(nil, nonce, plaintext, []byte(aad)), nil
}

// Open 解密一段密钥材料。aad 必须与 Seal 时完全一致。
//
// 错误信息刻意带上 aad 与两段长度：解不开时最常见的根因是「密文行被搬到了
// 另一个 site_id 下」或「主密钥文件被换过」，只报一句 "cipher: message
// authentication failed" 完全指不出方向。
func (b *Box) Open(aad string, nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != b.aead.NonceSize() {
		return nil, fmt.Errorf("secret: nonce 长度应为 %d 字节，实得 %d（密文行可能已损坏）",
			b.aead.NonceSize(), len(nonce))
	}
	pt, err := b.aead.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("secret: 解密失败（aad=%q，密文 %d 字节）——"+
			"通常是密文行被挪到了别的记录下，或主密钥文件（%s）已被替换：%w",
			aad, len(ciphertext), DefaultKeyPathEnv, err)
	}
	return pt, nil
}

// Fingerprint 返回一段密钥材料的**带密钥**指纹（HMAC-SHA256 的十六进制）。
//
// 用途只有一个：让运维能核对隧道两端是不是配了同一把 PSK，而不必回显原文。
//
// ★刻意不用裸 SHA-256(psk)：PSK 很可能是管理员手输的低熵口令，裸哈希（哪怕只
// 露前 8 位）足以离线爆破还原原文，等于把「只写不读」的承诺在指纹这一格漏掉。
// HMAC 让没有主密钥文件的人拿到指纹也无从下手。
//
// ★同样刻意**不掺 site_id**：掺了之后同一把 PSK 在两条站点上指纹不同，
// 「核对两端是否一致」这个唯一用途就没了。
func (b *Box) Fingerprint(material []byte) string {
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte("baidi-ipsec-psk-fingerprint\x00"))
	m.Write(material)
	return hex.EncodeToString(m.Sum(nil))
}

// ── 落盘（原子写 + 严格权限）──

func loadOrCreateKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(raw)
		if blk == nil || blk.Type != pemType {
			return nil, fmt.Errorf("secret: %s 不是有效的 %q PEM 文件", path, pemType)
		}
		if len(blk.Bytes) != KeyLen {
			return nil, fmt.Errorf("secret: %s 中的主密钥应为 %d 字节，实得 %d",
				path, KeyLen, len(blk.Bytes))
		}
		return blk.Bytes, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	buf := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: key})
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	// 原子写：先写同目录临时文件再 rename。直接写目标文件时，进程在写到一半被杀
	// 会留下一个半截的 PEM——下次启动解析失败，而此时库里的密文已经永久解不开了。
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return key, nil
}

// ── 进程级默认加密盒 ──

// defaultBox 懒初始化的进程级加密盒。
//
// ★为什么是包级单例而不是注入到 api.Server：本轮的施工纪律是不动 Server 结构体与
// main.go 的装配（那两处属于别的工作包/后续收口）。用 sync.OnceValues 至少保证
// 「只读一次文件、失败也只失败一次且原因可复现」，而不是每个请求各自打开文件。
// 后续把它并进 config/main 装配时，只需把这里换成构造参数，Seal/Open 语义不变。
var defaultBox = sync.OnceValues(func() (*Box, error) { return Open(DefaultKeyPath()) })

// Default 返回进程级加密盒（首次调用时载入/生成主密钥文件）。
func Default() (*Box, error) { return defaultBox() }
