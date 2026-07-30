package ike

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// ★套件参数化是本包的第一原则。
//
// IKEv2 的报文编解码、状态机、SPI 管理、rekey、NAT-T、ESP 封装——占了 90% 的工作量，
// 而这些**全部与具体算法无关**。只要从第一行就把算法藏在接口后面，增加一个套件
// （例如国密）的成本就退化为「注册表里加一行 + 几十行胶水」。反过来，如果先把
// AES 硬编码进流程再回头抽象，代价是重写整条链路。
//
// 这也是为什么国密套件能以极低成本存在——但**能实现不等于能声称合规**，
// 私有码点的边界见 const.go 中 EncrSM4GCM16 的注释。

// EncrAlg 加密算法。combined 模式（GCM）自带完整性，此时 Integ 必须为 NONE。
type EncrAlg interface {
	ID() uint16
	// KeyLen 密钥材料总长。★GCM 类算法**含 4 字节 salt**：
	// 派生出的密钥末尾 4 字节是 salt，真正的分组密钥是前面那段。
	// 把 salt 算漏是 combined 模式最常见的实现错误，症状是解密恒失败。
	KeyLen() int
	SaltLen() int
	// IVLen 线上 IV 字段长度。GCM 是 8 字节显式 nonce；CBC 是 16 字节随机 IV。
	IVLen() int
	// BlockSize 明文补齐用的分组长度。GCM 为 1（即不补齐，padLen 恒 0）。
	BlockSize() int
	// ICVLen combined 模式下的认证标签长度；非 combined 为 0（由 IntegAlg 负责）。
	ICVLen() int
	Combined() bool
	Seal(key, iv, aad, plain []byte) ([]byte, error)
	Open(key, iv, aad, ciphertext []byte) ([]byte, error)
}

// PRF 伪随机函数（IKE 的密钥派生与 AUTH 计算都用它）。
type PRF interface {
	ID() uint16
	KeyLen() int
	OutLen() int
	Sum(key, data []byte) []byte
}

// IntegAlg 完整性算法（非 combined 模式才有）。
type IntegAlg interface {
	ID() uint16
	KeyLen() int
	ICVLen() int
	Sum(key, data []byte) []byte
}

// Suite 一组协商定型的算法。Integ 在 combined 模式下为 nil。
type Suite struct {
	Encr  EncrAlg
	PRF   PRF
	Integ IntegAlg
	DH    DHGroup
	ESN   bool
}

// IntegKeyLen 完整性密钥长度；combined 模式为 0（不派生 SK_ai/SK_ar）。
func (s *Suite) IntegKeyLen() int {
	if s.Integ == nil {
		return 0
	}
	return s.Integ.KeyLen()
}

// ICVLen 该套件在 SK 载荷尾部的校验数据长度。
func (s *Suite) ICVLen() int {
	if s.Encr.Combined() {
		return s.Encr.ICVLen()
	}
	if s.Integ == nil {
		return 0
	}
	return s.Integ.ICVLen()
}

// ── AEAD（combined 模式）：AES-GCM / SM4-GCM ──

// aeadAlg 把任意 128 位分组密码包成 IKEv2/ESP 用的 GCM 算法。
// AES 与 SM4 的差异只有 newBlock 一个函数——这正是套件参数化的收益。
type aeadAlg struct {
	id       uint16
	keyBits  int
	newBlock func(key []byte) (cipher.Block, error)
}

func (a *aeadAlg) ID() uint16 { return a.id }

// KeyLen 分组密钥 + 4 字节 salt。
func (a *aeadAlg) KeyLen() int    { return a.keyBits/8 + 4 }
func (a *aeadAlg) SaltLen() int   { return 4 }
func (a *aeadAlg) IVLen() int     { return 8 }
func (a *aeadAlg) BlockSize() int { return 1 } // combined 模式不补齐
func (a *aeadAlg) ICVLen() int    { return 16 }
func (a *aeadAlg) Combined() bool { return true }

// gcm 由密钥材料构造 AEAD。key 的末 4 字节是 salt，不参与分组密钥。
func (a *aeadAlg) gcm(key []byte) (cipher.AEAD, []byte, error) {
	if len(key) != a.KeyLen() {
		return nil, nil, fmt.Errorf("ike: 密钥长度 %d 与套件要求 %d 不符", len(key), a.KeyLen())
	}
	ck, salt := key[:a.keyBits/8], key[a.keyBits/8:]
	blk, err := a.newBlock(ck)
	if err != nil {
		return nil, nil, err
	}
	// SM4 的 gmsm 实现了 cipher.gcmAble，故 stdlib NewGCM 会走它的汇编快路径。
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, err
	}
	return aead, salt, nil
}

func (a *aeadAlg) Seal(key, iv, aad, plain []byte) ([]byte, error) {
	aead, salt, err := a.gcm(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != a.IVLen() {
		return nil, fmt.Errorf("ike: IV 长度 %d 与套件要求 %d 不符", len(iv), a.IVLen())
	}
	// 密码学 nonce = salt(4) ‖ 线上 IV(8)。salt 不上线，靠双方各自从密钥材料里取，
	// 相当于把 nonce 的一半变成共享秘密，也顺带压缩了线上开销。
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, salt...)
	nonce = append(nonce, iv...)
	return aead.Seal(nil, nonce, plain, aad), nil
}

func (a *aeadAlg) Open(key, iv, aad, ct []byte) ([]byte, error) {
	aead, salt, err := a.gcm(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != a.IVLen() {
		return nil, fmt.Errorf("ike: IV 长度 %d 与套件要求 %d 不符", len(iv), a.IVLen())
	}
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, salt...)
	nonce = append(nonce, iv...)
	return aead.Open(nil, nonce, ct, aad)
}

// ── CBC（非 combined，需搭配 IntegAlg）──

type cbcAlg struct {
	id       uint16
	keyBits  int
	newBlock func(key []byte) (cipher.Block, error)
}

func (c *cbcAlg) ID() uint16     { return c.id }
func (c *cbcAlg) KeyLen() int    { return c.keyBits / 8 }
func (c *cbcAlg) SaltLen() int   { return 0 }
func (c *cbcAlg) IVLen() int     { return 16 }
func (c *cbcAlg) BlockSize() int { return 16 }
func (c *cbcAlg) ICVLen() int    { return 0 } // 完整性由 IntegAlg 承担
func (c *cbcAlg) Combined() bool { return false }

func (c *cbcAlg) Seal(key, iv, _, plain []byte) ([]byte, error) {
	blk, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != c.IVLen() || len(plain)%blk.BlockSize() != 0 {
		return nil, errors.New("ike: CBC 明文未按分组补齐或 IV 长度不符")
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, plain)
	return out, nil
}

func (c *cbcAlg) Open(key, iv, _, ct []byte) ([]byte, error) {
	blk, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != c.IVLen() || len(ct) == 0 || len(ct)%blk.BlockSize() != 0 {
		return nil, errors.New("ike: CBC 密文长度非法")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ct)
	return out, nil
}

// ── PRF / INTEG（HMAC 家族）──

type hmacPRF struct {
	id  uint16
	h   func() hash.Hash
	out int
}

func (p *hmacPRF) ID() uint16  { return p.id }
func (p *hmacPRF) KeyLen() int { return p.out }
func (p *hmacPRF) OutLen() int { return p.out }
func (p *hmacPRF) Sum(key, data []byte) []byte {
	m := hmac.New(p.h, key)
	m.Write(data)
	return m.Sum(nil)
}

type hmacInteg struct {
	id     uint16
	h      func() hash.Hash
	keyLen int
	icvLen int
}

func (i *hmacInteg) ID() uint16  { return i.id }
func (i *hmacInteg) KeyLen() int { return i.keyLen }
func (i *hmacInteg) ICVLen() int { return i.icvLen }

// Sum 返回**截断到 ICVLen** 的 MAC。IKEv2 的 AUTH_HMAC_SHA2_256_128 就是
// HMAC-SHA256 取前 128 bit——忘记截断会让 ICV 长度对不上而恒失败。
func (i *hmacInteg) Sum(key, data []byte) []byte {
	m := hmac.New(i.h, key)
	m.Write(data)
	return m.Sum(nil)[:i.icvLen]
}

// ── 算法注册表 ──

func newAES(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }
func newSM4(key []byte) (cipher.Block, error) { return sm4.NewCipher(key) }

// LookupEncr 按 Transform ID + 密钥长度属性取加密算法。
// keyBits 为 0 表示对端未带 Key Length 属性——对 AES/SM4 这是配置错误而非默认值：
// 与其猜一个长度然后在 AUTH 阶段以「认证失败」告终，不如在协商阶段就明确拒绝。
func LookupEncr(id uint16, keyBits int) (EncrAlg, error) {
	switch id {
	case EncrAESGCM16:
		if keyBits != 128 && keyBits != 256 {
			return nil, fmt.Errorf("ike: AES-GCM 需要 128/256 位密钥（收到 %d）", keyBits)
		}
		return &aeadAlg{id: id, keyBits: keyBits, newBlock: newAES}, nil
	case EncrAESCBC:
		if keyBits != 128 && keyBits != 256 {
			return nil, fmt.Errorf("ike: AES-CBC 需要 128/256 位密钥（收到 %d）", keyBits)
		}
		return &cbcAlg{id: id, keyBits: keyBits, newBlock: newAES}, nil
	case EncrSM4GCM16:
		// SM4 只有 128 位密钥，gmsm 的 NewCipher 也只接受 16 字节。
		if keyBits != 0 && keyBits != 128 {
			return nil, fmt.Errorf("ike: SM4 只支持 128 位密钥（收到 %d）", keyBits)
		}
		return &aeadAlg{id: id, keyBits: 128, newBlock: newSM4}, nil
	case EncrSM4CBC:
		if keyBits != 0 && keyBits != 128 {
			return nil, fmt.Errorf("ike: SM4 只支持 128 位密钥（收到 %d）", keyBits)
		}
		return &cbcAlg{id: id, keyBits: 128, newBlock: newSM4}, nil
	}
	return nil, fmt.Errorf("ike: 不支持的加密算法 %d", id)
}

// LookupPRF 按 Transform ID 取 PRF。
func LookupPRF(id uint16) (PRF, error) {
	switch id {
	case PRFHMACSHA256:
		return &hmacPRF{id: id, h: sha256.New, out: 32}, nil
	case PRFHMACSM3:
		// gmsm 未导出专用 HMAC；sm3.New 是标准 hash.Hash，
		// stdlib hmac.New(sm3.New, key) 即 RFC 2104 意义上的 HMAC-SM3。
		return &hmacPRF{id: id, h: sm3.New, out: 32}, nil
	}
	return nil, fmt.Errorf("ike: 不支持的 PRF %d", id)
}

// LookupInteg 按 Transform ID 取完整性算法。IntegNone 返回 (nil, nil)——
// combined 模式下这是合法且**必须**的取值。
func LookupInteg(id uint16) (IntegAlg, error) {
	switch id {
	case IntegNone:
		return nil, nil
	case IntegHMACSHA256128:
		return &hmacInteg{id: id, h: sha256.New, keyLen: 32, icvLen: 16}, nil
	case IntegHMACSM3128:
		return &hmacInteg{id: id, h: sm3.New, keyLen: 32, icvLen: 16}, nil
	}
	return nil, fmt.Errorf("ike: 不支持的完整性算法 %d", id)
}

// PRFPlus 实现 RFC 7296 §2.13 的 prf+ 展开：
//
//	prf+(K,S) = T1 ‖ T2 ‖ T3 ‖ …
//	T1 = prf(K, S ‖ 0x01)
//	Tn = prf(K, T(n-1) ‖ S ‖ n)      n ≥ 2
//
// 计数器是**单字节**，故最多 255 轮。本实现最大需求 224 字节（7 轮），留有充足余量。
func PRFPlus(prf PRF, key, seed []byte, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("ike: prf+ 长度不能为负")
	}
	out := make([]byte, 0, n)
	var prev []byte
	for i := 1; len(out) < n; i++ {
		if i > 255 {
			return nil, errors.New("ike: prf+ 轮数超过单字节计数器上限")
		}
		buf := make([]byte, 0, len(prev)+len(seed)+1)
		buf = append(buf, prev...)
		buf = append(buf, seed...)
		buf = append(buf, byte(i))
		prev = prf.Sum(key, buf)
		out = append(out, prev...)
	}
	return out[:n], nil
}

// RandBytes 生成 n 字节密码学随机数。失败即 panic：
// 熵源不可用时继续跑会产出可预测的 nonce/SPI/DH 私钥，静默降级比崩溃危险得多。
func RandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("ike: 系统熵源不可用: " + err.Error())
	}
	return b
}
