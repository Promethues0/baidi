package ike

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"math/big"

	gmecdh "github.com/emmansun/gmsm/ecdh"
)

// DHGroup 一个 Diffie-Hellman 群。
//
// ★线格式（wire format）是最容易踩的坑，各群规则不同且**不带自描述信息**：
//   - ECP-256（group19，RFC 5903）：KE 数据 = X(32) ‖ Y(32) = 64 字节，**不带 0x04 前缀**。
//     Go 的 crypto/ecdh 要求未压缩点带 0x04 前缀，故收发两侧都要手工加/去。
//   - MODP-2048（group14）：256 字节大端整数，**必须前导补零到定长**。
//     不补零是经典互通 bug——对端按定长解析，短一个字节整个共享秘密就错了。
//
// 而错误的表现形式统一是「AUTH 校验失败」这一句话，完全看不出根因在 KE 编码上。
type DHGroup interface {
	ID() uint16
	// PubLen 线上公钥字节数（用于解析期长度校验）。
	PubLen() int
	// SharedLen 共享秘密字节数。
	SharedLen() int
	Generate(rand io.Reader) (DHPrivate, error)
}

// DHPrivate 一次性 DH 私钥。
type DHPrivate interface {
	// Public 返回**线格式**公钥（已按上述规则处理前缀/补零）。
	Public() []byte
	// Shared 用对端线格式公钥算共享秘密，内含对端公钥合法性校验。
	Shared(peerPub []byte) ([]byte, error)
}

// LookupDH 按 Transform ID 取 DH 群。DHNone 返回 (nil, nil)——
// 无 PFS 的 Child SA 合法地不带 KE。
func LookupDH(id uint16) (DHGroup, error) {
	switch id {
	case DHNone:
		return nil, nil
	case DHEcp256:
		return &ecdhGroup{id: id, curve: stdCurve{ecdh.P256()}, coord: 32}, nil
	case DHSm2P256:
		// ★gmsm 的 ecdh.P256() 是 **sm2p256v1**，不是 NIST P-256——命名极易误读。
		// 它与 crypto/ecdh 的 P256() 是两条不同的曲线，绝不能互换。
		return &ecdhGroup{id: id, curve: gmCurve{gmecdh.P256()}, coord: 32}, nil
	case DHModp2048:
		return &modpGroup{id: id, p: modp2048P, g: big.NewInt(2), size: 256}, nil
	}
	return nil, fmt.Errorf("ike: 不支持的 DH 群 %d", id)
}

// ── ECDH（group19 / 国密 sm2p256v1）──

// ecdhKey / ecdhCurve 是对 crypto/ecdh 与 gmsm/ecdh 的最小抽象。
// 两个库的 PrivateKey/PublicKey 是**互不相同的具体类型**（不是同一接口的两个实现），
// 所以没法直接共用；抽到「拿公钥字节」「算共享秘密」这两个动作上就统一了，
// 各自的适配器只有几行。
type ecdhKey interface {
	// publicUncompressed 返回 0x04 ‖ X ‖ Y 形式的未压缩点。
	publicUncompressed() []byte
	// sharedWith 输入同样是未压缩点，返回 X 坐标（即 g^ir）。
	sharedWith(peerUncompressed []byte) ([]byte, error)
}

type ecdhCurve interface {
	generate(io.Reader) (ecdhKey, error)
}

// stdCurve 适配 crypto/ecdh（NIST 曲线，group19 走这条）。
type stdCurve struct{ c ecdh.Curve }

func (s stdCurve) generate(rand io.Reader) (ecdhKey, error) {
	k, err := s.c.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return stdKey{c: s.c, k: k}, nil
}

type stdKey struct {
	c ecdh.Curve
	k *ecdh.PrivateKey
}

func (s stdKey) publicUncompressed() []byte { return s.k.PublicKey().Bytes() }

func (s stdKey) sharedWith(peer []byte) ([]byte, error) {
	// NewPublicKey 内含曲线上点校验与无穷远点排除——
	// 无效点在这里就被拒，不需要（也不应该）自己实现点校验。
	pub, err := s.c.NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return s.k.ECDH(pub)
}

// gmCurve 适配 gmsm/ecdh（sm2p256v1）。
type gmCurve struct{ c gmecdh.Curve }

func (g gmCurve) generate(rand io.Reader) (ecdhKey, error) {
	k, err := g.c.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return gmKey{c: g.c, k: k}, nil
}

type gmKey struct {
	c gmecdh.Curve
	k *gmecdh.PrivateKey
}

func (g gmKey) publicUncompressed() []byte { return g.k.PublicKey().Bytes() }

func (g gmKey) sharedWith(peer []byte) ([]byte, error) {
	pub, err := g.c.NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return g.k.ECDH(pub)
}

type ecdhGroup struct {
	id    uint16
	curve ecdhCurve
	coord int // 单个坐标的字节数
}

func (g *ecdhGroup) ID() uint16     { return g.id }
func (g *ecdhGroup) PubLen() int    { return g.coord * 2 }
func (g *ecdhGroup) SharedLen() int { return g.coord }

func (g *ecdhGroup) Generate(rand io.Reader) (DHPrivate, error) {
	k, err := g.curve.generate(rand)
	if err != nil {
		return nil, err
	}
	return &ecdhPrivate{g: g, key: k}, nil
}

type ecdhPrivate struct {
	g   *ecdhGroup
	key ecdhKey
}

// Public 去掉 0x04 未压缩点前缀，得到 RFC 5903 规定的 X‖Y。
func (p *ecdhPrivate) Public() []byte {
	return p.key.publicUncompressed()[1:]
}

func (p *ecdhPrivate) Shared(peerPub []byte) ([]byte, error) {
	if len(peerPub) != p.g.PubLen() {
		return nil, fmt.Errorf("ike: KE 数据长度 %d 与群 %d 要求的 %d 不符", len(peerPub), p.g.id, p.g.PubLen())
	}
	// 补回 0x04 前缀交给库做点校验。
	uncompressed := make([]byte, 0, 1+len(peerPub))
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, peerPub...)
	shared, err := p.key.sharedWith(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("ike: 对端 KE 公钥非法: %w", err)
	}
	// 返回值正是 X 坐标，按 RFC 5903 它**就是** g^ir（不含 Y）。
	return shared, nil
}

// ── MODP（group14）──

type modpGroup struct {
	id   uint16
	p    *big.Int
	g    *big.Int
	size int // 定长字节数（2048 位 = 256）
}

func (m *modpGroup) ID() uint16     { return m.id }
func (m *modpGroup) PubLen() int    { return m.size }
func (m *modpGroup) SharedLen() int { return m.size }

func (m *modpGroup) Generate(rand io.Reader) (DHPrivate, error) {
	// 私钥取 256 位随机数即可：MODP-2048 的安全强度约 112 位，
	// 指数长度取到 2× 安全强度已远超需求，且远快于取满 2048 位。
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand, buf); err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(buf)
	if x.Sign() == 0 {
		return nil, errors.New("ike: DH 私钥为零（熵源异常）")
	}
	return &modpPrivate{g: m, x: x, pub: new(big.Int).Exp(m.g, x, m.p)}, nil
}

type modpPrivate struct {
	g   *modpGroup
	x   *big.Int
	pub *big.Int
}

// Public 前导补零到定长——这是 MODP 群互通的硬要求。
func (p *modpPrivate) Public() []byte {
	return p.pub.FillBytes(make([]byte, p.g.size))
}

func (p *modpPrivate) Shared(peerPub []byte) ([]byte, error) {
	if len(peerPub) != p.g.size {
		return nil, fmt.Errorf("ike: KE 数据长度 %d 与 MODP-%d 要求不符", len(peerPub), p.g.size*8)
	}
	y := new(big.Int).SetBytes(peerPub)
	// ★必须校验 1 < y < p-1。否则对端可送 0/1/p-1 这类小阶元素，
	// 使共享秘密落进极小的子群，DH 形同虚设（小子群约束攻击）。
	// crypto/ecdh 会替我们做等价校验，MODP 没有库可依赖，只能自己写。
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p.g.p, one)
	if y.Cmp(one) <= 0 || y.Cmp(pMinus1) >= 0 {
		return nil, errors.New("ike: 对端 DH 公钥落在小子群（1 < y < p-1 校验失败）")
	}
	return new(big.Int).Exp(y, p.x, p.g.p).FillBytes(make([]byte, p.g.size)), nil
}

// modp2048P 是 RFC 3526 §3 定义的 2048 位 MODP 群素数（group 14），生成元 g=2。
var modp2048P, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
