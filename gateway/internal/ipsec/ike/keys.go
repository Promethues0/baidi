package ike

import (
	"errors"
	"fmt"
)

// 本文件实现 RFC 7296 里的四处密钥派生。全部是纯函数——零 I/O、零状态、零随机，
// 因此可以逐字节快照锁死。这段代码值得用快照守住，原因不是它复杂，而是它**错了不报错**：
// 派生写错既不会让协商失败，也不会让任何一端抛异常，只会让后续的 AUTH 校验或 ESP 解密
// 恒失败，而两端日志里只有一句「认证失败」或「解密失败」——从现象上完全指不出根因在这里。
//
// 四个公式（§2.14 / §2.18 / §2.17）：
//
//	SKEYSEED        = prf( Ni ‖ Nr , g^ir )
//	{ SK_d ‖ SK_ai ‖ SK_ar ‖ SK_ei ‖ SK_er ‖ SK_pi ‖ SK_pr }
//	                = prf+( SKEYSEED , Ni ‖ Nr ‖ SPIi ‖ SPIr )
//	SKEYSEED(rekey) = prf( SK_d(旧) , g^ir(新) ‖ Ni ‖ Nr )
//	KEYMAT          = prf+( SK_d , [ g^ir(新) ‖ ] Ni ‖ Nr )
//
// ★三条硬约束，写错的症状都不是「报错」而是「莫名其妙不通」：
//
//  1. 七段密钥的**顺序与长度**都是硬要求。GCM 类算法的 SK_ei/SK_er 长 36 字节
//     （32 分组密钥 + 4 字节 salt），SK_ai/SK_ar 长 **0**。按 32 切会让 SK_er 之后
//     的每一段整体错位，症状是 IKE_AUTH 报文解密失败——而 IKE_SA_INIT 全绿。
//  2. seed 的拼接顺序 `Ni‖Nr‖SPIi‖SPIr` 与「本次交换谁发起」无关；SPI 取**报文头里的
//     原始 8 字节**（i 在前 r 在后）。按本端角色去调换顺序，两端就会各算一套自洽但
//     互不相同的密钥。
//  3. KEYMAT 顺序恒为 `encr_i ‖ integ_i ‖ encr_r ‖ integ_r`（§2.17）。按
//     `encr_i‖encr_r‖integ_i‖integ_r` 切是最常见的误读，且两端会算出**长度一致、
//     内容也一致、位置全错**的密钥——握手全绿，ESP 解密恒失败。

// SKEYSEED 计算 RFC 7296 §2.14 的 SKEYSEED。
//
// ★key 是 `Ni ‖ Nr` 两个 nonce 的**值**（不含 4 字节载荷头），data 是 g^ir。
// key 与 data 写反不会报错，只会让两端算出不同的种子——又一个只报「认证失败」的根因。
//
// g^ir 的口径由 dh.go 保证并在此复述，因为它是另一个静默失败点：
// ECP256/sm2p256 只取 **X 坐标 32 字节**（RFC 5903，不含 Y）；MODP2048 前导补零到 **256 字节**。
func SKEYSEED(prf PRF, ni, nr, dhShared []byte) []byte {
	key := make([]byte, 0, len(ni)+len(nr))
	key = append(key, ni...)
	key = append(key, nr...)
	return prf.Sum(key, dhShared)
}

// DeriveIKEKeys 由 DH 共享秘密与双方 nonce 派生一个新建 IKE SA 的七段密钥。
//
// spii/spir 直接取 IKE 头里的原始 8 字节，**不要**按本端角色调换。
func DeriveIKEKeys(su *Suite, dhShared, ni, nr []byte, spii, spir [8]byte) (*IKEKeys, error) {
	if err := checkKeyInputs(su, dhShared, ni, nr); err != nil {
		return nil, err
	}
	return expandIKEKeys(su, SKEYSEED(su.PRF, ni, nr, dhShared), ni, nr, spii, spir)
}

// DeriveRekeyedIKEKeys 派生 IKE SA 重协商（CREATE_CHILD_SA 换 IKE SA）后的新密钥。
//
// 与新建的唯一差别在 SKEYSEED：
//
//	SKEYSEED = prf( SK_d(旧) , g^ir(新) ‖ Ni ‖ Nr )
//
// ★注意三点：① key 是**旧 SA 的 SK_d**（这正是新旧 SA 之间的信任传递，也是
// 「rekey 不需要重新认证」的依据）；② data 的拼接顺序是 g^ir 在**最前**，与 §2.14
// 的 SKEYSEED 完全不同形状；③ 展开阶段的 SPIi/SPIr 用**新 SA 的** SPI、Ni/Nr 用
// 本次 CREATE_CHILD_SA 的新 nonce。三者任一沿用旧值，症状都是重协商后隧道静默断流。
func DeriveRekeyedIKEKeys(su *Suite, oldSKd, dhShared, ni, nr []byte, spii, spir [8]byte) (*IKEKeys, error) {
	if err := checkKeyInputs(su, dhShared, ni, nr); err != nil {
		return nil, err
	}
	if len(oldSKd) == 0 {
		return nil, errors.New("ike: IKE SA 重协商缺少旧 SA 的 SK_d（新旧 SA 的信任链就断在这里）")
	}
	seed := make([]byte, 0, len(dhShared)+len(ni)+len(nr))
	seed = append(seed, dhShared...)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	return expandIKEKeys(su, su.PRF.Sum(oldSKd, seed), ni, nr, spii, spir)
}

// expandIKEKeys 是 §2.14 的 prf+ 展开与切片，新建与重协商共用（只有 SKEYSEED 的算法不同）。
func expandIKEKeys(su *Suite, skeyseed, ni, nr []byte, spii, spir [8]byte) (*IKEKeys, error) {
	dLen, integLen, encrLen, pLen, err := ikeKeySizes(su)
	if err != nil {
		return nil, err
	}

	// seed = Ni ‖ Nr ‖ SPIi ‖ SPIr，SPI 各 8 字节、原始字节序。
	seed := make([]byte, 0, len(ni)+len(nr)+16)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	seed = append(seed, spii[:]...)
	seed = append(seed, spir[:]...)

	total := dLen + 2*integLen + 2*encrLen + 2*pLen
	buf, err := PRFPlus(su.PRF, skeyseed, seed, total)
	if err != nil {
		return nil, fmt.Errorf("ike: 展开 IKE 密钥失败（需 %d 字节）: %w", total, err)
	}

	// ★切片顺序 = SK_d ‖ SK_ai ‖ SK_ar ‖ SK_ei ‖ SK_er ‖ SK_pi ‖ SK_pr。
	// combined 模式下 integLen==0，SK_ai/SK_ar 各切 0 字节（返回 nil 而非空切片，
	// 让「没有完整性密钥」在调用方看来是明确的 nil，而不是一段长度为 0 的可疑材料）。
	var k IKEKeys
	off := 0
	k.SKd, off = cutKey(buf, off, dLen)
	k.SKai, off = cutKey(buf, off, integLen)
	k.SKar, off = cutKey(buf, off, integLen)
	k.SKei, off = cutKey(buf, off, encrLen)
	k.SKer, off = cutKey(buf, off, encrLen)
	k.SKpi, off = cutKey(buf, off, pLen)
	k.SKpr, off = cutKey(buf, off, pLen)
	if off != total {
		// 走到这里说明上面的切片清单与 total 的算式脱节了（改代码时最容易发生），
		// 与其带着错位的密钥继续跑，不如在这里炸掉。
		return nil, fmt.Errorf("ike: IKE 密钥切片长度自检失败（切了 %d 字节，应为 %d）", off, total)
	}
	return &k, nil
}

// ikeKeySizes 给出七段密钥的长度，并在此集中做套件自洽性校验。
//
// 校验放在这里而不是散在各处，是因为「算法组合非法」的两种形态都会在**更晚**的
// 地方以完全无关的症状暴露：
//   - AEAD 配了 INTEG：多派生 2×32 字节，其后所有段错位 → 解密失败；
//   - CBC 没配 INTEG：报文根本没有完整性保护，攻击者可任意翻转密文比特而无人察觉，
//     且**功能上完全正常**，测试也全绿——这是本文件里唯一一条纯安全性的闸。
func ikeKeySizes(su *Suite) (dLen, integLen, encrLen, pLen int, err error) {
	if su == nil || su.Encr == nil || su.PRF == nil {
		return 0, 0, 0, 0, errors.New("ike: 套件不完整（Encr/PRF 为空），无法派生密钥")
	}
	if su.Encr.Combined() && su.Integ != nil {
		return 0, 0, 0, 0, fmt.Errorf("ike: combined 模式（加密算法 %d 自带完整性）下 INTEG 必须为 NONE，实际配了 %d",
			su.Encr.ID(), su.Integ.ID())
	}
	if !su.Encr.Combined() && su.Integ == nil {
		return 0, 0, 0, 0, fmt.Errorf("ike: 加密算法 %d 不是 combined 模式，必须配 INTEG（否则报文没有任何完整性保护，且功能上一切正常）",
			su.Encr.ID())
	}
	return su.PRF.KeyLen(), su.IntegKeyLen(), su.Encr.KeyLen(), su.PRF.KeyLen(), nil
}

// DeriveChildKeys 派生一条 Child SA 的 KEYMAT 并按 §2.17 的顺序切片。
//
//	无 PFS:  KEYMAT = prf+( SK_d , Ni ‖ Nr )          —— dhShared 传 nil
//	有 PFS:  KEYMAT = prf+( SK_d , g^ir(新) ‖ Ni ‖ Nr )
//
// ★IKE_AUTH 里创建的第一个 Child SA 用的是 **IKE_SA_INIT 的那两个 nonce**，
// 不是别的；CREATE_CHILD_SA 创建的用该次交换的新 nonce。传错的症状是 ESP 解密恒失败
// 而 IKE 层一切正常——两端都会认为「隧道已建立」，只是没有一个包能解开。
//
// encrLen/integLen 是**单方向**的密钥长度，由 ESP 套件决定（GCM 的 encrLen 含 4 字节 salt，
// integLen 为 0）。返回值的 IntegI/IntegR 在 integLen==0 时为 nil。
func DeriveChildKeys(prf PRF, skd, dhShared, ni, nr []byte, encrLen, integLen int) (ChildKeys, error) {
	var ck ChildKeys
	if prf == nil {
		return ck, errors.New("ike: 派生 Child SA 密钥缺少 PRF")
	}
	if len(skd) == 0 {
		return ck, errors.New("ike: 派生 Child SA 密钥缺少 SK_d")
	}
	if len(ni) == 0 || len(nr) == 0 {
		return ck, fmt.Errorf("ike: 派生 Child SA 密钥缺少 nonce（Ni=%d 字节，Nr=%d 字节）", len(ni), len(nr))
	}
	if encrLen <= 0 {
		return ck, fmt.Errorf("ike: Child SA 加密密钥长度 %d 非法", encrLen)
	}
	if integLen < 0 {
		return ck, fmt.Errorf("ike: Child SA 完整性密钥长度 %d 非法", integLen)
	}

	seed := make([]byte, 0, len(dhShared)+len(ni)+len(nr))
	seed = append(seed, dhShared...) // 无 PFS 时为空，拼接自然退化成 Ni‖Nr
	seed = append(seed, ni...)
	seed = append(seed, nr...)

	total := 2 * (encrLen + integLen)
	buf, err := PRFPlus(prf, skd, seed, total)
	if err != nil {
		return ck, fmt.Errorf("ike: 展开 KEYMAT 失败（需 %d 字节）: %w", total, err)
	}

	// ★顺序：encr_i ‖ integ_i ‖ encr_r ‖ integ_r。别按方向分组以外的任何顺序切。
	off := 0
	ck.EncrI, off = cutKey(buf, off, encrLen)
	ck.IntegI, off = cutKey(buf, off, integLen)
	ck.EncrR, off = cutKey(buf, off, encrLen)
	ck.IntegR, off = cutKey(buf, off, integLen)
	if off != total {
		return ChildKeys{}, fmt.Errorf("ike: KEYMAT 切片长度自检失败（切了 %d 字节，应为 %d）", off, total)
	}
	return ck, nil
}

// cutKey 从 buf 的 off 处切走 n 字节，返回**独立副本**与新偏移。
//
// 复制而不是共享底层数组：七段密钥若都指向同一个 buf，任何一处 append 都会
// 静默改写相邻密钥。密钥材料上的这类别名 bug 排查代价极高（现象是「某天开始解密失败」），
// 而复制几十字节的成本可以忽略。n==0 返回 nil，让「无此密钥」是明确的 nil。
func cutKey(buf []byte, off, n int) ([]byte, int) {
	if n == 0 {
		return nil, off
	}
	out := make([]byte, n)
	copy(out, buf[off:off+n])
	return out, off + n
}

// checkKeyInputs 校验派生入参里那些「为空也能算出结果」的项。
//
// ★空 nonce / 空 g^ir 不会让 prf 报错——它照样吐出 32 字节看起来很正常的密钥。
// 于是一条**完全没有随机性**的隧道会顺利建立，两端都显示 up。必须在这里拦住。
func checkKeyInputs(su *Suite, dhShared, ni, nr []byte) error {
	if su == nil || su.PRF == nil {
		return errors.New("ike: 套件缺少 PRF，无法派生密钥")
	}
	if len(dhShared) == 0 {
		return errors.New("ike: DH 共享秘密为空（空值也能算出一套自洽的密钥，故必须显式拒绝）")
	}
	if len(ni) == 0 || len(nr) == 0 {
		return fmt.Errorf("ike: nonce 为空（Ni=%d 字节，Nr=%d 字节），密钥将不含任何一方的随机性", len(ni), len(nr))
	}
	return nil
}
