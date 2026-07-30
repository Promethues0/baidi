package ike

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// 本文件实现 RFC 7296 §2.15 的 PSK 认证：待签字节串的拼接与 AUTH 值的计算/校验。
//
// ★这是整个 PSK 路径上**最危险的一段代码**，不是因为难，而是因为它至少有 6 个
// 互不相干的根因会导致完全相同的一句报错「认证失败」：
//
//  1. "Key Pad for IKEv2" 常量带了 NUL 结尾或长度前缀；
//  2. Ni/Nr 交叉写反（算 Initiator 的 AUTH 要用 **Nr**，算 Responder 的用 **Ni**）；
//  3. RestOfIDPayload 少算了 3 个 RESERVED 字节（只拼 IDType‖Data）；
//  4. RealMessage1/2 被重新序列化过（哪怕语义完全等价，字节也可能不同）；
//  5. COOKIE / INVALID_KE_PAYLOAD 重试后用了第一条报文而不是重发的那条；
//  6. KE 载荷的 MODP 公钥没有前导补零 → g^ir 不同 → SKEYSEED 不同。
//
// 六个根因、一句报错。所以本文件做两件事：把①②③的正确形态写死在代码里（不留手拼余地），
// 并提供 SignedOctetsDigest 让排障时能一眼看出两端到底差在哪一段（④⑤⑥）。

// keyPadForIKEv2 是 RFC 7296 §2.15 规定的固定字符串。
//
// ★17 个 ASCII 字符，**无 NUL 结尾、无长度前缀**：
//
//	4B 65 79 20 50 61 64 20 66 6F 72 20 49 4B 45 76 32
//
// Go 的字符串字面量天然不带 NUL，所以这里是安全的——但从 C 移植或用
// `[18]byte` 之类的写法就会带上一个 0x00，而两端只要有一端多了这一个字节，
// AUTH 就恒不匹配，报错依然只有「认证失败」。auth_test.go 逐字节锁死了它。
const keyPadForIKEv2 = "Key Pad for IKEv2"

// MACedID 计算 MACedIDForI / MACedIDForR：
//
//	MACedIDForI = prf( SK_pi , RestOfInitIDPayload )
//	MACedIDForR = prf( SK_pr , RestOfRespIDPayload )
//
// ★skp 与 id 必须成对：算发起方身份用 SK_pi + IDi，算响应方身份用 SK_pr + IDr。
// 交叉传入不会报错，只会算出一个双方都无法复现的值。
//
// 输入取自 (*IDPayload).RestOfIDPayload()，即 `IDType(1) ‖ RESERVED(3) ‖ Data`——
// 载荷体全文、不含 4 字节通用头。**不要在调用处自己拼字节**：手拼版本漏掉那 3 个
// 保留字节是 PSK 路径上排第三的经典错误，而它同样只报「认证失败」。
func MACedID(prf PRF, skp []byte, id *IDPayload) []byte {
	if prf == nil {
		panic("ike: MACedID 缺少 PRF")
	}
	if id == nil {
		// 显式 panic 而不是让它裸崩：nil 解引用的报错是「invalid memory address」，
		// 对排障毫无帮助；这条消息至少指明是身份载荷没构造出来。
		panic("ike: MACedID 的 ID 载荷为空（IDi/IDr 没构造出来）")
	}
	if len(skp) == 0 {
		panic("ike: MACedID 缺少 SK_pi/SK_pr（密钥派生未完成就开始算 AUTH）")
	}
	return prf.Sum(skp, id.RestOfIDPayload())
}

// SignedOctets 拼出 RFC 7296 §2.15 的待签字节串：
//
//	InitiatorSignedOctets = RealMessage1 ‖ NonceRData ‖ MACedIDForI
//	ResponderSignedOctets = RealMessage2 ‖ NonceIData ‖ MACedIDForR
//
// 三条硬约束：
//
//  1. ★realInitMsg 必须是 `Message.Raw`——**收发时的原始字节**，从 SPIi 第一字节到
//     报文最后一字节，含 28 字节 IKE 头。绝不允许为了算 AUTH 重新序列化：载荷顺序、
//     属性编码形式、保留位的任何差异都会产出不同的字节串，而报错只有「认证失败」。
//  2. ★不含 UDP 4500 的 4 字节 non-ESP marker。RFC 里 GenIKEHDR 会带 marker，但
//     RealMessage1/2 用的是 RealIKEHDR。marker 的加减由 Transport 独占，永远不该
//     泄漏到这一层——泄漏的后果是**只在 NAT 路径上**炸，非 NAT 环境的测试永远发现不了。
//  3. ★peerNonce 是**对端**的 nonce 值（不含 4 字节载荷头），i/r 交叉。为免写反，
//     优先用下面的 InitiatorSignedOctets / ResponderSignedOctets 两个具名包装。
func SignedOctets(realInitMsg, peerNonce, macedID []byte) []byte {
	out := make([]byte, 0, len(realInitMsg)+len(peerNonce)+len(macedID))
	out = append(out, realInitMsg...)
	out = append(out, peerNonce...)
	return append(out, macedID...)
}

// InitiatorSignedOctets 计算发起方要签的字节串。
//
// ★存在的唯一目的是把「交叉」这件事写进函数名：发起方签的是 **Nr**（响应方的 nonce）
// 与 MACedIDForI（自己的身份）。这两个参数类型相同、长度也相同（都是 32 字节），
// 编译器不会替你挡住任何一种写反。
func InitiatorSignedOctets(realMessage1, nr, macedIDForI []byte) []byte {
	return SignedOctets(realMessage1, nr, macedIDForI)
}

// ResponderSignedOctets 计算响应方要签的字节串：RealMessage2 ‖ **Ni** ‖ MACedIDForR。
func ResponderSignedOctets(realMessage2, ni, macedIDForR []byte) []byte {
	return SignedOctets(realMessage2, ni, macedIDForR)
}

// PSKAuth 计算 AUTH 载荷的数据（RFC 7296 §2.15）：
//
//	AUTH = prf( prf( PSK , "Key Pad for IKEv2" ) , SignedOctets )
//
// ★内层 prf 的 key 是 **PSK 原文字节**，不做任何编码转换。控制面若以 hex/base64
// 保存密钥，必须在下发前解码完毕（口径写在 ipsec.SiteConfig.PSK 的注释里）。
// 两端对「原文」的理解不一致时，症状还是那句「认证失败」。
func PSKAuth(prf PRF, psk, signedOctets []byte) []byte {
	if prf == nil {
		panic("ike: PSKAuth 缺少 PRF")
	}
	if len(psk) == 0 {
		// ★空 PSK 在密码学上完全可用：两端都空就能顺利建立一条**没有任何认证**的隧道，
		// 全程零报错、界面显示 up。这正是必须炸掉而不是继续跑的理由。
		//
		// 真正的闸在 ipsec.SiteConfig.Validate()（装载期拒绝空 PSK），这里只是最后一道
		// 绊线；能触发说明有人绕过了配置校验。panic 的取舍与 crypto.go 的 RandBytes 一致：
		// 静默降级出的「安全隧道」比进程崩溃危险得多。
		panic("ike: PSK 为空——空 PSK 能协商成功，会建立一条没有任何认证的隧道")
	}
	if len(signedOctets) == 0 {
		panic("ike: 待签字节串为空（RealMessage1/2 没缓存下来）")
	}
	return prf.Sum(prf.Sum(psk, []byte(keyPadForIKEv2)), signedOctets)
}

// VerifyPSKAuth 校验对端 AUTH 载荷。
//
// ★用 hmac.Equal 做**常量时间**比较。逐字节短路比较会泄漏「前几个字节对了」，
// 攻击者据此可以按字节逐位爆破——虽然本场景下 AUTH 每次交换都变，可利用性不高，
// 但常量时间比较的成本是零，没有理由不用。
//
// 长度不等直接返回 false（hmac.Equal 本身也会处理，此处只是让意图显式）。
func VerifyPSKAuth(prf PRF, psk, signedOctets, got []byte) bool {
	if len(got) == 0 {
		// 空 AUTH 必须判假。若上层某处写成「长度为 0 则跳过比较」，空 AUTH 就成了万能钥匙。
		// （payload_id.go 的 AuthPayload.parseBody 已在解析层拒过一次，这里是第二道。）
		return false
	}
	return hmac.Equal(PSKAuth(prf, psk, signedOctets), got)
}

// SignedOctetsDigest 给出待签字节串的可记录摘要，专供 AUTH 失败时的排障日志。
//
// ★AUTH 失败时两端各持一份互不相同的字节串，但**谁也看不到对方的**。把这一行打进
// 两端日志再对比，就能立刻定位到是哪一段不同：
//   - 报文长度不同 → RealMessage1/2 取错了（多半是 COOKIE 重试后用了第一条，或重新序列化过）；
//   - nonce 长度/摘要不同 → Ni/Nr 交叉写反；
//   - MACedID 摘要不同 → RestOfIDPayload 拼错，或 SK_pi/SK_pr 用反。
//
// 只打长度与哈希前 8 字节，**不打任何密钥材料**：PSK、SK_p* 一次 debug 打印就是永久泄漏。
// 待签字节串本身是公开值（由两条明文 IKE_SA_INIT 报文 + 对端 nonce 组成），可以安全地摘要。
func SignedOctetsDigest(realInitMsg, peerNonce, macedID []byte) string {
	full := sha256.Sum256(SignedOctets(realInitMsg, peerNonce, macedID))
	nonce := sha256.Sum256(peerNonce)
	mid := sha256.Sum256(macedID)
	return fmt.Sprintf("待签=%x(%dB) 报文=%dB 对端nonce=%x(%dB) MACedID=%x(%dB)",
		full[:8], len(realInitMsg)+len(peerNonce)+len(macedID),
		len(realInitMsg),
		nonce[:8], len(peerNonce),
		mid[:8], len(macedID))
}
