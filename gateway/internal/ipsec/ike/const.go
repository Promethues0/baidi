// Package ike 实现 IKEv2（RFC 7296）的密钥协商控制面。
//
// # 实现范围
//
// 这是一个**刻意收敛**的 IKEv2 子集，目标是站点到站点（site-to-site）隧道模式组网：
//
//	IKE_SA_INIT → IKE_AUTH（PSK 认证）→ CREATE_CHILD_SA（rekey）→ INFORMATIONAL（DPD/Delete）
//
// # 明确不实现（不是"还没做"，是"本轮定义之外"）
//
//   - EAP、证书认证（AUTH 方法 1/9/14、RFC 7427）——只支持 PSK；
//   - IKEv1；MOBIKE；IKE 分片（RFC 7383）；配置载荷 CP（无虚拟 IP 下发）；
//   - ESN、传输模式、IPComp、TFC padding、多 TS 对与 narrowing、AH；
//   - 窗口 > 1（任一方向最多一个未完成请求）。
//
// 遇到这些配置一律在**装载期显式拒绝**（见 config.go），绝不静默降级——
// 静默降级会造成「控制台配了 A、实际跑了 B」这类无报错的假成功，是本项目历史上
// 最难排查的失败形态。
//
// # 安全边界（重要）
//
// 白帝其余对外端口靠 SPA 敲门 + 内核态丢包实现「隐身」。IKE 做不到：它必须监听
// UDP 500/4500，且**在任何认证之前就要解析对端报文**。这是网关上第一个「非暗」的
// 对外攻击面，因此 wire.go 的解析防护（长度自洽、载荷计数上限、速率限制）是
// 安全要求，不是工程洁癖。
//
// # 诚实声明
//
// 这是自实现的密码学协议，**未经安全审计、未与第三方设备做过实机互通验证**。
// 与主流实现（strongSwan/libreswan）的互通性按 RFC 逐字段对齐设计，但「按标准写」
// 与「实测互通」是两回事，不要混为一谈。
package ike

import "fmt"

// HeaderLen IKE 固定头长度（RFC 7296 §3.1）。
const HeaderLen = 28

// Version IKEv2 版本字节：高 4 位 MjVer=2，低 4 位 MnVer=0。
const Version = 0x20

// ExchangeType IKE 交换类型（RFC 7296 §3.1）。
type ExchangeType uint8

const (
	ExchangeIKESAInit     ExchangeType = 34
	ExchangeIKEAuth       ExchangeType = 35
	ExchangeCreateChildSA ExchangeType = 36
	ExchangeInformational ExchangeType = 37
)

func (e ExchangeType) String() string {
	switch e {
	case ExchangeIKESAInit:
		return "IKE_SA_INIT"
	case ExchangeIKEAuth:
		return "IKE_AUTH"
	case ExchangeCreateChildSA:
		return "CREATE_CHILD_SA"
	case ExchangeInformational:
		return "INFORMATIONAL"
	}
	return fmt.Sprintf("EXCHANGE(%d)", uint8(e))
}

// Flags IKE 头标志位。
//
// ★FlagInitiator 的语义是「本报文由该 IKE SA 的**原始发起方**发出」，
// 而不是「本次交换的发起方」——原始响应方后来自己发起 INFORMATIONAL 时，
// 该位仍为 0。写反会让对端的 Message ID 消歧逻辑错乱（同一个 MID 靠 I 位区分四条报文）。
type Flags uint8

const (
	FlagInitiator Flags = 0x08
	FlagVersion   Flags = 0x10 // 本轮恒 0：不声明支持更高次版本
	FlagResponse  Flags = 0x20
)

// PayloadType 载荷类型（RFC 7296 §3.2）。
type PayloadType uint8

const (
	PayloadNone    PayloadType = 0
	PayloadSA      PayloadType = 33
	PayloadKE      PayloadType = 34
	PayloadIDi     PayloadType = 35
	PayloadIDr     PayloadType = 36
	PayloadCERT    PayloadType = 37 // 本轮只跳过不解释
	PayloadCERTREQ PayloadType = 38 // 本轮只跳过不解释
	PayloadAUTH    PayloadType = 39
	PayloadNonce   PayloadType = 40 // Ni / Nr 共用
	PayloadNotify  PayloadType = 41
	PayloadDelete  PayloadType = 42
	PayloadVendor  PayloadType = 43 // 忽略
	PayloadTSi     PayloadType = 44
	PayloadTSr     PayloadType = 45
	PayloadSK      PayloadType = 46 // Encrypted and Authenticated
	PayloadCP      PayloadType = 47 // 本轮不实现
	PayloadEAP     PayloadType = 48 // 本轮不实现
)

func (p PayloadType) String() string {
	switch p {
	case PayloadNone:
		return "NONE"
	case PayloadSA:
		return "SA"
	case PayloadKE:
		return "KE"
	case PayloadIDi:
		return "IDi"
	case PayloadIDr:
		return "IDr"
	case PayloadCERT:
		return "CERT"
	case PayloadCERTREQ:
		return "CERTREQ"
	case PayloadAUTH:
		return "AUTH"
	case PayloadNonce:
		return "Ni/Nr"
	case PayloadNotify:
		return "N"
	case PayloadDelete:
		return "D"
	case PayloadVendor:
		return "V"
	case PayloadTSi:
		return "TSi"
	case PayloadTSr:
		return "TSr"
	case PayloadSK:
		return "SK"
	}
	return fmt.Sprintf("PAYLOAD(%d)", uint8(p))
}

// ProtocolID 安全协议标识（用于 Proposal / Notify / Delete）。
type ProtocolID uint8

const (
	ProtocolNone ProtocolID = 0 // Notify：不针对特定 SA
	ProtocolIKE  ProtocolID = 1
	ProtocolAH   ProtocolID = 2 // 不实现，仅为识别对端提案
	ProtocolESP  ProtocolID = 3
)

// TransformType SA 载荷中的变换类型（RFC 7296 §3.3.2）。
type TransformType uint8

const (
	TransformEncr  TransformType = 1 // ENCR
	TransformPRF   TransformType = 2 // PRF
	TransformInteg TransformType = 3 // INTEG
	TransformDH    TransformType = 4 // D-H
	TransformESN   TransformType = 5 // Extended Sequence Numbers
)

func (t TransformType) String() string {
	switch t {
	case TransformEncr:
		return "ENCR"
	case TransformPRF:
		return "PRF"
	case TransformInteg:
		return "INTEG"
	case TransformDH:
		return "DH"
	case TransformESN:
		return "ESN"
	}
	return fmt.Sprintf("TRANSFORM_TYPE(%d)", uint8(t))
}

// Transform ID：加密算法（Transform Type 1）。
//
// ★1024 起是 IANA 明文划出的私有使用段（Reserved for Private Use）。白帝的国密套件
// 只能落在这里——IANA **从未**为 SM 系列分配过 IKEv2 码点，而 GM/T 0022 是 IKEv1
// 血统的另一套协议栈，其码点亦不可考。用私有段不违规，但按定义**不保证跨厂商唯一**：
// 这些套件只承诺白帝↔白帝互通，绝不可对外声称"国密 IPSec"或 GM/T 合规。
const (
	EncrAESCBC   uint16 = 12   // ENCR_AES_CBC
	EncrAESGCM16 uint16 = 20   // ENCR_AES_GCM_16（combined mode，RFC 5282）
	EncrSM4GCM16 uint16 = 1044 // 白帝私有：SM4-GCM，16 字节 ICV
	EncrSM4CBC   uint16 = 1042 // 白帝私有：SM4-CBC
)

// Transform ID：伪随机函数（Transform Type 2）。
const (
	PRFHMACSHA256 uint16 = 5
	PRFHMACSM3    uint16 = 1025 // 白帝私有：HMAC-SM3
)

// Transform ID：完整性算法（Transform Type 3）。
const (
	IntegNone          uint16 = 0  // combined mode（GCM）下必须为 NONE
	IntegHMACSHA256128 uint16 = 12 // AUTH_HMAC_SHA2_256_128
	IntegHMACSM3128    uint16 = 1024
)

// Transform ID：DH 群（Transform Type 4）。
const (
	DHNone     uint16 = 0  // 无 PFS 的 Child SA
	DHModp2048 uint16 = 14 // MODP-2048（RFC 3526 §3）
	DHEcp256   uint16 = 19 // ECP-256（RFC 5903）
	DHSm2P256  uint16 = 1024
)

// Transform ID：扩展序列号（Transform Type 5）。本轮只提 ESNNone。
const (
	ESNNone uint16 = 0
	ESNUse  uint16 = 1
)

// AttrKeyLength 变换属性类型：密钥长度（TV 格式）。
//
// ★AES/SM4 的提案**必须**携带该属性，否则对端按默认（通常 128 位）解读。
// 密钥长度不一致的后果不是协商失败，而是协商"成功"后 AUTH 校验失败——
// 现象是一句无头无尾的「认证失败」，是最难定位的一类互通故障。
const AttrKeyLength uint16 = 14

// IDType 身份类型（RFC 7296 §3.5）。
type IDType uint8

const (
	IDIPv4Addr  IDType = 1
	IDFQDN      IDType = 2
	IDRFC822    IDType = 3
	IDIPv6Addr  IDType = 5
	IDDerASN1DN IDType = 9
	IDKeyID     IDType = 11
)

// AuthMethod AUTH 载荷的认证方法。本轮只支持 PSK。
type AuthMethod uint8

const (
	AuthRSASig       AuthMethod = 1 // 不支持，收到即 AUTHENTICATION_FAILED
	AuthSharedKeyMIC AuthMethod = 2 // PSK：唯一支持项
	AuthDSSSig       AuthMethod = 3 // 不支持
	AuthDigitalSig   AuthMethod = 14
)

// NotifyType 通知类型（RFC 7296 §3.10.1）。
//
// ★分界线在 16384：**小于 16384 是错误**，出现在响应里意味着交换失败；
// **大于等于 16384 是状态**，不认识的**必须静默忽略**。这条是互通的生命线——
// strongSwan 默认会发 IKE_FRAGMENTATION_SUPPORTED / SIGNATURE_HASH_ALGORITHMS /
// MOBIKE_SUPPORTED / REDIRECT_SUPPORTED，把它们当错误处理会导致完全无法建连。
type NotifyType uint16

const (
	// 错误类（< 16384）
	NotifyUnsupportedCriticalPayload NotifyType = 1
	NotifyInvalidIKESPI              NotifyType = 4
	NotifyInvalidMajorVersion        NotifyType = 5
	NotifyInvalidSyntax              NotifyType = 7
	NotifyInvalidMessageID           NotifyType = 9
	NotifyNoProposalChosen           NotifyType = 14
	NotifyInvalidKEPayload           NotifyType = 17
	NotifyAuthenticationFailed       NotifyType = 24
	NotifySinglePairRequired         NotifyType = 34
	NotifyNoAdditionalSAs            NotifyType = 35
	NotifyInternalAddressFailure     NotifyType = 36
	NotifyFailedCPRequired           NotifyType = 37
	NotifyTSUnacceptable             NotifyType = 38
	NotifyInvalidSelectors           NotifyType = 39
	NotifyTemporaryFailure           NotifyType = 43
	NotifyChildSANotFound            NotifyType = 44

	// 状态类（>= 16384）
	NotifyInitialContact            NotifyType = 16384
	NotifySetWindowSize             NotifyType = 16385
	NotifyNATDetectionSourceIP      NotifyType = 16388
	NotifyNATDetectionDestinationIP NotifyType = 16389
	NotifyCookie                    NotifyType = 16390
	NotifyUseTransportMode          NotifyType = 16391
	NotifyRekeySA                   NotifyType = 16393
	NotifyESPTFCPaddingNotSupported NotifyType = 16394
	NotifyNonFirstFragments         NotifyType = 16395
	NotifyMobikeSupported           NotifyType = 16396
	NotifyRedirectSupported         NotifyType = 16406
	NotifyIKEFragmentationSupported NotifyType = 16430
	NotifySignatureHashAlgorithms   NotifyType = 16431
)

// IsError 报告该通知是否为错误类（< 16384）。状态类未知值必须忽略，错误类未知值应中止交换。
func (n NotifyType) IsError() bool { return n < 16384 }

func (n NotifyType) String() string {
	switch n {
	case NotifyUnsupportedCriticalPayload:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case NotifyInvalidIKESPI:
		return "INVALID_IKE_SPI"
	case NotifyInvalidMajorVersion:
		return "INVALID_MAJOR_VERSION"
	case NotifyInvalidSyntax:
		return "INVALID_SYNTAX"
	case NotifyInvalidMessageID:
		return "INVALID_MESSAGE_ID"
	case NotifyNoProposalChosen:
		return "NO_PROPOSAL_CHOSEN"
	case NotifyInvalidKEPayload:
		return "INVALID_KE_PAYLOAD"
	case NotifyAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case NotifyTSUnacceptable:
		return "TS_UNACCEPTABLE"
	case NotifyTemporaryFailure:
		return "TEMPORARY_FAILURE"
	case NotifyChildSANotFound:
		return "CHILD_SA_NOT_FOUND"
	case NotifyInitialContact:
		return "INITIAL_CONTACT"
	case NotifyNATDetectionSourceIP:
		return "NAT_DETECTION_SOURCE_IP"
	case NotifyNATDetectionDestinationIP:
		return "NAT_DETECTION_DESTINATION_IP"
	case NotifyCookie:
		return "COOKIE"
	case NotifyRekeySA:
		return "REKEY_SA"
	}
	return fmt.Sprintf("NOTIFY(%d)", uint16(n))
}

// TSType 流量选择器类型（RFC 7296 §3.13.1）。
type TSType uint8

const (
	TSIPv4AddrRange TSType = 7
	TSIPv6AddrRange TSType = 8
)

// 解析防护上限。IKE_SA_INIT 是**未经认证**的攻击面，这些上限用于挡住
// 「用极少字节撑出极多结构」的资源耗尽型畸形包。数值取得比任何合法报文都宽松，
// 正常互通不会触碰。
const (
	MaxPayloads           = 32
	MaxProposals          = 16
	MaxTransformsPerPro   = 16
	MaxAttributesPerXform = 8
	MaxMessageLen         = 65535
	MinNonceLen           = 16
	MaxNonceLen           = 256
	MaxTrafficSelectors   = 8
)
