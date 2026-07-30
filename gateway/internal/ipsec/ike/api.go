package ike

import "net/netip"

// 本文件是 ike 包内部的**契约文件**：只声明跨工作包共享的数据形状，不含任何行为。
//
// 载荷的 appendBody/parseBody 由报文层实现（payload_*.go），密钥派生与 AUTH 由
// keys.go/auth.go 实现，状态机由 sa.go/initiator.go/responder.go 实现——
// Go 允许方法散落在同包不同文件，因此几个人可以同时动工而不碰同一个文件。
//
// ★改动本文件等于改动所有人的接口，必须先同步；其余文件各自独占。

// ── SA 载荷（Proposal / Transform 三层嵌套）──

// SAPayload 安全联盟载荷。
type SAPayload struct{ Proposals []Proposal }

// Proposal 一个提案。
//
// SPI 长度是三个易错点的集中地：
//   - IKE_SA_INIT 的 IKE 提案：SPI 长度 0（SPI 在报文头里）；
//   - CREATE_CHILD_SA 重协商 IKE SA：8 字节（发送方填自己新生成的那半）；
//   - ESP 提案：4 字节，填**发送方自己入向**的 SPI，语义是「请你用这个 SPI 发给我」。
type Proposal struct {
	Num        uint8 // 从 1 开始连续递增；响应必须回选中的那个编号
	Protocol   ProtocolID
	SPI        []byte
	Transforms []Transform
}

// Transform 一个变换。
//
// KeyLen 是 Key Length 属性（TV 格式，属性类型 14）的值，单位**位**；0 表示未携带。
// ★AES/SM4 提案必须携带它：漏掉不会协商失败，而是协商「成功」后 AUTH 校验失败，
// 现象是一句无头无尾的「认证失败」，属最难定位的一类互通故障。
type Transform struct {
	Type   TransformType
	ID     uint16
	KeyLen uint16
}

// ── KE / Nonce ──

// KEPayload 密钥交换载荷。Data 是**线格式**公钥（ECP256 去 0x04 前缀，MODP 前导补零到定长）。
type KEPayload struct {
	Group uint16
	Data  []byte
}

// NoncePayload Ni/Nr 共用。长度 16..256，且 ≥ PRF 密钥长度的一半；本实现固定发 32 字节。
type NoncePayload struct{ Nonce []byte }

// ── 身份与认证 ──

// IDPayload IDi/IDr。T 区分是哪一个（同一结构服务两种载荷类型）。
//
// ★Data 是 ID 数据本身；AUTH 计算用的 RestOfIDPayload 是
// `IDType(1) ‖ RESERVED(3) ‖ Data`，即去掉 4 字节通用头后的**全部**内容——
// 少算或多算那 3 个保留字节都会让 AUTH 对不上，且报错只有「认证失败」。
type IDPayload struct {
	T      PayloadType // PayloadIDi 或 PayloadIDr
	IDType IDType
	Data   []byte
}

// AuthPayload 认证载荷。本轮 Method 恒为 AuthSharedKeyMIC(2)，Data 为 PRF 输出（32 字节）。
type AuthPayload struct {
	Method AuthMethod
	Data   []byte
}

// ── 流量选择器 ──

// TrafficSelector 一个流量选择器（线格式，IPv4 固定 16 字节 / IPv6 固定 40 字节）。
type TrafficSelector struct {
	Type      TSType
	Proto     uint8 // 0 = 任意
	StartPort uint16
	EndPort   uint16
	Start     netip.Addr
	End       netip.Addr
}

// TSPayload TSi/TSr。T 区分是哪一个。
//
// ★本轮不做 narrowing：responder 要求收到的 TS 与本地配置**逐字节相等**，否则回
// TS_UNACCEPTABLE。理由是策略权威在控制面，网关侧自作主张收窄会造成
// 「控制台配了 /16、实际只通了 /24」这种无报错的假成功。
type TSPayload struct {
	T         PayloadType
	Selectors []TrafficSelector
}

// ── 通知 / 删除 ──

// NotifyPayload 通知载荷。SPI 长度随 Protocol 变化（ESP=4，IKE=0 或 8）。
//
// 字段名是 NotifyType 而不是 Type：Payload 接口已经占用了 Type() 方法名，
// 同名字段与方法在 Go 里不能共存（wire.go 的 FindNotify 也按这个名字读）。
type NotifyPayload struct {
	Protocol   ProtocolID
	SPI        []byte
	NotifyType NotifyType
	Data       []byte
}

// DeletePayload 删除载荷。删 IKE SA 时 Protocol=IKE 且 SPI 列表为空；
// 删 Child SA 时放**自己入向**的 SPI（4 字节）。
type DeletePayload struct {
	Protocol ProtocolID
	SPIs     [][]byte
}

// ── SK（加密载荷）──

// SKPayload 加密并完整性保护的载荷容器。
//
// Body 是**原样密文块**：`IV ‖ 密文 ‖ ICV`，长度切分由套件决定（IV/ICV 长度固定），
// 因此不需要额外的长度字段。解密由 DecryptSK 完成并把内层载荷填回 Message.Payloads。
//
// ★Inner 是通用头里的 Next Payload，指向**被加密的第一个内层载荷**类型，
// 不是外层链的下一个。Decode 解析到 SK 时必须把当时读到的 next 写进这里
// （wire.go 中的特判），否则解密后无从知道内层链的起点。
type SKPayload struct {
	Inner PayloadType
	Body  []byte
}

// ── 密钥材料 ──

// IKEKeys 一个 IKE SA 的七段密钥。
//
// 方向约定：i = **原始发起方 → 响应方**，与「本次交换谁发起」无关，永远看 IKE SA 的原始角色。
// 写反的表现是解密恒失败，而且两端日志都只说「解密失败」。
type IKEKeys struct {
	SKd  []byte // 派生 Child SA 密钥与 IKE 重协商用
	SKai []byte // 完整性：i 方向（combined 模式下为空）
	SKar []byte
	SKei []byte // 加密：i 方向（GCM 时末尾 4 字节是 salt）
	SKer []byte
	SKpi []byte // AUTH 里 MACedIDForI 用
	SKpr []byte
}

// ChildKeys 一条 Child SA 的 KEYMAT 切片结果。
//
// ★切片顺序是 RFC 7296 §2.17 写死的：encr_i ‖ integ_i ‖ encr_r ‖ integ_r，
// 即「i 方向的全部密钥在前，且每方向内加密在前、完整性在后」。
// 按 encr_i‖encr_r‖integ_i‖integ_r 切是常见误读，症状同样是解密恒失败。
type ChildKeys struct {
	EncrI, IntegI []byte
	EncrR, IntegR []byte
}
