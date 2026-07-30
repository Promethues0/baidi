package ike

import (
	"crypto/sha1"
	"encoding/binary"
	"net/netip"
	"time"
)

// NAT 穿越（RFC 3947/7296 §2.23，见 2-ike.md §8）。
//
// 判定的思路是「把我认为的地址签给你，你用实际收到的地址重算」：
// 中间若有 NAT 改写过地址或端口，两个哈希就对不上。这是一个**不需要任何外部
// 信息**就能发现 NAT 的巧妙构造，但它有三个必须逐字踩准的细节：
//
//	① 哈希固定用 **SHA-1**，与协商出的 PRF 无关。用 SHA-256 会算出 32 字节，
//	   对端按 20 字节比对必然不等 → 双方都判定"对端在 NAT 后" → 双双切 4500 →
//	   居然还能通！于是这个错误会一直潜伏到与第三方设备互通时才爆发。
//	② `SPIi ‖ SPIr` 取**本报文 IKE 头里的原始 16 字节**。IKE_SA_INIT 请求里
//	   SPIr 全零，也照样拼进去——不能"因为它是零就跳过"。
//	③ 比对是**交叉**的：我收到的 SOURCE_IP 要用「对端的实际源地址」重算，
//	   我收到的 DESTINATION_IP 要用「我自己实际收包的地址」重算。
//	   写反的症状是 NAT 判定恒反，隧道在**非** NAT 环境下反而建不起来。

// natDetectHash 计算 NAT 检测通知的数据：SHA1( SPIi ‖ SPIr ‖ IP ‖ Port )。
//
// IP 按地址族取 4 或 16 字节网络序，端口 2 字节网络序。
func natDetectHash(spii, spir [8]byte, ap netip.AddrPort) []byte {
	h := sha1.New()
	h.Write(spii[:])
	h.Write(spir[:])
	addr := ap.Addr()
	// ★统一成"IPv4 就是 4 字节"：netip 里的 IPv4-mapped IPv6 地址（::ffff:a.b.c.d）
	// As16() 会给出 16 字节，与对端按 4 字节算出的哈希对不上。Unmap 一次即可根治。
	addr = addr.Unmap()
	h.Write(addr.AsSlice())
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], ap.Port())
	h.Write(port[:])
	return h.Sum(nil)
}

// natNotifies 构造要发出去的两个 NAT 检测通知。
//
// local/remote 是**发送方视角**的源与目的。接收方会用「对端实际源地址」核对
// SOURCE_IP、用「自己实际收包地址」核对 DESTINATION_IP。
func natNotifies(spii, spir [8]byte, local, remote netip.AddrPort) []Payload {
	return []Payload{
		&NotifyPayload{
			Protocol:   ProtocolNone,
			NotifyType: NotifyNATDetectionSourceIP,
			Data:       natDetectHash(spii, spir, local),
		},
		&NotifyPayload{
			Protocol:   ProtocolNone,
			NotifyType: NotifyNATDetectionDestinationIP,
			Data:       natDetectHash(spii, spir, remote),
		},
	}
}

// detectNAT 按收到的报文判定两端是否在 NAT 后。
//
//	seenPeer  = 本端**实际观测到**的对端源地址（不是配置里的 Peer）
//	seenLocal = 本端**实际收包**的本地地址
//
// 返回 (对端在 NAT 后, 本端在 NAT 后, 对端是否发了 NAT 通知)。
//
// ★第三个返回值不可省：对端根本没发通知时，两个判定都必须是 false 而不是
// "哈希对不上所以在 NAT 后"。把"没发"当成"不匹配"会让所有不支持 NAT-T 的对端
// 被误判成 NAT 后，进而被切到 4500 端口——而它根本没监听 4500，隧道就此消失。
func detectNAT(m *Message, seenPeer, seenLocal netip.AddrPort) (peerNATed, localNATed, present bool) {
	src := m.FindNotify(NotifyNATDetectionSourceIP)
	dst := m.FindNotify(NotifyNATDetectionDestinationIP)
	if src == nil && dst == nil {
		return false, false, false
	}
	spii, spir := m.Hdr.SPIi, m.Hdr.SPIr
	if src != nil {
		// 对端说"我的源地址是 X"；我实际看到的是 seenPeer。不等 → 中间有 NAT 改写过源。
		peerNATed = !equalBytes(src.Data, natDetectHash(spii, spir, seenPeer))
	}
	if dst != nil {
		// 对端说"我发给的目的是 Y"；我实际收包的地址是 seenLocal。不等 → 我在 NAT 后。
		localNATed = !equalBytes(dst.Data, natDetectHash(spii, spir, seenLocal))
	}
	return peerNATed, localNATed, true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// applyNAT 把 NAT 判定结果落到 SA 上，并在需要时把收发端口切到 4500。
//
// 规则（2-ike.md §8.2）：
//   - IKE_SA_INIT 在 500 上收发；
//   - 任一侧检测到 NAT → **从 IKE_AUTH 开始**所有 IKE 报文改走 4500，源和目的都换；
//   - 4500 上的 IKE 报文前要加 4 字节 non-ESP marker，但那是 Transport 的事，
//     ★本层永远看不到 marker——RealMessage1/2 的签名字节串不含它（auth.go 第 2 条约束），
//     让 marker 泄漏到这一层就等于给自己埋一颗"只在 NAT 路径上炸"的雷。
//
// natLocal 是本端 4500 的落点。为空（未配 4500）时不切换：与其切到一个不存在的
// 端口让隧道彻底消失，不如维持 500 并把 NAT 情况记录下来。
func (s *IKESA) applyNAT(peerNATed, localNATed bool, natLocal netip.AddrPort, peerEncapPort uint16) {
	s.PeerNATed = peerNATed
	s.LocalNATed = localNATed
	if !peerNATed && !localNATed {
		return
	}
	if !natLocal.IsValid() {
		return
	}
	s.Local = natLocal

	// ★源换了，目的也必须换——否则报文从本端的 4500 口发出（Transport 会加 4 字节
	// non-ESP marker），却落到对端的 **500 口**，而那个口按设计不剥 marker，
	// 收端解析失败后静默丢弃：协商停在 IKE_AUTH，两侧日志都只显示「已发出」，
	// 没有任何一端报错。
	//
	// 但"该换成哪个端口"取决于本端是发起方还是响应方，两者**不能共用一套逻辑**：
	//
	//   响应方：观测到的源端口就是对端 NAT 映射出来的端口，保持它。对端随后从自己的
	//           封装口发来 IKE_AUTH 时，onAuthRequest 会用实测地址覆盖（responder.go
	//           里那句 `sa.Peer = d.Remote`），映射端口在那一刻才真正确定。
	//
	//   发起方：观测到的源端口对应的是响应方的 **IKE 口**（IKE_SA_INIT 从 500 发出）。
	//           响应方切到封装口后端口会变，保持旧值必然发到一个不再监听的端口。
	//           所以要主动切到对端的封装口：优先用配置的 PeerNATPort，没配则按对称
	//           假设取本端封装口的端口号（生产上两端都是 4500）。
	//
	// 不区分角色的后果是**双向 NAT 场景完全不通**（两个分支各自在 NAT 后、靠端口
	// 转发互通是企业组网的常见形态）：双方都保持观测到的对端 IKE 口，于是双方的
	// IKE_AUTH 都发给了对方不再监听的端口。
	if s.LocalIsInit {
		port := peerEncapPort
		if port == 0 {
			port = natLocal.Port()
		}
		s.Peer = netip.AddrPortFrom(s.Peer.Addr(), port)
		return
	}
	if !peerNATed {
		s.Peer = netip.AddrPortFrom(s.Peer.Addr(), natLocal.Port())
	}
}

// espEndpoints 返回这条 SA 的 **ESP 收发落点**（与 IKE 的落点分开算）。
//
// ★这是一个曾经真实存在的静默故障点，务必看完再改：
//
// 本实现刻意**只做 UDP 封装的 ESP（RFC 3948），不做裸 ESP（IP 协议号 50）**。
// 而 applyNAT 只在**检测到 NAT 时**才把落点切到 4500——于是「两端都有公网 IP、
// 中间没有 NAT」这种数据中心互联的常态下，ESP 会被发往对端的 **IKE 端口（500）**。
// 收端的 500 口按设计只跑 IKE，会把 ESP 字节当 IKE 报文解析、失败后静默丢弃。
//
// 结果就是本项目最忌讳的那种失败：**IKE 协商全绿、隧道显示 up、字节数恒为 0、
// 全程没有任何报错**。而且它只在没有 NAT 的部署里出现，有 NAT 的测试环境永远复现不了。
//
// 所以 ESP 的落点必须**无条件**走 UDP 封装口：
//   - 本端固定用 LocalNAT（ESP 只可能从 4500 那条 socket 发出去）；
//   - 对端在 NAT 后时用观测到的源端口（NAT 映射出来的那个）；
//   - 对端不在 NAT 后时用配置里的 PeerNATPort；没配则按对称假设取本端 NAT 口的端口号
//     （生产上两端都是 4500，等价于「对端 IP:4500」）。IKEv2 没有通告对端封装端口的
//     机制，RFC 3948 直接把它定死为 4500，所以非标准端口只能靠显式配置表达。
func (s *IKESA) espEndpoints(natLocal netip.AddrPort, peerEncapPort uint16) (local, peer netip.AddrPort) {
	local, peer = s.Local, s.Peer
	if !natLocal.IsValid() {
		// 没有 NAT-T 口可用（理论上不该发生，构造期就该拒绝）——
		// 保持原样并由上层的字节计数暴露问题，好过在这里猜一个端口。
		return local, peer
	}
	local = natLocal
	if !s.PeerNATed {
		port := peerEncapPort
		if port == 0 {
			port = natLocal.Port() // 对称假设：生产上两端都是 4500
		}
		peer = netip.AddrPortFrom(s.Peer.Addr(), port)
	}
	return local, peer
}

// natKeepaliveInterval NAT 后的一方向对端 4500 发单字节 0xFF 的间隔。
//
// 20 秒是经验值：常见 NAT 设备的 UDP 映射老化时间在 30~120 秒，取 20 秒能
// 覆盖最激进的一档。★不发 keepalive 的症状极具迷惑性——隧道建好后能正常跑，
// 空闲一两分钟后单向不通（NAT 映射老化，对端发来的包没有回程条目），
// 而本端主动发包又会立刻恢复，看起来像"网络时好时坏"。
const natKeepaliveInterval = 20 * time.Second
