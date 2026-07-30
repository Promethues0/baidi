package esp

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/ike"
)

// 本文件只放测试共用的构造器与断言辅助，不含任何断言逻辑本身。
// 名字统一带 esp 前缀，避免与将来加进本包的生产标识符撞名。

// espSuite 一个待测套件。keyLen/integLen 是**期望的密钥材料长度**，
// 写死在表里而不是从算法对象反查——反查等于用被测代码验证被测代码，
// 「salt 被算漏」这类错误会一起被漏掉。
type espSuite struct {
	name     string
	encrID   uint16
	keyBits  int
	integID  uint16
	keyLen   int
	integLen int
	ivLen    int
	icvLen   int
}

// espSuites 覆盖标准与国密两条路径。国密走 IANA 私有码点，只承诺白帝↔白帝互通，
// 但**加解密本身必须与标准算法一样被测到**——「SM 算法只在注册表里被 lookup 过、
// 整条数据面从没真跑过」正是最容易蒙混过关的形态。
var espSuites = []espSuite{
	{"AES256-GCM16", ike.EncrAESGCM16, 256, ike.IntegNone, 36, 0, 8, 16},
	{"AES128-GCM16", ike.EncrAESGCM16, 128, ike.IntegNone, 20, 0, 8, 16},
	{"AES256-CBC+HMAC-SHA256-128", ike.EncrAESCBC, 256, ike.IntegHMACSHA256128, 32, 32, 16, 16},
	{"SM4-GCM16（私有码点）", ike.EncrSM4GCM16, 128, ike.IntegNone, 20, 0, 8, 16},
	{"SM4-CBC+HMAC-SM3-128（私有码点）", ike.EncrSM4CBC, 128, ike.IntegHMACSM3128, 16, 32, 16, 16},
}

// espKey 生成一段确定性的密钥材料。seed 不同 = 密钥不同，且内容一眼可辨，
// 便于在失败输出里区分「拿错了哪一段」。
func espKey(n int, seed byte) []byte {
	if n == 0 {
		return nil
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = seed ^ byte(i*7+1)
	}
	return b
}

// espTSLocal / espTSRemote A 侧视角的两个受保护网段。
var (
	espTSA = netip.MustParsePrefix("10.60.0.0/24")
	espTSB = netip.MustParsePrefix("10.70.0.0/24")
	espEPA = netip.MustParseAddrPort("198.51.100.1:4500")
	espEPB = netip.MustParseAddrPort("198.51.100.2:4500")
)

// espPair 造出一对**互为镜像**的 ChildSAParams，模拟 IKE 协商后两端各自装载的结果。
//
// ★镜像关系是 ESP 能不能通的全部：A 的出向 SPI/密钥必须等于 B 的入向 SPI/密钥。
// 把它集中在一个构造器里，是为了让「方向写反」只可能错在这一处，而不是散落到每个测试。
func espPair(s espSuite) (a, b ipsec.ChildSAParams) {
	const (
		spiA = uint32(0x11223344) // A 的入向 = B 的出向
		spiB = uint32(0x55667788) // B 的入向 = A 的出向
	)
	kAB, iAB := espKey(s.keyLen, 0xA0), espKey(s.integLen, 0xA1) // A→B 方向
	kBA, iBA := espKey(s.keyLen, 0xB0), espKey(s.integLen, 0xB1) // B→A 方向

	a = ipsec.ChildSAParams{
		SiteID: "site-a", InSPI: spiA, OutSPI: spiB,
		EncrID: s.encrID, KeyBits: s.keyBits, IntegID: s.integID,
		OutEncrKey: kAB, OutIntegKey: iAB,
		InEncrKey: kBA, InIntegKey: iBA,
		LocalTS: espTSA, RemoteTS: espTSB,
		Local: espEPA, Peer: espEPB,
	}
	b = ipsec.ChildSAParams{
		SiteID: "site-b", InSPI: spiB, OutSPI: spiA,
		EncrID: s.encrID, KeyBits: s.keyBits, IntegID: s.integID,
		OutEncrKey: kBA, OutIntegKey: iBA,
		InEncrKey: kAB, InIntegKey: iAB,
		LocalTS: espTSB, RemoteTS: espTSA,
		Local: espEPB, Peer: espEPA,
	}
	return a, b
}

// espIPv4 造一个最小但结构合法的 IPv4 包（不算校验和——本包不校验，也不该校验：
// 校验和是内层端点的事，隧道中间层去算它只会在 TSO 场景下误杀）。
func espIPv4(src, dst string, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45 // Version 4 / IHL 5
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	copy(p[12:16], netip.MustParseAddr(src).AsSlice())
	copy(p[16:20], netip.MustParseAddr(dst).AsSlice())
	copy(p[20:], payload)
	return p
}

// espIPv6 造一个最小的 IPv6 包。
func espIPv6(src, dst string, payload []byte) []byte {
	p := make([]byte, 40+len(payload))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(len(payload)))
	p[6] = 17 // Next Header = UDP
	p[7] = 64 // Hop Limit
	copy(p[8:24], netip.MustParseAddr(src).AsSlice())
	copy(p[24:40], netip.MustParseAddr(dst).AsSlice())
	copy(p[40:], payload)
	return p
}

// espClock 注入时钟。生存期/rekey 判定绝不能靠 sleep：那样的测试慢且随机红绿，
// 最后必然被 -short 跳过，等于没有测试。
type espClock struct{ t time.Time }

func newESPClock() *espClock {
	return &espClock{t: time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)}
}

func (c *espClock) now() time.Time               { return c.t }
func (c *espClock) advance(d time.Duration)      { c.t = c.t.Add(d) }
func (c *espClock) at(d time.Duration) time.Time { return c.t.Add(d) }

// espMustInstall 装载并在失败时立即终止——装载失败后继续跑只会产生一串
// 互相掩盖的次生错误。
func espMustInstall(t *testing.T, e *Engine, p ipsec.ChildSAParams) {
	t.Helper()
	if err := e.Install(p); err != nil {
		t.Fatalf("装载 SA 失败（站点 %s）：%v", p.SiteID, err)
	}
}
