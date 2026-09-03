package dataplane

import (
	"fmt"
	"log/slog"
	"sync"
	"unicode"
)

// HealthState 是数据面真实健康状态的**共享载体**：一份状态，两种渲染
// （给桌面端的日志行 logHealth，给移动端绑定层的类型化 Snapshot）。
//
// ★为什么要把它从 tunneler 里抽出来（wave10 移动端接入态）：
// tunneler 是 Run 内部造的，外面一个字都读不到，于是移动端只能靠"Baidimobile.start 返回了"
// 判接入成功。2026-09-03 安卓真机（OPPO PKU110 / Android 16）实测正是这个形态——
// 同一时刻桥的 tunnelStatus() 回 {"stage":"up"}、startTunnel 回「数据面已就绪」，
// 而 Go 健康行是 knock=false tunnel=false err="取敲门令牌失败：… x509: certificate signed by
// unknown authority"：**引擎起来了、门没敲开，界面却显示已接入**。桌面端 wave10 已经把接入态
// 改判这份健康状态（tunnel.ts 的 parseHealth），移动端没跟上，因为它根本拿不到。
// 现在 HealthState 可以**先于 Run 存在**（调用方 new 好塞进 Config），绑定层因此能直接读。
//
// ★接入页此前把「已接入 / 数据面就绪」与「SPA 敲门保活」判成两行**启动日志**的存在
// （`/数据面就绪/.test(log)` 与 `/敲门保活/.test(log)`），而那两行分别打印于
// 任何一次 knock 与任何一次拨号**之前**——纯粹是"netstack 装好了""ticker 起来了"。
// 于是三类真实故障在界面上完全看不见：全部落点拨不通、gm 开关与网关不一致导致
// 握手 100% 失败、以及指纹钉扎失败（判定为"疑似中间人"）——界面一律绿色「已接入」。
// 现在改成按**真实事件**回报：敲门有没有成功过、隧道有没有拨通过、最近一次失败是什么。
//
// ★失败原因**按类别分记**（wave10）：此前只有一个 lastErr，markKnock 与 markTunnel 都不分类别地清空它，
// 而保活敲门每 15s 成功一次——「网关证书指纹不匹配（疑似中间人）」这类隧道拨号失败在健康行里最多挂 15s
// 就被一次与它无关的敲门成功擦掉，TS 侧只能靠粘性提示条兜底（见 docs/ARCHITECTURE.md 第七节
// 「桌面端接入态判据」边界①）。现在敲门成功只清 knockErr、隧道拨通只清 tunnelErr。
//
// 并发安全：knock() 对每个落点各起一个 goroutine，各自在成功/失败时调 mark*；
// 而移动端 UI 每 2s 从另一个线程调 Snapshot()。所有读写都在 mu 内。
type HealthState struct {
	mu         sync.Mutex
	knockOK    bool      // 至少成功发出过一次 SPA 敲门包
	tunnelOK   bool      // 至少成功拨通过一次隧道
	knockErr   string    // 最近一次**敲门类**失败（取令牌 / SPA 拨号），敲门成功即清
	tunnelErr  string    // 最近一次**隧道类**失败（落点拨不通 / 握手失败 / 指纹不匹配…），隧道拨通即清
	lastClass  failClass // 最近一次被 mark* 触碰的类别（err= 键按它取值，见 logHealth）
	lastHealth string    // 上一次打印的健康行，用于去重（每条流都打会把日志冲爆）
}

// NewHealthState 建一份空的健康状态：什么都还没发生过（Observed 为 false）。
func NewHealthState() *HealthState { return &HealthState{} }

// HealthSnapshot 是健康状态在某一瞬间的整体快照，供绑定层/客户端做类型化判定。
//
// ★为什么要**整体**快照而不是给每项配一个 getter：调用方要按「knock ∧ err 为空」这类
// 组合条件判就绪，逐项读的话两次读之间状态会变（保活敲门每 15s 就动一次），
// 于是能读出「knock=true 且 err 非空」这种从未真实存在过的组合，判定结果无法复现。
type HealthSnapshot struct {
	// Observed 报告「这份状态里有没有任何真实事件」。
	//
	// ★它是**派生量、不另存字段**：多存一个 bool 就多一个会与三项事实走散的真相来源。
	// 它的用途是把「还没敲过第一次门」与「敲过了、没问题」分开——两者的处置相反：
	// 前者应当继续等（接入中），后者才是就绪。塌成同形正是本波要消灭的那个形态。
	Observed bool

	Knock  bool // 曾成功发出过 SPA 敲门包（粘性）
	Tunnel bool // 曾拨通过隧道（粘性）

	KnockErr  string // 最近一次敲门类失败（空 = 该类当前无失败）
	TunnelErr string // 最近一次隧道类失败（= 健康行的 terr=）
	Err       string // 最近一次被触碰的那一类的当前错误（= 健康行的 err=，语义见 healthPrefix）
}

// Snapshot 一次持锁取全部六项。
func (h *HealthState) Snapshot() HealthSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.snapshotLocked()
}

// snapshotLocked 是**这份状态唯一的读出口**（须持 mu）：Snapshot 与 logHealth 都从它取值。
//
// ★为什么必须同源：日志行与类型化读端若各读各的字段，就是两个真相来源——
// 出现不一致时两边都不报错，而排障的人手里正好只有这两样东西（真机上捞日志、界面上看状态），
// 两者互相印证是唯一的自证手段。让 logHealth 变成"同一份快照的另一种渲染"，
// 不一致在结构上就不可能发生。
func (h *HealthState) snapshotLocked() HealthSnapshot {
	s := HealthSnapshot{
		Knock: h.knockOK, Tunnel: h.tunnelOK,
		KnockErr: h.knockErr, TunnelErr: h.tunnelErr,
		Err: h.currentErrLocked(),
	}
	s.Observed = s.Knock || s.Tunnel || s.KnockErr != "" || s.TunnelErr != ""
	return s
}

// failClass 是健康状态里失败原因的类别：敲门类 / 隧道类。
type failClass uint8

const (
	classKnock  failClass = iota // 取敲门令牌 / SPA 拨号
	classTunnel                  // 隧道落点拨号 / 握手 / 指纹钉扎
)

// 健康行的固定前缀。客户端（tunnel.ts）按它解析，改这里要同步改那边的正则。
//
// ★健康行契约（键序即契约，客户端 `tunnel.ts parseHealth` 按键名解析）：
// `数据面健康 knock=<bool> tunnel=<bool> terr=<str> err=<str>`
// · knock / tunnel：粘性位，「曾」成功过（tunnel 只在业务流真拨通时置位，Run 启动期不预拨）。
// · err：**语义与拆分前逐字一致**——最近一次被触碰的那一类的当前错误：任何一次失败把它设成该原因，
// 任何一次成功（含每 15s 的保活敲门）把它清成 `-`。旧 TS 按 `ready = knock ∧ err 为空` 判接入态，
// 这个键必须保持这个语义：若让隧道类失败在 err 里粘住，旧 TS 会在一次瞬时拨号失败后把 `ready`
// 卡成 false → 应用页拒绝「访问」→ 永远产生不出下一条流去清它（就是边界①里写过的那种死锁）。
// · terr（wave10 新增）：**隧道类**最近一次失败，只被隧道拨通清掉、敲门成功碰不到它——持续性的
// 「指纹不匹配 / 落点拨不通 / gm 开关不一致」告警靠它稳定在界面上。为空时同样写 `-`。
// · ★terr 必须排在 err **之前**：parseHealth 对 err 取的是 `err=` 之后到行尾的全部（值是含空格与中文标点
// 的自由文本，slog 可能加引号也可能不加），排在后面会被旧 TS 当成 err 值的一部分吞掉。
// `terr=` 前面是字母 t 不是空白，不会被 `(?:^|\s)err=` 误配。
// · ★值域由 `sanitizeReason` 统一消毒（wave10）：失败原因里**结构性地不可能**出现
// `<空白><名字>=`——否则 terr 值里塞一个 ` err=` 就能把旧 TS 的字段起点抢到自己身上，
// 而那段文本可以是对端可控的（见 sanitizeReason 上方的实测说明）。
// TS 侧的 parseHealth 容忍未知键，故老壳/老 TS 读新行照旧只认 err；新 TS **已消费** terr
// （`TunHealth.terr` 三态：键缺席=不可判定 / `-`=隧道类无失败 / 非空=仍挂着），用它判隧道类失败是否真恢复。
const healthPrefix = "数据面健康"

// logHealth 打一行结构固定的健康状态，供客户端解析真实接入态。
//
// ★与「网关落点」那行同一条纪律（见 tunnel.ts 对 endpoint 字段的说明）：只在**状态变化**时打，
// 否则每条流一行会把 4000 字节的日志尾巴瞬间冲满，反而把该看的信息挤出窗口。
//
// ★状态字段必须在锁内**快照成局部变量**再打日志。此前 `slog.Info` 那行是在解锁之后
// 直接读 `t.knockOK / t.tunnelOK / t.lastErr`——`knock()` 对每个落点各起一个 goroutine
// 并发调 markKnock/markFail，于是 A 在锁外打日志时 B 正在锁内改字段，`-race` 报 data race
// （CI 约 2/5 间歇红）。这不是授权/信任链上的竞态，只是日志行的撕裂读：去重比的是 `line`，
// 真打出去的却可能是另一个更新的状态，两者对不上号。快照之后打出去的恒等于去重那一份。
func (h *HealthState) logHealth() {
	h.mu.Lock()
	s := h.snapshotLocked()
	terrStr, errStr := orNone(s.TunnelErr), orNone(s.Err)
	line := fmt.Sprintf("knock=%t tunnel=%t terr=%s err=%s", s.Knock, s.Tunnel, terrStr, errStr)
	if line == h.lastHealth {
		h.mu.Unlock()
		return
	}
	h.lastHealth = line
	h.mu.Unlock()
	slog.Info(healthPrefix, "knock", s.Knock, "tunnel", s.Tunnel, "terr", terrStr, "err", errStr)
}

// currentErrLocked 是 `err=` 键的取值：最近一次被触碰的那一类的当前错误（须持 mu）。
// 这正好复现拆分前单个 lastErr 的语义——任何失败设成该原因、任何成功清空——
// 而不必再留第三个字段（见 healthPrefix 上方的契约说明）。
func (h *HealthState) currentErrLocked() string {
	if h.lastClass == classTunnel {
		return h.tunnelErr
	}
	return h.knockErr
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// markKnock / markTunnel / markKnockFail / markTunnelFail 记录真实事件。
// 成功只清掉**同类**上一次的错误——留着会让一次早已恢复的瞬时失败永远挂在界面上；
// 清到别的类头上则会让一次与之无关的成功擦掉一条还在持续的告警（见 HealthState 字段注释）。
func (h *HealthState) markKnock() {
	h.mu.Lock()
	h.knockOK, h.knockErr, h.lastClass = true, "", classKnock
	h.mu.Unlock()
	h.logHealth()
}

func (h *HealthState) markTunnel() {
	h.mu.Lock()
	h.tunnelOK, h.tunnelErr, h.lastClass = true, "", classTunnel
	h.mu.Unlock()
	h.logHealth()
}

func (h *HealthState) markKnockFail(reason string) {
	reason = sanitizeReason(reason)
	h.mu.Lock()
	h.knockErr, h.lastClass = reason, classKnock
	h.mu.Unlock()
	h.logHealth()
}

func (h *HealthState) markTunnelFail(reason string) {
	reason = sanitizeReason(reason)
	h.mu.Lock()
	h.tunnelErr, h.lastClass = reason, classTunnel
	h.mu.Unlock()
	h.logHealth()
}

// healthReasonMax 是健康行里单条失败原因的字符（rune）上限。
// 对端可控文本同样可以很长，而健康行整条纪律就是别把 4000 字节的日志尾巴冲掉
// （Rust 壳只从日志尾巴里捞最后一条健康行）。
const healthReasonMax = 200

// sanitizeReason 把失败原因折成「一行、无裸 `=`、有长度上限」的文本，是健康行值域的唯一消毒口。
//
// ★为什么必须有这道纵深：`markTunnelFail` 的 reason 直接来自 `dialEndpoint` 的 error，
// 而那条 error 能带上**对端可控的原文**——中间人出示一张 SAN 里塞了
// `http://a b err=网关一切正常` 的证书，crypto/tls 在 ParseCertificate 阶段就会把它拼进错误
// （`x509: cannot parse URI %q: …`，Go 1.26 实测），一路进到 `terr=`。健康行是
// `knock= tunnel= terr= err=`，而客户端 `tunnel.ts parseHealth` 用 `(?:^|\s)err=(.*)$` 取行尾：
// **最左**那个 ` err=`——落在 terr 值里的那个——会被当成字段起点，于是界面上「失败原因」
// 头几个字变成攻击者写的话（真实原因被推到后面）。它不会把 `ready` 翻绿（行尾还有真正的
// `err=`，取到的值非空），但正被钉扎拦下的中间人能替我们给用户写提示语。
// TS 侧的根治是带引号感知的分词，这里做的是数据面侧的纵深：**值里结构性地不可能出现
// `<空白><名字>=` 这种字段起始形态**。
//
// 三条规则：
//   - 所有空白（含换行/制表）折成单个 ASCII 空格并 trim——换行会让按行解析的消费方
//     直接把一行劈成两行（TextHandler 会转义，但这个判据不该依赖谁挑了哪个 handler）；
//   - ASCII `=` 一律换成全角 `＝`。**刻意不按键名清单匹配**：按清单写的话，下次给健康行加一个键
//     就会静默地把洞开回来（本仓最常见的「纪律只做了一半」）。合法 reason 里本来就不含 `=`
//     ——取令牌失败 / SPA 拨号失败 / 指纹不匹配三类都没有，故这条规则的实际代价是零。
//   - 超过 healthReasonMax 个字符**可见地**截断（截断必须看得见，否则读的人不知道话没说完）。
func sanitizeReason(reason string) string {
	// ①折空白（行首行尾的直接吃掉，中间的折成一个 ASCII 空格）+ ②换裸 `=`
	out := make([]rune, 0, len(reason))
	space := false // 上一段是否吃掉过空白，且前面已经有内容
	for _, r := range reason {
		if unicode.IsSpace(r) {
			space = len(out) > 0
			continue
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		if r == '=' {
			r = '＝'
		}
		out = append(out, r)
	}
	// ③可见截断
	if len(out) > healthReasonMax {
		return string(out[:healthReasonMax]) + "…（原因过长已截断）"
	}
	return string(out)
}
