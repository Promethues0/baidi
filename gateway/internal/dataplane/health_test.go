package dataplane

import (
	"bytes"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"baidi.dev/gateway/internal/knock"
)

// 接入态判据必须来自**真实事件**，不能是两行启动日志。
//
// ★改造前：`ready` 判 `/数据面就绪/`、`keepalive` 判 `/敲门保活/`，而这两行分别打印于
// 任何一次 knock 与任何一次拨号**之前**——纯粹是"netstack 装好了""ticker 起来了"。
// 于是三类真实故障在接入页上完全看不见，界面一律绿色「已接入 · 隧道活动」：
//   ① 全部网关落点拨不通；
//   ② config.gm 与网关模式不一致导致握手 100% 失败；
//   ③ 指纹钉扎失败（数据面自己判定为"疑似中间人"）。
// 而且业务流量一多，那两行会被挤出 4000 字节的日志尾巴 → 健康隧道反被判「未见保活」。
func TestHealthReflectsRealEvents(t *testing.T) {
	tn := newTestTunneler()

	// 初始：什么都没发生过——**不能**是"就绪"
	if tn.knockOK || tn.tunnelOK {
		t.Fatal("初始状态不得声称敲门/隧道已成功")
	}

	// 拨号失败要留下原因（此前这条失败在运行中恒到不了界面）
	tn.markTunnelFail("网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def")
	if healthErr(tn) == "" {
		t.Error("拨号失败必须记下原因")
	}
	if tn.tunnelOK {
		t.Error("失败不该把隧道标成通")
	}

	// 敲门真的发出去了
	tn.markKnock()
	if !tn.knockOK {
		t.Error("敲门成功应被记录")
	}
	// ★err= 键的语义拆分前后逐字一致（旧 TS 按 `ready = knock ∧ err 为空` 判接入态，见 healthPrefix 上方契约）：
	// 任何一次成功都把它清空——留着会让一次早已恢复的瞬时失败永远挂在界面上，并把旧 TS 的 ready 卡死。
	if got := healthErr(tn); got != "" {
		t.Errorf("成功后 err= 应清空（旧契约），实得 %q", got)
	}

	// 隧道真的拨通了
	tn.markTunnel()
	if !tn.tunnelOK {
		t.Error("隧道拨通应被记录")
	}
}

// 健康行只在**状态变化**时打——每条流都打会把 4000 字节的日志尾巴瞬间冲满，
// 反而把该看的信息（含落点行）挤出窗口（Rust 壳只从尾巴里捞最后一条健康行）。
//
// ★改造前这条用例**钉不住任何东西**：它断言的是 `tn.lastHealth` 前后一不一样，
// 而 `lastHealth` 在去重早退**之前**就被赋成了同一个字符串——把 logHealth 里
// `if line == t.lastHealth { … return }` 整段删掉（保留赋值），断言照样全绿。
// 现在改成数**真打出去的记录条数**，那才是这条属性的唯一可观测面。
func TestHealthLineDedup(t *testing.T) {
	lines := captureHealth(t)
	tn := newTestTunneler()

	tn.markTunnel()
	if got := lines(); len(got) != 1 {
		t.Fatalf("首次状态变化应恰好打 1 条健康行，实得 %d 条：%q", len(got), got)
	}
	tn.markTunnel() // 同样的状态再来一次
	if got := lines(); len(got) != 1 {
		t.Errorf("状态未变时不应再打健康行（去重早退没生效），实得 %d 条：%q", len(got), got)
	}
	tn.markTunnelFail("隧道拨号失败")
	got := lines()
	if len(got) != 2 {
		t.Fatalf("状态变了必须打新行，否则界面停在旧结论上；实得 %d 条：%q", len(got), got)
	}
	assertHealthKeys(t, got[1])
}

// captureHealth 把 slog 换成写进 buffer 的 TextHandler（结束按 t.Cleanup 还原，
// 与同包 TestHealthMarksConcurrentlyRaceFree 各自 Cleanup、互不影响），
// 返回「取出目前为止打过的健康行」的闭包。
//
// ★断言的对象刻意是**真打出去的那一行**而不是 `tn.lastHealth`：后者只是去重键，
// 客户端一个字都读不到；而 slog 会给含空格的值加引号，两者并不逐字相同。
func captureHealth(t *testing.T) func() []string {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return func() []string {
		var out []string
		for _, l := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
			if strings.Contains(l, healthPrefix) {
				out = append(out, l)
			}
		}
		return out
	}
}

// 失败原因里的**对端可控文本**不得伪造出字段分隔符（security-5 的数据面侧纵深）。
//
// ★这不是假想：中间人出示一张 SAN 里塞了 `http://a b err=…` 的证书，crypto/tls 在
// ParseCertificate 阶段就把那串原文拼进错误（`x509: cannot parse URI %q: …`，Go 1.26 实测），
// 经 `dialTunnel` → `markTunnelFail` 进 `terr=`。健康行 terr 排在 err 之前，而旧 TS 用
// `(?:^|\s)err=(.*)$` 取行尾 → **最左**那个 ` err=`（在 terr 值里）被当成字段起点，
// 界面上「失败原因」的头几个字就成了攻击者写的话。根治在 TS 侧做带引号感知的分词，
// 这里保证数据面这一侧写不出这种行。
func TestHealthReasonCannotForgeFields(t *testing.T) {
	// 探针实测拿到的那条 error 原文（对端只需在证书 SAN 里放一个带空格的 URI）
	const evil = `tls: failed to parse certificate from server: x509: cannot parse URI "http://a b err=网关一切正常": invalid domain`

	lines := captureHealth(t)
	tn := newTestTunneler()
	tn.markTunnelFail(evil)
	tn.markKnock() // err= 按旧契约清空，terr= 留着——被污染的正是这一格
	got := lines()
	if len(got) != 2 {
		t.Fatalf("应打 2 条健康行，实得 %d 条：%q", len(got), got)
	}
	for _, line := range got {
		if n := strings.Count(line, " err="); n != 1 {
			t.Errorf("行内 ` err=` 只能出现一次（多出来的会抢走字段起点），实得 %d 次：%s", n, line)
		}
		if n := strings.Count(line, " terr="); n != 1 {
			t.Errorf("行内 ` terr=` 只能出现一次，实得 %d 次：%s", n, line)
		}
	}
	// 直接拿旧 TS 的那条正则验「按键切分」：敲门成功后 err 必须是空标记 `-`
	m := tsErrRe.FindStringSubmatch(got[1])
	if m == nil {
		t.Fatalf("旧 TS 正则取不到 err=：%s", got[1])
	}
	if m[1] != "-" {
		t.Errorf("terr= 里的文本污染了 err=：取到 %q，应为 \"-\"（原行：%s）", m[1], got[1])
	}
}

// tsErrRe 复刻桌面端 tunnel.ts parseHealth 取 err 的那条正则，用来在 Go 侧验证
// 「健康行按键切分」这个跨端契约（改那边的正则要连这里一起改）。
var tsErrRe = regexp.MustCompile(`(?:^|\s)err=(.*)$`)

// sanitizeReason 的三条规则各自钉一条。
func TestSanitizeReason(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"正常原因逐字不动", "SPA 拨号失败：网络不可达", "SPA 拨号失败：网络不可达"},
		{"裸等号换成全角", "err=x", "err＝x"},
		{"换行折成空格", "第一行\n第二行\t第三行", "第一行 第二行 第三行"},
		{"首尾空白裁掉", "  abc  ", "abc"},
		{"连续空白折成一个", "a \t\n b", "a b"},
	}
	for _, c := range cases {
		if got := sanitizeReason(c.in); got != c.want {
			t.Errorf("%s：sanitizeReason(%q) = %q，应为 %q", c.name, c.in, got, c.want)
		}
	}
	// 截断必须**可见**：读的人得知道话没说完
	long := strings.Repeat("长", healthReasonMax+50)
	got := sanitizeReason(long)
	if !strings.HasSuffix(got, "…（原因过长已截断）") {
		t.Errorf("超长原因必须可见地截断，实得：%s", got)
	}
	if n := len([]rune(strings.TrimSuffix(got, "…（原因过长已截断）"))); n != healthReasonMax {
		t.Errorf("截断后正文应为 %d 个字符，实得 %d", healthReasonMax, n)
	}
	// 恰好等于上限时不加截断标记（免得每条正常原因都挂个"已截断"）
	if got := sanitizeReason(strings.Repeat("长", healthReasonMax)); strings.Contains(got, "截断") {
		t.Errorf("正好 %d 个字符不该判截断：%s", healthReasonMax, got)
	}
}

// newTestTunneler 造一个只带健康状态的 tunneler。
//
// ★健康状态搬进 HealthState 之后（wave10 移动端接入态），`&tunneler{}` 里那个内嵌
// `*HealthState` 是 nil，第一次 mark* 就会空指针崩溃。生产路径上只有 newTunneler 一个入口
// （它按 cfg.Health 取或自建），测试里也只留这一个入口，免得下次有人再手写字面量。
// 这里刻意**不建 pick / deny**：健康态用例一条都不碰它们，建了反而像是在测一个真引擎。
func newTestTunneler() *tunneler {
	return &tunneler{HealthState: NewHealthState()}
}

// healthErr 取健康行 `err=` 键的当前取值（即旧 TS 读到的那个值），测试用。
func healthErr(tn *tunneler) string {
	return tn.Snapshot().Err
}

// assertHealthKeys 断言健康行带齐客户端解析所需的键，且 terr 排在 err 之前
// （parseHealth 对 err 取到行尾，terr 排后面会被旧 TS 当成 err 值吞掉——契约见 healthPrefix）。
func assertHealthKeys(t *testing.T, line string) {
	t.Helper()
	for _, want := range []string{"knock=", "tunnel=", "terr=", "err="} {
		if !strings.Contains(line, want) {
			t.Errorf("健康行缺字段 %q：%s", want, line)
		}
	}
	if ti, ei := strings.Index(line, " terr="), strings.Index(line, " err="); ti < 0 || ei < 0 || ti > ei {
		t.Errorf("terr= 必须排在 err= 之前，否则旧 TS 的 `err=(.*)$` 会把它吞进 err 值：%s", line)
	}
}

// 失败原因按 knock/tunnel 分类记（wave10）。
//
// ★改造前只有一个 lastErr，markKnock 与 markTunnel 都不分类别地清空它，而保活敲门每 15s 成功一次：
// 「网关证书指纹不匹配（疑似中间人）」这类隧道拨号失败在健康行里最多挂 15s 就被一次与它无关的敲门成功
// 擦掉，界面上一条持续性的中间人告警只是闪一下，TS 侧只能靠粘性提示条兜底。现在健康行多带 `terr=`
// （隧道类最近失败，只被隧道拨通清掉），`err=` 保持旧语义供旧 TS 继续按它判 ready。
func TestHealthTunnelErrSurvivesKnockSuccess(t *testing.T) {
	tn := newTestTunneler()
	const mitm = "网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def"
	tn.markTunnelFail(mitm)
	assertHealthKeys(t, tn.lastHealth)
	if !strings.Contains(tn.lastHealth, "terr="+mitm) {
		t.Fatalf("隧道失败后 terr= 应带原因：%s", tn.lastHealth)
	}
	if !strings.Contains(tn.lastHealth, "err="+mitm) {
		t.Fatalf("隧道失败后 err= 同样带原因（旧契约）：%s", tn.lastHealth)
	}

	// 一次保活敲门成功：err= 按旧契约清空，terr= **不动**——这就是拆分的全部意义
	tn.markKnock()
	if got := healthErr(tn); got != "" {
		t.Errorf("敲门成功后 err= 应清空（旧契约），实得 %q", got)
	}
	if !strings.Contains(tn.lastHealth, "terr="+mitm) {
		t.Errorf("敲门成功不得擦掉隧道类失败（这正是改造前每 15s 发生一次的事）：%s", tn.lastHealth)
	}
	if !strings.Contains(tn.lastHealth, " err=-") {
		t.Errorf("err= 应显示为 -：%s", tn.lastHealth)
	}

	// 敲门类失败不碰 terr，且 err= 跟随最近一次触碰的类别
	tn.markKnockFail("SPA 拨号失败：网络不可达")
	if got := healthErr(tn); got != "SPA 拨号失败：网络不可达" {
		t.Errorf("敲门失败后 err= 应为该原因，实得 %q", got)
	}
	if !strings.Contains(tn.lastHealth, "terr="+mitm) {
		t.Errorf("敲门类失败不得覆盖隧道类失败：%s", tn.lastHealth)
	}

	// 只有隧道真拨通才清 terr
	tn.markTunnel()
	if !strings.Contains(tn.lastHealth, " terr=- ") {
		t.Errorf("隧道拨通后 terr= 应清空：%s", tn.lastHealth)
	}
	if got := healthErr(tn); got != "" {
		t.Errorf("隧道拨通后 err= 应清空（旧契约），实得 %q", got)
	}
	if !tn.tunnelOK || !tn.knockOK {
		t.Error("两个粘性位都该已置位")
	}
}

// 健康行的状态字段被多个 goroutine 并发改写：`knock()` 对每个落点各起一个 goroutine，
// 各自在成功/失败时调 markKnock/markFail。
//
// ★此用例只在 `-race` 下才会红（CI 正是这么跑的）：改造前 logHealth 在**解锁之后**才读
// `knockOK/tunnelOK/lastErr` 去打日志，与另一个 goroutine 锁内的写构成 data race——
// 表现为 TestKnock_ReachesEveryEndpointWithItsOwnToken 约 2/5 间歇红。这里不依赖真实
// UDP 落点，直接并发调三个 mark 函数把那条路径打满，让竞态检测器稳定抓到而不是靠运气。
func TestHealthMarksConcurrentlyRaceFree(t *testing.T) {
	// 每次 markTunnelFail 的原因都不重样 → 每次都真打一行健康行，2000 次 ≈ 2000 行 stderr；
	// 用例要的只是 -race 下的内存访问模式，日志丢弃（结束恢复，别影响同包其他用例的输出）。
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	tn := newTestTunneler()
	var wg sync.WaitGroup
	// 几个 goroutine 各自用**不重样**的失败原因反复调 markFail：每一次都会绕过去重、
	// 走到"解锁后打日志"那一步，正是撕裂读所在；掺进 markKnock/markTunnel 覆盖另两个字段。
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				switch i % 8 {
				case 3:
					tn.markKnock()
				case 6:
					tn.markTunnel()
				case 5:
					tn.markKnockFail("SPA 拨号失败：g" + strconv.Itoa(g) + " #" + strconv.Itoa(i))
				default:
					tn.markTunnelFail("拨号失败 g" + strconv.Itoa(g) + " #" + strconv.Itoa(i))
				}
			}
		}(g)
	}
	wg.Wait()
	if !tn.knockOK || !tn.tunnelOK {
		t.Fatal("并发标记之后成功事件必须都被记下")
	}
	assertHealthKeys(t, tn.lastHealth)
}

// healthLineRe 从 slog TextHandler 打出的健康行里取回四个字段。
// 用例里的失败原因刻意**不含空格**，于是 slog 不会给值加引号，`\S+` 就能整段取回；
// 这里要验的是"两种渲染取自同一份状态"，不是 slog 的引号规则。
var healthLineRe = regexp.MustCompile(`knock=(true|false) tunnel=(true|false) terr=(\S+) err=(\S+)$`)

// 日志行与 Snapshot() 必须**逐项一致**——这是把健康态抽成 HealthState 时真正要守的不变式。
//
// ★为什么它值得一条用例：桌面端读的是日志行（Rust 壳从 stdout 尾巴里捞），移动端读的是
// Snapshot()。两条读路一旦各读各的字段，就是两个真相来源：不一致时**两边都不报错**，
// 而排障的人手里正好只有这两样东西（真机日志 + 界面），互相印证是唯一的自证手段。
// 具体能走散的地方就在 err 这一格：它取的是「最近被触碰的那一类」的错误（currentErrLocked），
// 谁要是在 logHealth 里图省事直接读 knockErr，隧道类失败时两边就会给出不同的原因，
// 而 knock=/tunnel= 两格照样一致，看起来毫无异样。
func TestHealthLineMatchesSnapshot(t *testing.T) {
	lines := captureHealth(t)
	tn := newTestTunneler()

	steps := []struct {
		name string
		do   func()
	}{
		{"隧道类失败", func() { tn.markTunnelFail("网关证书指纹不匹配") }},
		{"敲门成功（err 按旧契约清空、terr 留着）", tn.markKnock},
		{"敲门类失败", func() { tn.markKnockFail("取敲门令牌失败：控制中心证书不受信任") }},
		{"隧道拨通", tn.markTunnel},
		{"再来一次隧道类失败", func() { tn.markTunnelFail("落点全部拨不通") }},
	}
	for _, st := range steps {
		st.do()
		got := lines()
		if len(got) == 0 {
			t.Fatalf("%s：一条健康行都没打出来", st.name)
		}
		m := healthLineRe.FindStringSubmatch(got[len(got)-1])
		if m == nil {
			t.Fatalf("%s：健康行取不到四个字段：%s", st.name, got[len(got)-1])
		}
		s := tn.Snapshot()
		if want := strconv.FormatBool(s.Knock); m[1] != want {
			t.Errorf("%s：日志行 knock=%s，Snapshot().Knock=%s", st.name, m[1], want)
		}
		if want := strconv.FormatBool(s.Tunnel); m[2] != want {
			t.Errorf("%s：日志行 tunnel=%s，Snapshot().Tunnel=%s", st.name, m[2], want)
		}
		if want := orNone(s.TunnelErr); m[3] != want {
			t.Errorf("%s：日志行 terr=%q，Snapshot().TunnelErr=%q", st.name, m[3], want)
		}
		if want := orNone(s.Err); m[4] != want {
			t.Errorf("%s：日志行 err=%q，Snapshot().Err=%q", st.name, m[4], want)
		}
	}
}

// Observed 区分「还没敲过第一次门」与「敲过了、当前没问题」——两者的处置相反
// （前者继续等，后者才是就绪），塌成同形正是 2026-09-03 安卓真机上那个形态的根。
//
// ★它是派生量：多存一个字段就多一个会与三项事实走散的真相来源。这条用例连同
// TestHealthLineMatchesSnapshot 一起，把「派生」这件事钉在唯一的读出口 snapshotLocked 上。
func TestHealthObservedDistinguishesNothingHappened(t *testing.T) {
	captureHealth(t) // 丢弃日志，本用例只看快照
	h := NewHealthState()
	if s := h.Snapshot(); s.Observed {
		t.Fatalf("什么都没发生过时 Observed 必须为假（否则「还没敲门」会被读成「敲过了没问题」）：%+v", s)
	}

	// 只有失败、没有任何成功：同样算"观察到了"——不然一台连控制面都连不上的终端
	// 会与一台刚起步的终端完全同形，而前者要报错、后者要继续等。
	h2 := NewHealthState()
	h2.markKnockFail("取敲门令牌失败：控制中心证书不受信任")
	s2 := h2.Snapshot()
	if !s2.Observed {
		t.Error("有过失败事件就必须 Observed=true")
	}
	if s2.Knock || s2.Tunnel {
		t.Error("失败不得把粘性位置真")
	}
	if s2.KnockErr == "" || s2.Err != s2.KnockErr {
		t.Errorf("敲门类失败应同时出现在 KnockErr 与 Err 上：%+v", s2)
	}
	if s2.TunnelErr != "" {
		t.Errorf("敲门类失败不得写到 TunnelErr 上：%+v", s2)
	}

	h3 := NewHealthState()
	h3.markKnock()
	if s := h3.Snapshot(); !s.Observed || !s.Knock || s.Err != "" {
		t.Errorf("敲门成功后应为 Observed=true / Knock=true / Err 空：%+v", s)
	}
}

// Snapshot() 与 mark* 并发跑：**只在 `-race` 下才会红**，CI 正是这么跑的。
//
// ★改造前根本不存在这条读路——健康状态是 tunneler 的私有字段，只有引擎自己的 goroutine 碰。
// 现在移动端 UI 每 2s 从另一个线程调 Snapshot()，而 knock() 对每个落点各起一个 goroutine
// 在改这些字段：漏掉 Snapshot 里的加锁（或者图省事在 snapshotLocked 之外读一格），
// 单测全绿、真机上只会偶发地读到半新半旧的组合（比如 knock=true 配着一条早已清掉的 err），
// 那种界面上"一闪而过的错误提示"没人排得出来。
func TestHealthSnapshotConcurrentlyRaceFree(t *testing.T) {
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	h := NewHealthState()
	var wg sync.WaitGroup
	// 写侧：不重样的失败原因保证每次都绕过去重、真走到"解锁后打日志"那一步
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				switch i % 4 {
				case 0:
					h.markKnock()
				case 1:
					h.markTunnel()
				case 2:
					h.markKnockFail("取令牌失败 g" + strconv.Itoa(g) + " #" + strconv.Itoa(i))
				default:
					h.markTunnelFail("拨号失败 g" + strconv.Itoa(g) + " #" + strconv.Itoa(i))
				}
			}
		}(g)
	}
	// 读侧：模拟移动端 UI 轮询
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				s := h.Snapshot()
				// 快照内部必须自洽：Observed 是同一次持锁里派生的，不可能与三项事实矛盾
				if !s.Observed && (s.Knock || s.Tunnel || s.KnockErr != "" || s.TunnelErr != "") {
					t.Error("快照内部不自洽：Observed 与事实矛盾（说明 Observed 不是同一次持锁派生出来的）")
					return
				}
			}
		}()
	}
	wg.Wait()
	if s := h.Snapshot(); !s.Observed || !s.Knock || !s.Tunnel {
		t.Fatalf("并发之后成功事件必须都被记下：%+v", s)
	}
}

// 控制面归因文案必须能**原样**穿过 sanitizeReason——这是它进健康行、进界面的必经之路。
//
// ★为什么这条用例要写在 dataplane 侧：sanitizeReason 是健康行值域的唯一消毒口，
// 而它在这个包里；knock 是上游、导不过来。文案被消毒（`=` 换成全角、多空格被折、
// 超长被截）**不会报任何错**，只会在真机日志与用户界面上出现一句被削过的话，
// 而写文案的人自己永远看不到那一步。knock 侧另有一条同族用例断言那三条规则的属性，
// 这一条是端到端的：真跑一遍消毒口，逐字比对。
func TestControlErrMessagesSurviveSanitize(t *testing.T) {
	errs := []error{
		x509.UnknownAuthorityError{},
		x509.HostnameError{Host: "control.example.com"},
		x509.CertificateInvalidError{Reason: x509.Expired},
		&net.DNSError{Name: "control.internal", Err: "no such host"},
		&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
	}
	for _, e := range errs {
		// knockOne 里就是这么拼的：前缀 + 归因，整条进 markKnockFail → sanitizeReason
		raw := "取敲门令牌失败：" + knock.ClassifyControlErr(e).Error()
		if got := sanitizeReason(raw); got != raw {
			t.Errorf("归因被消毒口改写了（说明文案违约）：\n  原文：%s\n  实得：%s", raw, got)
		}
	}
}

// Config.Health 传进来的那份状态必须**就是**引擎写的那份；不传则自建。
//
// ★这条接线漏掉是静默的：引擎照常自建一份、照常写日志行，而调用方（移动端绑定层）
// 手里那份永远没人写 → Observed() 恒为假 → 原生壳永远停在「接入中」，
// 日志里一个字的异常都没有。反过来，nil 时不自建则是第一次 mark* 空指针崩溃，
// 那会让 baidi-tun 在取令牌失败的那一刻整个挂掉（本该只是打一行健康行）。
func TestNewTunnelerUsesProvidedHealthState(t *testing.T) {
	h := NewHealthState()
	tn := newTunneler(&Config{SpaAddr: "127.0.0.1:1", ProxyAddr: "127.0.0.1:2", Health: h})
	if tn.HealthState != h {
		t.Fatal("引擎必须写调用方传进来的那份 HealthState，否则调用方读到的是一份永远没人写的状态")
	}

	// 不传：自建，且能正常工作（baidi-tun 与既有调用方一个字都不用改）
	tn2 := newTunneler(&Config{SpaAddr: "127.0.0.1:1", ProxyAddr: "127.0.0.1:2"})
	if tn2.HealthState == nil {
		t.Fatal("Config.Health 为 nil 时必须自建，否则第一次 mark* 就空指针崩溃")
	}
	captureHealth(t)
	tn2.markKnock() // 真跑一次，确认自建的那份可用
	if s := tn2.Snapshot(); !s.Knock || !s.Observed {
		t.Errorf("自建状态应正常记事件：%+v", s)
	}
}
