package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"baidi.dev/gateway/internal/cplane"
	"baidi.dev/gateway/internal/ipsec"
)

// 本文件是控制面与数据面之间的**唯一**搬运工：
//
//	拉站点 → 按 pskVersion 决定要不要单取密钥 → 全量声明式对账 → 回报实测状态
//
// 三条贯穿全文件的原则，每一条都对应一种真实发生过（或极易发生）的事故：
//
//  1. **fail-closed 是"保留配置"而不是"拆掉隧道"**。控制面拉不到时保留上一轮配置继续跑，
//     ★绝不能把站点全拆了——控制面抖一下就让所有分支断网，是比"配置略微过期"严重得多的
//     故障。但过期这件事必须**看得见**：回报里会给每条站点挂上「控制面已 X 未响应」。
//  2. **密钥按版本单取**。策略每 15s 拉一轮，PSK 若跟着重传就是每 15s 让它在网络上出现一次。
//  3. **本地判定的问题也要变成控制台上的一行字**。取不到 PSK、网段解析失败这类问题，
//     状态机根本不知道，Backend 也报不出来——只有本文件知道，所以由本文件把它写进
//     SiteState.LastError。否则界面上就是一条"永远 connecting 且没有任何解释"的站点。

// controlClient 是本同步循环对控制面的**全部**需求。
//
// 抽成接口不是为了将来换实现（不会有第二个实现），而是为了让同步逻辑能被单测：
// 真实的 *cplane.Client 必须持一张 mTLS 客户端证书才能构造，把"版本没变就不取密钥"
// 这种规则的验证成本抬到要先签一套 CA，结果必然是这条规则根本没人测。
type controlClient interface {
	IpsecSites() ([]cplane.IpsecSiteDTO, error)
	IpsecPSK(siteID string) ([]byte, int, error)
	ReportIpsecStatus(states []ipsec.SiteState) ([]string, error)
}

// backendDiag 是 Backend 的可选诊断能力（*site.GoBackend 实现）。
//
// ★这两个数字在 ipsec.SiteState 里**没有字段可放**（契约层已冻结），
// 而 NoPolicyDrops 恰恰是「流量本该进隧道却没走隧道」的唯一可见信号——
// 埋在库里没人读、埋在日志里没人看，所以这里每轮主动把它的变化量喊出来。
type backendDiag interface {
	NoPolicyDrops() uint64
	TransportStats() (dropIKE, dropESP, keepalives uint64)
}

// pskEntry 本地持有的一把站点密钥。
//
// ★version 记的是"我手上这把密钥的版本"，不是"控制面说的最新版本"。
// 两者必须分开：取密钥失败时若把控制面的新版本号连同旧密钥一起下发给 Backend，
// 配置指纹（site.fingerprint 含 PSKVersion）就变了，Backend 会判定"配置已变更"
// 而拆掉重建 SA——用的还是旧密钥。结果是每 15 秒重建一次、每次都认证失败，
// 而日志里显示的是"配置已更新，重新协商"，指不到真正的根因上。
type pskEntry struct {
	version int
	psk     []byte
}

// syncer 一轮同步的全部状态。
type syncer struct {
	cp   controlClient
	gwID string
	back ipsec.Backend
	log  *slog.Logger

	// routes 路由钩子：把"该进隧道的网段"写进系统路由表（TUN 模式）。
	// 为 nil 表示当前数据面不需要路由（netstack 自检数据面自带默认路由）。
	routes func([]netip.Prefix)

	mu sync.RWMutex
	// extra 控制面下发了、但 SiteConfig 装不下的开关（pqHybrid / ikeVersion）。
	// Backend 通过 BackendOptions.Extra 回调读它，据此当面拒绝不支持的组合。
	extra map[string]ipsec.ExtraOptions
	// psk 本地密钥缓存。站点从控制面消失时必须清理（见 round 尾部）。
	psk map[string]pskEntry
	// notes 本地判定的站点问题（key=站点 id）。只有本文件知道这些原因，
	// 由 report 把它盖到 SiteState.LastError 上。
	notes map[string]string

	// failStreak 连续拉取失败次数；lastOK 最近一次成功拉到配置的时刻。
	// 两者一起决定回报里那句「配置已过期」怎么写。
	failStreak int
	lastOK     time.Time

	// lastNoPolicy 上一轮的无策略丢弃计数，用于只在**变化时**喊话。
	lastNoPolicy uint64
	lastDropIKE  uint64

	now func() time.Time
}

func newSyncer(cp controlClient, gwID string, back ipsec.Backend, log *slog.Logger, routes func([]netip.Prefix)) *syncer {
	return &syncer{
		cp: cp, gwID: gwID, back: back, log: log, routes: routes,
		extra: map[string]ipsec.ExtraOptions{},
		psk:   map[string]pskEntry{},
		notes: map[string]string{},
		now:   time.Now,
	}
}

// extraOf 供 site.BackendOptions.Extra 回调。
func (s *syncer) extraOf(siteID string) ipsec.ExtraOptions {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extra[siteID]
}

// run 同步循环：立刻跑一轮，之后每 interval 一轮，直到 ctx 结束。
func (s *syncer) run(ctx context.Context, interval time.Duration) {
	s.round(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.round(ctx)
		}
	}
}

// round 一轮同步。
func (s *syncer) round(ctx context.Context) {
	dtos, err := s.cp.IpsecSites()
	if err != nil {
		s.failStreak++
		// ★这里**不调 Apply**。传空列表会被 Backend 当成"管理员把站点删光了"而
		// 拆掉全部隧道——控制面抖一下就让所有分支断网，那是比配置过期严重得多的故障。
		// 保留上一轮配置继续跑，同时把"过期"如实写进回报。
		s.log.Warn("拉取站点配置失败：保留上一轮配置继续运行（不拆隧道）",
			"err", err.Error(), "连续失败", s.failStreak, "最近一次成功", s.sinceOK())
		s.report(ctx)
		return
	}
	if s.failStreak > 0 {
		s.log.Info("控制面已恢复，站点配置重新同步", "此前连续失败", s.failStreak)
	}
	s.failStreak = 0
	s.lastOK = s.now()

	cfgs := s.convert(dtos)
	if s.routes != nil {
		s.routes(desiredRoutes(cfgs))
	}
	// Apply 是全量声明式对账：本地站点集合收敛到 cfgs 描述的目标状态。
	// 单条站点的拒绝落到那条站点的 SiteState，不会让整批失败（见 site.GoBackend.Apply）。
	if err := s.back.Apply(ctx, cfgs); err != nil {
		s.log.Error("站点对账失败（整批）", "err", err.Error(), "站点数", len(cfgs))
	}
	s.report(ctx)
	s.diag()
}

// convert 把控制面 DTO 翻成 SiteConfig，并顺带解决密钥与本地诊断。
//
// ★解析失败的站点**不会被丢掉**。丢掉的后果是它在控制台上凭空消失，
// 管理员看不到任何错误也找不到那条站点；保留下来（字段留零值）交给 Validate 拒绝，
// 再由 notes 把真正的原因（"peer=\"203.0.113.\" 解析失败"）盖到 LastError 上，
// 界面上才会出现一行红色的、说得出所以然的记录。
func (s *syncer) convert(dtos []cplane.IpsecSiteDTO) []ipsec.SiteConfig {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.extra = make(map[string]ipsec.ExtraOptions, len(dtos))
	notes := make(map[string]string, len(dtos))
	seen := make(map[string]bool, len(dtos))

	out := make([]ipsec.SiteConfig, 0, len(dtos))
	for _, d := range dtos {
		id := strings.TrimSpace(d.ID)
		if id == "" {
			s.log.Warn("控制面下发了一条没有 id 的站点，已忽略（无从与控制面记录对应，也就无从回报状态）",
				"name", d.Name)
			continue
		}
		// ★归属过滤：不是本机的站点整条忽略。
		// 多网关部署下两台抢同一条站点会各建一条 SA、互相 rekey/删除，
		// 表现为隧道周期性抖动，而两台各自的日志都显示"一切正常"。
		//
		// 正常情况下走不到这里——控制面已按证书 CN 过滤过一遍。真走到了就说明
		// -gwid 与证书 CN 不一致（启动期已有硬校验，此处是第二道），必须喊出来：
		// 静默忽略的结果是"控制面下发了站点、网关一条都不建、双方零报错"。
		if gw := strings.TrimSpace(d.GatewayID); gw != "" && gw != s.gwID {
			s.log.Warn("忽略不归本机承载的站点（本机 gwid 与站点 gatewayId 不符）",
				"站点", id, "站点归属", gw, "本机", s.gwID,
				"含义", "若控制面确实把它派给了本机，说明 -gwid 与 mTLS 证书 CN 不一致，站点永远不会被建立")
			continue
		}
		if seen[id] {
			s.log.Warn("控制面下发了两条 id 相同的站点，已忽略后者", "站点", id)
			continue
		}
		seen[id] = true

		s.extra[id] = ipsec.ExtraOptions{IKEVersion: d.IKEVersion, PqHybrid: d.PqHybrid}

		cfg := ipsec.SiteConfig{
			ID: id, Name: d.Name, GatewayID: d.GatewayID, Enabled: d.Enabled,
			LocalID: d.LocalID, RemoteID: d.RemoteID,
			Auth:   d.Auth,
			Suite:  d.Suite,
			Phase1: ipsec.Phase{Enc: d.Phase1.Enc, Hash: d.Phase1.Hash, DH: d.Phase1.DH},
			Phase2: ipsec.Phase{Enc: d.Phase2.Enc, Hash: d.Phase2.Hash, DH: d.Phase2.DH},
			PFS:    d.PFS,
			// ★PeerNATPort 必须逐字段拷过来：漏掉它，控制面配的对端封装口就到不了
			// espEndpoints，ESP 按对称假设发往「对端 IP + 本端 -natt-port」——对端
			// 改过端口时那里没人监听。症状恰是这个字段本身要防的静默失效：IKE 协商
			// 全绿、隧道 up、tx 增长、rx 恒 0、两端零报错（见 ipsec.SiteConfig 注释）。
			PeerNATPort: uint16(d.PeerNATPort),
		}
		// GatewayID 为空时补成本机：Validate 对空 GatewayID 是**拒绝**的
		// （无主站点会被所有网关同时拿去建 SA）。但控制面既然只把它下发给了本机，
		// 空值就只是一条数据缺陷，补齐比让它永久 failed 更接近管理员的意图。
		if strings.TrimSpace(cfg.GatewayID) == "" {
			cfg.GatewayID = s.gwID
		}

		var problems []string
		peer, err := parsePeer(d.Peer)
		if err != nil {
			problems = append(problems, err.Error())
		} else {
			cfg.Peer = peer
		}
		if p, err := parsePrefix("localSubnet", d.LocalSubnet); err != nil {
			problems = append(problems, err.Error())
		} else {
			cfg.LocalSubnet = p
		}
		if p, err := parsePrefix("remoteSubnet", d.RemoteSubnet); err != nil {
			problems = append(problems, err.Error())
		} else {
			cfg.RemoteSubnet = p
		}

		psk, ver, note := s.resolvePSK(d)
		cfg.PSK, cfg.PSKVersion = psk, ver
		if note != "" {
			problems = append(problems, note)
		}

		if len(problems) > 0 {
			notes[id] = "控制面下发的配置无法使用：" + strings.Join(problems, "；")
		}
		out = append(out, cfg)
	}

	// 站点从控制面消失（删除或改派）：清掉它的密钥缓存。
	// ★不清的后果有两层：一是密钥材料在内存里无限期留存，二是同 id 站点若被重建，
	// 会先拿一把陈旧的密钥去协商，得到一句"认证失败"而管理员刚刚才设过密钥。
	for id, e := range s.psk {
		if seen[id] {
			continue
		}
		clear(e.psk)
		delete(s.psk, id)
		s.log.Info("站点已从控制面移除，清理本地密钥缓存", "站点", id)
	}
	s.notes = notes
	return out
}

// resolvePSK 决定这一轮该给这条站点用哪把密钥。
//
// 返回 (密钥, 该密钥的版本, 本地诊断)。★返回的版本永远是"我手上这把的版本"，
// 不是控制面声称的最新版本——理由见 pskEntry 的注释。
func (s *syncer) resolvePSK(d cplane.IpsecSiteDTO) ([]byte, int, string) {
	cur, hasCur := s.psk[d.ID]

	// pskVersion=0：控制面明说这条站点还没配过密钥。
	// ★不能拿空 PSK 去协商：两端都空时 AUTH **完全通得过**，隧道真的建起来、
	// 界面真的显示 up，只是认证强度为零，任何人抓到一个 IKE_SA_INIT 就能冒充对端接进来。
	if d.PSKVersion <= 0 {
		if hasCur {
			// 版本从 ≥1 退回 0 = 密钥行被删了。跟着丢掉本地缓存是正确的：
			// 保留会让一条"控制面认为没配密钥"的站点继续跑着，管理员无从停下它。
			clear(cur.psk)
			delete(s.psk, d.ID)
		}
		return nil, 0, "控制面尚未为该站点配置 PSK（pskVersion=0），请在控制台「IPSec 组网」里录入预共享密钥"
	}

	if hasCur && cur.version == d.PSKVersion {
		return cur.psk, cur.version, "" // 版本没变：不取密钥（一把密钥一生只传输它被修改的那几次）
	}

	psk, ver, err := s.cp.IpsecPSK(d.ID)
	if err != nil {
		switch {
		case errors.Is(err, cplane.ErrIpsecPSKUnavailable):
			// 控制面明确说没有。重试一万次也没用，必须把话说到界面上。
			if hasCur {
				// 手上还有旧密钥：继续用它跑，不因为一次控制面侧的删除/改派把在跑的隧道打断。
				s.log.Warn("控制面已取不到该站点的 PSK，暂沿用本地缓存的密钥",
					"站点", d.ID, "本地版本", cur.version, "err", err.Error())
				return cur.psk, cur.version, fmt.Sprintf(
					"控制面已取不到该站点的 PSK（未配置或已改派给其它网关），当前仍在使用本地缓存的 v%d", cur.version)
			}
			return nil, 0, "控制面未下发该站点的 PSK（未配置，或该站点已不归本网关承载）"
		default:
			// 网络抖动之类的瞬时失败：有缓存就接着用，别让一次取密钥失败把隧道拆了。
			if hasCur {
				s.log.Warn("取 PSK 失败，沿用本地缓存的密钥继续运行",
					"站点", d.ID, "本地版本", cur.version, "控制面版本", d.PSKVersion, "err", err.Error())
				return cur.psk, cur.version, fmt.Sprintf(
					"控制面已把 PSK 更新到 v%d，但网关取密钥失败，当前仍在使用 v%d（取到新密钥后会自动重建 SA）：%s",
					d.PSKVersion, cur.version, err.Error())
			}
			s.log.Warn("取 PSK 失败且本地无缓存，该站点无法协商", "站点", d.ID, "err", err.Error())
			return nil, 0, "取 PSK 失败，且本地没有可用的缓存：" + err.Error()
		}
	}
	if ver <= 0 {
		// 控制面返回了密钥却没给版本号：按站点清单里的版本记账，否则本地版本永远是 0，
		// 于是每一轮都会重新取一次密钥（密钥在网络上出现的次数从"改几次传几次"退化成每 15s 一次）。
		ver = d.PSKVersion
	}
	if ver != d.PSKVersion {
		// 两次请求之间管理员又改了一次密钥。以取回来的版本为准（那才是这把密钥的版本），
		// 下一轮会因为版本仍落后而再取一次，自然收敛。
		s.log.Info("取回的 PSK 版本与站点清单不一致（期间密钥被再次修改）",
			"站点", d.ID, "清单版本", d.PSKVersion, "取回版本", ver)
	}
	if hasCur {
		clear(cur.psk)
	}
	s.psk[d.ID] = pskEntry{version: ver, psk: psk}
	s.log.Info("已取得站点 PSK", "站点", d.ID, "版本", ver, "长度", len(psk))
	return psk, ver, ""
}

// report 回报实测运行态，并把只有本层知道的原因补进去。
func (s *syncer) report(ctx context.Context) {
	states, err := s.back.States(ctx)
	if err != nil {
		s.log.Error("读取本地运行态失败，本轮不回报", "err", err.Error())
		return
	}
	s.enrich(states)
	rejected, err := s.cp.ReportIpsecStatus(states)
	if err != nil {
		// 回报失败不影响数据面：隧道该跑还跑，只是控制台上的数字会停在上一次。
		// 界面据 reportedAt 标注「最近更新 N 秒前」，停更是看得见的。
		s.log.Warn("回报运行态失败（隧道不受影响，控制台数字会停更）", "err", err.Error(), "站点数", len(states))
		return
	}
	if len(rejected) > 0 {
		// 本网关在白报：控制面认为这些站点不归它。
		s.log.Warn("控制面拒收了部分站点的运行态（这些站点已不归本机承载）",
			"站点", strings.Join(rejected, ","),
			"含义", "本地仍留着控制面已删除或已改派的站点，检查 -gwid 与证书 CN 是否一致")
	}
}

// enrich 把本地诊断与"配置已过期"补进回报。
func (s *syncer) enrich(states []ipsec.SiteState) {
	s.mu.RLock()
	notes := s.notes
	s.mu.RUnlock()

	stale := ""
	if s.failStreak > 0 {
		// ★配置过期必须**看得见**。fail-closed 保留旧配置是对的，但如果不说，
		// 管理员看到的就是一条状态正常的隧道，而它跑的可能是十分钟前的配置——
		// 「停用了却还通」「改了配置没生效」都会从这里开始变成玄学。
		stale = fmt.Sprintf("（控制面已 %s 未响应，连续 %d 次拉取失败；本站点仍按上一次成功下发的配置运行，配置可能已过期）",
			s.sinceOK(), s.failStreak)
	}
	now := s.now().Unix()
	for i := range states {
		if note := notes[states[i].SiteID]; note != "" {
			// 本地诊断优先：Backend 报的是"PSK 为空"这类**症状**，
			// 本层知道的是"控制面还没配 PSK"这个**根因**，后者才能指导下一步动作。
			states[i].LastError = note
			states[i].LastErrorAt = now
		}
		if stale != "" {
			states[i].LastError += stale
			if states[i].LastErrorAt == 0 {
				states[i].LastErrorAt = now
			}
		}
	}
}

// diag 把两个"没地方放"的引擎级计数在变化时喊出来。
func (s *syncer) diag() {
	d, ok := s.back.(backendDiag)
	if !ok {
		return
	}
	if n := d.NoPolicyDrops(); n != s.lastNoPolicy {
		delta := n - s.lastNoPolicy
		s.lastNoPolicy = n
		// ★这是「流量本该进隧道却没走隧道」的唯一可见信号。
		// 隧道刚建好的瞬间出现一点是正常的；持续增长意味着业务地址与下发的网段对不上，
		// 那些包正在被**丢弃**（而不是明文直连出去，那条路已被 pump 堵死）。
		s.log.Warn("出向包无匹配 IPSec 策略的丢弃数在增长",
			"本轮新增", delta, "累计", n,
			"含义", "目的地址不在任何站点的 remoteSubnet 内，或对应站点尚未建立 Child SA；"+
				"若隧道显示 up 而这个数字持续增长，说明业务地址与控制面下发的网段对不上")
	}
	if dropIKE, _, _ := d.TransportStats(); dropIKE != s.lastDropIKE {
		s.lastDropIKE = dropIKE
		// IKE 支路队列满 = 状态机的事件循环卡住过。窗口=1 的协议正常时队列里不会超过个位数报文。
		s.log.Error("IKE 报文因分流队列满被丢弃：状态机事件循环曾卡住，协商可能间歇性失败",
			"累计丢弃", dropIKE)
	}
}

// sinceOK 距上一次成功拉到配置有多久（从未成功过时说明白）。
func (s *syncer) sinceOK() string {
	if s.lastOK.IsZero() {
		return "从未成功过"
	}
	return s.now().Sub(s.lastOK).Round(time.Second).String()
}

// shutdownReport 进程退出前的最后一次回报。
//
// ★不报的后果很具体：控制面的运行态是**网关全量覆写**的，网关一停，库里那行
// state=up 就永久留在那里。控制台上会看到一条"已建立"的隧道，而承载它的进程
// 早就没了——正是本项目反复出现的「界面上那条 up 的残影」。
//
// 这里把状态改成 failed 而不是 down：down 的语义是"管理员没启用"，
// 而此刻的事实是"启用着，但承载它的网关退出了"，那是故障不是意图。
func (s *syncer) shutdownReport(ctx context.Context, reason string) {
	states, err := s.back.States(ctx)
	if err != nil {
		return
	}
	now := s.now().Unix()
	for i := range states {
		if states[i].State == ipsec.StateDown {
			continue // 本来就没启用，不必改写成故障
		}
		states[i].State = ipsec.StateFailed
		states[i].LastError = "承载该站点的网关 " + s.gwID + " 已退出（" + reason + "），隧道已发 Delete 拆除"
		states[i].LastErrorAt = now
		states[i].EstablishedAt = 0
	}
	if _, err := s.cp.ReportIpsecStatus(states); err != nil {
		s.log.Warn("退出前回报状态失败：控制台上可能残留一条已不存在的隧道", "err", err.Error())
		return
	}
	s.log.Info("退出前已回报站点下线状态", "站点数", len(states))
}

// ── 解析辅助 ──

// parsePeer 解析对端 IKE 落点，端口可省（由 Validate 补 500）。
func parsePeer(v string) (netip.AddrPort, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return netip.AddrPort{}, errors.New("peer 为空：网关不会去猜对端在哪（策略权威在控制面）")
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		// 端口留 0，由 SiteConfig.Validate 补成 DefaultIKEPort（500）。
		// 在这里补也行，但那会让"缺省值到底在哪补"出现第二个答案。
		return netip.AddrPortFrom(a.Unmap(), 0), nil
	}
	return netip.AddrPort{}, fmt.Errorf("peer=%q 既不是 IP 也不是 IP:端口（本实现不做 DNS 解析："+
		"隧道对端在 DNS 抖动时切换落点，会得到一条谁也解释不清的间歇性故障）", v)
}

// parsePrefix 解析受保护网段。
func parsePrefix(field, v string) (netip.Prefix, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return netip.Prefix{}, fmt.Errorf("%s 为空：它就是 TSi/TSr，没有它无从判断哪些流量该进隧道", field)
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		// 只写了个地址是最常见的手误，给出可直接照抄的写法。
		if a, aerr := netip.ParseAddr(v); aerr == nil {
			return netip.Prefix{}, fmt.Errorf("%s=%q 缺少前缀长度：单机请写 %s/%d，整段请写成 CIDR",
				field, v, a, a.BitLen())
		}
		return netip.Prefix{}, fmt.Errorf("%s=%q 不是合法 CIDR：%v", field, v, err)
	}
	// ★4-in-6 形态（::ffff:10.0.0.0/120）当面拒绝，不做自动折算。
	// 它与同值的 IPv4 网段用 == 比**不相等**，一旦混进来，流量选择器匹配、
	// SPD 选路、地址族一致性检查会各自在不同的地方对不上，而每一处的表现
	// 都只是"某些地址不通"，没有任何一处会说出真正的原因。
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%s=%q 是 IPv4-in-IPv6 形态：请直接写 IPv4 网段（如 10.20.0.0/16），"+
			"混用会让流量选择器与路由匹配在多处静默对不上", field, v)
	}
	return p, nil
}

// desiredRoutes 算出"该被路由进隧道"的网段集合：所有**已启用**站点的 remoteSubnet。
//
// ★路由清单必须由控制面下发，不能让管理员手填。CLAUDE.md 记着的那个事故形态
// （业务地址散落在多个网段，只接管一条，隧道建起来了、点开应用却直连不走隧道，
// 无报错、UI 显示已接入）就出在"路由是人填的"这一点上。
//
// 停用的站点不出现在这里，但已经写进系统的路由**不会被撤**——见 routeAdder 的说明。
func desiredRoutes(cfgs []ipsec.SiteConfig) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	out := make([]netip.Prefix, 0, len(cfgs))
	for _, c := range cfgs {
		if !c.Enabled || !c.RemoteSubnet.IsValid() {
			continue
		}
		p := c.RemoteSubnet.Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	// 稳定顺序：日志与路由写入顺序可预期，排障时两次运行的输出能直接对比。
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
