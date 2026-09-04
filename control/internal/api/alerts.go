package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/alerting"
	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/license"
	"baidi.dev/control/internal/notify"
	"baidi.dev/control/internal/store"
)

// ── 业务告警（PRD ch5 FR-MON-21~25）──
//
// 三段式：真实信号取数（本文件 alertSnapshot）→ 纯判定（internal/alerting.Evaluate）
// → 落库去重（store.RaiseAlert，按 (规则,对象) 冷却）。
//
// 权限归属（新端点必须想清楚归哪一权）：
//   - 读（GET /alerts、GET /alerts/rules）= 任意管理员，且**现算角色**（requireAdmin）。
//     告警是运维待办，系统管理员看不到网关离线、审计管理员看不到链断裂都说不通。
//     其中审计链那条只呈现「链在第 N 条断裂」这一个事实，不含任何审计正文，
//     故不需要 PermAudit——把它藏进审计权反而让防篡改自检失去意义。
//   - 写（处置 / 规则 CRUD / 立即检测）= PermSecurity：「什么算异常、这条异常怎么处置」
//     与安全基线、认证策略同性质，归安全权。

// alertEvalInterval 周期评估间隔的默认值（BAIDI_ALERT_INTERVAL 可覆盖，见 config）。
// alertChainInterval 审计链自检的间隔：全链重算比其余信号贵得多，不跟着每分钟跑。
const (
	alertEvalInterval  = time.Minute
	alertChainInterval = 15 * time.Minute
	// alertMetricsFresh 网关资源指标样本的新鲜度上限。
	alertMetricsFresh = 10 * time.Minute
)

// alertNotifyBudget 单轮评估最多同步发出多少条告警通知。
//
// ★通知是**同步**发的（理由见 notifyAlert），而单轮新产生的告警条数没有天然上界：
// 升级后首轮评估、或一次性接入几十台网关时，一轮就可能产出上百条候选。
// 每条 × 每个启用通道 × SMTP 默认 15s 超时 = 「立即检测」这个 handler 挂住几十分钟。
// 超出预算的那些告警**照常落库**（页面上一条不少），只是不再逐条外发，
// 并统一落一条审计说明差额——"少发几封邮件"远好过"评估循环被自己卡死"。
const alertNotifyBudget = 20

// alertErr 本文件的静态错误文案。
type alertErr string

func (e alertErr) Error() string { return string(e) }

// notifyNoChannelReason 尚未配置任何可用消息通道时给控制台的说明。
const notifyNoChannelReason = "尚未配置任何启用中的消息通道（系统 → 消息通道）：告警只在本页与 API 中呈现，不会外发。"

// alertChannelOption 规则编辑器里的一个可选通知通道（不含任何配置细节）。
type alertChannelOption struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
}

// alertChannelOptions 列出可选通知通道，并返回其中**启用中**的条数。
// 存储不支持消息通道时返回空——不编造可选项。
func (s *Server) alertChannelOptions(ctx context.Context) ([]alertChannelOption, int) {
	ns, ok := s.store.(notifyStore)
	if !ok {
		return []alertChannelOption{}, 0
	}
	chans, err := ns.NotifyChannels(ctx)
	if err != nil {
		slog.Warn("告警规则：读消息通道清单失败", "err", err.Error())
		return []alertChannelOption{}, 0
	}
	out, enabled := make([]alertChannelOption, 0, len(chans)), 0
	for _, c := range chans {
		if c.Enabled {
			enabled++
		}
		out = append(out, alertChannelOption{ID: c.ID, Name: c.Name, Kind: c.Kind, Enabled: c.Enabled})
	}
	return out, enabled
}

// alertProbeStore 网关资源指标数据源的运行时探测（只有 SQLiteStore 实现）。
type alertProbeStore interface {
	GatewayMetricsProbe(ctx context.Context) (store.MetricsProbe, error)
}

// alertWriter 告警落库能力（store.Writer 的子集，便于本文件读起来知道它只用到这几个写口）。
type alertWriter interface {
	RaiseAlert(ctx context.Context, a store.Alert, cooldownSec int) (store.Alert, bool, error)
	SetAlertStatus(ctx context.Context, id, status, by string, at int64) (store.Alert, error)
	SaveAlertRule(ctx context.Context, r store.AlertRule) (store.AlertRule, error)
	DeleteAlertRule(ctx context.Context, id string) error
}

// metricsProbe 探测网关资源指标数据源；存储不支持探测时如实回报，不假装就绪。
func (s *Server) metricsProbe(ctx context.Context) store.MetricsProbe {
	p, ok := s.store.(alertProbeStore)
	if !ok {
		return store.MetricsProbe{Reason: "当前存储后端不支持指标探测（内存种子模式）"}
	}
	res, err := p.GatewayMetricsProbe(ctx)
	if err != nil {
		return store.MetricsProbe{Reason: "指标数据源探测失败：" + err.Error()}
	}
	return res
}

// alertSnapshot 采集一次评估所需的全部**真实**信号。
//
// 每一项都注明取数点。取不到的信号一律留空（该规则本轮不产生候选），
// 而不是拿零值当"正常"——把"没查到"当"没问题"是本项目反复出现的静默失效形态。
func (s *Server) alertSnapshot(ctx context.Context, withChain bool) alerting.Snapshot {
	now := time.Now().Unix()
	snap := alerting.Snapshot{
		Now:             now,
		OfflineAfterSec: int64(gatewayOnlineWindow / time.Second),
		MetricsFreshSec: int64(alertMetricsFresh / time.Second),
		// 敲门令牌有效期：时钟偏差告警的文案用它说清临界点（与签发常量同源，不另抄一份数）。
		KnockTTLSec: int64(knockTTL / time.Second),
	}
	// 设备异常 ①：网关心跳 + 自报时钟。取的是控制面 mTLS 注册表——与在线用户统计同一份内存态。
	s.mu.Lock()
	for id, gw := range s.gateways {
		snap.Gateways = append(snap.Gateways, alerting.GatewayStat{ID: id, LastSeen: gw.LastSeen, SkewSec: gw.SkewSec})
	}
	s.mu.Unlock()
	// 设备异常 ②：资源水位（数据源可能还不存在，探测结论一并带上）。
	snap.Metrics = s.metricsProbe(ctx)

	// 授权信息 ①②：JIT 授予（有效/已过期未回收）。
	if gs, err := s.store.ActiveGrants(ctx); err == nil {
		snap.ActiveGrants = gs
	} else {
		slog.Warn("告警评估：读有效 JIT 授予失败，本轮跳过该规则", "err", err.Error())
	}
	if gs, err := s.store.StaleGrants(ctx, now); err == nil {
		snap.StaleGrants = gs
	} else {
		slog.Warn("告警评估：读过期未回收授予失败，本轮跳过该规则", "err", err.Error())
	}
	// 授权信息 ③：应用无法经隧道访问（与客户端剖面 warnings 同一条信号）。
	//
	// ★判据此前是 `ResourceID == ""`，两个方向都错：
	//   - **漏报悬空引用**：资源被删掉后 apps.resource_id 仍留着那个 id（没有外键、
	//     下架不级联），此时剖面会报 warning「未关联受控资源」而告警一声不响——
	//     而 Signal 里自称"与剖面 warnings 同一条信号"，两者实际不同真同假；
	//   - **误报直连书签**：mode=global 不经网关、不进隧道路由，本来就不需要资源
	//     （appAccessState 直接给 Accessible:true）。演示库里「知网文献」因此永久挂着
	//     一条无法处置的待办——管理员点「已处理」，下一轮评估又冒出来。
	// 判据收敛到一处：先排除 global，再判"没关联"或"关联了但资源不存在"。
	if ab, err := s.store.Apps(ctx); err == nil {
		known := map[string]bool{}
		if rs, rerr := s.store.Resources(ctx); rerr == nil {
			for _, r := range rs {
				known[r.ID] = true
			}
		} else {
			// 读不到资源清单就只判"完全没关联"那一半——**绝不把全部应用当成悬空**，
			// 那会在一次读库抖动时给每个应用各产生一条告警。降级方向恒为少报。
			slog.Warn("告警评估：读资源清单失败，本轮只判「未关联」不判「悬空引用」", "err", rerr.Error())
			known = nil
		}
		for _, a := range ab.Apps {
			if a.Status != "running" || a.Mode == "global" {
				continue
			}
			rid := strings.TrimSpace(a.ResourceID)
			if rid == "" {
				snap.UnlinkedApps = append(snap.UnlinkedApps, alerting.AppRef{ID: a.ID, Name: a.Name})
				continue
			}
			if known != nil && !known[rid] {
				snap.UnlinkedApps = append(snap.UnlinkedApps, alerting.AppRef{ID: a.ID, Name: a.Name})
			}
		}
	} else {
		slog.Warn("告警评估：读应用清单失败，本轮跳过该规则", "err", err.Error())
	}

	// 安全 ①：登录防爆破锁定。取 Guard 的生效清单——**登录链路正在执行的就是这一份**，
	// 而不是再去查一遍 login_lockouts（那份可能含尚未被懒清理的过期行）。
	if s.lockout != nil {
		snap.Lockouts = s.lockout.Active()
	}
	// 安全 ②：终端合规判 block 的账号（与拒发敲门令牌、撤窗断隧道同一份名单）。
	if accs, err := s.store.PostureBlockedUsers(ctx); err == nil {
		snap.PostureBlocked = accs
	} else {
		slog.Warn("告警评估：读终端合规阻断名单失败，本轮跳过该规则", "err", err.Error())
	}
	// 安全 ③：License 状态与席位——与 GET /api/v1/license、建号/签证书容量闸
	// 完全同一份判定（licenseStatus/licenseUsage 现算）。demo 不注入（无需判）。
	if ls := s.licenseStatus(ctx); ls.Mode != license.ModeDemo {
		users, gateways := s.licenseUsage(ctx)
		days := int(time.Until(licExpireEnd(ls.Manifest.ExpiresAt)).Hours() / 24)
		snap.License = &alerting.LicenseStat{
			Mode: ls.Mode, Reason: ls.Reason, ExpiresAt: ls.Manifest.ExpiresAt, DaysLeft: days,
			Users: users, MaxUsers: ls.Manifest.MaxUsers,
			Gateways: gateways, MaxGateways: ls.Manifest.MaxGateways,
		}
	}
	// 安全 ④：控制面自身的审计写入健康。**唯一一条不查库的信号**——
	// 库正是可能坏掉的那一环，再去查它只会一起失败（见 audit_health.go 的三层信号）。
	if h := s.auditWrite.snapshot(); h.Failures > 0 {
		snap.AuditWrite = &alerting.AuditWriteStat{
			Failures: h.Failures, FirstAt: h.FirstAt, LastAt: h.LastAt,
			LastErr: h.LastErr, LastEvent: h.LastEvent,
		}
	}
	// 安全 ⑤：审计防篡改链自检。
	if withChain {
		snap.AuditChain = s.verifyChainForAlert(ctx)
	}
	// 安全 ⑥：审计外送出口的投递健康与队列积压。
	//
	// ★这条信号此前不存在，而外送失败的全部信号面只有进程日志一行 slog.Warn
	// 与系统页里那一格 lastStatus——合规链路可以**静默断掉**：审计照常落本地库、
	// 页面一切正常，而 SIEM 那边从某一刻起再也没收到过东西。
	// 只取**启用中**的出口：关掉的出口本来就不该发，给它报警是噪声。
	if fs, ok := s.store.(store.AuditForwardStore); ok {
		if targets, err := fs.AuditForwardTargets(ctx); err == nil {
			for _, t := range targets {
				if t.Enabled {
					snap.ForwardTargets = append(snap.ForwardTargets, t)
				}
			}
			snap.ForwardQueueMax = fs.AuditForwardQueueMax()
		} else {
			slog.Warn("告警评估：读审计外送出口失败，本轮跳过该规则", "err", err.Error())
		}
	}
	return snap
}

// verifyChainForAlert 跑一次审计链全量重算。返回 nil = 当前存储不支持链校验（Memory 种子），
// 此时「审计链」规则本轮不产生任何结论——刻意不把"查不了"记成"没问题"。
func (s *Server) verifyChainForAlert(ctx context.Context) *alerting.ChainStatus {
	cs, ok := s.store.(auditChainStore)
	if !ok {
		return nil
	}
	res, err := cs.VerifyAuditChain(ctx)
	if err != nil {
		return &alerting.ChainStatus{Err: err.Error()}
	}
	return &alerting.ChainStatus{OK: res.OK, Checked: res.Checked, BrokenAt: res.BrokenAt}
}

// EvaluateAlerts 跑一轮告警评估：取信号 → 判定 → 落库（含冷却期去重）。
// 返回本轮**真正新产生**的告警（被冷却掉的不算，绝不谎报）。
func (s *Server) EvaluateAlerts(ctx context.Context, withChain bool) ([]store.Alert, error) {
	rules, err := s.store.AlertRules(ctx)
	if err != nil {
		return nil, err
	}
	wr, ok := s.writer.(alertWriter)
	if !ok {
		return nil, alertErr("当前存储后端不支持告警落库")
	}
	snap := s.alertSnapshot(ctx, withChain)
	cands := alerting.Evaluate(rules, snap)
	created := []store.Alert{}
	for _, c := range cands {
		a := store.Alert{
			RuleID: c.RuleID, Kind: c.Kind, Category: c.Category, Severity: c.Severity,
			Title: c.Title, Detail: c.Detail, ObjectKey: c.ObjectKey,
			Status: store.AlertPending, TriggeredAt: snap.Now,
		}
		saved, ok, err := wr.RaiseAlert(ctx, a, c.CooldownSec)
		if err != nil {
			slog.Error("告警落库失败", "rule", c.RuleID, "object", c.ObjectKey, "err", err.Error())
			continue
		}
		if !ok {
			continue // 冷却期内已有同规则同对象的告警
		}
		created = append(created, saved)
		if len(created) <= alertNotifyBudget {
			s.notifyAlert(ctx, ruleOf(rules, saved.RuleID), saved)
		}
	}
	// 超预算的部分只落一条汇总审计，措辞只说已发生的事实：告警**都已落库**，
	// 只是没有逐条外发。不写"已通知"，也不假装它们被丢弃了。
	if over := len(created) - alertNotifyBudget; over > 0 {
		slog.Warn("单轮新增告警超过通知预算，超出部分未逐条外发（告警已全部落库）",
			"新增", len(created), "预算", alertNotifyBudget, "未外发", over)
		s.auditBG(ctx, "security", fmt.Sprintf(
			"本轮业务告警评估新增 %d 条，超过单轮通知预算 %d：其中 %d 条已落库但未逐条外发"+
				"（同步发送会把评估循环拖住几十分钟，页面与 API 里这些告警一条不少）",
			len(created), alertNotifyBudget, over), "fail")
	}
	return created, nil
}

func ruleOf(rules []store.AlertRule, id string) store.AlertRule {
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	return store.AlertRule{ID: id}
}

// notifyAlert 把一条**已经产生**的告警送到消息通道（internal/notify，PRD ch15.2）。
//
// 目标通道 = 规则的 channels（留空 = 全部启用通道）。方向上宁多勿漏：
// 一条没送到的告警不会在任何页面上留下痕迹，而多发一份只是吵。
//
// ★同步发送，与安全事件通知（notifySecurityEvent 走异步派发器）刻意不同：
// 那条链路挂在**登录主流程**上，一台连不上的 SMTP 会把登录接口拖成十几秒，
// 而账号已经锁了、处置早已生效，通知发不发得出去不改变任何安全结论；
// 这里跑在后台评估循环上（手动「立即检测」是管理员自己在等一个结果），
// 同步换来的是"这一条到底发出去没有"当场可知、可落审计。上界由各通道自己的
// Timeout 管，且只有**新产生**的告警才走这里（冷却期已经把量压下来了）。
func (s *Server) notifyAlert(ctx context.Context, rule store.AlertRule, a store.Alert) {
	ns, ok := s.store.(notifyStore)
	if !ok {
		return
	}
	chans, err := ns.NotifyChannels(ctx)
	if err != nil {
		slog.Error("告警通知：通道清单读取失败，本条未发出", "alert", a.ID, "err", err.Error())
		s.auditBG(ctx, "security", "业务告警通知未发出（消息通道清单读取失败）："+a.Title, "fail")
		return
	}
	want := map[string]bool{}
	for _, id := range rule.Channels {
		want[id] = true
	}
	subject := "[白帝告警] " + a.Title
	body := "类别：" + store.AlertCategoryZh[a.Category] + "\n" +
		"对象：" + a.ObjectKey + "\n" +
		"时间：" + time.Unix(a.TriggeredAt, 0).Format("2006-01-02 15:04:05") + "\n\n" + a.Detail
	msg := notify.Message{Event: "alert", Subject: subject, Body: body}

	seen, sent := map[string]bool{}, 0
	for _, rec := range chans {
		if len(want) > 0 && !want[rec.ID] {
			continue
		}
		seen[rec.ID] = true
		if !rec.Enabled {
			// 规则显式点名了一条已停用的通道：这条必须留痕，否则就是"配了通知却没人收到"。
			if want[rec.ID] {
				s.auditBG(ctx, "security", "业务告警通知未发出（通道「"+rec.Name+"」已停用）："+a.Title, "fail")
			}
			continue
		}
		sent++
		detail, err := s.sendVia(ctx, ns, rec, msg, nil)
		if err != nil {
			slog.Error("业务告警通知发送失败", "channel", rec.Name, "alert", a.ID, "err", err.Error())
			s.auditBG(ctx, "security",
				"业务告警通知发送失败（通道「"+rec.Name+"」/"+rec.Kind+"）："+a.Title+" —— "+detail, "fail")
			continue
		}
		s.auditBG(ctx, "security",
			"业务告警通知已发出（通道「"+rec.Name+"」/"+rec.Kind+"，"+detail+"）："+a.Title, "ok")
	}
	// 规则点名的通道已经被删掉了：同样必须留痕（规则看起来还配着通知，实际发不出去）。
	for id := range want {
		if !seen[id] {
			s.auditBG(ctx, "security", "业务告警通知未发出（通道 "+id+" 不存在，可能已被删除）："+a.Title, "fail")
		}
	}
	if sent == 0 {
		slog.Warn("业务告警产生但没有可用的消息通道，通知未发出", "alert", a.ID, "title", a.Title)
	}
}

// StartAlertLoop 起周期性告警评估。ctx 取消即退出；interval<=0 表示不启用。
//
// 审计链自检按 chainEvery 单独节流（全链重算比其余信号贵得多）。
// ★这条循环本身就是「防篡改链有人定期查」的执行方：链没人查，防篡改就只是个说法。
func (s *Server) StartAlertLoop(ctx context.Context, interval, chainEvery time.Duration) {
	if interval <= 0 {
		slog.Warn("业务告警周期评估未启用（间隔 <=0）：告警只在管理员手动「立即检测」时产生")
		return
	}
	if chainEvery <= 0 {
		chainEvery = alertChainInterval
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		var lastChain time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			withChain := time.Since(lastChain) >= chainEvery
			if withChain {
				lastChain = time.Now()
			}
			created, err := s.EvaluateAlerts(ctx, withChain)
			if err != nil {
				slog.Error("业务告警评估失败", "err", err.Error())
				continue
			}
			if len(created) > 0 {
				slog.Info("业务告警", "新增", len(created), "含审计链自检", withChain)
			}
		}
	}()
}

// ── REST ──

// handleAlerts GET /api/v1/alerts?status=&category=&from=&to=&limit=（任意管理员，角色现算）。
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	query := store.AlertQuery{
		Status:   strings.TrimSpace(q.Get("status")),
		Category: strings.TrimSpace(q.Get("category")),
	}
	if query.Status != "" && !store.ValidAlertStatus(query.Status) {
		httpx.Error(w, http.StatusBadRequest, "status 须为 pending|ignored|handled")
		return
	}
	if query.Category != "" && !store.ValidAlertCategory(query.Category) {
		httpx.Error(w, http.StatusBadRequest, "category 须为 device|authz|security")
		return
	}
	var perr error
	if query.From, perr = parseAlertTime(q.Get("from"), "00:00:00"); perr != nil {
		httpx.Error(w, http.StatusBadRequest, "from 须为 Unix 秒或 2006-01-02[ 15:04:05]")
		return
	}
	if query.To, perr = parseAlertTime(q.Get("to"), "23:59:59"); perr != nil {
		httpx.Error(w, http.StatusBadRequest, "to 须为 Unix 秒或 2006-01-02[ 15:04:05]")
		return
	}
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			httpx.Error(w, http.StatusBadRequest, "limit 须为正整数")
			return
		}
		query.Limit = n
	}
	list, err := s.store.Alerts(r.Context(), query)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load alerts")
		return
	}
	// 计数**不受过滤与 LIMIT 影响**：角标与页头统计要的是全局待办量，
	// 按当前筛选算的话，切一下类别角标就跟着变，那个数字谁也不敢信。
	counts, err := s.store.AlertCounts(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to count alerts")
		return
	}
	// ★截断必须可见：total 是**当前筛选条件下库里的行数**，不是 len(list)——
	//   后者恒等于上限，truncated 永远算出 false，那句提示等于白加（wave8 行动 17
	//   在 /jit/grants 与 /posture 上踩过同一个坑）。
	total, err := s.store.CountAlerts(r.Context(), query)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to count alerts")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"alerts": list, "counts": counts, "categories": store.AlertCategoryZh,
		"total": total, "limit": store.AlertListLimit, "truncated": total > len(list),
	})
}

// parseAlertTime 解析时间过滤参数：Unix 秒 或 2006-01-02[ 15:04:05]（按本地时区）。
func parseAlertTime(v, bound string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n, nil
	}
	if len(v) == len("2006-01-02") {
		v += " " + bound
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", v, time.Local)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// handleIgnoreAlert POST /api/v1/alerts/{id}/ignore（PermSecurity）。
func (s *Server) handleIgnoreAlert(w http.ResponseWriter, r *http.Request) {
	s.decideAlert(w, r, store.AlertIgnored)
}

// handleHandleAlert POST /api/v1/alerts/{id}/handle（PermSecurity）。
func (s *Server) handleHandleAlert(w http.ResponseWriter, r *http.Request) {
	s.decideAlert(w, r, store.AlertHandled)
}

func (s *Server) decideAlert(w http.ResponseWriter, r *http.Request, status string) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	wr, ok := s.writer.(alertWriter)
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "当前存储后端不支持告警处置")
		return
	}
	id := r.PathValue("id")
	// 处置人留痕取当前令牌身份（显示名优先回退账号），与审计行为人同口径。
	actor := "—"
	if c, found := auth.FromContext(r.Context()); found {
		switch {
		case c.Name != "":
			actor = c.Name
		case c.Sub != "":
			actor = c.Sub
		}
	}
	a, err := wr.SetAlertStatus(r.Context(), id, status, actor, time.Now().Unix())
	switch err {
	case nil:
	case store.ErrAlertNotFound:
		httpx.Error(w, http.StatusNotFound, "告警不存在")
		return
	case store.ErrAlertDecided:
		httpx.Error(w, http.StatusConflict, "该告警已处置，不能重复处置")
		return
	default:
		httpx.Error(w, http.StatusInternalServerError, "failed to update alert")
		return
	}
	// 审计只记已发生的事实：状态确实改了才落这一条，且不声称"已通知申请人"之类没做过的动作。
	s.audit(r, "admin", "业务告警「"+a.Title+"」置「"+store.AlertStatusZh[status]+"」", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "alert": a})
}

// handleAlertRules GET /api/v1/alerts/rules（任意管理员，角色现算）。
//
// 一并返回：kind 元信息（前端表单据此渲染阈值项，不写死第二份）、
// 通知通道接线状态、以及**数据源就绪状态**——「等待数据面上报」必须让管理员看得见，
// 否则一条永远不触发的规则在页面上与正常规则长得一模一样。
func (s *Server) handleAlertRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rules, err := s.store.AlertRules(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load alert rules")
		return
	}
	probe := s.metricsProbe(r.Context())
	type dataSource struct {
		Kind   string `json:"kind"`
		Ready  bool   `json:"ready"`
		Reason string `json:"reason,omitempty"`
	}
	sources := []dataSource{{
		Kind: store.AlertKindGatewayLoad, Ready: probe.Ready, Reason: probe.Reason,
	}}
	// 可选通知通道：只给 id/名称/类型/启用态，**不含**主机名、URL 这类内网拓扑
	// （那些在 GET /notify/channels 里，归 PermSystem）。读面同样现算角色。
	opts, enabled := s.alertChannelOptions(r.Context())
	notifyBlock := map[string]any{"wired": enabled > 0, "channels": opts,
		"note": "规则留空 = 发给全部启用中的通道；点名则只发这几条。"}
	if enabled == 0 {
		notifyBlock["reason"] = notifyNoChannelReason
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"rules": rules, "kinds": store.AlertKindSpecs(), "sources": sources, "notify": notifyBlock,
		"cooldown": map[string]int{
			"default": store.DefaultAlertCooldownSec,
			"min":     store.MinAlertCooldownSec,
			"max":     store.MaxAlertCooldownSec,
		},
	})
}

// handleSaveAlertRule POST /api/v1/alerts/rules（PermSecurity）：新增/修改规则。
func (s *Server) handleSaveAlertRule(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	wr, ok := s.writer.(alertWriter)
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "当前存储后端不支持告警规则")
		return
	}
	var rule store.AlertRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid alert rule payload")
		return
	}
	rule.Name = strings.TrimSpace(rule.Name)
	spec, known := store.AlertKindSpecOf(rule.Kind)
	if !known {
		httpx.Error(w, http.StatusBadRequest, "未知的规则种类 "+rule.Kind+"（它背后没有任何真实信号）")
		return
	}
	if rule.Name == "" {
		rule.Name = spec.Name
	}
	// ★点名的通道必须真实存在。不校验的话，一个打错的（或已被删的）通道 id
	// 会让这条规则的通知**永远发不出去**，而规则行上那个通道标签看起来完全正常——
	// 与资源授权拒收未知组织 id 是同一条纪律。
	if len(rule.Channels) > 0 {
		opts, _ := s.alertChannelOptions(r.Context())
		known := map[string]bool{}
		for _, c := range opts {
			known[c.ID] = true
		}
		if len(known) == 0 {
			httpx.Error(w, http.StatusBadRequest, notifyNoChannelReason)
			return
		}
		for _, c := range rule.Channels {
			if !known[c] {
				httpx.Error(w, http.StatusBadRequest, "通知通道 "+c+" 不存在")
				return
			}
		}
	}
	saved, err := wr.SaveAlertRule(r.Context(), rule)
	// 阈值越界：400 + **后端原话**（哪一项、越了哪一边、后果是什么）。
	// 走 errors.Is 而不是加进下面那个 switch：错误正文里带着具体项目名，
	// 不是可比较的单例；落进 default 会变成 500「failed to save alert rule」，
	// 管理员照着去查后端连接，而真实原因是他把某个阈值框清空了。
	if err != nil && errors.Is(err, store.ErrThresholdRange) {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	switch err {
	case nil:
	case store.ErrUnknownAlertKind:
		httpx.Error(w, http.StatusBadRequest, "未知的规则种类")
		return
	case store.ErrUnknownThreshold:
		httpx.Error(w, http.StatusBadRequest, "阈值项不属于该规则种类（拼错的阈值会被静默忽略，故直接拒绝）")
		return
	default:
		httpx.Error(w, http.StatusInternalServerError, "failed to save alert rule")
		return
	}
	state := "启用"
	if !saved.Enabled {
		state = "停用"
	}
	s.audit(r, "admin", "保存告警规则「"+saved.Name+"」("+saved.Kind+"，"+state+
		"，冷却 "+strconv.Itoa(saved.CooldownSec)+"s)", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "rule": saved})
}

// handleDeleteAlertRule DELETE /api/v1/alerts/rules/{id}（PermSecurity）。
// 已产生的告警不级联删除（既成事实不该随规则消失）。
func (s *Server) handleDeleteAlertRule(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	wr, ok := s.writer.(alertWriter)
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "当前存储后端不支持告警规则")
		return
	}
	id := r.PathValue("id")
	if err := wr.DeleteAlertRule(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete alert rule")
		return
	}
	s.audit(r, "admin", "删除告警规则 "+id+"（历史告警保留）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleEvaluateAlerts POST /api/v1/alerts/evaluate（PermSecurity）：立即跑一轮评估。
// 手动触发**强制**跑审计链自检（管理员点的就是"现在查一遍"，节流留给后台循环）。
func (s *Server) handleEvaluateAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	created, err := s.EvaluateAlerts(r.Context(), true)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "告警评估失败："+err.Error())
		return
	}
	// 审计记的是事实：新增了几条（被冷却掉的不算"新增"）。
	s.audit(r, "admin", "手动执行业务告警检测，新增 "+strconv.Itoa(len(created))+" 条告警", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "created": created})
}

// licExpireEnd 到期日的当日末刻（License 语义是含当日）。解析失败回零值——
// DaysLeft 会是一个巨大的负数，expiry 规则按已过期报，方向 fail-closed。
func licExpireEnd(d string) time.Time {
	t, err := time.ParseInLocation("2006-01-02", d, time.Local)
	if err != nil {
		return time.Time{}
	}
	return t.Add(24*time.Hour - time.Second)
}
