package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/risk"
	"baidi.dev/control/internal/store"
)

// postureFreshTTL posture 报告新鲜窗口（strict 模式缺报/过期即拒；block 判定不看新鲜度，见 spec DP-04）。
const postureFreshTTL = 10 * time.Minute

// validReportPlatform 上报可接受的平台（对齐基线检查的平台枚举，但不含 "All"）。
// 服务端对基线 platform 有严格枚举，对上报 platform 同样校验，杜绝"未知平台跳过全部基线→allow 顶掉 block"。
var validReportPlatform = map[string]bool{"Windows": true, "macOS": true, "Linux": true}

// handlePostureReport 终端 posture 上报：风险引擎按安全基线评估 → 落库最新报告 → 回传可解释判定。
// 判定权在控制面；判定转入/转出 block 落 security 审计（自动收缩/恢复留痕）。
func (s *Server) handlePostureReport(w http.ResponseWriter, r *http.Request) {
	// requireUser：拒网关身份与 WebAuthn 中间票据(role=mfa)——只有完整会话才能上报终端环境。
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var b struct {
		Device        string                     `json:"device"`
		Platform      string                     `json:"platform"`
		OS            string                     `json:"os"`
		ClientVersion string                     `json:"clientVersion"`
		Checks        []store.PostureCheckResult `json:"checks"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&b); err != nil ||
		strings.TrimSpace(b.Device) == "" {
		httpx.Error(w, http.StatusBadRequest, "device 必填")
		return
	}
	if !validReportPlatform[b.Platform] {
		httpx.Error(w, http.StatusBadRequest, "platform 取值须为 Windows|macOS|Linux")
		return
	}
	if len(b.Device) > 128 || len(b.Checks) > 32 {
		httpx.Error(w, http.StatusBadRequest, "device 过长或检查项超限（≤32）")
		return
	}
	// os / clientVersion 同样是终端**自报**、且此前完全不校验的字段：os 会成为设备台账里的
	// 设备名（enrollReportingDevice → EnrollDevice），两者都会进 posture_reports 并被
	// 设备页、合规页、审计正文反复渲染。请求体上限 32 KiB 意味着一次上报就能塞进一坨文本，
	// 每账号还能重复 MaxDevicesPerAccount 次。入口限长是第一道，store 侧
	// EnrollDevice 按 DeviceNameMaxRunes 截断是第二道（同一列只有一份口径）。
	if len([]rune(b.OS)) > 128 || len([]rune(b.ClientVersion)) > 64 {
		httpx.Error(w, http.StatusBadRequest, "os（≤128 字）或 clientVersion（≤64 字）过长")
		return
	}
	// 管理侧删除接口经 URL 路径定位设备（DELETE /posture/{user}/{device}）：
	// "."/".." 会被 mux 路径清洗成 301、斜杠会拆散路径段，落库后即成永远删不掉的记录，入口拒绝。
	if b.Device == "." || b.Device == ".." || strings.ContainsAny(b.Device, "/\\") {
		httpx.Error(w, http.StatusBadRequest, "device 不可为 . / .. 或含斜杠")
		return
	}
	// 规则源：安全中心基线。读失败 fail-closed（不评估就不落库，避免坏数据顶掉有效判定）。
	baselines, err := s.store.Baselines(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load baselines")
		return
	}
	// ★client_version 这一项由**控制面**判：目标版本只有控制面知道（灰度发布里配的稳定版），
	// 终端手里只有自己的版本号。采集器如实报 unknown，这里重算并**写回 checks**，
	// 于是「终端合规页渲染的那一格」与「风险引擎判定的那一格」是同一个结论——
	// 只判不写回的话，页面仍会照客户端那份渲染，两边说不同的话。
	checks := risk.ResolveClientVersion(b.Checks, b.ClientVersion, s.minClientVersion(r.Context(), b.Platform))
	// StrictUnknown 跟随 postureStrict：strict 已是「说不清楚就不放行」（缺报/过期即拒），
	// 探不到的检查项同口径处理；observe 下不可判定只单列展示，不误拒真实合规的终端。
	// ★按适用范围过滤（wave8 行动 13-④）：只把「这个账号在范围内」的基线交给判定。
	// 过滤放在这里而不是 risk.Evaluate 里——Evaluate 是纯函数、不碰 IO，
	// 把 SubjectIndex 取数塞进去就再也测不动了。
	baselines = s.baselinesInScope(r.Context(), normUser(c.Name), baselines)
	v := risk.Evaluate(b.Platform, checks, baselines, risk.Options{StrictUnknown: s.postureStrict})

	user := normUser(c.Name)
	// 转换审计口径须与执行闸门一致——都用用户级「跨设备最差」判定，而非单设备前值
	// （否则设备 B 恢复合规会误记「已解除」，但闸门按最差仍在拦该用户）。
	prevWorst, hadPrev, _ := s.store.PostureVerdict(r.Context(), user)
	rep := store.PostureReport{
		User: user, Device: b.Device, Platform: b.Platform, OS: b.OS, ClientVersion: b.ClientVersion,
		Checks: checks, Verdict: v.Disposal, Score: v.Score, Level: v.Level, Reasons: v.Reasons,
		TS: time.Now().Unix(),
	}
	// ★设备台账登记排在报告落库**之前**：单账号设备上限（MaxDevicesPerAccount）的
	// 权威判定点是 trusted_devices（两表按 (账号,指纹) 一一对应，口径必须只有一份）。
	// 反过来先落报告的话，超限时会留下一条没有设备登记的孤儿报告——终端管理页看不见它，
	// 而它照样把「跨设备取最差」的判定拉低，管理员翻遍设备页也找不到那台机器。
	// 上限判定在 EnrollDevice 的事务内原子完成（handler 层 check-then-act 在并发突发下会越界）。
	if _, _, derr := s.enrollReportingDevice(r, user, b.Device, b.Platform, b.OS); derr != nil {
		if errors.Is(derr, store.ErrDeviceCap) {
			httpx.Error(w, http.StatusForbidden,
				fmt.Sprintf("终端设备数超限（最多 %d 台），请在管理台「终端管理」页清理陈旧设备后重试", store.MaxDevicesPerAccount))
			return
		}
		httpx.Error(w, http.StatusInternalServerError, "failed to enroll device")
		return
	}
	// 设备基数上限在 store 写入语句内也各有一道（纵深，正常路径下先被 EnrollDevice 拦住）。
	if err := s.writer.SavePostureReport(r.Context(), rep); err != nil {
		if errors.Is(err, store.ErrPostureDeviceCap) {
			httpx.Error(w, http.StatusForbidden,
				fmt.Sprintf("终端设备数超限（最多 %d 台），请在管理台「终端管理」页清理陈旧设备后重试", store.MaxDevicesPerAccount))
			return
		}
		httpx.Error(w, http.StatusInternalServerError, "failed to save posture report")
		return
	}
	// 判定转换留痕（用户级）：转入 block = 自动收缩；转出 = 恢复合规。best-effort。
	nowWorst, _, _ := s.store.PostureVerdict(r.Context(), user)
	prevBlocked := hadPrev && prevWorst.Verdict == "block"
	nowBlocked := nowWorst.Verdict == "block"
	if nowBlocked && !prevBlocked {
		s.audit(r, "security", "终端环境不合规，自动收缩接入："+c.Name+"（"+strings.Join(nowWorst.Reasons, "、")+"）", "deny")
		// 通知只在**转入** block 那一次发（与审计同一条判据）：posture 是每次上报都来一遍的，
		// 按"当前是 block"发的话，一台不合规的终端会按上报频率把管理员的邮箱刷爆，
		// 而真正需要被看见的是"状态变了"这一刻。异步入队，不阻塞上报应答。
		s.notifySecurityEvent("posture-block", "【白帝】终端不合规，接入已收缩："+c.Name,
			"该账号的终端合规判定已转入 block，接入被自动收缩（拒发敲门令牌 + 撤窗断隧道）。\n\n账号："+c.Name+
				"\n触发设备："+b.Device+"（"+b.Platform+" "+b.OS+"）\n命中基线："+strings.Join(nowWorst.Reasons, "、")+
				"\n\n终端整改后重新上报即自动解除；本条只在判定**转入** block 时发一次。")
	} else if !nowBlocked && prevBlocked {
		s.audit(r, "security", "终端环境恢复合规，解除接入收缩："+c.Name, "ok")
	}
	// unknowns 单独回传：这些项没被计入判定，但终端必须看见「有几项探不到」——
	// 否则一台探测全失败的机器会显示成完全合规（observe 下判定确实是 allow）。
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "verdict": v.Disposal, "score": v.Score, "level": v.Level,
		"reasons": v.Reasons, "unknowns": v.Unknowns,
	})
}

// grayObserveInterval 同一账号两条 observing 审计之间的最小间隔。
//
// ★为什么要节流：策略下发是网关每 30s 一次的轮询，且网关可能有多台。不节流的话
// 一个灰度账号一天会产出近 3000 条内容完全相同的审计——审计表被冲刷成噪声之后，
// 真正的处置事件（block 转入/转出、强制下线）就淹没在里面翻不出来了，
// 这与「提高审计粒度」的初衷正好相反。5 分钟足以让「正在被观察」这件事在时间线上连续可见。
const grayObserveInterval = 5 * time.Minute

// auditGrayObserved 为当前处于灰度观察档（disposal=gray）的账号落 observing 审计。
//
// 灰度观察的**全部执行内容**就是这条审计 + 用户状态页的档位显示：访问权一字不改
// （既不进 DenyUsers、也不进撤销名单）。这是刻意的——gray 的定位是"先看着"，
// 一旦它开始改变访问权，管理员就再也没有一个"只观察不影响业务"的档位可用了。
//
// 措辞只陈述已发生的事实：「终端风险灰度观察中」+ 命中的基线项，
// 不写"已收缩""已限制"之类根本没发生的动作。
func (s *Server) auditGrayObserved(r *http.Request) {
	accounts, err := s.store.PostureUsersByDisposal(r.Context(), store.DisposalGray)
	if err != nil {
		slog.Error("灰度观察名单读取失败，本轮不记 observing 审计", "err", err.Error())
		return
	}
	now := time.Now().Unix()
	gap := int64(grayObserveInterval.Seconds())
	for _, acc := range accounts {
		key := normUser(acc)
		// ★节流先判、查询后做（wave9）。此前 PostureVerdict 排在节流之前，于是
		// 节流拦下的只是**审计写**，而每个 gray 账号每轮仍真查一次库——这条 N+1
		// 的库成本完全不受节流约束，还随网关台数相乘（每台网关每 15s 各跑一遍）。
		s.mu.Lock()
		last, seen := s.grayObserved[key]
		s.mu.Unlock()
		if seen && now-last < gap {
			continue
		}

		// 「任一设备 gray」不等于「这个人此刻处于 gray 档」：另一台设备判 degrade/block 时
		// 他真正被执行的是那一档。按最差判定过滤，免得审计里写着"正在观察"、
		// 而这个人其实已经被降权甚至阻断了——审计只记已发生的事实。
		worst, ok, verr := s.store.PostureVerdict(r.Context(), key)
		if verr != nil || !ok || worst.Verdict != store.DisposalGray {
			// 不更新时间戳：这一档不属于他，下一轮该重新判（与改造前逐字一致）。
			continue
		}
		// 双重检查：上面那次读锁与这里之间可能有另一台网关的轮询挤进来。
		// 判定与更新必须在同一次持锁内完成，否则两台网关同时到期会各记一条。
		s.mu.Lock()
		last, seen = s.grayObserved[key]
		due := !seen || now-last >= gap
		if due {
			s.grayObserved[key] = now
		}
		s.mu.Unlock()
		if !due {
			continue
		}
		reasons := ""
		if len(worst.Reasons) > 0 {
			reasons = "（" + strings.Join(worst.Reasons, "、") + "）"
		}
		s.auditAs(r, acc, "security", "终端风险灰度观察中："+acc+reasons+"，访问权未变更", "observing")
	}
}

// handlePostureList 最新终端报告清单（admin，安全中心「终端合规」）。
func (s *Server) handlePostureList(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	reports, total, err := s.postureReportsPage(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load posture reports")
		return
	}
	// 截断必须可见（同 handleJitGrants）。判定面不受这道上限影响——
	// 准入闸走 PostureUsersByDisposal 的独立 DISTINCT 查询——但一份被截断的
	// 合规清单被当成全量，管理员会据此判断「没有不合规终端」。
	httpx.JSON(w, http.StatusOK, map[string]any{
		"reports": reports, "total": total, "limit": store.ListLimit,
		"truncated": total > len(reports)})
}

// handleDeletePostureReport 删除某设备的终端报告（admin，设备退役 / 清理陈旧记录）。
// ★安全语义：删掉一条 block 报告会把该用户从"跨设备最差"判定里摘除 → 若无其他 block 设备，
// 该用户即刻解除接入收缩（等价于"退役问题设备后放行"）。故审计为 security 事件留痕。
func (s *Server) handleDeletePostureReport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	user := r.PathValue("user")
	device := r.PathValue("device")
	if strings.TrimSpace(user) == "" || strings.TrimSpace(device) == "" {
		httpx.Error(w, http.StatusBadRequest, "user/device 必填")
		return
	}
	deleted, err := s.writer.DeletePostureReport(r.Context(), user, device)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete posture report")
		return
	}
	if deleted {
		// ★措辞把两表的关系说清楚：删的是**报告**，设备登记（trusted_devices）仍在，
		// 因此单账号设备名额也没有被释放。要退役整台设备走「终端管理」页的删除
		// （那一处同删两表）。不写清楚的话，管理员会在这里反复删报告、纳闷为什么
		// 还是提示设备数超限——而两处操作在页面上看起来是同一件事。
		s.audit(r, "security", "删除终端环境报告："+user+" / 设备 "+device+
			"（若为 block 报告则解除该设备触发的接入收缩；设备登记与授信状态不变，名额未释放——"+
			"整台设备退役请在「终端管理」页删除）", "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

// minClientVersion 该平台「客户端至少要跑到哪一版」——client_version 合规判定的判据。
//
// 两个真实来源，按此顺序取第一个有值的：
//
//  1. **灰度计划的 Stable**（`升级 → 灰度发布`）。它是管理员的显式声明——「不在灰度内的
//     账号应该拿这一版」。取 Stable 而不是 Version（灰度版）：灰度的意义是「先小范围
//     验证再放开」，拿灰度版当合规线会让全体没进灰度批次的终端一夜之间集体不合规，
//     而他们装的恰恰是管理员让他们装的那一版。
//  2. **下载中心正在分发的那一版**（manifest 里 available 的条目）。这是兜底，也是绝大多数
//     部署的真实形态：`SaveGrayPlan` 对 `Version==""` 的计划是**整条丢弃**的
//     （见 store.SaveGrayPlan，那是「置空版本即撤销灰度」的语义），所以「我没在灰度，
//     但我想声明稳定版是 0.3.0」这件事今天根本表达不出来。只认来源 1 的话，
//     没跑灰度的部署里这一项会恒「无法判定」——比假绿好，但仍然等于没做。
//     「你装的包比我们正在分发的旧」本身就是一句站得住的合规判据。
//
// 两个来源都取不到就回空串 → ResolveClientVersion 判「无法判定」而不是「合规」：
// 该平台既没发布计划也没在分发包时，「是不是最新版」这个问题本身没有答案，
// 而假绿正是这次要消灭的东西。读失败同理（宁可不可判定，不可假绿）。
func (s *Server) minClientVersion(ctx context.Context, platform string) string {
	// 灰度计划的平台键是小写（macos/windows/linux/…），posture 上报是强枚举
	// Windows|macOS|Linux——两处口径不同，必须归一，否则永远匹配不上而恒「无法判定」。
	want := strings.ToLower(strings.TrimSpace(platform))
	if s.upg != nil {
		plans, err := s.upg.GrayPlans(ctx)
		if err != nil {
			// 读失败**直接返回不可判定**，不退到来源 2：此刻我们不知道管理员是不是配了
			// 一个更高的稳定版，用分发包那一版去判会把「其实已经不合规」说成合规。
			slog.Warn("读灰度计划失败，本次 client_version 按「无法判定」处理（不假绿）",
				"平台", platform, "err", err.Error())
			return ""
		}
		for _, p := range plans {
			if strings.ToLower(strings.TrimSpace(p.Platform)) == want && strings.TrimSpace(p.Stable) != "" {
				return p.Stable
			}
		}
	}
	for _, c := range s.loadManifest().Clients {
		// 只认 available 的条目：占位条目（「构建中，敬请期待」/ UNVERIFIED 不进下载中心）
		// 的 version 要么为空、要么是个没人能装到的版本号，拿它当合规线是在要求用户
		// 去装一个下载中心根本不给他的包。
		if c.Available && strings.ToLower(strings.TrimSpace(c.Platform)) == want {
			return strings.TrimSpace(c.Version)
		}
	}
	return ""
}

// postureReportsPage 取清单 + 库里总行数；后端不支持分页时回退成「总数=已读条数」。
func (s *Server) postureReportsPage(ctx context.Context) ([]store.PostureReport, int, error) {
	if p, ok := s.store.(interface {
		PostureReportsPage(ctx context.Context) ([]store.PostureReport, int, error)
	}); ok {
		return p.PostureReportsPage(ctx)
	}
	l, err := s.store.PostureReports(ctx)
	return l, len(l), err
}
