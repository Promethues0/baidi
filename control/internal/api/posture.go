package api

import (
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
	// StrictUnknown 跟随 postureStrict：strict 已是「说不清楚就不放行」（缺报/过期即拒），
	// 探不到的检查项同口径处理；observe 下不可判定只单列展示，不误拒真实合规的终端。
	v := risk.Evaluate(b.Platform, b.Checks, baselines, risk.Options{StrictUnknown: s.postureStrict})

	user := normUser(c.Name)
	// 转换审计口径须与执行闸门一致——都用用户级「跨设备最差」判定，而非单设备前值
	// （否则设备 B 恢复合规会误记「已解除」，但闸门按最差仍在拦该用户）。
	prevWorst, hadPrev, _ := s.store.PostureVerdict(r.Context(), user)
	rep := store.PostureReport{
		User: user, Device: b.Device, Platform: b.Platform, OS: b.OS, ClientVersion: b.ClientVersion,
		Checks: b.Checks, Verdict: v.Disposal, Score: v.Score, Level: v.Level, Reasons: v.Reasons,
		TS: time.Now().Unix(),
	}
	// 设备基数上限在 store 写入语句内原子判定（handler 层 check-then-act 在并发突发下会越过上限）。
	if err := s.writer.SavePostureReport(r.Context(), rep); err != nil {
		if errors.Is(err, store.ErrPostureDeviceCap) {
			httpx.Error(w, http.StatusForbidden,
				fmt.Sprintf("终端设备数超限（最多 %d 台），请联系管理员清理", store.MaxPostureDevices))
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
		// 「任一设备 gray」不等于「这个人此刻处于 gray 档」：另一台设备判 degrade/block 时
		// 他真正被执行的是那一档。按最差判定过滤，免得审计里写着"正在观察"、
		// 而这个人其实已经被降权甚至阻断了——审计只记已发生的事实。
		worst, ok, verr := s.store.PostureVerdict(r.Context(), key)
		if verr != nil || !ok || worst.Verdict != store.DisposalGray {
			continue
		}
		s.mu.Lock()
		last, seen := s.grayObserved[key]
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
	reports, err := s.store.PostureReports(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load posture reports")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"reports": reports})
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
		s.audit(r, "security", "删除终端报告："+user+" / 设备 "+device+"（设备退役，若为 block 报告则解除该设备触发的接入收缩）", "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}
