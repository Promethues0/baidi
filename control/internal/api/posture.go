package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/risk"
	"baidi.dev/control/internal/store"
)

// postureFreshTTL posture 报告新鲜窗口（strict 模式缺报/过期即拒；block 判定不看新鲜度，见 spec DP-04）。
const postureFreshTTL = 10 * time.Minute

// maxPostureDevices 单账号最多留存的终端设备报告数（防用随机 device 无界撑大 posture_reports）。
const maxPostureDevices = 20

// validReportPlatform 上报可接受的平台（对齐基线检查的平台枚举，但不含 "All"）。
// 服务端对基线 platform 有严格枚举，对上报 platform 同样校验，杜绝"未知平台跳过全部基线→allow 顶掉 block"。
var validReportPlatform = map[string]bool{"Windows": true, "macOS": true, "Linux": true}

// handlePostureReport 终端 posture 上报：风险引擎按安全基线评估 → 落库最新报告 → 回传可解释判定。
// 判定权在控制面；判定转入/转出 block 落 security 审计（自动收缩/恢复留痕）。
func (s *Server) handlePostureReport(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.FromContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "未认证")
		return
	}
	if c.Role == "gateway" {
		httpx.Error(w, http.StatusForbidden, "网关身份不能上报终端环境")
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
	// 规则源：安全中心基线。读失败 fail-closed（不评估就不落库，避免坏数据顶掉有效判定）。
	baselines, err := s.store.Baselines(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load baselines")
		return
	}
	v := risk.Evaluate(b.Platform, b.Checks, baselines)

	user := normUser(c.Name)
	// 设备基数上限：新 device 才计数（已存在的 upsert 不增行）；防随机 device 无界撑大 posture_reports。
	if _, exists, err := s.store.PostureReportFor(r.Context(), user, b.Device); err == nil && !exists {
		if n, err := s.store.PostureDeviceCount(r.Context(), user); err == nil && n >= maxPostureDevices {
			httpx.Error(w, http.StatusForbidden, "终端设备数超限（最多 20 台），请联系管理员清理")
			return
		}
	}
	// 转换审计口径须与执行闸门一致——都用用户级「跨设备最差」判定，而非单设备前值
	// （否则设备 B 恢复合规会误记「已解除」，但闸门按最差仍在拦该用户）。
	prevWorst, hadPrev, _ := s.store.PostureVerdict(r.Context(), user)
	rep := store.PostureReport{
		User: user, Device: b.Device, Platform: b.Platform, OS: b.OS, ClientVersion: b.ClientVersion,
		Checks: b.Checks, Verdict: v.Disposal, Score: v.Score, Level: v.Level, Reasons: v.Reasons,
		TS: time.Now().Unix(),
	}
	if err := s.writer.SavePostureReport(r.Context(), rep); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save posture report")
		return
	}
	// 判定转换留痕（用户级）：转入 block = 自动收缩；转出 = 恢复合规。best-effort。
	nowWorst, _, _ := s.store.PostureVerdict(r.Context(), user)
	prevBlocked := hadPrev && prevWorst.Verdict == "block"
	nowBlocked := nowWorst.Verdict == "block"
	if nowBlocked && !prevBlocked {
		s.audit(r, "security", "终端环境不合规，自动收缩接入："+c.Name+"（"+strings.Join(nowWorst.Reasons, "、")+"）", "deny")
	} else if !nowBlocked && prevBlocked {
		s.audit(r, "security", "终端环境恢复合规，解除接入收缩："+c.Name, "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "verdict": v.Disposal, "score": v.Score, "level": v.Level, "reasons": v.Reasons,
	})
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
