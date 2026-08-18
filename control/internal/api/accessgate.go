package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 接入策略闸（PRD FR-POLICY-29/30，wave8 行动 13-①）──
//
// 「策略管理 → 用户策略」页此前是一整套**继承编辑器**：8 个设置项 × 组织树继承 ×
// 打破继承 × 30s 撤销条 × 保存前影响预览。它们全部落进 `policy_overrides.settings`
// 这个 JSON blob，而全仓**零消费方**——保存成功的提示却写着
// 「策略已保存并下发至「X」的代理网关」。影响预览里的平台分布是 `members×0.62/0.16`
// 现编的，冲突检查引用的还是 wave7 已经摘掉的那个开关。
//
// 那套编辑器已整批摘除，换成这两条**真有执行方**的规则。选它们两条是因为执行位点现成：
// 敲门令牌是「这台终端此刻能不能接入」的唯一命门（网关 strict 模式只认它，30s 过期，
// 客户端每 15s 回来续一次），把闸装在这里，撤销在一个保活周期内必然生效。

// accessOnlineWindowSec 多久没再取敲门令牌就算这台终端已经离线。
//
// 客户端保活周期是 15s、令牌 TTL 30s，取 90s = 6 个保活周期的容错。
// ★宁可判「还在线」也不判「已离线」：判早了会让刚拔网线的那台机器继续占着名额，
// 用户只是要多等一会儿；判晚了没有任何坏处。相反方向（窗口取得太短）会让
// 网络抖一下就把名额让出去，两台机器互相顶替，表现为轮流掉线。
const accessOnlineWindowSec int64 = 90

// devSessions 接入会话存储（纯 Memory 后端为 nil，此时整块策略不生效）。
func (s *Server) devSessions() store.DevSessionStore { return s.devSess }

// accessPolicy 读当前接入策略；读不到一律回默认值（两条规则都关）。
//
// ★回落方向恒定为"不生效"：一次读失败若回落成"上限 0"，就是全员禁止接入。
func (s *Server) accessPolicy(ctx context.Context) store.AccessPolicy {
	ls, ok := s.writer.(interface {
		Setting(ctx context.Context, k string) (string, bool, error)
	})
	if !ok {
		return store.DefaultAccessPolicy()
	}
	raw, found, err := ls.Setting(ctx, store.AccessPolicySettingKey)
	if err != nil {
		slog.Error("读接入策略失败，本次按「两条规则都不生效」处理", "err", err.Error())
		return store.DefaultAccessPolicy()
	}
	return store.ParseAccessPolicy(raw, found)
}

// accessSessionGate 接入策略闸：这台终端此刻还能不能取敲门令牌。
//
// 返回 false 时响应已写好。**放在 deviceAdmissionGate 之后**——那道是「这台设备
// 允不允许接入」（长期授信），这道是「此刻的名额与活跃度」（运行态）；
// 授信没过就没必要谈名额，反过来则会让一台未授信设备先占掉别人的名额。
func (s *Server) accessSessionGate(w http.ResponseWriter, r *http.Request, account, fingerprint string) bool {
	ds := s.devSessions()
	if ds == nil {
		return true // 纯 Memory 后端：整块策略不生效（页面上如实说明，不是静默跳过）
	}
	p := s.accessPolicy(r.Context())
	// 没开任何规则时**仍然记账**：会话表是页面上「谁在线、哪台机器、多久没流量」的
	// 唯一来源，也是管理员开启规则前判断阈值该设多少的依据。
	// ★指纹为空（老客户端不报）时不记账也不判：拿空串当一台设备的话，
	// 全公司所有老客户端会共用同一行，互相顶替 last_active 与名额。
	if fingerprint == "" {
		return true
	}
	now := time.Now().Unix()
	platform := s.devicePlatform(r.Context(), account, fingerprint)
	prev, existed, err := ds.TouchDeviceSession(r.Context(), account, fingerprint, platform, s.clientIP(r), now)
	if err != nil {
		// fail-open：会话表写不进去不代表这个人该被挡在门外。
		// 这与「基线读不到时保留全部基线」方向相反是有意的——那边缺的是**限制**，
		// 这边缺的是**记账**，把记账失败升级成拒绝接入是拿可用性给一张辅助表陪葬。
		slog.Error("接入会话记账失败，本次放行", "账号", account, "err", err.Error())
		return true
	}
	// ★self 必须是**续期前**的快照：判定要看的是"上一次敲门在什么时候、上次是什么状态"。
	// 把 LastKnock 改成 now 会让「本机是否已经在线」恒为真，同时在线上限对谁都不触发。
	self := prev
	if !existed {
		self = store.DeviceSession{Account: account, Fingerprint: fingerprint,
			IP: s.clientIP(r), FirstSeen: now, LastKnock: now, State: store.DevSessionActive}
	}
	self.Platform = platform
	sessions, err := ds.DeviceSessions(r.Context(), account)
	if err != nil {
		slog.Error("读接入会话失败，本次放行", "账号", account, "err", err.Error())
		return true
	}
	d := store.EvaluateAccess(p, sessions, self, existed, now, accessOnlineWindowSec)
	if d.Allowed {
		return true
	}
	// 超时注销要落库（下一次保活直接被"已注销"拦住，不必再算一遍空闲时长），
	// 且只在**首次**判定时落——否则每 15s 一条审计。
	if d.Rule == "idle" && self.State != store.DevSessionTimeout {
		if err := ds.EndDeviceSession(r.Context(), account, fingerprint, d.Reason, now); err != nil {
			slog.Error("标记接入会话注销失败", "账号", account, "err", err.Error())
		}
		s.audit(r, "security", "接入超时注销："+account+" 的终端 "+shortFp(fingerprint)+"（"+d.Reason+"）", "deny")
	} else if d.Rule == "concurrency" {
		// ★回滚记账：这台终端**没进来**。记账发生在判定之前（并发下必须如此），
		// 把行留着的话，它会在下一轮排名里参与竞争，把一台真正在线的终端挤掉——
		// 症状是「明明只开了 N 台、却总有一台莫名掉线」，而被挤掉的那台什么都看不到。
		if !existed {
			if err := ds.DeleteDeviceSession(r.Context(), account, fingerprint); err != nil {
				slog.Error("回滚接入会话记账失败", "账号", account, "err", err.Error())
			}
		}
		// 并发上限的拒绝按 (账号,指纹) 节流，理由同 auditGrayObserved：
		// 被挡住的客户端会每 15s 重试一次，不节流一天 5760 条。
		s.auditAccessDenied(r, account, fingerprint, d.Reason)
	}
	httpx.Error(w, http.StatusForbidden, d.Reason)
	return false
}

// devicePlatform 取这台终端的平台（分平台计数用）。
//
// 唯一真实来源是 posture 上报（`trusted_devices.platform`）——敲门令牌请求里没有平台字段，
// 加一个的话就是让**被判定方自报判据**：改一个字符串就能从 PC 名额切到移动端名额。
// 取不到回空串，`store.IsMobilePlatform` 按 PC 处理。
func (s *Server) devicePlatform(ctx context.Context, account, fingerprint string) string {
	dv, found, err := s.store.DeviceByFingerprint(ctx, account, fingerprint)
	if err != nil || !found {
		return ""
	}
	return dv.Platform
}

// auditAccessDenied 并发上限拒绝的节流审计（5min/(账号,指纹)）。
func (s *Server) auditAccessDenied(r *http.Request, account, fingerprint, reason string) {
	key := "access:" + account + "|" + fingerprint
	now := time.Now().Unix()
	s.mu.Lock()
	last := s.accessDenied[key]
	if now-last < 300 {
		s.mu.Unlock()
		return
	}
	s.accessDenied[key] = now
	s.mu.Unlock()
	s.audit(r, "security", "拒发敲门令牌："+account+" 的终端 "+shortFp(fingerprint)+"（"+reason+"）", "deny")
}

// shortFp 指纹截断展示（审计正文里放全长既没用又难读）。
func shortFp(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "…"
}

// ── REST ──

// handleAccessPolicy GET /api/v1/policies/access —— 读接入策略 + 它当前**是否真能生效**。
func (s *Server) handleAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	p := s.accessPolicy(r.Context())
	out := map[string]any{"policy": p, "onlineWindowSec": accessOnlineWindowSec}
	// ★能力声明：两条规则各自依赖什么信号、当下有没有。页面据此置灰或提示，
	// 而不是让管理员配好一条永远不会触发的规则（与告警规则的「数据源未就绪」同一套做法）。
	ds := s.devSessions()
	out["storeReady"] = ds != nil
	if ds != nil {
		all, err := ds.AllDeviceSessions(r.Context())
		if err == nil {
			known := 0
			for _, x := range all {
				if x.ActivityKnown {
					known++
				}
			}
			out["sessions"] = all
			out["activityKnown"] = known
			// idleReady：有没有任何一条会话拿到过网关的活跃回执。全都没有的话，
			// FR-POLICY-30 开了也不会触发——必须当面说清，别让它变成第二个假开关。
			out["idleReady"] = known > 0
		}
	}
	httpx.JSON(w, http.StatusOK, out)
}

// handleSaveAccessPolicy PUT /api/v1/policies/access（PermSecurity）。
func (s *Server) handleSaveAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var p store.AccessPolicy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&p); err != nil {
		httpx.Error(w, http.StatusBadRequest, "配置格式不正确")
		return
	}
	if err := p.Validate(); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	ls, ok := s.writer.(interface {
		SetSetting(ctx context.Context, k, v string) error
	})
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储后端不支持保存接入策略")
		return
	}
	raw, _ := json.Marshal(p)
	if err := ls.SetSetting(r.Context(), store.AccessPolicySettingKey, string(raw)); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save access policy")
		return
	}
	s.audit(r, "policy", "保存接入策略："+accessPolicyZh(p), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "policy": p})
}

// accessPolicyZh 审计正文（要能从审计里读出这次到底改成了什么）。
func accessPolicyZh(p store.AccessPolicy) string {
	out := "同时在线设备上限="
	if !p.DeviceLimitEnabled {
		out += "关闭"
	} else if p.SplitPlatform {
		out += "PC " + strconv.Itoa(p.MaxDevices) + " 台 / 移动端 " + strconv.Itoa(p.MaxDevicesMobile) + " 台"
	} else {
		out += strconv.Itoa(p.MaxDevices) + " 台"
	}
	out += "；接入超时注销="
	if p.IdleEnabled {
		out += strconv.Itoa(p.IdleMinutes) + " 分钟无业务流量"
	} else {
		out += "关闭"
	}
	return out
}

// recordSessionActivity 把网关上报的会话活跃时刻落进 device_sessions。
//
// 匹配键是 (账号, 源IP)：网关的会话表按源 IP 记，它不知道设备指纹（SPA 单包里没有）。
// 匹配不上任何一行时静默跳过——那多半是「这个人经浏览器走 L7 进来的」或
// 「敲门令牌是另一个 IP 取的」，都不构成活跃证据，更不能反过来当成"该注销"。
func (s *Server) recordSessionActivity(r *http.Request, sessions []GwSession) {
	ds := s.devSessions()
	if ds == nil {
		return
	}
	for _, sess := range sessions {
		if sess.LastActive == nil || sess.User == "" || sess.IP == "" {
			continue // nil = 这台网关不报活跃时刻，什么都不能推断
		}
		if err := ds.MarkDeviceActivity(r.Context(), sess.User, sess.IP, *sess.LastActive); err != nil {
			slog.Error("落业务活跃回执失败", "账号", sess.User, "ip", sess.IP, "err", err.Error())
		}
	}
}
