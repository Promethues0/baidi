package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/lockout"
	"baidi.dev/control/internal/store"
)

// ── 登录防爆破（FR-MON-17/18 + NFR-SEC-06）──
//
// 接线点：/auth/login 与 /portal/login 进门先查锁；口令错误 / WebAuthn 断言失败计一次；
// 登录成功清零该账号计数；认证源故障不计数（故障 ≠ 密码错误，见 login_authsrc.go）。
// 源 IP 一律取 clientIP（XFF 信任边界判定后的值）——绝不直信裸 X-Forwarded-For。

// loginGateLocked 登录进门锁检查：账号锁或 IP 锁命中即 403 并告知剩余时间。
// ★响应不泄露账号是否存在：失败计数对目录中不存在的账号同样进行，「已锁定」
// 推不出「账号存在」；文案也刻意不说命中的是账号锁还是 IP 锁。
func (s *Server) loginGateLocked(w http.ResponseWriter, r *http.Request, account string) bool {
	lk, hit := s.lockout.Check(normUser(account), s.clientIP(r))
	if !hit {
		return false
	}
	httpx.Error(w, http.StatusForbidden,
		fmt.Sprintf("登录失败次数过多，已被临时锁定，请约 %s后重试", remainStr(lk.Until)))
	return true
}

// remainStr 锁定剩余时间的可读形态（向上取整到分钟，最小 1 分钟）。
func remainStr(until int64) string {
	sec := until - time.Now().Unix()
	if sec < 1 {
		sec = 1
	}
	return fmt.Sprintf("%d 分钟", (sec+59)/60)
}

// noteLoginFailure 登记一次登录失败；若触发新锁定则写审计（category=security，
// 只记确实建立了的锁定——Fail 返回的就是已发生的事实）。
func (s *Server) noteLoginFailure(r *http.Request, account string) {
	for _, lk := range s.lockout.Fail(r.Context(), normUser(account), s.clientIP(r)) {
		subj := "账号 " + lk.Key
		if lk.Kind == store.LockKindIP {
			subj = "来源 IP " + lk.Key
		}
		s.auditAs(r, account, "security",
			subj+" 触发登录防爆破锁定（"+lk.Reason+"，锁定至 "+time.Unix(lk.Until, 0).Format("15:04")+"）", "deny")
	}
}

// handleLockouts 列当前生效的账号锁 + IP 锁（admin）。
func (s *Server) handleLockouts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"lockouts": s.lockout.Active()})
}

// handleUnlockLockout 管理员解锁一条防爆破锁定（body {kind,key}）。
func (s *Server) handleUnlockLockout(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var b struct {
		Kind string `json:"kind"`
		Key  string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Key == "" ||
		(b.Kind != store.LockKindAccount && b.Kind != store.LockKindIP) {
		httpx.Error(w, http.StatusBadRequest, "kind 须为 account|ip，key 不能为空")
		return
	}
	key := b.Key
	if b.Kind == store.LockKindAccount {
		key = normUser(key) // 账号锁按规范化账号存取（与计数/查锁同口径）
	}
	removed, err := s.lockout.Unlock(r.Context(), b.Kind, key)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to unlock")
		return
	}
	if !removed {
		httpx.Error(w, http.StatusNotFound, "未找到生效中的锁定（可能已到期自动解除）")
		return
	}
	subj := map[string]string{store.LockKindAccount: "账号 ", store.LockKindIP: "来源 IP "}[b.Kind] + key
	s.audit(r, "security", "解除登录防爆破锁定（"+subj+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "kind": b.Kind, "key": key})
}

// handleLockoutConfig 读当前生效的防爆破配置（admin）。
func (s *Server) handleLockoutConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	httpx.JSON(w, http.StatusOK, s.lockout.Config())
}

// handleSaveLockoutConfig 保存防爆破配置（admin）：settings 落库 + 即时生效。
// 这是策略页「同 IP / 同用户名连续登录错误锁定」开关与阈值的真实后端——
// 消费方是登录链路的 Guard，本配置不是摆设。
func (s *Server) handleSaveLockoutConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var c lockout.Config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		httpx.Error(w, http.StatusBadRequest, "配置格式不正确")
		return
	}
	if err := c.Validate(); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.lockout.SetConfig(r.Context(), c); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save lockout config")
		return
	}
	onOff := func(b bool) string {
		if b {
			return "开"
		}
		return "关"
	}
	s.audit(r, "admin", fmt.Sprintf("更新登录防爆破配置（阈值 %d 次 / 窗口 %ds / 锁定 %ds / IP 维度%s / 账号维度%s）",
		c.Threshold, c.WindowSec, c.DurationSec, onOff(c.IPEnabled), onOff(c.AccountEnabled)), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "config": c})
}

// overlayBruteLocks 把生效中的账号防爆破锁定叠加进用户态势：
//   - 已在受关注清单里的账号：打 BruteLocked 标记 + 追加原因（不改 store 给出的 state——
//     目录状态是管理员权威，爆破锁定是另一种锁，两者用字段区分而不是混成一个值）；
//   - 不在清单里的账号（目录状态正常，甚至可能不在目录）：合成一行 locked 展示，
//     ID 留空——它没有目录行可操作，解锁只走 /security/lockouts/unlock。
//
// 展示值来自数据面真正在用的那份：锁定的执行源就是 login_lockouts/Guard，这里读的即执行态。
func (s *Server) overlayBruteLocks(r *http.Request, b *store.UserStateBundle) {
	idx := map[string]int{}
	for i := range b.Items {
		idx[normUser(b.Items[i].Account)] = i
	}
	for _, lk := range s.lockout.Active() {
		if lk.Kind != store.LockKindAccount {
			continue
		}
		reason := lk.Reason + "，触发防爆破锁定（至 " + time.Unix(lk.Until, 0).Format("15:04") + "）"
		if i, ok := idx[lk.Key]; ok {
			b.Items[i].BruteLocked = true
			b.Items[i].Reasons = append(b.Items[i].Reasons, reason)
			continue
		}
		name, org := lk.Key, "—"
		if u, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool {
			return normUser(du.Account) == lk.Key
		}); err == nil && found {
			name, org = u.Name, u.Org
		}
		b.Items = append(b.Items, store.UserStateItem{
			User: name, Account: lk.Key, Org: org, State: "locked", Risk: "high",
			BruteLocked: true, Reasons: []string{reason},
			LastEvent: "登录防爆破自动锁定", LastSeen: lk.CreatedAt,
		})
	}
	// locked 桶计数对齐叠加后的事实：目录锁定 ∪ 爆破锁定
	n := 0
	for _, it := range b.Items {
		if it.State == "locked" || it.BruteLocked {
			n++
		}
	}
	for i := range b.Buckets {
		if b.Buckets[i].Key == "locked" {
			b.Buckets[i].Count = n
		}
	}
}
