package api

// 闲置账号治理（wave7 行动 8②：FR-MON-19/20）。
//
// 识别（GET）读 = 任意管理员现算角色；批量锁定（POST）写 = PermSecurity，
// 且目标是管理员时逐个抬到 PermAdmins（与单个置状态的 guardAdminTarget 同一道闸，
// 批量不是绕过分权的后门）；最后一名超管由 store.SetUserStatus 的防自锁拦截。
//
// ★批量锁定复用单个置状态的全部语义：同一个 SetUserStatus（带防自锁事务）、
// 同一条数据面联动（入封禁表 → 网关轮询撤窗断隧道）、逐账号落审计。
// 「批量」只是循环，不是一条绕开任何守卫的快速通道。

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// idleStore SQLiteStore 的闲置识别能力（Memory 种子模式没有——闲置判据 last_login
// 是真实数据域，演示数据里的"最后登录"本来就是编的，不值得为它出一份假清单）。
type idleStore interface {
	IdleAccounts(ctx context.Context, thresholdDays int) ([]store.IdleAccount, error)
}

// idlePolicy 取落库的闲置治理策略（读不到一律回默认：90 天 + 不自动锁定）。
//
// ★阈值此前**只从 URL 参数取**，管理员在页面上调过的值不落库：刷新一次、
// 换台机器、或者后台任务（那时根本没有 URL）都会回到写死的 90 天。
// PRD FR-MON-19 要的是一份**策略**（阈值 + 是否自动锁定），不是一个查询参数。
func (s *Server) idlePolicy(ctx context.Context) store.IdlePolicy {
	ls, ok := s.store.(interface {
		Setting(ctx context.Context, k string) (string, bool, error)
	})
	if !ok {
		return store.DefaultIdlePolicy()
	}
	raw, found, err := ls.Setting(ctx, store.IdlePolicySettingKey)
	if err != nil {
		// 读不到就按"不生效"走：绝不让一次库抖动变成"按默认阈值开始锁人"。
		return store.DefaultIdlePolicy()
	}
	return store.ParseIdlePolicy(raw, found)
}

// idleDaysParam 本次识别用的阈值：**默认取落库策略**，`?days=` 只是页面上的
// 「先按 N 天看看」预览覆盖（不改策略）。夹取走 store.ClampIdleDays 一处实现——
// 识别清单与后台自动锁定必须用同一个值，各夹各的会让两边算出不同的账号集合。
func (s *Server) idleDaysParam(r *http.Request) int {
	policy := s.idlePolicy(r.Context())
	d, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || d == 0 {
		return store.ClampIdleDays(policy.ThresholdDays)
	}
	return store.ClampIdleDays(d)
}

// handleIdleAccounts GET /api/v1/users/idle?days=N——闲置账号清单（读，任意管理员）。
func (s *Server) handleIdleAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	is, ok := s.store.(idleStore)
	if !ok {
		// 内存种子模式：如实说没有判据，不出一份编造的清单。
		httpx.JSON(w, http.StatusOK, map[string]any{"days": s.idleDaysParam(r), "accounts": []store.IdleAccount{}, "note": "当前后端无登录记录数据，无法判定闲置"})
		return
	}
	days := s.idleDaysParam(r)
	accounts, err := is.IdleAccounts(r.Context(), days)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "闲置账号清单读取失败")
		return
	}
	// 带上策略：页面要能区分「这是落库的阈值」与「这是我临时预览的天数」，
	// 也要知道自动锁定开没开——否则管理员看到一份清单，不知道系统会不会自己动手。
	httpx.JSON(w, http.StatusOK, map[string]any{
		"days": days, "accounts": accounts, "policy": s.idlePolicy(r.Context()),
	})
}

// handleIdleLock POST /api/v1/users/idle/lock {ids:[...]}——批量锁定闲置账号。
// 逐账号执行、逐账号回报：部分失败不该让整批悄悄回滚（管理员要的是"哪些没锁上、为什么"）。
func (s *Server) handleIdleLock(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var b struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&b); err != nil || len(b.IDs) == 0 {
		httpx.Error(w, http.StatusBadRequest, "ids 不能为空")
		return
	}
	if len(b.IDs) > 500 {
		httpx.Error(w, http.StatusBadRequest, "单批最多 500 个账号")
		return
	}
	// 管理员目标的权限抬升只判一次（判据与 guardAdminTarget 相同），逐目标应用。
	callerRole, roleOK := s.currentAdminRoleQuiet(r)
	adminsOK := roleOK && callerRole.Allows(store.PermAdmins)

	locked := []string{}
	skips := []idleSkip{}
	for _, id := range b.IDs {
		acct, skip := s.lockIdleAccount(r.Context(), id, adminsOK, func(cat, ev, vd string) { s.audit(r, cat, ev, vd) })
		if skip != nil {
			skips = append(skips, *skip)
			continue
		}
		locked = append(locked, acct)
	}
	s.audit(r, "admin", "闲置账号批量锁定完成："+strconv.Itoa(len(locked))+" 个已锁定、"+strconv.Itoa(len(skips))+" 个跳过", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "locked": locked, "skipped": skips})
}

// idleSkip 一个没锁上的账号与原因（回给页面，管理员要的是"哪些没锁上、为什么"）。
type idleSkip struct {
	ID      string `json:"id"`
	Account string `json:"account,omitempty"`
	Reason  string `json:"reason"`
}

// lockIdleAccount 锁定**一个**闲置账号。
//
// ★手工批量与后台自动锁定共用这一条路径，不做第二份实现。理由与「批量只是循环」
// 同源：自动锁定若另写一遍，它迟早会漏掉其中一道守卫（防自锁 / 管理员目标 /
// 数据面撤窗），而漏掉的那一条在页面上完全看不出来——账号照样显示"已锁定"。
//
// adminsOK 调用方是否持 PermAdmins。**后台自动锁定恒传 false**：那条路径上根本
// 没有"调用方"可以拿去比对权限，而一个能自己锁掉管理员的定时任务，
// 最坏情况是把整套系统锁到没人能登进去（`SetUserStatus` 的防自锁只保最后一名超管，
// 保不住"审计管理员和系统管理员一起被锁"）。
//
// auditf 由调用方给：手工路径记到操作的管理员头上，后台路径记到 system 头上——
// 异步动作记到某个管理员名下是最难自证的错记（见 auditBG 的注释）。
func (s *Server) lockIdleAccount(ctx context.Context, id string, adminsOK bool,
	auditf func(category, event, verdict string)) (string, *idleSkip) {
	target, found, err := s.lookupDirUser(ctx, func(du store.DirUser) bool { return du.ID == id })
	if err != nil {
		return "", &idleSkip{ID: id, Reason: "目录读取失败"}
	}
	if !found {
		return "", &idleSkip{ID: id, Reason: "账号不存在"}
	}
	if target.Status != "active" {
		return "", &idleSkip{ID: id, Account: target.Account,
			Reason: "当前状态为「" + statusZh[target.Status] + "」，无需锁定"}
	}
	if target.Role == "admin" && !adminsOK {
		// 与 guardAdminTarget 同一道闸：批量不是安全管理员锁掉审计/系统管理员的后门，
		// 定时任务更不是。
		auditf("security", "拒绝越权：闲置锁定跳过管理员账号「"+target.Account+"」（需要权限 "+store.PermAdmins+"）", "deny")
		return "", &idleSkip{ID: id, Account: target.Account,
			Reason: "目标是管理员，需要「管理员与角色管理」权限"}
	}
	if err := s.writer.SetUserStatus(ctx, id, "locked"); err != nil {
		// 防自锁（最后一名超管）等领域错误：如实回报，不中断整批。
		return "", &idleSkip{ID: id, Account: target.Account, Reason: err.Error()}
	}
	// 数据面联动与单个置状态完全一致：入封禁表，网关下一轮策略即撤窗断隧道。
	key := normUser(target.Account)
	s.mu.Lock()
	s.revoked[key] = revokeInfo{Reason: "账号已锁定（闲置治理）", Until: time.Now().Add(kickBanTTL).Unix(), Display: target.Account}
	s.mu.Unlock()
	auditf("admin", "闲置治理：锁定账号「"+target.Account+"」（数据面撤窗断隧道）", "ok")
	return target.Account, nil
}

// currentAdminRoleQuiet 取当前管理员角色但不写响应（批量路径逐项判定用；
// currentAdminRole 会直接把 403 写进 w，批量里那等于第一个管理员目标就中断整批）。
func (s *Server) currentAdminRoleQuiet(r *http.Request) (store.AdminRole, bool) {
	c, ok := auth.FromContext(r.Context())
	if !ok || c.Role != "admin" {
		return store.AdminRole{}, false
	}
	role, found, err := s.store.AdminRoleFor(r.Context(), c.Sub)
	if err != nil || !found {
		return store.AdminRole{}, false
	}
	return role, true
}

/* ── 闲置治理策略（PRD FR-MON-19）与自动锁定循环 ───────────────────────── */

// handleIdlePolicy GET /api/v1/users/idle/policy（读，任意管理员现算角色）。
func (s *Server) handleIdlePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	_, canIdentify := s.store.(idleStore)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"policy":  s.idlePolicy(r.Context()),
		"minDays": store.MinIdleDays, "maxDays": store.MaxIdleDays,
		// storeReady=false 时（内存种子模式）没有 last_login 判据，自动锁定不会有
		// 任何动作——页面必须当面说清，而不是画一个永远不触发的开关。
		"storeReady": canIdentify,
		// 后台自动锁定**永远不动管理员账号**：那条路径上没有调用方可比对权限。
		"autoLockSkipsAdmins": true,
	})
}

// handleSaveIdlePolicy PUT /api/v1/users/idle/policy（PermSecurity，与批量锁定同权）。
func (s *Server) handleSaveIdlePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var p store.IdlePolicy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&p); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体格式不正确")
		return
	}
	// ★入口校验与执行层同一份判据（store.IdlePolicy.Validate）。放行一个执行层
	// 必然夹掉的值，管理员会拿到 200 OK 而实际生效的是另一个数——那正是
	// CLAUDE.md 记的「入口比实现宽」。
	if err := p.Validate(); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	ls, ok := s.store.(interface {
		SetSetting(ctx context.Context, k, v string) error
	})
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前后端不支持持久化配置")
		return
	}
	raw, _ := json.Marshal(p)
	if err := ls.SetSetting(r.Context(), store.IdlePolicySettingKey, string(raw)); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "闲置治理策略保存失败")
		return
	}
	s.audit(r, "policy", "保存闲置治理策略："+idlePolicyZh(p), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "policy": p})
}

// idlePolicyZh 策略的人话（进审计正文——一条只写"已保存"的审计等于没记）。
func idlePolicyZh(p store.IdlePolicy) string {
	auto := "不自动锁定（仅识别与人工处置）"
	if p.AutoLock {
		auto = "自动锁定（后台按周期执行，跳过管理员账号）"
	}
	return "闲置判定 " + strconv.Itoa(p.ThresholdDays) + " 天未登录；" + auto
}

// StartIdleLockLoop 闲置账号自动锁定循环（PRD FR-MON-19 后半 + 验收 905 行
// 「若开启自动锁定，Then 该账号被自动锁定」）。
//
// ★这条循环是「自动锁定」的**唯一执行方**。在它之前，`autoLockEnabled` 这个
// 配置项整个不存在，闲置治理必须有人记得点进那一页、手工选中、手工点批量锁定——
// 一个要靠人记得去点的"自动治理"等于没有治理，而页面上看不出这个区别。
//
// 三条纪律：
//   - **默认关**（store.DefaultIdlePolicy），且每一轮都重新读策略：管理员关掉它之后
//     下一轮就必须停手，不能靠重启才生效。
//   - **不动管理员账号**（lockIdleAccount 的 adminsOK 恒 false）。
//   - **每一次锁定都落审计，行为人是 system**：这是系统在没人看着的时候动了别人的
//     账号，记到某个管理员头上是最难自证的错记。
func (s *Server) StartIdleLockLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		slog.Warn("闲置账号自动锁定循环未启用（间隔 <=0）：即使策略里开了「自动锁定」也不会有任何动作")
		return
	}
	if _, ok := s.store.(idleStore); !ok {
		return // 无 last_login 判据（内存种子模式）：不跑，也不假装跑过
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			s.RunIdleAutoLock(ctx)
		}
	}()
}

// RunIdleAutoLock 跑一轮自动锁定。导出给测试用——同一条代码路径，不做第二份实现。
func (s *Server) RunIdleAutoLock(ctx context.Context) {
	policy := s.idlePolicy(ctx)
	if !policy.AutoLock {
		return
	}
	is, ok := s.store.(idleStore)
	if !ok {
		return
	}
	days := store.ClampIdleDays(policy.ThresholdDays)
	accounts, err := is.IdleAccounts(ctx, days)
	if err != nil {
		slog.Error("闲置自动锁定：清单读取失败，本轮跳过", "err", err)
		return
	}
	locked, failed, admins := 0, 0, 0
	for _, a := range accounts {
		// ★管理员账号在**调 lockIdleAccount 之前**就跳过，而不是让那道闸去拒。
		//   两者结果一样，但那道闸会为每个管理员写一条「拒绝越权」审计——而这是一条
		//   每小时都跑的循环，一个长期不登录的审计管理员就够把审计冲成每天 24 条
		//   同样的噪声（与 auditGrayObserved 的节流、撤销回执的去重同一条纪律）。
		//   结构性的、每轮都成立的跳过不是"事件"。
		if a.IsAdmin {
			admins++
			continue
		}
		if _, skip := s.lockIdleAccount(ctx, a.ID, false, func(cat, ev, vd string) {
			s.auditBG(ctx, cat, ev, vd)
		}); skip != nil {
			failed++
			continue
		}
		locked++
	}
	// ★只在真锁了什么、或有账号锁失败时才记这条汇总。每轮都记的话，一套没有闲置账号的
	// 部署会每小时多一条"0 个已锁定"的审计（与 wave8 行动 8 那条「撤销回执只在真
	// 切断了什么时才报」同一条纪律）。管理员跳过数只作为上下文附在这条里，
	// 自己不触发记录——它每一轮都成立。
	if locked > 0 || failed > 0 {
		msg := "闲置账号自动锁定（阈值 " + strconv.Itoa(days) + " 天）：" +
			strconv.Itoa(locked) + " 个已锁定、" + strconv.Itoa(failed) + " 个失败"
		if admins > 0 {
			msg += "；另跳过 " + strconv.Itoa(admins) + " 个管理员账号（自动锁定不处置管理员）"
		}
		s.auditBG(ctx, "admin", msg, "ok")
	}
}
