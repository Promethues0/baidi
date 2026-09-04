package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// objectExists 报告对象库中是否存在给定 kind(addr|service|time) 的对象 id（点查，挡悬空引用）。
func (s *Server) objectExists(ctx context.Context, kind, id string) (bool, error) {
	return s.store.ObjectExists(ctx, kind, id)
}

// ── 监控中心 · 在线用户 ──

// handleOnline 返回实时在线会话：**唯一来源**是在线数据面网关上报的真实敲门会话
// （离线网关的会话快照不计入），叠加"已强制下线"覆盖层。
//
// ★这里曾经有一条回退：没有网关上报时渲染 store 里的 10 条演示会话（source=demo）。
// 已删除。在线用户是安全读数——空着说明"没有网关在报"，编 10 条会话则等于告诉
// 管理员"接入链路是通的、正有人在用"，而真实情况可能是数据面根本没起来。
// 页面 source 恒为 live：控制台自己在后端不可达时的内置降级演示与本端点无关。
func (s *Server) handleOnline(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) { // 在线会话（账号/IP/网关/踢人原因）属监控中心敏感数据，仅 admin 可见
		return
	}
	now := time.Now()
	window := int64(gatewayOnlineWindow / time.Second)

	// 聚合在线网关上报的真实会话（离线网关的会话不计入）
	sessions := []store.OnlineSession{}
	s.mu.Lock()
	for id, sess := range s.gwSess {
		gw, ok := s.gateways[id]
		if !ok || now.Unix()-gw.LastSeen > window {
			continue
		}
		for _, se := range sess {
			loginT := time.Unix(se.Since, 0)
			sessions = append(sessions, store.OnlineSession{
				ID: id + ":" + se.IP, User: se.User, Account: se.User,
				IP: se.IP, Auth: "SPA 敲门 + 隧道", Gateway: id,
				LoginAt: loginT.Format("15:04"), Duration: humanizeDuration(now.Sub(loginT)),
				Status: "online",
			})
		}
	}
	s.mu.Unlock()
	// ★组织 / 授信态 / 风险档由控制面**按账号**从库里现取，绝不硬编码。
	// 此前这三格分别是 "—" / "trusted" / "none"，其中后两个是**正向断言**：
	// observe 模式下被放行的未授信终端、被 degrade 降权的账号，在这一页上
	// 全部显示成「授信 / 无风险」——比补 0 更坏，因为它替一个已知为坏的状态背书。
	s.enrichSessions(r.Context(), sessions)

	s.mu.Lock()
	for i := range sessions {
		if reason, ok := s.kicked[sessions[i].ID]; ok {
			sessions[i].Status = "offline"
			sessions[i].KickReason = reason
		}
	}
	s.mu.Unlock()
	httpx.JSON(w, http.StatusOK, map[string]any{
		"sessions":    sessions,
		"generatedAt": now.Format(time.RFC3339),
		"source":      "live",
	})
}

// handleKickSession 强制下线一条会话（admin）——真实的数据面处置：
// 除显示覆盖层外，把账号记入封禁表（kickBanTTL）；网关下次轮询即撤销放行窗口、
// 切断该账号活跃隧道、封禁期内拒绝重新敲门，控制面同时拒发敲门令牌。
func (s *Server) handleKickSession(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	// 解析会话账号：只认网关上报的真实会话（id 形如 gwid:ip）。演示种子那条回退分支
	// 已随种子一起删除——它会让管理员"下线"一个并不存在的人，落一条同样不存在的
	// 处置审计，还顺手把这个虚构账号写进封禁表（真会挡住同名真人重新敲门）。
	// 仅允许下线真实存在的会话：既是正确的 404 语义，也避免覆盖层/封禁表被任意 id 无限撑大。
	var user string
	s.mu.Lock()
	for gwid, sess := range s.gwSess {
		for _, se := range sess {
			if gwid+":"+se.IP == id {
				user = se.User
			}
		}
	}
	s.mu.Unlock()
	if user == "" {
		httpx.Error(w, http.StatusNotFound, "session not found")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	reason := body.Reason
	if reason == "" {
		reason = "管理员强制下线"
	}
	until := time.Now().Add(kickBanTTL).Unix()
	s.mu.Lock()
	s.kicked[id] = reason
	s.revoked[normUser(user)] = revokeInfo{Reason: reason, Until: until, Display: user}
	s.mu.Unlock()
	s.audit(r, "security", "强制下线 "+user+"（会话 "+id+" · "+reason+"；封禁接入至 "+time.Unix(until, 0).Format("15:04")+"）", "deny")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "user": user, "status": "offline", "reason": reason, "banUntil": until})
}

// handleUserState 返回用户态势（分桶聚合 + 受关注用户清单）。
func (s *Server) handleUserState(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) { // 用户态势属监控中心敏感数据，仅 admin 可见
		return
	}
	b, err := s.store.UserStates(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user state")
		return
	}
	// 叠加登录防爆破锁定（执行源即 Guard/login_lockouts）：目录状态之外的另一种「已锁定」。
	s.overlayBruteLocks(r, &b)
	// ★「在线」必须与「在线用户」页、「用户与角色」页**同一个判据**：网关上报的真实会话。
	//
	//   store 侧算的是 `hasRep && now-rep.TS <= 600`（monitor_sqlite.go）——
	//   "这台终端十分钟内上报过环境"，那是**采集器还活着**，不是"这个人此刻连着隧道"。
	//   两个意思在同一套控制台上并排出现过：一个人后台挂着客户端按 60s 上报 posture，
	//   这一页给他画绿点「在线」，而「在线用户」页里查无此人。
	//   这一页的定位是"就近处置"——要不要现在踢他，取决于他现在有没有连着。
	//
	//   store 层拿不到 gwSess（那是 api 层的内存登记），所以在这里覆盖，
	//   与 handleUsers 的 enrichDirUsers 走同一个 onlineAccounts()。
	//   ★一台在线网关都没有时**这一列整个缺席**（不可判定），而不是全判成离线：
	//   网关心跳断了（证书过期 / 控制面刚重启 / mTLS 口挂了）时敲门与隧道照常，
	//   人是真连着的。而这一页正是"要不要现在踢他"的决策入口——
	//   告诉管理员"已经离线了"，他就不动手了。
	online, onlineKnown := s.onlineAccounts()
	for i := range b.Items {
		if onlineKnown {
			on := online[normUser(b.Items[i].Account)]
			b.Items[i].Online = &on
		}
	}
	httpx.JSON(w, http.StatusOK, b)
}

// ★IPSec VPN 组网的 handlers 已整体搬到 ipsec.go（admin 侧）与 ipsec_gateway.go
// （mTLS 侧）。搬走的原因不只是文件变长：原先 handleToggleIpsec 写的审计是
// 「建立 IPSec 隧道 site-sh · ok」，而它实际只把一个字符串列改成了 'up'——
// 审计断言了一个从未发生的事实。新实现里 toggle 只记「下发启用意图」，
// 真正的 up/down 由网关回报后另记一条。

// ── 对象库 ──

// handleObjects 对象库清单（地址 / 服务 / 时间对象）。
// 与紧随其后的 handleObjectsUsage 同门槛：对象库是管理配置（内网网段、端口、时段），
// 此前这一条漏了闸，任何登录用户都能拉走一份内网地址清单。
func (s *Server) handleObjects(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	b, err := s.store.Objects(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load objects")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

// handleObjectsUsage 返回对象库「被引用」反查表：objectID → 引用它的消费者（资源 / IPSec）。
// 引用拓扑属管理配置（与 handleResources 一致），仅 admin 可读。
func (s *Server) handleObjectsUsage(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	usage, err := s.store.ObjectUsage(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load object usage")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"usage": usage})
}

func (s *Server) handleSaveObject(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	kind := r.PathValue("kind")
	switch kind {
	case "addr":
		var o store.AddrObject
		if err := json.NewDecoder(r.Body).Decode(&o); err != nil || o.Name == "" || o.Value == "" {
			httpx.Error(w, http.StatusBadRequest, "name/value 必填")
			return
		}
		saved, err := s.writer.SaveAddrObject(r.Context(), o)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to save addr object")
			return
		}
		s.audit(r, "admin", "保存地址对象「"+saved.Name+"」", "ok")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "object": saved})
	case "service":
		var o store.ServiceObject
		if err := json.NewDecoder(r.Body).Decode(&o); err != nil || o.Name == "" || o.Proto == "" {
			httpx.Error(w, http.StatusBadRequest, "name/proto 必填")
			return
		}
		saved, err := s.writer.SaveServiceObject(r.Context(), o)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to save service object")
			return
		}
		s.audit(r, "admin", "保存服务对象「"+saved.Name+"」", "ok")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "object": saved})
	case "time":
		var o store.TimeObject
		if err := json.NewDecoder(r.Body).Decode(&o); err != nil || o.Name == "" || o.Spec == "" {
			httpx.Error(w, http.StatusBadRequest, "name/spec 必填")
			return
		}
		saved, err := s.writer.SaveTimeObject(r.Context(), o)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to save time object")
			return
		}
		s.audit(r, "admin", "保存时间对象「"+saved.Name+"」", "ok")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "object": saved})
	default:
		httpx.Error(w, http.StatusBadRequest, "kind must be addr|service|time")
	}
}

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	kind := r.PathValue("kind")
	switch kind {
	case "addr", "service", "time":
	default:
		httpx.Error(w, http.StatusBadRequest, "kind must be addr|service|time")
		return
	}
	id := r.PathValue("id")
	// 删除守卫（事务内复核引用，原子互斥并发保存，杜绝 TOCTOU）：被引用则不删，返回 409。
	deleted, err := s.writer.DeleteObjectIfUnreferenced(r.Context(), kind, id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete object")
		return
	}
	if !deleted {
		// 复读引用清单仅供前端展示「被谁引用」；权威判定已由上面的事务给出。
		consumers := []store.ObjectRef{}
		if usage, uerr := s.store.ObjectUsage(r.Context()); uerr == nil {
			consumers = usage[id]
		}
		s.audit(r, "admin", "删除对象 "+id+" 被拒（被引用）", "deny")
		httpx.JSON(w, http.StatusConflict, map[string]any{
			"error":     map[string]any{"message": "对象被引用，无法删除；请先在引用方解除引用"},
			"consumers": consumers,
		})
		return
	}
	s.audit(r, "admin", "删除"+map[string]string{"addr": "地址", "service": "服务", "time": "时间"}[kind]+"对象 "+id, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "kind": kind, "id": id})
}
