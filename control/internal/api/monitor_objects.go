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

// handleOnline 返回实时在线会话；叠加本进程内记录的"已强制下线"覆盖层。
func (s *Server) handleOnline(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.OnlineSessions(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load sessions")
		return
	}
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
		"generatedAt": time.Now().Format(time.RFC3339),
	})
}

// handleKickSession 强制下线一条会话（admin）。记录在内存覆盖层，重启后会话视为已重连。
func (s *Server) handleKickSession(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	// 仅允许下线真实存在的会话：既是正确的 404 语义，也避免 kicked 覆盖层被任意 id 无限撑大。
	sessions, err := s.store.OnlineSessions(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load sessions")
		return
	}
	found := false
	for _, ss := range sessions {
		if ss.ID == id {
			found = true
			break
		}
	}
	if !found {
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
	s.mu.Lock()
	s.kicked[id] = reason
	s.mu.Unlock()
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "status": "offline", "reason": reason})
}

// handleUserState 返回用户态势（分桶聚合 + 受关注用户清单）。
func (s *Server) handleUserState(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.UserStates(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user state")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

// ── IPSec VPN 组网 ──

func (s *Server) handleIpsec(w http.ResponseWriter, r *http.Request) {
	sites, err := s.store.Ipsec(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load ipsec sites")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sites": sites})
}

func (s *Server) handleSaveIpsec(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var it store.IpsecSite
	if err := json.NewDecoder(r.Body).Decode(&it); err != nil || it.Name == "" || it.Peer == "" {
		httpx.Error(w, http.StatusBadRequest, "name/peer 必填")
		return
	}
	// 网段引用必须指向真实存在的地址对象，挡住悬空引用。
	for _, ref := range []string{it.LocalRef, it.RemoteRef} {
		if ref == "" {
			continue
		}
		if ok, err := s.objectExists(r.Context(), "addr", ref); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to validate addr ref")
			return
		} else if !ok {
			httpx.Error(w, http.StatusBadRequest, "引用的地址对象不存在")
			return
		}
	}
	saved, err := s.writer.SaveIpsecSite(r.Context(), it)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save ipsec site")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "site": saved})
}

func (s *Server) handleDeleteIpsec(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.writer.DeleteIpsecSite(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete ipsec site")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func (s *Server) handleToggleIpsec(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	status, err := s.writer.ToggleIpsecSite(r.Context(), id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to toggle ipsec site")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "status": status})
}

// ── 对象库 ──

func (s *Server) handleObjects(w http.ResponseWriter, r *http.Request) {
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
	if !s.requireAdmin(w, r) {
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
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "object": saved})
	default:
		httpx.Error(w, http.StatusBadRequest, "kind must be addr|service|time")
	}
}

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
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
		httpx.JSON(w, http.StatusConflict, map[string]any{
			"error":     map[string]any{"message": "对象被引用，无法删除；请先在引用方解除引用"},
			"consumers": consumers,
		})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "kind": kind, "id": id})
}
