package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 应用的编辑与下架（FR-APP-01，wave8 行动 14）──
//
// 改造前 /apps 只有 GET 与 POST。后果不只是缺功能：发布时填错内网地址或选错资源
// 之后既改不了也下不了架，那条磁贴会永久留在门户与客户端剖面里；
// 而控制台那个「编辑」按钮走的是发布向导 → POST，点一次就多出一条同名应用。

// appWriter 应用的写侧（SQLite 后端实现）。
type appWriter interface {
	UpdateApp(ctx context.Context, a store.App) (store.App, error)
	DeleteApp(ctx context.Context, id string) (store.App, error)
}

// handleUpdateApp PUT /api/v1/apps/{id}（PermSecurity，与发布同权）。
func (s *Server) handleUpdateApp(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	wr, ok := s.writer.(appWriter)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储后端不支持编辑应用")
		return
	}
	var a store.App
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&a); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid app payload")
		return
	}
	// ★路径里的 id 说了算，请求体里的 id 一律忽略。两者不一致时按请求体走的话，
	// 一次「编辑 A」会改到 B 身上，而 URL 与审计里记的都是 A。
	a.ID = r.PathValue("id")
	a.Name, a.Addr = strings.TrimSpace(a.Name), strings.TrimSpace(a.Addr)
	if a.Name == "" || a.Addr == "" || a.Mode == "" {
		httpx.Error(w, http.StatusBadRequest, "name / addr / mode 均不可为空")
		return
	}
	if !validAppMode[a.Mode] {
		httpx.Error(w, http.StatusBadRequest, "mode 只能是 tunnel | web | global")
		return
	}
	if a.Status == "" {
		a.Status = "running"
	}
	if a.Status != "running" && a.Status != "stopped" {
		httpx.Error(w, http.StatusBadRequest, "status 只能是 running | stopped")
		return
	}
	before, found := s.appByID(r, a.ID)
	updated, err := wr.UpdateApp(r.Context(), a)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrAppNotFound):
		httpx.Error(w, http.StatusNotFound, "应用不存在（可能已被下架）")
		return
	case errors.Is(err, store.ErrUnknownAppCategory):
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	default:
		httpx.Error(w, http.StatusInternalServerError, "failed to update app")
		return
	}
	// 审计要能看出改了什么——「修改了应用 x」这种措辞在事后复盘时说明不了任何问题
	// （与 handleUpdateAppCategory 同一条口径）。
	s.audit(r, "admin", "修改应用「"+updated.Name+"」("+updated.ID+")："+appDiffZh(before, updated, found), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "app": updated})
}

// handleDeleteApp DELETE /api/v1/apps/{id}（PermSecurity）。
func (s *Server) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	wr, ok := s.writer.(appWriter)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储后端不支持下架应用")
		return
	}
	gone, err := wr.DeleteApp(r.Context(), r.PathValue("id"))
	switch {
	case err == nil:
	case errors.Is(err, store.ErrAppNotFound):
		// ★不回 200：那会落一条「下架应用 xxx」的审计，而库里根本没有这一行——
		// 审计里出现一件没发生过的事（与 handleDecideApproval 同一条纪律）。
		httpx.Error(w, http.StatusNotFound, "应用不存在")
		return
	default:
		httpx.Error(w, http.StatusInternalServerError, "failed to delete app")
		return
	}
	// 关联资源**不动**，且必须在回执里说清楚：不说的话，管理员会以为下架顺手
	// 收回了访问权，而资源侧的 ACL 与 JIT 授予原样有效（隧道照样能连）。
	note := ""
	if gone.ResourceID != "" {
		note = "；关联的受控资源 " + gone.ResourceID + " 未删除，访问控制仍按资源策略生效"
	}
	s.audit(r, "admin", "下架应用「"+gone.Name+"」("+gone.ID+")"+note, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": gone.ID, "resourceId": gone.ResourceID, "note": strings.TrimPrefix(note, "；")})
}

// validAppMode 发布形态白名单。字典外的值会让磁贴与剖面走进各自的 default 分支，
// 而两处的 default 不一定同向。
var validAppMode = map[string]bool{"tunnel": true, "web": true, "global": true}

// appByID 读一条应用（供审计写出改前值）。读不到不阻断主操作。
func (s *Server) appByID(r *http.Request, id string) (store.App, bool) {
	b, err := s.store.Apps(r.Context())
	if err != nil {
		return store.App{}, false
	}
	for _, a := range b.Apps {
		if a.ID == id {
			return a, true
		}
	}
	return store.App{}, false
}

// appDiffZh 改前改后的差异描述（审计正文）。
func appDiffZh(before, after store.App, found bool) string {
	if !found {
		return "名称「" + after.Name + "」· 地址 " + after.Addr + " · 模式 " + after.Mode
	}
	var parts []string
	add := func(label, a, b string) {
		if a != b {
			parts = append(parts, label+"「"+a+"」→「"+b+"」")
		}
	}
	add("名称", before.Name, after.Name)
	add("地址", before.Addr, after.Addr)
	add("模式", before.Mode, after.Mode)
	add("分类", before.Category, after.Category)
	add("状态", before.Status, after.Status)
	add("关联资源", before.ResourceID, after.ResourceID)
	if len(parts) == 0 {
		return "无字段变化"
	}
	return strings.Join(parts, "，")
}
