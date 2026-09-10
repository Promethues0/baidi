package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
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
	if err := normalizeAppInput(&a); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
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

// normalizeAppInput 发布（POST）与编辑（PUT）**共用**的入口校验与归一。
//
// ★为什么必须共用：改造前 `POST /apps` 的全部校验是 `name != "" && mode != ""`，
// 比后补的 PUT 松一大截，而 validAppMode 就放在同一个文件里。三种字典外的值
// 各有一种「接口回 201、页面上找不出毛病、功能静默不生效」的形态：
//
//   - **mode 写错**（大小写不同 / 拼错 / 前端把中文 label 传上来）：判定它的三处
//     各按自己的 default 解释——`appAccessState` 只对 `"global"` 走直连书签分支，
//     其余一律当受控资源判；门户与移动端的 modeMeta 查不到就回落成 WEB 那一档；
//     `alertSnapshot` 的「排除直连书签」判据也是 `a.Mode == "global"`。
//     于是一条 `mode:"Global"` 的应用会被当成受控应用、常年挂一条「未关联受控资源」
//     告警，而管理员在应用页上看到的是「直连书签」以外的另一个模式标签。
//   - **addr 空**：发布向导里它是必填项，PUT 也拒空，只有 POST 放行；门户与移动端
//     磁贴上那行地址就是空白，管理员无从判断是「没填」还是「渲染坏了」。
//   - **status 写错**：`handlePortalApps` 与客户端剖面只放行 `status == "running"`，
//     于是 `status:"Running"` 的应用**永远不出现在门户与终端上**，而应用页照常列着它、
//     状态列渲染成「已停用」（那一栏的判据是 `=== 'running'`）——两个界面对同一条
//     应用给出的答案都不是真的。
//
// 归一只做 TrimSpace（名称/地址前后的空白是复制粘贴来的），**不做大小写折叠**：
// 把 `"Global"` 悄悄改成 `"global"` 等于替管理员猜他想选哪个模式，而这三个值在
// 发布向导里是点出来的、不是打出来的——真出现别的值就是有人在直接调接口，该拒。
func normalizeAppInput(a *store.App) error {
	a.Name, a.Addr = strings.TrimSpace(a.Name), strings.TrimSpace(a.Addr)
	a.Mode, a.Status = strings.TrimSpace(a.Mode), strings.TrimSpace(a.Status)
	if a.Name == "" || a.Addr == "" || a.Mode == "" {
		return errors.New("name / addr / mode 均不可为空")
	}
	if !validAppMode[a.Mode] {
		return errors.New("mode 只能是 tunnel | web | global（收到 " + strconv.Quote(a.Mode) +
			"）：字典外的值会让门户磁贴、客户端剖面、告警评估三处各按自己的默认分支解释它")
	}
	if a.Status == "" {
		// 与 SQLiteStore.CreateApp 的缺省同值。这里先落定是为了让 PUT 也有同一个缺省，
		// 且让下面那道枚举校验对「没填」与「填错」给出不同结论。
		a.Status = "running"
	}
	if a.Status != "running" && a.Status != "stopped" {
		return errors.New("status 只能是 running | stopped（收到 " + strconv.Quote(a.Status) +
			"）：门户与客户端剖面只放行 running，别的值等于这个应用对所有终端都不存在")
	}
	return nil
}

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
