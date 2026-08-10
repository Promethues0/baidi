package api

import (
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// auditChainStore 审计链校验/导出能力（SQLiteStore 实现；Memory 种子无链可校）。
type auditChainStore interface {
	VerifyAuditChain(ctx context.Context) (store.AuditVerifyResult, error)
	ExportAudit(ctx context.Context, category, from, to string, fn func(store.AuditEntry) error) error
}

// handleAuditVerify GET /api/v1/audit/verify（admin）：HMAC-SM3 全链重算，返回 {ok, checked, brokenAt}。
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	cs, ok := s.store.(auditChainStore)
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "当前存储不支持审计链校验")
		return
	}
	res, err := cs.VerifyAuditChain(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "审计链校验失败")
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// normDayBound 把纯日期（2006-01-02）补齐为当日边界的可比时间串；已带时间的原样返回。
func normDayBound(v, bound string) string {
	if len(v) == len("2006-01-02") {
		return v + " " + bound
	}
	return v
}

// handleAuditExport GET /api/v1/audit/export?category=&from=&to=（admin）：流式导出 CSV 附件。
// 逐行写出不整表进内存；文件名带导出日期。
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	cs, ok := s.store.(auditChainStore)
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "当前存储不支持审计导出")
		return
	}
	category := r.URL.Query().Get("category")
	switch category {
	case "", "access", "auth", "admin", "security", "dataplane":
	default:
		httpx.Error(w, http.StatusBadRequest, "category 须为 access|auth|admin|security|dataplane 或留空")
		return
	}
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	if from != "" {
		from = normDayBound(from, "00:00:00")
	}
	if to != "" {
		to = normDayBound(to, "23:59:59")
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="baidi-audit-`+time.Now().Format("20060102")+`.csv"`)
	w.WriteHeader(http.StatusOK)
	// UTF-8 BOM：Excel 打开含中文的 CSV 不乱码。
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"时间", "类别", "行为人", "源IP", "事件", "判定"})
	n := 0
	err := cs.ExportAudit(r.Context(), category, from, to, func(e store.AuditEntry) error {
		n++
		return cw.Write([]string{e.Time, e.Category, e.User, e.SrcIP, e.Event, e.Verdict})
	})
	cw.Flush()
	if err != nil {
		// 响应头已发出，无法改状态码；只能靠截断让下载侧感知失败，不落「已导出」审计。
		return
	}
	// 审计措辞只记已发生的事实：流式写完才算导出完成。
	s.audit(r, "admin", "导出审计日志 CSV（"+exportScopeZh(category, from, to)+"），共 "+strconv.Itoa(n)+" 条", "ok")
}

// exportScopeZh 拼导出范围的中文描述（供审计留痕）。
func exportScopeZh(category, from, to string) string {
	catZh := map[string]string{"access": "访问决策", "auth": "登录认证", "admin": "管理操作", "security": "安全事件", "dataplane": "数据面回执"}
	scope := "全部类别"
	if z, ok := catZh[category]; ok {
		scope = "类别「" + z + "」"
	}
	switch {
	case from != "" && to != "":
		scope += "，" + from + " 至 " + to
	case from != "":
		scope += "，自 " + from
	case to != "":
		scope += "，至 " + to
	}
	return scope
}
