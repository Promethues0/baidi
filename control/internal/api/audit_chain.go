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

// handleAuditVerify GET /api/v1/audit/verify（PermAudit）：HMAC-SM3 全链重算，返回 {ok, checked, brokenAt}。
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermAudit) {
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

// handleAuditExport GET /api/v1/audit/export?category=&from=&to=（PermAudit）：流式导出 CSV 附件。
// 逐行写出不整表进内存；文件名带导出日期。
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermAudit) {
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
	// ★末尾两列是防篡改链的序号与 MAC，与 /audit 列表、外送出口同源（store.AuditEntry）。
	// 不带它们的话，导出给审计方的那份 CSV 无法被独立验真——只是一堆自称是审计的文本。
	// 追加在末尾而不是插在中间：既有的下游脚本按前六列取值，不会被这次改动打断。
	_ = cw.Write([]string{"时间", "类别", "行为人", "源IP", "事件", "判定", "链序号", "链MAC"})
	n := 0
	err := cs.ExportAudit(r.Context(), category, from, to, func(e store.AuditEntry) error {
		n++
		// 全列过 csvCell：行为人（登录用户名原样入审计）与事件文本都可能含攻击者输入，
		// 与其逐列判断哪列「可信」，不如统一中和——审计导出就是给人拿电子表格打开的。
		return cw.Write([]string{csvCell(e.Time), csvCell(e.Category), csvCell(e.User),
			csvCell(e.SrcIP), csvCell(e.Event), csvCell(e.Verdict),
			strconv.FormatInt(e.Seq, 10), csvCell(e.MAC)})
	})
	cw.Flush()
	if err != nil {
		// 响应头已发出，无法改状态码；只能靠截断让下载侧感知失败，不落「已导出」审计。
		return
	}
	// 审计措辞只记已发生的事实：流式写完才算导出完成。
	s.audit(r, "admin", "导出审计日志 CSV（"+exportScopeZh(category, from, to)+"），共 "+strconv.Itoa(n)+" 条", "ok")
}

// csvCell 中和 CSV 公式注入：以 = + - @ 或制表符/回车开头的单元格在
// Excel/LibreOffice 里会被当公式求值（DDE 可外带数据甚至执行命令），而行为人
// 一列就是攻击者可控的登录用户名。csv.Writer 只处理引号与分隔符，不管这个；
// 前缀单引号是电子表格通行的「强制文本」记号——牺牲一点原样性，换掉这个执行面。
func csvCell(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
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
