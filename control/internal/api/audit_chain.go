package api

import (
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// auditChainStore 审计链校验/导出能力（SQLiteStore 实现；Memory 种子无链可校）。
type auditChainStore interface {
	VerifyAuditChain(ctx context.Context) (store.AuditVerifyResult, error)
	ExportAudit(ctx context.Context, q store.AuditQuery, fn func(store.AuditEntry) error) error
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
	if category != "" && !store.ValidAuditCategory(category) {
		httpx.Error(w, http.StatusBadRequest, "未知的审计类别："+category+"（留空 = 全部类别）")
		return
	}
	// ★导出条件与列表检索**同构**（同一个 store.AuditQuery、同一个 auditWhere）。
	//   此前导出只认 category/from/to 三维，而页面上刚筛过的账号与源 IP 两维
	//   压根传不进来：屏幕上筛出 12 条、导出的 CSV 里是 8 万条，而管理员会以为
	//   这份 CSV 就是他刚看到的那些行，拿去交差。
	aq := store.AuditQuery{
		Category: category,
		Actor:    strings.TrimSpace(r.URL.Query().Get("actor")),
		SrcIP:    strings.TrimSpace(r.URL.Query().Get("srcIp")),
		Keyword:  strings.TrimSpace(r.URL.Query().Get("q")),
		From:     normDayBound(r.URL.Query().Get("from"), "00:00:00"),
		To:       normDayBound(r.URL.Query().Get("to"), "23:59:59"),
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
	err := cs.ExportAudit(r.Context(), aq, func(e store.AuditEntry) error {
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
	s.audit(r, "admin", "导出审计日志 CSV（"+exportScopeZh(aq)+"），共 "+strconv.Itoa(n)+" 条", "ok")
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
// ★条件多了账号/源 IP/关键词三维之后，这句话必须一起带上：
// 审计里只写「类别 X · 某年某月」而实际导出的是某一个人的行，那条留痕是错的。
func exportScopeZh(q store.AuditQuery) string {
	parts := []string{}
	if q.Category != "" {
		parts = append(parts, "类别「"+store.AuditCategoryZh(q.Category)+"」")
	} else {
		parts = append(parts, "全部类别")
	}
	if q.Actor != "" {
		parts = append(parts, "账号「"+q.Actor+"」")
	}
	if q.SrcIP != "" {
		parts = append(parts, "源 IP 前缀「"+q.SrcIP+"」")
	}
	if q.Keyword != "" {
		parts = append(parts, "关键词「"+q.Keyword+"」")
	}
	switch {
	case q.From != "" && q.To != "":
		parts = append(parts, q.From+" 至 "+q.To)
	case q.From != "":
		parts = append(parts, q.From+" 起")
	case q.To != "":
		parts = append(parts, "截至 "+q.To)
	default:
		parts = append(parts, "全部时间")
	}
	return strings.Join(parts, "，")
}
