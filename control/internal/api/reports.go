package api

// 运营报表（PRD ch15）：GET /api/v1/audit/report?days=7|30
//
// ★权限是 PermAudit、路由挂在 /api/v1/audit/ 之下，两件事是同一个决定：
// 报表的原料是审计正文（谁登录了几次、谁被拒了——聚合并不脱敏），三权分立下
// 只有审计管理员读得到它；挂这个前缀让「审计管理员只读 /api/v1/audit*」这条
// 既有约定原样成立，不新开一个要单独解释的路径。
//
// ★days 只收 7 / 30 两档，拼错明确 400 而不是静默回落——一个拼错的窗口静默换成
// 别的天数，会让人对着 7 天的表讨论"这个月"（与设备状态 range 参数同一条纪律）。

import (
	"net/http"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// opsReportDays 允许的窗口档位。
var opsReportDays = map[string]int{"7": 7, "30": 30}

func (s *Server) handleOpsReport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermAudit) {
		return
	}
	key := r.URL.Query().Get("days")
	if key == "" {
		key = "7"
	}
	days, ok := opsReportDays[key]
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "days 只能是 7 / 30，本次为 "+key)
		return
	}
	rep, ok := s.store.(store.OpsReporter)
	if !ok {
		// Memory 种子没有可聚合的真实历史。刻意不编一份演示报表：
		// 编造的报表与真实聚合在页面上无法区分（与设备状态/业务告警两页同一条例外纪律）。
		httpx.Error(w, http.StatusNotImplemented, "当前存储后端不支持运营报表（内存种子模式无真实历史可聚合）")
		return
	}
	out, err := rep.OpsReport(r.Context(), days)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "报表聚合失败："+err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, out)
}
