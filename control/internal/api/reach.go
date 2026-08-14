package api

// 网关→后端可达性（wave7 行动 9：FR-SCEN-26）。
//
// 网关侧拨测（gateway/internal/reachprobe）→ 心跳 reach 字段捎带 →
// 这里存内存（与 gwSess/gwTunnelFP 同款：心跳刷新态，重启后一个心跳周期内重建）→
// 两个消费方：/diag 的「后端可达性」检查项 + 资源页的可达列。
//
// ★三态纪律：旧网关不带 reach 字段 → 该网关对所有资源都是「未探测」，绝不当
// 「可达」也绝不当「不可达」；离线网关（心跳过期）的数据整份不参与聚合——
// 它说的是断联前的世界。

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"baidi.dev/control/internal/httpx"
)

// gwReachResult 心跳里的一条拨测结果（与 gateway cplane.ReachResult 同构）。
type gwReachResult struct {
	ID  string `json:"id"`
	OK  bool   `json:"ok"`
	MS  int    `json:"ms"`
	Err string `json:"err,omitempty"`
	TS  int64  `json:"ts"`
}

// gwReachInfo 某台网关最近一次心跳捎带的整份拨测快照。
type gwReachInfo struct {
	Results []gwReachResult
	At      int64 // 控制面收到的时刻
}

// ReachAgg 一条资源跨网关聚合后的可达性（资源页消费）。
type ReachAgg struct {
	// Status ok | partial | fail | unknown。
	//   ok      全部有报告的在线网关都连得上；
	//   partial 部分网关连不上——落到那台网关的用户点开就炸，必须与 ok 区分；
	//   fail    有报告的网关全都连不上；
	//   unknown 没有任何在线网关报告过它（旧网关 / 新资源未到下一轮拨测）。
	Status string `json:"status"`
	// Detail 逐网关一句话（"gw-1 可达 2ms" / "gw-2: connection refused"）。
	Detail []string `json:"detail"`
	// MS 最快的一次成功拨号耗时（status 含 ok 成分时有意义）。
	MS int `json:"ms"`
}

// reachAggregate 把各在线网关的拨测快照聚合成按资源的可达性。
// 只吃新鲜心跳的网关（gatewayFresh 同一口径）；快照本身超过 staleAfter 也不吃——
// 网关在线但拨测停摆（不该发生）时宁可显示未探测，也不拿陈旧结论背书。
func (s *Server) reachAggregate() map[string]*ReachAgg {
	const staleAfter = 5 * 60 // 秒；拨测周期 60s，5 个周期没更新就算陈旧
	now := time.Now()
	agg := map[string]*ReachAgg{}
	s.mu.Lock()
	defer s.mu.Unlock()
	// 网关 id 排序遍历：Detail 顺序稳定，页面不跳
	ids := make([]string, 0, len(s.gwReach))
	for id := range s.gwReach {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		g, online := s.gateways[id]
		if !online || !gatewayFresh(g.LastSeen, now) {
			continue
		}
		info := s.gwReach[id]
		if now.Unix()-info.At > staleAfter {
			continue
		}
		for _, r := range info.Results {
			a, ok := agg[r.ID]
			if !ok {
				a = &ReachAgg{Status: "unknown", Detail: []string{}}
				agg[r.ID] = a
			}
			if r.OK {
				a.Detail = append(a.Detail, fmt.Sprintf("%s 可达 %dms", id, r.MS))
				if a.MS == 0 || r.MS < a.MS {
					a.MS = r.MS
				}
				switch a.Status {
				case "unknown":
					a.Status = "ok"
				case "fail":
					a.Status = "partial"
				}
			} else {
				a.Detail = append(a.Detail, fmt.Sprintf("%s: %s", id, r.Err))
				switch a.Status {
				case "unknown":
					a.Status = "fail"
				case "ok":
					a.Status = "partial"
				}
			}
		}
	}
	return agg
}

// handleResourceReach GET /api/v1/resources/reach——逐资源可达性（读，任意管理员）。
func (s *Server) handleResourceReach(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": s.reachAggregate()})
}

// checkBackendReach /diag 的「后端可达性」检查项。
func (s *Server) checkBackendReach() DiagCheck {
	c := DiagCheck{Key: "backendReach", Category: "dataplane", Name: "网关→业务后端可达性"}
	s.mu.Lock()
	totalGW := len(s.gateways)
	s.mu.Unlock()
	if totalGW == 0 {
		c.Status = "skip"
		c.Summary = "无数据面网关，无从拨测业务后端"
		return c
	}
	agg := s.reachAggregate()
	if len(agg) == 0 {
		c.Status = "warn"
		c.Summary = "在线网关尚未上报后端拨测结果（网关版本低于 v0.9，或资源刚发布未到下一轮拨测）"
		c.Hint = "升级网关后每 60 秒自动拨测一轮；旧网关不上报按「未探测」处理，不代表后端可达"
		return c
	}
	okN, badN := 0, 0
	ids := make([]string, 0, len(agg))
	for id := range agg {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := agg[id]
		st := "pass"
		val := fmt.Sprintf("可达 · %dms", a.MS)
		switch a.Status {
		case "fail":
			st, val = "fail", "不可达："+firstOr(a.Detail, "无详情")
			badN++
		case "partial":
			st, val = "warn", "部分网关不可达："+firstOr(a.Detail, "无详情")
			badN++
		default:
			okN++
		}
		c.Items = append(c.Items, DiagItem{Label: id, Value: val, Status: st})
	}
	c.Metric = fmt.Sprintf("可达 %d / 拨测 %d", okN, len(agg))
	switch {
	case badN > 0:
		c.Status = "fail"
		c.Summary = fmt.Sprintf("%d 个资源的后端从网关连不通——用户点开对应应用就是这个失败", badN)
		c.Hint = "确认后端服务在跑、网关到业务网段路由/防火墙放行；这正是「一切显示正常、点开才炸」的根因"
	default:
		c.Status = "pass"
		c.Summary = "全部已拨测资源的后端从网关可达"
	}
	return c
}

func firstOr(ss []string, def string) string {
	// 优先挑失败的那句（Detail 里成功失败混排）
	for _, s2 := range ss {
		for i := 0; i+1 < len(s2); i++ {
			if s2[i] == ':' && s2[i+1] == ' ' {
				return s2
			}
		}
	}
	if len(ss) > 0 {
		return ss[0]
	}
	return def
}
