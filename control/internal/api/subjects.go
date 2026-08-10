package api

import (
	"context"
	"log/slog"

	"baidi.dev/control/internal/store"
)

// ── 授权主体（组织 / 用户组）在控制面的两个出口 ──
//
// 资源可以按角色、账号、用户组、组织（含子树）四维授权，但**数据面只认账号与角色**。
// 组织与组的展开发生在控制面，且只有 store.SubjectIndex 一份实现（见 store/subjects.go）。
// 控制面有两个判定点，两者必须同真同假：
//
//	① handleGatewayPolicy → expandForGateway   把主体展开进 AllowUsers 后下发网关（权威闸）
//	② buildProfile        → authorizeRes       决定剖面里给不给这个资源排路由（路由提示）
//
// ①②口径不一致的症状在本项目里出现过不止一次，且两个方向都很难查：
//   - ①宽②窄：网关放行、客户端却排不出路由 → 用户看到"有权限但连不上"，无任何报错；
//   - ①窄②宽：客户端把流量接管进隧道，网关再拒 → 表现成"时通时不通"的连接重置。
//
// 所以两处都只调 store.SubjectIndex 的方法，不各自解释组织树。

// subjectIndex 取一份「组织/用户组 → 账号」展开索引。
//
// ★读失败返回空索引（fail-closed 方向）：组织/组两维全部落空，静态 ACL 与 JIT 授予
// 仍照常生效。反过来"读不到就当全放行"会让一次数据库抖动变成一次全量提权。
// 失败要记 Error——静默降级正是"配置齐全却不生效"那一族缺陷的温床。
func (s *Server) subjectIndex(ctx context.Context) store.SubjectIndex {
	ix, err := s.store.SubjectIndex(ctx)
	if err != nil {
		slog.Error("授权主体展开索引读取失败，本次判定按「组织/用户组授权不生效」处理（静态 ACL 与 JIT 授予不受影响）",
			"err", err.Error())
		return store.SubjectIndex{}
	}
	return ix
}

// gwResource 下发给网关的资源视图：**只有角色与账号两维**。
//
// 刻意不带 allowGroups/allowOrgs：数据面不该知道组织树，多下发一份它读不懂的字段，
// 只会诱使后来者在网关里补第二套判定——那正是本任务要避免的分叉。
// 字段名与 gateway/internal/cplane 的 resourceDTO 逐字对应（camelCase）。
type gwResource struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Backend    string   `json:"backend"`
	AllowRoles []string `json:"allowRoles"`
	AllowUsers []string `json:"allowUsers"`
}

// expandForGateway 把控制面资源清单转成网关视图：组织/用户组主体展开成账号并进 AllowUsers。
//
// 返回的是新切片、新数组，绝不写回库——策略下发是每次现算的投影，
// 把展开结果 SaveResource 回去等于把"某一刻的组织快照"冻成静态 ACL，
// 之后组织怎么变都不再影响它（与 JIT 授予并入 AllowUsers 是同一条纪律）。
func expandForGateway(rs []store.Resource, ix store.SubjectIndex) []gwResource {
	out := make([]gwResource, 0, len(rs))
	for _, r := range rs {
		users := append([]string(nil), r.AllowUsers...)
		if len(r.AllowGroups) > 0 || len(r.AllowOrgs) > 0 {
			// ★哨兵先于展开结果加入：即使展开为空（空部门 / 成员刚被移走），
			// 这条也让网关看到"AllowUsers 非空"，从而维持「限定了主体」的语义。
			// 少了它，一个成员为零的组织授权会在网关侧退化成"对所有人开放"，
			// 而控制面这边判定的是"对所有人关闭"——方向相反且两边都不报错。
			users = append(users, store.DenyAllSubject)
			users = append(users, ix.SubjectAccounts(r)...)
		}
		out = append(out, gwResource{
			ID: r.ID, Name: r.Name, Backend: r.Backend,
			AllowRoles: append([]string(nil), r.AllowRoles...), AllowUsers: users,
		})
	}
	return out
}

// authorizeRes 控制面侧的可达性判定，与网关 registry.Authorize 在展开后同构：
// 四个主体维度都空 = 不限；任一非空则须命中其一（组织/组经 SubjectIndex 展开后比对）。
//
// 对应关系（必须成立，isomorphism 测试钉住）：
//
//	authorizeRes(u,role,res,ix) == registry.Authorize(u, role, expandForGateway([res],ix)[0])
func authorizeRes(user, role string, res store.Resource, ix store.SubjectIndex) bool {
	if len(res.AllowUsers) > 0 && containsFold(res.AllowUsers, user) {
		return true
	}
	if len(res.AllowRoles) > 0 && containsFold(res.AllowRoles, role) {
		return true
	}
	if ix.SubjectAllows(res, user) {
		return true
	}
	return !res.Restricted()
}
