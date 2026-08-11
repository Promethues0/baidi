package api

import (
	"context"
	"log/slog"

	"baidi.dev/control/internal/store"
)

// ── 可达性判定在控制面的两个出口（主体维度 + 风险降权维度）──
//
// 资源可以按角色、账号、用户组、组织（含子树）四维授权，但**数据面只认账号与角色**。
// 组织与组的展开发生在控制面，且只有 store.SubjectIndex 一份实现（见 store/subjects.go）。
// 控制面有两个判定点，两者必须同真同假：
//
//	① handleGatewayPolicy → expandForGateway   把主体展开进 AllowUsers、把降权名单写进
//	                                           DenyUsers 后下发网关（权威闸）
//	② buildProfile        → accessibleFor      决定剖面里给不给这个资源排路由（路由提示）
//
// ①②口径不一致的症状在本项目里出现过不止一次，且两个方向都很难查：
//   - ①宽②窄：网关放行、客户端却排不出路由 → 用户看到"有权限但连不上"，无任何报错；
//   - ①窄②宽：客户端把流量接管进隧道，网关再拒 → 表现成"时通时不通"的连接重置。
//
// 所以两处都只调 store.SubjectIndex 的方法，不各自解释组织树；风险降权同理，
// 「什么算高敏」只由 store.Resource.HighSensitivity 回答。

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

// gwResource 下发给网关的资源视图：角色 + 账号两维允许集合，外加一条降权否决名单。
//
// 刻意不带 allowGroups/allowOrgs/sensitivity：数据面不该知道组织树，也不该自己解释
// 「什么算高敏」——多下发一份它读不懂的字段，只会诱使后来者在网关里补第二套判定。
// DenyUsers 是**已经算好的结论**（"这几个账号此刻不许碰这个资源"），网关只机械执行，
// 判定权仍然全在控制面，与组织展开成账号是同一条纪律。
// 字段名与 gateway/internal/cplane 的 resourceDTO 逐字对应（camelCase）。
type gwResource struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Backend    string   `json:"backend"`
	AllowRoles []string `json:"allowRoles"`
	AllowUsers []string `json:"allowUsers"`
	// DenyUsers 否决名单：命中即拒，**优先于一切允许来源**（静态 ACL、组织展开、JIT 授予）。
	// 当前唯一来源是终端风险降权（disposal=degrade）对高敏资源的收缩。
	//
	// ★为什么必须是"否决"而不是"从允许集合里删掉"：绝大多数资源根本没设 ACL
	// （四维全空 = 不限），删无可删；要靠允许集合表达"除了这几个人"就得把全体账号
	// 枚举进去，那份名单会随目录变化而过期，且一旦漏算就是静默放行。
	DenyUsers []string `json:"denyUsers,omitempty"`
	// WebScheme 七层代理拨后端用的协议（http|https）。
	//
	// ★它是**拨号参数**，与上面几维的性质完全不同：网关必须知道内网应用是 http
	// 还是 https 才连得上，而它无从推导。这不违反"数据面不做策略推导"——
	// 判定（谁能访问、哪些资源是 Web 应用）仍全在控制面，这里只回答"怎么拨"，
	// 与 Backend 同一档。
	WebScheme string `json:"webScheme,omitempty"`
}

// expandForGateway 把控制面资源清单转成网关视图：组织/用户组主体展开成账号并进 AllowUsers，
// 终端降权账号写进高敏资源的 DenyUsers。
//
// 返回的是新切片、新数组，绝不写回库——策略下发是每次现算的投影，
// 把展开结果 SaveResource 回去等于把"某一刻的组织快照"冻成静态 ACL，
// 之后组织怎么变都不再影响它（与 JIT 授予并入 AllowUsers 是同一条纪律）。
// degraded 同理每轮现算：终端恢复合规后，下一次轮询名单里就没有他了。
// ★这只是**网关这半边**自动恢复。客户端那半不自动：baidi-tun 的路由与 DNS 记录
// 在拉起那一刻定死，降级期间建立的隧道里没有高敏资源的 VIP /32，恢复后仍需重新接入
// （剖面 warnings 已把这半写进文案，见 api.degradeWarning）。
func expandForGateway(rs []store.Resource, ix store.SubjectIndex, degraded []string) []gwResource {
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
		g := gwResource{
			ID: r.ID, Name: r.Name, Backend: r.Backend,
			AllowRoles: append([]string(nil), r.AllowRoles...), AllowUsers: users,
			WebScheme: store.NormalizeWebScheme(r.WebScheme, r.Backend),
		}
		// 降权只摘高敏资源——这正是「降权而非全断」的落点：同一个降级用户，
		// 普通资源的 DenyUsers 是空的，照常可访问。
		if r.HighSensitivity() && len(degraded) > 0 {
			g.DenyUsers = append([]string(nil), degraded...)
		}
		out = append(out, g)
	}
	return out
}

// accessibleFor 控制面侧「此刻这个人能不能访问这个资源」的**唯一**判定入口
// （剖面的路由提示由它决定），与网关侧展开后的判定同构：
//
//	accessibleFor(u,role,res,ix,grant,deg) ==
//	    registry.Authorize(u, role, expandForGateway([res],ix,degradedOf(deg))[0]) || grant∧¬deny
//
// 求值顺序即安全语义：降权否决排在所有允许来源**之前**，与网关侧 DenyUsers 先判一致。
// 反过来（先看有没有 JIT 授予、命中就放行）会让一张审批单把降权整个绕过去，
// 而这恰恰是最需要收缩的场景——终端已经不合规了，临时授权更不该开高敏的门。
func accessibleFor(user, role string, res store.Resource, ix store.SubjectIndex, hasGrant, degraded bool) bool {
	if degraded && res.HighSensitivity() {
		return false
	}
	return authorizeRes(user, role, res, ix) || hasGrant
}

// authorizeRes 静态 ACL ∪ 组织/用户组展开的判定（不含降权与 JIT，见 accessibleFor）：
// 四个主体维度都空 = 不限；任一非空则须命中其一（组织/组经 SubjectIndex 展开后比对）。
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

// degradedUsers 取当前被降权的账号名单（规范化、定序），供下发网关的 DenyUsers 用。
//
// ★口径必须与剖面侧的 degradeStateOf 逐字一致，否则同一个人在两处得到不同答案。
// 两者都是「跨设备取最差 == degrade」，这里由「任一设备 degrade」减去「任一设备 block」
// 等价推出（degrade 是次高档，无 block 时它必然是最差档）。
// 少了这一减：一台设备 degrade、另一台 block 的账号会**同时**出现在降权名单与撤销名单里，
// 剖面却按最差判定说他是 block 而非 degrade——他被全断了，界面上却提示"高敏资源已暂停"。
//
// ★读失败返回空名单并记 Error，与 subjectIndex 的姿态相反，是刻意的：
// 降权是**收缩**动作，读不到名单时"当作没人被降权"只是短暂放宽高敏访问；
// 而反过来"读不到就把所有人降权"会在一次数据库抖动里让全体用户失去财务系统，
// 且用户侧看到的是"明明有权限却打不开"——那是本项目反复警告的失败形态。
// 真正的 fail-closed 底线由 block 档与敲门令牌闸承担，degrade 是动态收缩而非最后防线。
func (s *Server) degradedUsers(ctx context.Context) []string {
	list, err := s.store.PostureUsersByDisposal(ctx, store.DisposalDegrade)
	if err != nil {
		slog.Error("终端降权名单读取失败，本轮按「无人被降权」下发（高敏资源不做收缩）", "err", err.Error())
		return nil
	}
	blocked, err := s.store.PostureBlockedUsers(ctx)
	if err != nil {
		slog.Error("终端阻断名单读取失败，本轮不下发降权名单（避免与剖面判定口径分叉）", "err", err.Error())
		return nil
	}
	isBlocked := make(map[string]bool, len(blocked))
	for _, u := range blocked {
		isBlocked[normUser(u)] = true
	}
	out := make([]string, 0, len(list))
	for _, u := range list {
		if k := normUser(u); k != "" && !isBlocked[k] {
			out = append(out, k)
		}
	}
	return out
}
