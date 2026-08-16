package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"baidi.dev/control/internal/store"
)

// ── 可达性判定在控制面的两个出口（主体维度 + 风险降权维度）──
//
// 资源可以按角色、账号、用户组、组织（含子树）四维授权，但**数据面只认账号与角色**。
// 组织与组的展开发生在控制面，且只有 store.SubjectIndex 一份实现（见 store/subjects.go）。
// 控制面有**四个**判定点，四者必须同真同假：
//
//	① handleGatewayPolicy → expandForGateway   把主体展开进 AllowUsers、把降权名单写进
//	                                           DenyUsers 后下发网关（权威闸）
//	② buildProfile        → appAccessState     决定剖面里给不给这个资源排路由（路由提示）
//	③ handlePortalApps    → appAccessState     决定门户磁贴是「访问」还是「申请权限」
//	④ handleWebTicket     → accessibleFor      决定签不签这张七层入口票据
//
// 口径不一致的症状在本项目里出现过不止一次，且每个方向都很难查：
//   - ①宽②窄：网关放行、客户端却排不出路由 → 用户看到"有权限但连不上"，无任何报错；
//   - ①窄②宽：客户端把流量接管进隧道，网关再拒 → 表现成"时通时不通"的连接重置；
//   - ③与①②④分叉：门户上「需申请」而客户端上直接能进（或反过来），同一个人同一个资源
//     两个界面给相反答案——③曾经就是自己写了一份只看 sensitivity 的判据，见 appAccessState。
//
// 所以四处都只调 store.SubjectIndex 的方法，不各自解释组织树；风险降权同理，
// 「什么算高敏」只由 store.Resource.HighSensitivity 回答。
// ②③进一步收敛成同一个 appAccessState——它们要回答的是同一个问题（"这个应用现在什么状态"），
// 只是一个渲染成路由、一个渲染成磁贴。

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

// appState 一个已发布应用此刻对某个人呈现成什么样。两个出口共用（见 appAccessState）。
//
// Accessible 与 Unavailable 是**两件事**，不能合并成一个 bool：
//   - !Accessible 是授权结论 —— 下一步是「申请权限」；
//   - Unavailable 是配置缺口 —— 申请也没用（JIT 闸会以「该应用不支持自助申请」拒掉），
//     下一步是让管理员去改配置。
//
// 把后者渲染成前者，用户会为一个根本连不上的东西提交审批单；渲染成「可访问」则更糟，
// 那就是「按钮亮着、点了打不开」——本项目反复指认的那种失败形态。
type appState struct {
	Sensitivity string
	Accessible  bool
	Degraded    bool // 因终端风险降权而不可访问（而非缺授权）
	// Unavailable 该应用**结构上不可用**：与授权无关，隧道与七层两条路都必然不通。
	//
	// ★两种成因合并成同一个状态是有意的——对用户它们是同一件事（点了打不开、申请也没用、
	// 只能找管理员），对剖面也是同一个动作（丢弃 + 给管理员一条 warning）。分开的只有
	// Reason 那句话，它决定管理员该去改哪一栏。
	// 合并还让「剖面缺席 ⟺ 门户标不可用」成为**双向**不变式：此前只覆盖了「未关联资源」
	// 一种成因，剖面另一条丢弃路径（后端不是 host:port）会让门户继续把按钮亮着。
	Unavailable bool
	Reason      string // 不可用的具体原因（面向管理员，直接渲染给用户看）
}

// appAccessState 回答「此刻这个人打开门户/客户端，这个应用该是什么状态」。
//
// ★这是**门户磁贴与客户端剖面**的共同判定来源（七层票据经 accessibleFor 走同一条判据），
// 它们必须同真同假。此前门户自己写了一份判据（只看 sensitivity：普通资源恒可访问、
// 高敏恒需申请），于是控制面出现了第四个可访问性判定点，且方向与另外三处相反——
// 三种失败形态全部无报错：
//   - 普通资源未授权：磁贴恒亮「访问」，点下去才 403；
//   - 高敏资源已授权：磁贴恒「需申请」，逼人为自己已有的权限走审批，而同一个人
//     经桌面客户端立刻能进（审批退化成纸面闸）；
//   - 高敏 + 未设 ACL：磁贴锁着、点「申请权限」被 JIT 闸以「无需申请」400 顶回来（死路），
//     而该资源经隧道与 Web 票据对全体登录用户开放，方向完全相反。
//
// ★第三种死路之所以不会复活，靠的是**两步**，缺一不可：
//  1. 这里：`!Restricted() ⟹ authorizeRes 放行 ⟹ Accessible`，所以「不可访问 ∧ 非降权 ∧
//     非不可用 ⟹ Restricted()」，JIT 闸必然收单（用例真的把申请打出去断言不是 400）；
//  2. 三端 UI：把 Degraded / Unavailable 两个分支**排在**「申请权限」之前。
//     少了第 2 步，一个降权态下的高敏不限资源会立刻画出「申请权限」，而 JIT 闸仍会
//     以「无需申请」400 顶回来——原缺陷原样复活。改前端时别把这两个分支合并掉。
//
// 返回的 store.Resource 是解析到的受控资源（global / 未关联资源时为零值，调用方按
// a.Mode 与 appState.Unavailable 判断，不要直接用零值）。
func appAccessState(user, role string, a store.App, byRes map[string]store.Resource,
	ix store.SubjectIndex, granted map[string]bool, degraded bool) (store.Resource, appState) {
	// global 模式（*.cnki.net 这类全网资源）没有受控资源可判，也不经网关代理。
	// 两个出口都如实标 normal + 可见——它**绕过授权判定**这件事本身是一处未表态的缺口
	// （见 docs/charter/wave8.md 行动 14），但在处置它之前两处必须先同口径：
	// 一处放行一处拦，会让门户与客户端对同一个应用给出相反答案，比现状更难查。
	if a.Mode == "global" {
		return store.Resource{}, appState{Sensitivity: store.SensitivityNormal, Accessible: true}
	}
	res, ok := byRes[a.ResourceID]
	if !ok {
		// 应用未桥接到受控资源（或引用了一条已被删除的资源）：网关按 id 查不到后端，
		// 隧道与七层两条路都必然不通。剖面对这类应用是「丢弃 + 给管理员一条 warning」，
		// 门户没有 warnings 通道，故改由磁贴自己如实呈现。
		return store.Resource{}, appState{
			Sensitivity: store.SensitivityNormal, Unavailable: true,
			Reason: "未关联受控资源（请在资源策略页为它关联一个资源）",
		}
	}
	// 后端地址不是 host:port：剖面同样丢弃它（下面那条 net.SplitHostPort 分支），
	// 网关拿一个没有端口的地址也拨不出去。判据必须**和剖面在同一处**，否则门户会继续
	// 把按钮亮着，而这正是本行动要消灭的那种「按钮亮着、点了打不开」。
	// 根因是 handleSaveResource 不校验 backend 形态（存量库里可能已有这样的行，
	// 故这里只能读侧兜底，不能指望入口拦住）——入口校验另立项，见 docs/charter/wave8.md。
	if _, _, err := net.SplitHostPort(res.Backend); err != nil {
		return res, appState{
			Sensitivity: store.NormalizeSensitivity(res.Sensitivity), Unavailable: true,
			Reason: fmt.Sprintf("资源「%s」的后端地址 %q 不是 host:port 形式，网关无法拨号", res.Name, res.Backend),
		}
	}
	return res, appState{
		Sensitivity: store.NormalizeSensitivity(res.Sensitivity),
		Accessible:  accessibleFor(user, role, res, ix, granted[res.ID], degraded),
		Degraded:    degraded && res.HighSensitivity(),
	}
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
