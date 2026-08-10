package store

import (
	"sort"
	"strings"
)

// ── 授权主体展开（PRD ch8 AppAuthorization.subjectType = org | group | user）──
//
// 资源授权从「角色 + 账号」两维扩到四维：角色 / 账号 / 用户组 / 组织（含子树）。
// 组织与用户组是**控制面概念**，数据面对它们一无所知：
//
//	控制面（这里）：组织/用户组 --展开--> 账号集合 --> 并进 AllowUsers --> 下发网关
//	数据面（网关） ：只看见账号与角色，registry.Authorize 一行未改
//
// ★为什么展开而不是把组下发给网关：判定权必须留在控制面——只有控制面同时知道
// 组织树长什么样、谁在哪个部门、谁刚被移走。把树推给网关等于让被保护方自己推导
// 策略，而网关是按 30s 周期拉取的：一旦两侧对树的理解出现哪怕一点偏差（比如网关
// 缓存了旧的父子关系），结果就是「控制台上人已经移走了、隧道还通着」，且无处可查。
//
// ★子树展开在本文件里只发生一次（buildSubjectIndex）。控制面有两个判定点——
// 下发给网关的 handleGatewayPolicy 与客户端剖面的 buildProfile——两处都必须从
// 同一个 SubjectIndex 取答案。各写一遍必然分叉，分叉的形态就是本项目最难查的那类：
// 「审批/授权明明生效了，客户端却排不出路由」或者反过来「剖面里有、连上去被拒」。

// DenyAllSubject 空主体哨兵账号，展开结果里恒定附带（仅当资源确实按组织/用户组授权时）。
//
// ★为什么必须有它：网关的判定语义是「AllowUsers 与 AllowRoles 都空 = 不限」。
// 一个只按组织授权的资源，若那些组织当下**一个人都没有**（新建的空部门、成员刚被移走），
// 展开结果为空，下发到网关就退化成「两维都空」= 对所有人开放——控制面判定「谁都不能访问」，
// 数据面判定「谁都能访问」，方向完全相反，而且两边日志都正常。
// 附上这个永不匹配的账号，让「限定了主体、但主体集为空」如实表达成「拒绝所有人」。
//
// 值里的 NUL 字节保证它不可能与真实账号相等：账号来自目录/JWT sub，全链路按可打印串处理，
// 而且 users.account 上有规范化唯一索引，没有任何路径能造出含 NUL 的账号。
const DenyAllSubject = "\x00baidi:deny-all"

// SubjectIndex 「授权主体 → 账号集合」的一次性展开结果。
//
// 它是**快照**而非活对象：调用方每次判定前重新取一份（见 SQLiteStore.SubjectIndex 的
// "不缓存"说明），所以这里的 map 只读、不含任何失效逻辑。
type SubjectIndex struct {
	// OrgAccounts 组织 id → 该组织**及其全部后代组织**下的账号（已规范化）。
	// 子树语义已经在建索引时展平，取用方一次查表即可，不必也不该再走树。
	OrgAccounts map[string][]string
	// GroupAccounts 用户组 id → 成员账号（含 kind=role 的派生成员）。
	GroupAccounts map[string][]string
}

// orgPathIDs 从物化路径 "/root/dev/team/" 拆出 [root dev team]——
// 即「该组织自身 + 它的全部祖先」。挂在这条路径上的账号，被授权给其中**任意一个**
// 组织时都应当覆盖到，子树继承就是这么来的：不必递归查库，冗余 path 那一列
// 已经把整条祖先链写在行上（这也是 orgs.go 里保留 path 的第二个用途）。
func orgPathIDs(path string) []string {
	out := []string{}
	for _, seg := range strings.Split(path, "/") {
		if seg = strings.TrimSpace(seg); seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// buildSubjectIndex 由「账号 → 所属组织的物化路径」与「组 id → 成员账号」构建展开索引。
// 纯函数，子树展开的唯一实现处；SQL 取数在 subjects_sqlite.go。
func buildSubjectIndex(userOrgPath map[string]string, groupAccounts map[string][]string) SubjectIndex {
	ix := SubjectIndex{
		OrgAccounts:   map[string][]string{},
		GroupAccounts: map[string][]string{},
	}
	seen := map[string]map[string]bool{} // 组织 id → 账号集合（去重：同一账号只挂一条路径，但祖先会重复命中）
	for acct, path := range userOrgPath {
		acct = normAccount(acct)
		if acct == "" {
			continue
		}
		for _, orgID := range orgPathIDs(path) {
			if seen[orgID] == nil {
				seen[orgID] = map[string]bool{}
			}
			if seen[orgID][acct] {
				continue
			}
			seen[orgID][acct] = true
			ix.OrgAccounts[orgID] = append(ix.OrgAccounts[orgID], acct)
		}
	}
	for id := range ix.OrgAccounts {
		sort.Strings(ix.OrgAccounts[id]) // 稳定顺序：下发给网关的 AllowUsers 不该每次轮询都抖动
	}
	for gid, accts := range groupAccounts {
		uniq := map[string]bool{}
		list := make([]string, 0, len(accts))
		for _, a := range accts {
			if a = normAccount(a); a == "" || uniq[a] {
				continue
			}
			uniq[a] = true
			list = append(list, a)
		}
		sort.Strings(list)
		ix.GroupAccounts[gid] = list
	}
	return ix
}

// accountSet 返回 res 因组织/用户组主体而获得访问权的账号集合（规范化账号）。
// SubjectAccounts 与 SubjectAllows 都只走这一个函数——两个出口共用一份判定，
// 才谈得上「控制面下发给网关的结果」与「剖面里算出来的结果」同真同假。
func (ix SubjectIndex) accountSet(res Resource) map[string]bool {
	out := map[string]bool{}
	for _, gid := range res.AllowGroups {
		for _, a := range ix.GroupAccounts[strings.TrimSpace(gid)] {
			out[a] = true
		}
	}
	for _, oid := range res.AllowOrgs {
		for _, a := range ix.OrgAccounts[strings.TrimSpace(oid)] {
			out[a] = true
		}
	}
	return out
}

// SubjectAccounts 把 res 的组织/用户组主体展开成账号切片（去重、字典序）。
// 网关策略下发把它并进 AllowUsers——数据面因此只看见账号，看不见组织树。
func (ix SubjectIndex) SubjectAccounts(res Resource) []string {
	set := ix.accountSet(res)
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// SubjectAllows 报告 account 是否被 res 的组织/用户组主体覆盖（account 内部规范化）。
func (ix SubjectIndex) SubjectAllows(res Resource, account string) bool {
	if len(res.AllowGroups) == 0 && len(res.AllowOrgs) == 0 {
		return false
	}
	return ix.accountSet(res)[normAccount(account)]
}
