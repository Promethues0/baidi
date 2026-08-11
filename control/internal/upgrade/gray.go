package upgrade

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// 客户端灰度升级（PRD FR-UPG-19）：服务端按比例/分组分批放新版本，
// 先小范围验证再全量。
//
// ★这一条与第 4 章其余需求不同——它**不需要**替换服务端二进制，
// 因此可以完整实现并端到端验证：下载中心已有 manifest，灰度只是决定
// 「这个账号此刻该被告知哪个版本」。

// GrayPlan 一个平台的灰度计划。
type GrayPlan struct {
	Platform string `json:"platform"` // macos | windows | linux | android | ios | harmony
	// Version 灰度中的新版本。空 = 该平台无灰度，所有人拿稳定版。
	Version string `json:"version"`
	// Percent 灰度比例 0-100。100 = 全量。
	Percent int `json:"percent"`
	// Accounts 定向名单：无论比例如何，这些账号一定拿到新版本（内测/回归用）。
	Accounts []string `json:"accounts"`
	// Groups 定向用户组 id（成员由控制面展开后传进 Decide）。
	Groups []string `json:"groups"`
	// Stable 稳定版本：不在灰度内的账号拿这个。
	Stable string `json:"stable"`
	Note   string `json:"note,omitempty"`
}

var ErrGrayPlan = errors.New("灰度计划不合法")

// Validate 校验一条灰度计划。
func (p GrayPlan) Validate() error {
	if strings.TrimSpace(p.Platform) == "" {
		return fmt.Errorf("%w: 平台不能为空", ErrGrayPlan)
	}
	if p.Percent < 0 || p.Percent > 100 {
		return fmt.Errorf("%w: 灰度比例必须在 0-100 之间（实际 %d）", ErrGrayPlan, p.Percent)
	}
	for _, v := range []struct{ label, val string }{{"灰度版本", p.Version}, {"稳定版本", p.Stable}} {
		if v.val == "" {
			continue
		}
		if _, err := ParseVersion(v.val); err != nil {
			return fmt.Errorf("%w: %s %v", ErrGrayPlan, v.label, err)
		}
	}
	// 灰度版本必须**高于**稳定版：反过来配的话，「灰度」实际是在把一部分人降级，
	// 而页面上显示的是正在推新版本。
	if p.Version != "" && p.Stable != "" {
		nv, e1 := ParseVersion(p.Version)
		sv, e2 := ParseVersion(p.Stable)
		if e1 == nil && e2 == nil && nv.Compare(sv) <= 0 {
			return fmt.Errorf("%w: 灰度版本 %s 不高于稳定版本 %s——那不是灰度，是把一部分用户降级",
				ErrGrayPlan, p.Version, p.Stable)
		}
	}
	if p.Version == "" && (p.Percent > 0 || len(p.Accounts) > 0 || len(p.Groups) > 0) {
		return fmt.Errorf("%w: 配了灰度范围却没有灰度版本", ErrGrayPlan)
	}
	return nil
}

// Decision 一次灰度判定的结果。
type Decision struct {
	Version string `json:"version"` // 该账号此刻应被告知的版本
	InGray  bool   `json:"inGray"`  // 是否落在灰度批次里
	Reason  string `json:"reason"`  // 为什么（定向 / 比例命中 / 未命中 / 无灰度）
}

// Decide 判定某账号在某平台上该拿哪个版本。
//
// ★分桶必须**稳定**：同一个账号在比例不变时永远落在同一侧。
// 用随机数或时间的话，同一个人每次检查更新都可能被推到不同版本之间来回横跳——
// 而这在服务端日志上看不出任何异常。故用 SHA-256(platform|account) 取模，
// 与账号绑定、与时间无关。
//
// 带上 platform 做盐是有意的：不加的话，同一批「运气不好」的账号会在
// 所有平台上同时被排除在灰度之外，灰度样本永远覆盖不到他们。
//
// groupMembers 是该账号所属用户组 id 集合（由控制面展开后传入——
// 数据面/判定层不查库，与资源授权的组织展开同一条纪律）。
func Decide(p GrayPlan, account string, groupMembers []string) Decision {
	if p.Version == "" {
		return Decision{Version: p.Stable, Reason: "该平台当前没有灰度计划"}
	}
	acct := strings.ToLower(strings.TrimSpace(account))

	for _, a := range p.Accounts {
		if strings.ToLower(strings.TrimSpace(a)) == acct && acct != "" {
			return Decision{Version: p.Version, InGray: true, Reason: "定向灰度名单"}
		}
	}
	if len(p.Groups) > 0 {
		inGroup := map[string]bool{}
		for _, g := range groupMembers {
			inGroup[strings.TrimSpace(g)] = true
		}
		for _, g := range p.Groups {
			if inGroup[strings.TrimSpace(g)] {
				return Decision{Version: p.Version, InGray: true, Reason: "所属用户组在灰度范围内"}
			}
		}
	}

	if p.Percent >= 100 {
		return Decision{Version: p.Version, InGray: true, Reason: "已全量发布"}
	}
	if p.Percent <= 0 || acct == "" {
		return Decision{Version: p.Stable, Reason: "未在灰度范围内"}
	}
	if bucket(p.Platform, acct) < uint32(p.Percent) {
		return Decision{Version: p.Version, InGray: true,
			Reason: fmt.Sprintf("按 %d%% 灰度比例命中", p.Percent)}
	}
	return Decision{Version: p.Stable, Reason: fmt.Sprintf("未落入 %d%% 灰度批次", p.Percent)}
}

// bucket 把 (平台, 账号) 稳定映射到 [0,100)。
func bucket(platform, account string) uint32 {
	sum := sha256.Sum256([]byte(strings.ToLower(platform) + "|" + account))
	return binary.BigEndian.Uint32(sum[:4]) % 100
}

// Coverage 估算某比例下会命中多少账号（供控制台显示「预计影响 N 人」）。
//
// ★是**精确计算**而不是 accounts*percent/100 的估算：分桶是确定性的，
// 真实命中数可以直接数出来。显示一个算出来的近似值会让管理员在
// 「说好 10% 结果 13 个人」时怀疑灰度本身有问题。
func Coverage(p GrayPlan, accounts []string, groupsOf func(string) []string) int {
	n := 0
	for _, a := range accounts {
		var groups []string
		if groupsOf != nil {
			groups = groupsOf(a)
		}
		if Decide(p, a, groups).InGray {
			n++
		}
	}
	return n
}
