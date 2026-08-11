// Package upgrade 是产品升级管理的判定层（PRD 第 4 章）：版本比较、升级链路校验、
// 升级包完整性与签名校验、组件一致性。
//
// ★做成纯函数包，取数与副作用留在 api 层——升级判定写反的后果（放行了一次禁止的降级、
// 或拦住了一次合法升级）在集成环境里与「一切正常」难以区分，只有纯函数测得住。
//
// ★与源 PRD 的偏差（**刻意的**，不是遗漏）：
// PRD 第 4 章的版本链（2.1.1→2.1.5→2.1.12）、包格式（.run/.ssu/.bin）、B17 镜像门槛、
// 后台账号与默认口令（quickstart / SangforSDP@1220）都是**源产品的实现事实**。
// 白帝当前版本是 0.3.0，把那些数字照搬进来就是编造自己没有的历史。
// 这里保留的是可迁移的**机制**：语义化版本序、禁降级、可配置的强制跳跃链路、
// 组件一致性、签名与校验和。链路规则由管理员配置（UpgradeRules），不写死任何版本号。
package upgrade

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version 语义化版本（major.minor.patch，可带 -pre 后缀）。
type Version struct {
	Major, Minor, Patch int
	Pre                 string // 预发布标识（如 rc1）；有 Pre 的版本**低于**同号正式版
	Raw                 string
}

var ErrBadVersion = errors.New("版本号格式不合法")

// ParseVersion 解析 "0.3.0" / "v1.2.3" / "1.2.3-rc1"。
//
// 容忍前导 v：网关版本是编译期 -ldflags 注入的，运维习惯写 v0.4.0，
// 而 control 的常量写的是 0.3.0。两种写法在同一个系统里并存是常态，
// 解析层不容忍的话，组件一致性校验会把 "v0.4.0" 与 "0.4.0" 判成不一致。
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	v := Version{Raw: raw}
	body := strings.TrimPrefix(raw, "v")
	if i := strings.IndexByte(body, '-'); i >= 0 {
		v.Pre, body = body[i+1:], body[:i]
	}
	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("%w: %q（应形如 1.2.3）", ErrBadVersion, s)
	}
	dst := []*int{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("%w: %q 的第 %d 段不是非负整数", ErrBadVersion, s, i+1)
		}
		*dst[i] = n
	}
	return v, nil
}

// Compare 返回 -1/0/1。预发布版低于同号正式版（1.0.0-rc1 < 1.0.0）。
func (v Version) Compare(o Version) int {
	for _, p := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "": // 正式版 > 预发布版
		return 1
	case o.Pre == "":
		return -1
	case v.Pre < o.Pre:
		return -1
	default:
		return 1
	}
}

func (v Version) String() string {
	if v.Raw != "" {
		return v.Raw
	}
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Hop 一条强制跳跃规则：低于 Below 的版本必须先升到 Next，不得直升更高版本。
//
// PRD FR-UPG-05 要求这个机制，但**具体版本号由管理员配置**，不在代码里写死——
// 写死等于把源产品的历史（2.1.1→2.1.5→2.1.12）冒充成白帝自己的升级链。
type Hop struct {
	Below string `json:"below"` // 起始版本上界（不含）
	Next  string `json:"next"`  // 强制下一跳
}

// Rules 升级校验规则（可配置，落库在 settings）。
type Rules struct {
	// AllowDowngrade 是否允许降级。默认 false（FR-UPG-06）。
	AllowDowngrade bool `json:"allowDowngrade"`
	// RequireComponentMatch 分离式部署下是否要求控制面与全部网关版本一致（FR-UPG-07）。
	RequireComponentMatch bool `json:"requireComponentMatch"`
	// Hops 强制跳跃链路（FR-UPG-05）。空 = 不限制，可直升。
	Hops []Hop `json:"hops"`
}

// DefaultRules 出厂规则：禁降级、要求组件一致、无强制跳跃。
//
// 无强制跳跃不是「没做这个功能」，而是**白帝目前确实没有已知的不可直升版本对**——
// 编一条出来会让管理员以为系统知道某种他不知道的升级约束。
func DefaultRules() Rules {
	return Rules{AllowDowngrade: false, RequireComponentMatch: true}
}

// Check 的判定结果。Blocked 为真时 UI 必须禁用升级按钮并显示 Reasons。
type Check struct {
	Blocked  bool     `json:"blocked"`
	Reasons  []string `json:"reasons"` // 每条都要能指导下一步动作
	Warnings []string `json:"warnings"`
	// NextHop 被强制跳跃拦住时，管理员应该先升到哪个版本。
	NextHop string `json:"nextHop,omitempty"`
}

func (c *Check) block(format string, a ...any) {
	c.Blocked = true
	c.Reasons = append(c.Reasons, fmt.Sprintf(format, a...))
}

// Components 参与一致性校验的组件版本快照。
type Components struct {
	Control  string            `json:"control"`  // 控制面当前版本
	Gateways map[string]string `json:"gateways"` // 网关 id → 上报的版本（空串=旧网关不上报）
}

// CheckUpgrade 判定「当前版本 → 目标版本」这次升级是否放行。
//
// ★所有判定都必须给出**可执行的**理由：升级被拦住而不说清先做什么，
// 管理员唯一的选择就是绕过它（去后台手工升），那这道闸等于没有。
func CheckUpgrade(current, target string, rules Rules, comp Components) Check {
	var c Check
	cur, err := ParseVersion(current)
	if err != nil {
		c.block("无法解析当前版本 %q：%v", current, err)
		return c
	}
	tgt, err := ParseVersion(target)
	if err != nil {
		c.block("无法解析升级包版本 %q：%v", target, err)
		return c
	}

	switch cmp := tgt.Compare(cur); {
	case cmp == 0:
		c.block("升级包版本与当前运行版本相同（%s），无需升级", cur)
	case cmp < 0 && !rules.AllowDowngrade:
		// FR-UPG-06。降级最常见的后果是数据库 schema 已被新版迁移过，旧版读不了——
		// 而那时系统已经起不来，没有界面可以再点回滚。
		c.block("检测到降级（当前 %s → 目标 %s），已拒绝：数据库结构已被当前版本迁移过，"+
			"旧版本无法读取。确需降级请先恢复升级前的配置备份。", cur, tgt)
	case cmp < 0:
		c.Warnings = append(c.Warnings,
			fmt.Sprintf("这是一次降级（%s → %s），且已在规则中显式允许。数据库结构可能不兼容，务必先备份。", cur, tgt))
	}

	// FR-UPG-05 强制跳跃链路。
	for _, h := range rules.Hops {
		below, err1 := ParseVersion(h.Below)
		next, err2 := ParseVersion(h.Next)
		if err1 != nil || err2 != nil {
			continue // 规则本身不合法：保存时已校验过，这里不因坏规则拦住合法升级
		}
		if cur.Compare(below) < 0 && tgt.Compare(next) > 0 {
			c.NextHop = next.String()
			c.block("禁止跨版本直升：当前版本 %s 低于 %s，必须先升级到 %s，再升更高版本。",
				cur, below, next)
		}
	}

	// FR-UPG-07 分离式组件一致性。
	if rules.RequireComponentMatch {
		var stale []string
		for id, v := range comp.Gateways {
			if strings.TrimSpace(v) == "" {
				// 旧网关不上报版本：无法判定，如实说不可判定而不是当成一致。
				c.Warnings = append(c.Warnings,
					fmt.Sprintf("网关 %s 未上报版本（版本低于 v0.4 的网关不上报），无法校验组件一致性。", id))
				continue
			}
			gv, err := ParseVersion(v)
			if err != nil || gv.Compare(tgt) != 0 {
				stale = append(stale, fmt.Sprintf("%s(%s)", id, v))
			}
		}
		if len(stale) > 0 {
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("升级后以下网关版本将与控制面不一致，须同步升级：%s。"+
					"控制面与网关版本不一致时，新增的下发字段旧网关读不到（表现为策略配了不生效）。",
					strings.Join(stale, "、")))
		}
	}
	return c
}
