package darkfw

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ── 内核态隐身的**实测**回执（wave8 行动 7）──
//
// 隐身是白帝的第一卖点，NFR-SEC-01 的验收就是「外部扫描端口全闭」。此前控制面
// 对它一个字都不知道：网关页写死「内核态默认丢弃 / 端口扫描全程超时 / 攻击面 = 0」，
// `/diag` 的 checkStealth 只要有网关在线就恒 pass。而参考部署与在线演示站**都没启用**
// （`deploy/systemd/baidi-gateway.service` 明写默认不开 -pf，`install-remote.sh`
// 全程不执行 `baidi-nft.sh`）——未开时未敲门的连接走 proxy.go 的 accept-then-close，
// **TCP 三次握手已经完成**，nmap 判 open。「握手后被断开」与页面断言的「等同于不存在」
// 是两种安全等级。
//
// 控制面确实无法从外部实测端口可见性，但**网关自己完全知道**——不上报等于把可判定的事
// 硬做成不可判定。这个文件就是把它变回可判定的那一步。
//
// ★为什么不能拿 Available() 当回执：它只查 `nft`/`pfctl` **二进制在不在 PATH 上**。
// 几乎所有 Linux 都装了 nft，于是它几乎恒为 true——用它当「隐身已启用」的判据，
// 与写死一个 true 没有区别。真正要回答的是**规则集到底装没装**，而那是能探的。
//
// ★最危险的一种形态是 `-pf` 开着、规则集不在：`AllowIP` 每次敲门都失败（表不存在），
// 而**默认 DROP 那条规则同样不存在**，于是端口对全世界敞开、走用户态兜底，
// 管理侧看起来却是「隐身已配置」。它必须与「压根没开」区分开——后者至少没人误以为安全。

// State 内核态隐身的实测状态。**每一格都可能是"不可判定"，绝不用好值顶包。**
type State struct {
	// Wanted `-pf` 管理意图（管理员想不想开）。与下面的实测态分开，
	// 与 NAT 回执同一条纪律：`enabled` 一列同时表达「想开」和「真的开着」正是被批判的形态。
	Wanted bool `json:"wanted"`
	// Backend 内核后端名：nftables(Linux) / pf(macOS) / none。
	Backend string `json:"backend"`
	// Root 进程是否以 root 运行。非 root 时 AllowIP/DenyIP 每次都会失败——
	// 规则集若在，合法用户会被一路 DROP；规则集若不在，就是完全没有保护。
	Root bool `json:"root"`
	// Ruleset 规则集（nft table inet baidi 的集合 / pf anchor 的表）**实际**在不在。
	// ★指针三态：nil = 探不到（非 root、命令异常），不是「不在」。
	// 探不到就说探不到——报成"不在"是虚警，报成"在"是替一台可能裸奔的网关背书。
	Ruleset *bool `json:"ruleset,omitempty"`
	// GuardedPort 规则集里那条默认 DROP 规则**实际**保护的 TCP 端口。
	// ★指针三态：nil = 解析不出来。它存在的理由：setup 脚本的 PROXY_PORT 默认 18443，
	// 而网关可以 `-proxy :18444` 启动——规则集装得好好的、保护的却是另一个端口，
	// 隧道口照样全世界可见，两侧都不报错。与 wintun 的架构错配同族。
	GuardedPort *int `json:"guardedPort,omitempty"`
	// Detail 探测过程中的异常说明（命令报错等），供控制面原样呈现。
	Detail string `json:"detail,omitempty"`
}

// Probe 实测一次内核态隐身状态。wanted 是 `-pf` 开关。
//
// ★`wanted=false` 时**照样探**。看起来多余（没开 -pf，规则集在不在都走用户态兜底），
// 实际上那个组合是一种会让整台网关彻底不可用、且全程无报错的形态：
// 规则集装着（有人跑过 setup 脚本）+ 网关没带 -pf 启动
//
//	→ 内核那条 `tcp dport <proxy> drop` 一直在生效，端口确实是 filtered；
//	→ 但放行集合 @baidi_allowed **永远是空的**（OnAllow 回调只在 `if *pf` 里挂），
//	  网关不会为任何一次成功敲门往里加 IP；
//	→ 于是**每一个合法用户都连不上**：敲门成功、令牌有效、网关日志一切正常、
//	  控制台显示在线，客户端只是拨号超时。
//
// 不探就报不出它。一次本地 exec（毫秒级）换这个，划算。
//
// 成本：一次本地 `nft list` / `pfctl -T show`，随心跳调用。
func Probe(wanted bool) State {
	st := State{Wanted: wanted, Backend: Backend(), Root: os.Geteuid() == 0}
	if be == none {
		return st
	}
	// ★非 root 时探测命令本身会因权限失败，那时**分不出**「规则集不在」与「看不见」。
	// 直接留 nil 并说明原因，不去猜。
	if !st.Root {
		st.Detail = "非 root 运行，读不到内核规则集——隐身是否生效不可判定"
		return st
	}
	switch be {
	case nft:
		out, err := exec.Command("nft", "list", "table", "inet", "baidi").CombinedOutput()
		if err != nil {
			// nft 对不存在的 table 报错退出：这**就是**「规则集没装」，是确定的结论。
			no := false
			st.Ruleset = &no
			st.Detail = "内核里没有 table inet baidi（未执行 gateway/firewall/baidi-nft.sh setup）"
			return st
		}
		yes := true
		st.Ruleset = &yes
		st.GuardedPort = parseNftDropPort(string(out))
	case pf:
		if _, err := exec.Command("pfctl", "-a", pfAnchor, "-t", Table, "-T", "show").CombinedOutput(); err != nil {
			no := false
			st.Ruleset = &no
			st.Detail = "pf anchor " + pfAnchor + " 里没有表 " + Table + "（未执行 gateway/firewall/setup-pf.sh）"
			return st
		}
		yes := true
		st.Ruleset = &yes
		if out, err := exec.Command("pfctl", "-a", pfAnchor, "-sr").CombinedOutput(); err == nil {
			st.GuardedPort = parsePfDropPort(string(out))
		}
	}
	return st
}

// pfAnchor setup-pf.sh 装规则用的 anchor 名（两处必须一致，改一处就探不到了）。
const pfAnchor = "baidi-gw"

// nftDrop 匹配 `tcp dport 18443 drop`（baidi-nft.sh 灌的默认丢弃那条）。
var nftDrop = regexp.MustCompile(`tcp\s+dport\s+(\d+)\s+drop`)

// parseNftDropPort 从 `nft list table` 输出里取出被默认 DROP 保护的端口。
// 解析不出来回 nil——**不猜一个默认值**：猜 18443 恰好会在"脚本用默认端口、
// 网关换了端口"这个最需要报警的组合上给出"一切正常"。
func parseNftDropPort(out string) *int {
	m := nftDrop.FindStringSubmatch(out)
	if m == nil {
		return nil
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return nil
	}
	return &n
}

// pfDrop 匹配 pf 的 `block drop in quick proto tcp from any to any port = 18443`。
var pfDrop = regexp.MustCompile(`block\s+drop\s+in\s+quick\s+proto\s+tcp.*?port\s*=\s*(\d+)`)

// parsePfDropPort 同上，pf 版。
func parsePfDropPort(out string) *int {
	for _, line := range strings.Split(out, "\n") {
		m := pfDrop.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		return &n
	}
	return nil
}
