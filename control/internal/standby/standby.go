// Package standby 控制面温备（warm standby）的领域模型与新鲜度判定。
//
// ★先把形态说死，免得被当成双活：**SQLite 是单写者，白帝做不了多活控制面。**
// 硬做（两个实例同时写同一个库文件）会在写冲突时静默丢配置——比没有 HA 更糟：
// 管理员改完策略、页面回了 200，那条策略却在另一台的写入里消失了，两边都不报错。
//
// 所以这里实现的是温备：
//
//	备机周期性从主机拉一份**加密配置备份**（复用 upgrade.CreateBackup，不另造一套），
//	校验通过才落盘，并把「我这份是什么时候的」回报给主机；
//	备机**不对外提供服务**（它连 HTTP 监听都不开），切换由人工/脚本触发。
//
// ★为什么不做自动选主：两节点没有仲裁第三方，自动选主必然脑裂，而脑裂在这个系统里
// 意味着两个控制面同时签发令牌、下发彼此相反的策略——网关会照着后到的那份执行，
// 现场没有任何一处会显示"你们有两个大脑"。宁可多一次人工确认。
//
// ★RPO = 同步间隔，且必须在页面上明说。让人以为温备是零丢失，比没有温备更危险。
package standby

import (
	"fmt"
	"strings"
	"time"
)

// mTLS 契约：备机的机器身份是一张 CN 以 standby- 开头的客户端证书（照 ipsec- 前缀分权的既有做法）。
// 路径常量在这里定义一份，主机侧路由与备机侧拉取共用——两边各写一份字符串，
// 拼错时的症状是 404，而 404 会被备机记成"主机不可达"，指向完全错误的排查方向。
const (
	CNPrefix   = "standby-"
	PathBackup = "/api/v1/standby/backup"
	PathStatus = "/api/v1/standby/status"
)

// 同步节奏与新鲜度阈值。
const (
	// DefaultInterval 备机默认同步间隔，也是默认 RPO。
	DefaultInterval = 10 * time.Minute
	// MinInterval 同步间隔下限。每一轮都要主机现做一份全量加密备份
	// （PBKDF2 600k 轮 + 全库打包），设成秒级等于给自己造一个稳定的 CPU 压测。
	MinInterval = time.Minute
	// DefaultStaleAfter 判「落后」的全局阈值。
	DefaultStaleAfter = 15 * time.Minute
	// MaxStaleAfter 阈值上限。逐节点阈值会取 max(全局, 3×备机自报间隔)，
	// 而间隔是**备机自报**的——不封顶的话，一台自报间隔 30 天的备机永远不会被判落后。
	MaxStaleAfter = 6 * time.Hour
)

// 集群形态。
const (
	ModeSingle = "single"       // 未配置备机：单机形态
	ModeWarm   = "warm-standby" // 已配置温备
)

// 备机状态（NodeView.State）。
const (
	StateFresh = "fresh" // 盘上那份在阈值内
	StateStale = "stale" // 落后超阈值
	StateNever = "never" // 从未成功同步过（有节点登记，但一次都没校验通过）
)

// Node 一台备机在主机侧的登记（standby_nodes 表一行）。
//
// ★两个时间刻意分开记，且**新鲜度只看 LastSyncAt**：
//
//	LastPullAt —— 主机观测到的「它来拉过」。这只证明我发了字节出去。
//	LastSyncAt —— 备机回报的「校验通过并已落盘」，由**主机**在收到回报时按服务端时间写。
//
// 只有后者代表备机手上真有一份可用的备份。拿 LastPullAt 当新鲜度，会把
// 「每 10 分钟准时来拉、但每次校验都失败」显示成一台健康备机——而那正是
// 切换那天会发现自己没有备份的情形。（展示值必须来自真正在用的那份。）
type Node struct {
	NodeID string `json:"nodeId"` // 权威来源是 mTLS 证书 CN，不采信请求体自报
	Addr   string `json:"addr"`   // 备机自报的落点（仅展示，不参与任何判定）
	// IntervalSec 备机自报的同步间隔，即这套温备的实际 RPO。
	// 0 = 尚未回报过（此时逐节点阈值退化为全局阈值）。
	IntervalSec int
	LastPullAt  int64 // Unix 秒；0 = 从未来拉过
	LastSyncAt  int64 // Unix 秒；0 = 从未成功同步（不是「不可判定」，是确凿的"一次都没成功"）
	// 备份头部里的信息（明文头，不含任何凭据），由备机回报。
	BackupVersion   string
	BackupCreatedAt string
	BackupSHA256    string
	// 备机侧的**版本身份**，两组分别回答两个不同的问题（wave11 行动 18）：
	//
	//	NodeSemver/NodeBuild       —— 备机上跑的 baidi-standby 是哪一版。
	//	ControlSemver/ControlBuild —— 备机上那份 **baidi-control** 是哪一版，
	//	    由备机跑 `baidi-control -version` 实测得来。**它才是切换后真正被启动的进程**，
	//	    也是唯一该拿去与主机比对的那个值。
	//
	// ★四项都可能是空串 = **不可判定**（旧备机不上报 / 二进制未注入版本 / 探不到）。
	// 绝不在任何一层补成主机的版本——那等于替一台还没说话的备机宣布"我们一致"，
	// 而这条信息存在的全部意义就是发现"不一致"。
	NodeSemver    string
	NodeBuild     string
	ControlSemver string
	ControlBuild  string
	LastStatus    string // ok | fail；"" = 从未回报
	LastDetail    string
	UpdatedAt     int64
}

// NodeView 一台备机的展示态（System 页 / /diag 共用）。
type NodeView struct {
	NodeID string `json:"nodeId"`
	Addr   string `json:"addr"`
	State  string `json:"state"` // fresh | stale | never
	// LagSeconds 盘上那份落后多久。-1 = 不可判定（从未成功同步过，没有"落后多久"可言）。
	// 这里绝不补 0——0 的意思是"刚刚同步过"，与"一次都没同步过"恰好相反。
	LagSeconds      int64  `json:"lagSeconds"`
	LagText         string `json:"lagText"`
	IntervalSec     int    `json:"intervalSec"`  // 即 RPO
	ThresholdSec    int    `json:"thresholdSec"` // 本节点实际生效的落后阈值
	LastSyncAt      string `json:"lastSyncAt"`   // "" = 从未
	LastPullAt      string `json:"lastPullAt"`   // "" = 从未
	BackupVersion   string `json:"backupVersion"`
	BackupCreatedAt string `json:"backupCreatedAt"`
	BackupSHA256    string `json:"backupSha256"`
	// 备机侧版本身份（见 Node 上同名字段的注释）。空串 = 不可判定。
	NodeSemver    string `json:"nodeSemver"`
	NodeBuild     string `json:"nodeBuild"`
	ControlSemver string `json:"controlSemver"`
	ControlBuild  string `json:"controlBuild"`
	// VersionState 备机上那份 baidi-control 与主机的版本关系：
	// unknown（不可判定）| match（一致）| mismatch（确定不一致）。
	VersionState string `json:"versionState"`
	// VersionText 上面那个结论的人话，页面原样显示（后端不让前端自己编）。
	VersionText string `json:"versionText"`
	LastStatus  string `json:"lastStatus"`
	LastDetail  string `json:"lastDetail"`
}

// 备机版本一致性的三态取值。
const (
	// VersionUnknown 判不出来：备机没报、或两侧任一未注入版本。
	// **不翻状态**，只如实呈现——它与 VersionMismatch 的处置完全不同
	// （前者去升级/重建备机的包，后者是切换那天真会出事的事实）。
	VersionUnknown  = "unknown"
	VersionMatch    = "match"
	VersionMismatch = "mismatch"
)

// ClusterView 集群区块的完整答案。System 页与 /diag checkCluster 读的是同一个它，
// 两处口径不可能再分叉（此前是两份各自写死的文案）。
type ClusterView struct {
	Mode     string `json:"mode"`     // single | warm-standby
	Deployed bool   `json:"deployed"` // 是否配了备机
	// Status 与 /diag 的取值域一致：pass | warn | skip。
	// skip = 该能力未部署，不参与健康分（单机形态不该因为"没有备机"被扣分）。
	Status        string     `json:"status"`
	Summary       string     `json:"summary"`
	Note          string     `json:"note"`
	RPO           string     `json:"rpo"`
	StaleAfterSec int        `json:"staleAfterSec"`
	Nodes         []NodeView `json:"nodes"`
	// Boundaries 诚实边界，直接展示在页面上（与 upgradeBoundaries 同一条做法）。
	Boundaries []string `json:"boundaries"`
	// PromoteCmd 切换命令。写一段"请手工恢复"等于没做——这里给的是真能跑的那条。
	PromoteCmd string `json:"promoteCmd"`
}

// PromoteCommand 提升备机为主机的命令（deploy/promote-standby.sh 真实存在且可 --dry-run）。
const PromoteCommand = "sudo BAIDI_STANDBY_PASSPHRASE=… /opt/baidi/bin/promote-standby.sh --dry-run   # 先干跑，确认无误后去掉 --dry-run"

// singleNote 单机形态的说明。
const singleNote = "未配置备机（当前为单机形态：1 进程 + SQLite）。控制面数据只有一份，" +
	"丢了就是丢了；如需冗余请部署温备节点（baidi-standby）或坚持做加密配置备份。"

// Boundaries 温备的诚实边界。四条都是"用的人若不知道就会做出错误决策"的那种。
//
// ★纯文本、不写 markdown 强调符：页面是 {{ b }} 原样渲染的，写了 ** 就会在界面上
// 显示成一对星号。要强调请靠句子本身的位置与措辞。
func Boundaries() []string {
	return []string{
		"温备不是双活：备机不对外提供服务，也不接管任何流量。SQLite 是单写者，" +
			"两个实例同时写同一个库会在写冲突时静默丢配置——那比没有 HA 更糟。",
		"RPO = 同步间隔（下方逐节点显示的就是备机自报的那个值），不是零丢失。" +
			"最后一次成功同步之后的配置改动，在切换时会全部丢失。",
		"切换需人工触发：跑 deploy/promote-standby.sh（校验备份 → 解开覆盖 → 起服务 → 自检）。" +
			"刻意不做自动选主——两节点没有仲裁第三方，自动选主必然脑裂，而脑裂意味着" +
			"两个控制面同时签发令牌、下发相反的策略，现场没有任何一处会显示这件事。",
		"网关侧的多活是另一件事（剖面下发有序落点清单，见 FR-ARCH-03/04）。" +
			"控制面短暂不可用时，网关按既有 fail-closed 语义在 -ttl(30s) 内自然关窗，" +
			"不会因为控制面没了就把门一直开着。",
	}
}

// evaluateNeverSeen 台账为空时的两种结论，**必须分开**。
//
// standby_nodes 的行只在备机成功连上主机 mTLS 口那一刻才建立（拉备份或回报状态）。
// 于是「运维签好了 standby- 证书、备机也在跑，但 BAIDI_MTLS_ADDR 只听回环 / 被防火墙挡了」
// 与「根本没配备机」在页面与 /diag 上此前完全同形：都是 skip「未配置备机（单机形态）」，
// 不扣健康分、不告警。而前者恰恰就是"切换那天手上没有备份"的形态。
//
// 主机侧其实有可交叉核对的事实——已签发的备机证书（CN standby-*）。有证书却没有任何
// 台账行，就是「配了但一次都没连上来」，判 warn 并把该说的话说出来。
func evaluateNeverSeen(v ClusterView, issuedCNs []string) ClusterView {
	if len(issuedCNs) == 0 {
		v.Status = "skip"
		v.Summary = "未配置备机（当前为单机形态）"
		v.Note = singleNote
		v.RPO = "—（没有备机就没有 RPO 可言：控制面数据只有一份）"
		return v
	}
	v.Status = "warn"
	v.Summary = fmt.Sprintf("已签发 %d 张备机证书（%s），但没有任何一台备机连上过主机",
		len(issuedCNs), strings.Join(issuedCNs, "、"))
	v.Note = "备机台账为空 = 主机一次都没被备机拉过备份、也没收到过回报。" +
		"这与「未配置备机」不是一回事：材料都备齐了，同步却从未发生，" +
		"盘上没有任何一份可用于切换的备份。常见成因：BAIDI_MTLS_ADDR 只监听回环、" +
		"备机到主机 mTLS 端口被防火墙挡住、备机进程未启动、证书未分发到备机。"
	v.RPO = "—（从未同步过，没有 RPO 可言）"
	return v
}

// Unsupported 后端不支持温备状态记录（纯内存演示栈）时的诚实回答。
// 与「未配置备机」区分开：前者是"这个后端记不下来"，后者是"确实没配"，
// 混成一句话会让人在演示栈上以为自己已经确认过没有备机。
func Unsupported(reason string) ClusterView {
	return ClusterView{
		Mode: ModeSingle, Status: "skip",
		Summary:    "温备状态不可判定：" + reason,
		Note:       reason + "——这里不显示「未配置备机」，那是另一件事（确实没配 vs 记不下来）。",
		RPO:        "—",
		Nodes:      []NodeView{},
		Boundaries: Boundaries(),
		PromoteCmd: PromoteCommand,
	}
}

// Unknown 读取备机状态失败时的回答：**warn 而不是 pass**。
// 读不到就说读不到——回一句"集群健康"是这套系统里最贵的那种谎。
func Unknown(reason string) ClusterView {
	return ClusterView{
		Mode: ModeSingle, Status: "warn",
		Summary:    "备机同步状态读取失败，温备是否新鲜无法判定",
		Note:       reason,
		RPO:        "—",
		Nodes:      []NodeView{},
		Boundaries: Boundaries(),
		PromoteCmd: PromoteCommand,
	}
}

// Self 主机自身的版本身份，用于与备机上那份 baidi-control 比对。
//
// ★为什么必须由调用方传进来而不是在这里读 buildinfo：Evaluate 是纯函数，
// 判定条件写反在集成环境里与"一切正常"无法区分（同 alerting.Evaluate 的理由），
// 而一个直接读进程全局的函数，测试里就永远造不出"版本不一致"这个场景。
type Self struct {
	Semver string // "" = 主机自己也未注入版本 → 一致性不可判定
	Build  string
}

// Evaluate 按主机侧登记算出集群视图。纯函数：吃快照吐结论，条件写反在集成环境里
// 与"一切正常"无法区分，只有纯函数测得住（同 alerting.Evaluate 的理由）。
//
// issuedCNs 是主机上**已签发过的备机证书 CN**（非吊销）。它只在 nodes 为空时起作用，
// 用来把「配了备机但它一次都没连上来」与「根本没配备机」区分开——见 evaluateNeverSeen。
//
// staleAfter <= 0 时取 DefaultStaleAfter。
func Evaluate(nodes []Node, now time.Time, staleAfter time.Duration, self Self, issuedCNs ...string) ClusterView {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	v := ClusterView{
		Mode: ModeSingle, StaleAfterSec: int(staleAfter / time.Second),
		Nodes: []NodeView{}, Boundaries: Boundaries(), PromoteCmd: PromoteCommand,
	}
	if len(nodes) == 0 {
		return evaluateNeverSeen(v, issuedCNs)
	}

	v.Mode, v.Deployed = ModeWarm, true
	worst, fresh, minInterval := "pass", 0, 0
	var worstNode NodeView
	var mismatched []string
	for _, n := range nodes {
		nv := evalNode(n, now, staleAfter, self)
		v.Nodes = append(v.Nodes, nv)
		if nv.IntervalSec > 0 && (minInterval == 0 || nv.IntervalSec < minInterval) {
			minInterval = nv.IntervalSec
		}
		st := "pass"
		switch {
		case nv.State != StateFresh:
			st = "warn"
		case nv.LastStatus == "fail":
			// 盘上那份还新鲜，但最近一轮同步失败了：现在没事，再失败两轮就有事。
			st = "warn"
		case nv.VersionState == VersionMismatch:
			// ★版本**确定**不一致才翻 warn；不可判定不翻（见 VersionUnknown 的注释）。
			// 切换后启动的是备机上那份 baidi-control，它读的是主机版本迁移过的库——
			// 版本对不上时最好的结局是进程起不来，最坏是起来了、库被旧版半迁回去。
			st = "warn"
		}
		if nv.VersionState == VersionMismatch {
			mismatched = append(mismatched, nv.NodeID)
		}
		if st == "pass" {
			fresh++
		} else if worst == "pass" {
			worst, worstNode = st, nv
		}
	}
	v.Status = worst
	switch {
	case worst == "pass":
		v.Summary = fmt.Sprintf("温备就绪：%d 台备机同步新鲜（最近一次落盘 %s）",
			fresh, freshestText(v.Nodes))
	case len(mismatched) > 0 && worstNode.VersionState == VersionMismatch:
		v.Summary = fmt.Sprintf("备机 %s 上的 baidi-control 是 %s，主机是 %s：切换后会跨版本恢复",
			worstNode.NodeID, worstNode.ControlSemver, self.Semver)
	case worstNode.State == StateNever:
		v.Summary = fmt.Sprintf("备机 %s 从未成功同步过：切换时手上没有可用备份", worstNode.NodeID)
	case worstNode.State == StateStale:
		v.Summary = fmt.Sprintf("备机 %s 已落后 %s（阈值 %s）",
			worstNode.NodeID, worstNode.LagText, HumanDuration(time.Duration(worstNode.ThresholdSec)*time.Second))
	default:
		v.Summary = fmt.Sprintf("备机 %s 最近一次同步失败：%s",
			worstNode.NodeID, orDash(worstNode.LastDetail))
	}
	v.Note = "温备形态：备机只保持数据新鲜，不对外提供服务；切换由人工/脚本触发（见下方命令）。"
	if minInterval > 0 {
		v.RPO = fmt.Sprintf("RPO = 同步间隔 = %s（最后一次成功同步之后的改动，切换时会丢）",
			HumanDuration(time.Duration(minInterval)*time.Second))
	} else {
		v.RPO = "RPO 尚不可判定：备机还没回报过它的同步间隔"
	}
	return v
}

// evalNode 单台备机的判定。
func evalNode(n Node, now time.Time, staleAfter time.Duration, self Self) NodeView {
	th := thresholdFor(n, staleAfter)
	nv := NodeView{
		NodeID: n.NodeID, Addr: n.Addr, IntervalSec: n.IntervalSec,
		ThresholdSec:    int(th / time.Second),
		LastSyncAt:      tsText(n.LastSyncAt),
		LastPullAt:      tsText(n.LastPullAt),
		BackupVersion:   n.BackupVersion,
		BackupCreatedAt: n.BackupCreatedAt,
		BackupSHA256:    n.BackupSHA256,
		NodeSemver:      n.NodeSemver,
		NodeBuild:       n.NodeBuild,
		ControlSemver:   n.ControlSemver,
		ControlBuild:    n.ControlBuild,
		LastStatus:      n.LastStatus,
		LastDetail:      n.LastDetail,
	}
	nv.VersionState, nv.VersionText = versionVerdict(n, self)
	if n.LastSyncAt <= 0 {
		nv.State, nv.LagSeconds = StateNever, -1
		nv.LagText = "从未成功同步"
		return nv
	}
	lag := now.Sub(time.Unix(n.LastSyncAt, 0))
	if lag < 0 {
		lag = 0 // 时钟回拨：报 0 而不是负数，"落后 -3 分钟"只会让人怀疑页面坏了
	}
	nv.LagSeconds = int64(lag / time.Second)
	nv.LagText = HumanDuration(lag)
	nv.State = StateFresh
	if lag > th {
		nv.State = StateStale
	}
	return nv
}

// versionVerdict 「切换到这台备机之后，跑起来的会是哪一版」的三态判定（wave11 行动 18）。
//
// 判据是**备机上那份 baidi-control 的语义版本**，不是 baidi-standby 自己的：
// 提升脚本最后一步 `systemctl start baidi-control` 启动的是前者，而两个二进制
// 由同一次构建产出只是部署脚本的约定，不是可核实的事实（手工替换过其中一个、
// 或上一次部署只覆盖了一半，恰恰是最该在切换前发现的形态）。
//
// ★三态里最容易被写坏的是 unknown：任一侧为空就必须停在"不可判定"，
// 绝不能让 `"" == ""` 走进 match 分支——那会把「两台机器都不知道自己是哪一版」
// 显示成「版本一致，可以切」，方向正好相反，而它恰恰是升级到本版本之前
// 所有存量部署的形态。
func versionVerdict(n Node, self Self) (string, string) {
	cur := strings.TrimSpace(self.Semver)
	got := strings.TrimSpace(n.ControlSemver)
	switch {
	case got == "" && strings.TrimSpace(n.NodeSemver) == "":
		return VersionUnknown, "备机未回报版本身份（baidi-standby 版本过旧）：" +
			"切换后会启动哪一版 baidi-control 无从判断。升级备机上的白帝交付包即可回报。"
	case got == "":
		return VersionUnknown, "备机报了自身版本（baidi-standby " + n.NodeSemver +
			"），但探不到同机 baidi-control 的版本：可能这台机器上没装它（那样提升流程最后一步会失败），" +
			"也可能它未注入版本身份。到备机上跑一次 `baidi-control -version` 即可分辨。"
	case cur == "":
		return VersionUnknown, "主机自身未注入语义版本，无法与备机的 baidi-control（" + got + "）比对。"
	case cur == got:
		return VersionMatch, "备机上的 baidi-control 与主机同为 " + cur + "。" +
			"★版本号相同不等于同一次构建：确认构建标识也一致才是真的同一批（主机 " +
			orDash(self.Build) + " / 备机 " + orDash(n.ControlBuild) + "）。"
	default:
		return VersionMismatch, "备机上的 baidi-control 是 " + got + "，主机是 " + cur +
			"：切换后那台会用 " + got + " 打开一个被 " + cur + "迁移过的库。" +
			"最好的结局是进程起不来（切换失败但数据还在），最坏是它起来了并把库按旧结构半迁回去。" +
			"切换前先把备机上的白帝交付包升到与主机同一版。"
	}
}

// thresholdFor 逐节点的落后阈值 = max(全局阈值, 3×备机自报间隔)，并封顶到 MaxStaleAfter。
//
// ★为什么按 3 轮：一次网络抖动不该把页面刷红，连续三轮拉不到才是真出事了。
// ★为什么封顶：间隔是备机自报的，一台配错（或被改过）的备机自报一个巨大的间隔，
// 就能让自己永远显示新鲜——判定材料来自被判定方时，必须给它一个它抬不过去的天花板。
func thresholdFor(n Node, staleAfter time.Duration) time.Duration {
	th := staleAfter
	if n.IntervalSec > 0 {
		if x := 3 * time.Duration(n.IntervalSec) * time.Second; x > th {
			th = x
		}
	}
	if th > MaxStaleAfter {
		th = MaxStaleAfter
	}
	return th
}

// freshestText 最新那台的落后时长文案。
func freshestText(nodes []NodeView) string {
	best := int64(-1)
	for _, n := range nodes {
		if n.LagSeconds >= 0 && (best < 0 || n.LagSeconds < best) {
			best = n.LagSeconds
		}
	}
	if best < 0 {
		return "不可判定"
	}
	return HumanDuration(time.Duration(best)*time.Second) + "前"
}

func tsText(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

func orDash(s string) string {
	if s == "" {
		return "（无详情）"
	}
	return s
}

// HumanDuration 人话时长（与控制台其余处的粒度一致：秒/分钟/小时/天）。
func HumanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1f 小时", d.Hours())
	default:
		return fmt.Sprintf("%.1f 天", d.Hours()/24)
	}
}
