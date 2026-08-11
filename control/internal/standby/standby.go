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
	LastStatus      string // ok | fail；"" = 从未回报
	LastDetail      string
	UpdatedAt       int64
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
	LastStatus      string `json:"lastStatus"`
	LastDetail      string `json:"lastDetail"`
}

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

// Evaluate 按主机侧登记算出集群视图。纯函数：吃快照吐结论，条件写反在集成环境里
// 与"一切正常"无法区分，只有纯函数测得住（同 alerting.Evaluate 的理由）。
//
// staleAfter <= 0 时取 DefaultStaleAfter。
func Evaluate(nodes []Node, now time.Time, staleAfter time.Duration) ClusterView {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	v := ClusterView{
		Mode: ModeSingle, StaleAfterSec: int(staleAfter / time.Second),
		Nodes: []NodeView{}, Boundaries: Boundaries(), PromoteCmd: PromoteCommand,
	}
	if len(nodes) == 0 {
		v.Status = "skip"
		v.Summary = "未配置备机（当前为单机形态）"
		v.Note = singleNote
		v.RPO = "—（没有备机就没有 RPO 可言：控制面数据只有一份）"
		return v
	}

	v.Mode, v.Deployed = ModeWarm, true
	worst, fresh, minInterval := "pass", 0, 0
	var worstNode NodeView
	for _, n := range nodes {
		nv := evalNode(n, now, staleAfter)
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
func evalNode(n Node, now time.Time, staleAfter time.Duration) NodeView {
	th := thresholdFor(n, staleAfter)
	nv := NodeView{
		NodeID: n.NodeID, Addr: n.Addr, IntervalSec: n.IntervalSec,
		ThresholdSec:    int(th / time.Second),
		LastSyncAt:      tsText(n.LastSyncAt),
		LastPullAt:      tsText(n.LastPullAt),
		BackupVersion:   n.BackupVersion,
		BackupCreatedAt: n.BackupCreatedAt,
		BackupSHA256:    n.BackupSHA256,
		LastStatus:      n.LastStatus,
		LastDetail:      n.LastDetail,
	}
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
