package standby

import (
	"strings"
	"testing"
	"time"
)

// 温备节点的版本一致性（wave11 行动 18-③）。
//
// 改造前温备**整个不在版本一致性视野里**：控制面不知道备机上那份 baidi-control 是哪一版，
// 而升级页的边界文案还断言「温备节点上没有需要升级的服务端进程」——那句话是错的
// （备机上跑着 baidi-standby，还装着提升后真正会被启动的 baidi-control）。
//
// 判据必须是**备机上那份 baidi-control 的语义版本**，不是 baidi-standby 自己的：
// 提升脚本最后一步 `systemctl start baidi-control` 启动的是前者。

func freshNode(mut func(*Node)) Node {
	n := Node{
		NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600,
		LastSyncAt: now.Add(-time.Minute).Unix(), LastPullAt: now.Add(-time.Minute).Unix(),
		LastStatus: "ok", BackupVersion: "0.3.0",
	}
	if mut != nil {
		mut(&n)
	}
	return n
}

// TestVersionMismatchFlipsClusterToWarn 备机上的 baidi-control 与主机不同版：
// 同步再新鲜也要 warn，因为切换那天它会用旧版打开一个被新版迁移过的库。
//
// ★变异检验：把 Evaluate 里 `case nv.VersionState == VersionMismatch: st = "warn"`
// 那一行删掉，这条立刻红在 status 那一行。
func TestVersionMismatchFlipsClusterToWarn(t *testing.T) {
	n := freshNode(func(n *Node) {
		n.NodeSemver, n.ControlSemver = "0.3.0", "0.3.0"
	})
	v := Evaluate([]Node{n}, now, 15*time.Minute, Self{Semver: "0.4.0"})
	if v.Status != "warn" {
		t.Fatalf("备机 baidi-control 0.3.0 vs 主机 0.4.0，应判 warn，得到 %q", v.Status)
	}
	nv := v.Nodes[0]
	if nv.VersionState != VersionMismatch {
		t.Fatalf("应判 mismatch，得到 %q", nv.VersionState)
	}
	if !strings.Contains(nv.VersionText, "0.3.0") || !strings.Contains(nv.VersionText, "0.4.0") {
		t.Errorf("文案要把两边的版本都说出来：%q", nv.VersionText)
	}
	if !strings.Contains(v.Summary, "standby-1") {
		t.Errorf("摘要要点名是哪台备机：%q", v.Summary)
	}
	// 同步本身是新鲜的：不能因为版本不一致就把落后状态也说反。
	if nv.State != StateFresh {
		t.Errorf("版本不一致与同步新鲜是两回事，State 应仍是 fresh：%q", nv.State)
	}
}

// TestVersionUnknownDoesNotFlipStatus 不可判定**不翻状态**，但必须如实说出来。
//
// 这是与 mismatch 刻意的区别：升级到本版本之前的所有存量部署都是"备机不报版本"的形态，
// 把它当告警会让每一套部署在升级当天集体变黄，而那不是一件新发生的坏事。
// 但它也绝不能被显示成"一致"——那才是真正危险的方向。
func TestVersionUnknownDoesNotFlipStatus(t *testing.T) {
	cases := []struct {
		name string
		node Node
		self Self
		want string // VersionText 里必须出现的关键词
	}{
		{"旧备机什么都不报", freshNode(nil), Self{Semver: "0.4.0"}, "未回报版本身份"},
		{"报了自身但探不到同机 control",
			freshNode(func(n *Node) { n.NodeSemver = "0.4.0" }), Self{Semver: "0.4.0"}, "探不到"},
		{"主机自己也没注入版本",
			freshNode(func(n *Node) { n.NodeSemver, n.ControlSemver = "0.4.0", "0.4.0" }),
			Self{}, "主机自身未注入"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Evaluate([]Node{c.node}, now, 15*time.Minute, c.self)
			if v.Status != "pass" {
				t.Fatalf("不可判定不该把集群翻黄（那会让每套存量部署升级当天集体变色）：%q / %q",
					v.Status, v.Summary)
			}
			nv := v.Nodes[0]
			if nv.VersionState != VersionUnknown {
				t.Fatalf("应判 unknown，得到 %q", nv.VersionState)
			}
			if !strings.Contains(nv.VersionText, c.want) {
				t.Errorf("文案要说清是哪一种不可判定（三种的处置完全不同）：%q", nv.VersionText)
			}
		})
	}
}

// TestEmptyVersusEmptyIsNotAMatch 最容易写坏的那一处：`"" == ""` 不算一致。
//
// 两台机器都不知道自己是哪一版时，页面若显示「版本一致，可以切」，
// 方向正好与事实相反——而这恰恰是升级到本版本之前所有存量部署的形态。
func TestEmptyVersusEmptyIsNotAMatch(t *testing.T) {
	n := freshNode(nil) // 四项版本字段全空
	v := Evaluate([]Node{n}, now, 15*time.Minute, Self{})
	if got := v.Nodes[0].VersionState; got != VersionUnknown {
		t.Fatalf("两边都空必须停在 unknown，得到 %q", got)
	}
	if strings.Contains(v.Nodes[0].VersionText, "同为") {
		t.Errorf("不许把「都不知道」说成「一致」：%q", v.Nodes[0].VersionText)
	}
}

// TestVersionMatchStillWarnsAboutBuildID 版本号相同 ≠ 同一次构建。
//
// 同一个 0.4.0 可以被构建一百次，其中九十九次含着不同的代码（含 schema 迁移）。
// 「一致」那句话必须把构建标识一并摆出来，否则它是一句过度自信的结论。
func TestVersionMatchStillWarnsAboutBuildID(t *testing.T) {
	n := freshNode(func(n *Node) {
		n.NodeSemver, n.ControlSemver = "0.4.0", "0.4.0"
		n.ControlBuild = "aaaaaaa · 2026-09-01T00:00:00Z"
	})
	v := Evaluate([]Node{n}, now, 15*time.Minute,
		Self{Semver: "0.4.0", Build: "bbbbbbb · 2026-09-10T00:00:00Z"})
	if v.Status != "pass" {
		t.Fatalf("版本一致时不该翻黄：%q", v.Status)
	}
	nv := v.Nodes[0]
	if nv.VersionState != VersionMatch {
		t.Fatalf("应判 match，得到 %q", nv.VersionState)
	}
	for _, want := range []string{"aaaaaaa", "bbbbbbb"} {
		if !strings.Contains(nv.VersionText, want) {
			t.Errorf("一致的结论里必须并列两侧的构建标识（版本号相同不等于同一次构建）：%q", nv.VersionText)
		}
	}
}

// TestJudgedOnControlBinaryNotStandbyBinary 判据是备机上那份 **baidi-control**，
// 不是 baidi-standby 自己。
//
// 现实形态：上一次部署只覆盖了 baidi-standby、没覆盖 baidi-control（或反过来）。
// 拿 baidi-standby 的版本去比，这台机器会显示"一致"，而切换那天启动的是旧版控制面。
func TestJudgedOnControlBinaryNotStandbyBinary(t *testing.T) {
	n := freshNode(func(n *Node) {
		n.NodeSemver = "0.4.0"    // 同步进程已经升到新版
		n.ControlSemver = "0.3.0" // 而真正会被启动的那个还是旧版
	})
	v := Evaluate([]Node{n}, now, 15*time.Minute, Self{Semver: "0.4.0"})
	if v.Nodes[0].VersionState != VersionMismatch {
		t.Fatalf("判据必须是 ControlSemver：baidi-standby 已是 0.4.0 但 baidi-control 还是 0.3.0，"+
			"得到 %q", v.Nodes[0].VersionState)
	}
}

// TestMismatchOnOneNodeDoesNotHideOthers 多台备机时逐台判，结论不互相掩盖。
func TestMismatchOnOneNodeDoesNotHideOthers(t *testing.T) {
	good := freshNode(func(n *Node) {
		n.NodeID = "standby-a"
		n.NodeSemver, n.ControlSemver = "0.4.0", "0.4.0"
	})
	bad := freshNode(func(n *Node) {
		n.NodeID = "standby-b"
		n.NodeSemver, n.ControlSemver = "0.4.0", "0.3.0"
	})
	v := Evaluate([]Node{good, bad}, now, 15*time.Minute, Self{Semver: "0.4.0"})
	if v.Status != "warn" {
		t.Fatalf("有一台不一致就该 warn：%q", v.Status)
	}
	byID := map[string]NodeView{}
	for _, nv := range v.Nodes {
		byID[nv.NodeID] = nv
	}
	if byID["standby-a"].VersionState != VersionMatch {
		t.Errorf("好的那台不该被连坐：%+v", byID["standby-a"])
	}
	if byID["standby-b"].VersionState != VersionMismatch {
		t.Errorf("坏的那台要判出来：%+v", byID["standby-b"])
	}
}
