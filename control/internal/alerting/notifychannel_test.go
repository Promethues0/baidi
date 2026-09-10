package alerting

import (
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── wave11 行动 17①：消息通道发送失败告警（FR-SYSCFG-19）──
//
// 被修的坏形态：通道失效的**全部**信号面是系统页深处那一格 last_status 变红。
// 没有告警规则、没有 /diag 项，而爆破锁定、终端判定阻断、业务告警三条链路
// 全都压在通道上——通道一坏，页面上一切正常，管理员从此再收不到任何东西。
//
// ★这里断言的三条边界比"能报出来"更要紧，它们把「通道停用/删除」与「发送失败」
// 分开（合成一条 = 对着一次正常的运维动作报警，管理员很快就会学会忽略这条规则）：
//   - 停用的通道不产生候选；
//   - **从未发送过**的通道不产生候选（不可判定 ≠ 发不出去）；
//   - 最近一次成功的通道不产生候选。
//
// ★变异实测（含一次**逃逸**，按纪律记下来）：
//   - 去掉 `if !ch.Enabled { continue }`                 → …DisabledIsNotAFailure 红；
//   - 去掉 `if ch.LastStatus != store.NotifySendFail`    → …OKProducesNothing 与
//     …NeverSentIsUndecidable 同时红；
//   - 把它写成 `== store.NotifySendOK { continue }`      → …NeverSentIsUndecidable 红
//     （空串会被放行成"发送失败"，等于替一条还没说过话的通道编结论）。
//
// ★逃逸记录：初版把「从未发过」写成一段独立的 `if ch.LastStatus == "" { continue }`，
// 排在 `!= NotifySendFail` 之前。删掉那一段，四条用例**一条都不红**——因为
// `"" != "fail"` 恒真，后一条把它完全吞掉了，那是一段不可观测的代码。
// 处置不是"再补一条测不到的用例"，而是把两者合成一个判据、把三种取值各自的理由
// 写在那一处（见 alerting.go 里 notify_channel_fail 那段），下面三条用例分别钉住
// ""、ok、fail 三个取值的结论。

func notifyRule() store.AlertRule {
	return store.AlertRule{ID: "ar-notify", Kind: store.AlertKindNotifyChannelFail, Enabled: true}
}

func TestNotifyChannelFailProducesCandidate(t *testing.T) {
	cs := Evaluate([]store.AlertRule{notifyRule()}, Snapshot{
		Now: 1700000000,
		NotifyChannels: []store.NotifyChannel{{
			ID: "ch1", Name: "值班邮箱", Kind: "smtp", Enabled: true,
			LastStatus: store.NotifySendFail, LastDetail: "dial tcp 10.0.0.9:587: i/o timeout",
			LastEvent: "lockout", LastAt: 1699999000,
		}},
	})
	if len(cs) != 1 {
		t.Fatalf("启用中的通道最近一次发送失败必须产生一条候选，实得 %d 条", len(cs))
	}
	if cs[0].ObjectKey != "notify:ch1" {
		t.Fatalf("对象键要带通道 id（冷却按 (规则,对象) 计，少了它多条通道只剩一条），实得 %q", cs[0].ObjectKey)
	}
	// 正文必须带**后端原话**：只说"发送失败"会让管理员去猜是网络还是凭据。
	if !strings.Contains(cs[0].Detail, "i/o timeout") {
		t.Errorf("正文要转述真实错误（last_detail），实得：%s", cs[0].Detail)
	}
	// 后果要写出来：不写的话这条告警看起来只是"少一封邮件"。
	if !strings.Contains(cs[0].Detail, "不会有任何人收到通知") {
		t.Errorf("正文要说清后果（三条链路都经它外发），实得：%s", cs[0].Detail)
	}
}

func TestNotifyChannelDisabledIsNotAFailure(t *testing.T) {
	// 停用是管理员的**显式动作**（且有一条保存审计），不是故障。
	// 给它报警只会训练人忽略这条规则；「全部停用」那件事由 /diag 的消息通道项承担。
	cs := Evaluate([]store.AlertRule{notifyRule()}, Snapshot{
		Now: 1700000000,
		NotifyChannels: []store.NotifyChannel{{
			ID: "ch1", Name: "值班邮箱", Enabled: false,
			LastStatus: store.NotifySendFail, LastAt: 1699999000,
		}},
	})
	if len(cs) != 0 {
		t.Fatalf("停用的通道不该产生候选（它是显式关掉的，不是坏了），实得 %v", cs)
	}
}

func TestNotifyChannelNeverSentIsUndecidable(t *testing.T) {
	// last_status 为空 = 从未真正发过（那四列只由 api.sendVia 写）。
	// 那是**不可判定**：可能刚配好还没轮到，也可能这套部署至今一次事件都没发生。
	// 判成"失败"就是替一条还没说过话的通道编一个结论。
	cs := Evaluate([]store.AlertRule{notifyRule()}, Snapshot{
		Now:            1700000000,
		NotifyChannels: []store.NotifyChannel{{ID: "ch1", Name: "值班邮箱", Enabled: true}},
	})
	if len(cs) != 0 {
		t.Fatalf("从未发送过 = 不可判定，不产生候选，实得 %v", cs)
	}
}

func TestNotifyChannelOKProducesNothing(t *testing.T) {
	cs := Evaluate([]store.AlertRule{notifyRule()}, Snapshot{
		Now: 1700000000,
		NotifyChannels: []store.NotifyChannel{{
			ID: "ch1", Name: "值班邮箱", Enabled: true,
			LastStatus: store.NotifySendOK, LastAt: 1699999000,
		}},
	})
	if len(cs) != 0 {
		t.Fatalf("最近一次成功的通道不该产生候选，实得 %v", cs)
	}
}

// TestNotifyChannelNoChannelsProducesNothing 一条通道都没配的部署不该常年挂告警
// （与 audit_forward_fail 同一条纪律：没用这个功能就别报警）。
// 「没配通道」这件事本身由 /diag 以 skip + 写明后果的方式呈现。
func TestNotifyChannelNoChannelsProducesNothing(t *testing.T) {
	cs := Evaluate([]store.AlertRule{notifyRule()}, Snapshot{Now: 1700000000})
	if len(cs) != 0 {
		t.Fatalf("没有任何通道时不产生候选，实得 %v", cs)
	}
}
