package api

import (
	"context"
	"fmt"

	"baidi.dev/control/internal/store"
)

// ── /diag：消息通道（wave11 行动 17①，PRD FR-SYSCFG-19）──

// checkNotifyChannels 报告「安全事件真发生时，通知到底发不发得出去」。
//
// ★改造前这件事的全部信号面是**系统页深处那一格 last_status 变红**：没有告警规则、
// 没有 /diag 项，进程日志里那行 slog.Error 也没人盯。而爆破锁定、终端判定阻断、
// 业务告警三条链路全都压在通道上——通道一坏，页面上一切正常，而管理员从此
// 再收不到任何东西。
//
// ★四种处境必须**分开**呈现，它们的下一步动作完全不同。这也是「通道停用/删除
// 与发送失败不是一回事」这条纪律在体检面上的落点：
//
//	一条都没配        skip  没用这个功能（与 checkNAT 同档），但 summary 要写明后果
//	配了、但全部停用  warn  **不是故障**（管理员显式关的、且已有保存审计），
//	                        可后果与"坏了"一样：既不能判 pass，也不能像"没配过"那样 skip
//	启用中、从未发过  warn  不可判定：没有任何证据说它能用（照 checkAuditForward 的 never 档）
//	启用中、最近失败  fail  真·发不出去
//
// 告警规则 notify_channel_fail 只覆盖最后一档（它要能被处置、有冷却期）；
// 中间两档没有"事件"可言，只适合体检式呈现。
func (s *Server) checkNotifyChannels(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "notify", Category: "system", Name: "消息通道（安全事件通知）"}
	ns, ok := s.store.(notifyStore)
	if !ok {
		c.Status = "skip"
		c.Summary = "当前存储后端不支持消息通道（纯内存演示栈）"
		return c
	}
	chans, err := ns.NotifyChannels(ctx)
	if err != nil {
		// 读不出来是**不可判定**，不是"没有通道"：判 warn 并转述后端原话。
		c.Status = "warn"
		c.Summary = "读消息通道清单失败：" + err.Error()
		c.Hint = "这一项判不出来，不代表通道有问题；先排查管理库可读性"
		return c
	}
	if len(chans) == 0 {
		c.Status = "skip"
		c.Summary = "尚未配置任何消息通道：爆破锁定、终端判定阻断、业务告警都只会留在控制台与审计里，不会通知到任何人"
		c.Metric = "已配 0 个"
		c.Hint = "如需外发：系统 → 消息通道，新建 SMTP / webhook 通道并点一次「测试」"
		return c
	}
	live, failing, never := 0, 0, 0
	items := make([]DiagItem, 0, len(chans))
	for _, ch := range chans {
		it := DiagItem{Label: ch.Name + "（" + ch.Kind + "）"}
		switch {
		case !ch.Enabled:
			// ★停用**不算失败**：这是管理员的显式动作，且它已经有一条保存审计。
			// 但也不能当成正常——这条通道此刻不参与任何派发，如实说出来。
			it.Status, it.Value = "warn", "已停用：不参与任何事件派发"
		case ch.LastStatus == "":
			live++
			never++
			it.Status, it.Value = "warn", "启用中，但从未发送过——还没有任何证据说它能用"
		case ch.LastStatus == store.NotifySendFail:
			live++
			failing++
			it.Status = "fail"
			it.Value = "最近一次（" + tsText(ch.LastAt) + "，事件 " + orElse(ch.LastEvent, "—") +
				"）失败：" + orElse(ch.LastDetail, "—")
		default:
			live++
			it.Status = "pass"
			it.Value = "最近一次成功 " + tsText(ch.LastAt) + "（" + orElse(ch.LastDetail, "—") + "）"
		}
		items = append(items, it)
	}
	c.Items = items
	c.Metric = fmt.Sprintf("已配 %d 个 · 启用 %d · 失败 %d", len(chans), live, failing)
	if s.notices != nil {
		if d := s.notices.Dropped(); d > 0 {
			// 队列溢出是**真实**的丢弃计数：管理员没收到通知时，它区分
			// 「压根没触发」与「触发了但队列满了没发出去」。
			c.Metric += fmt.Sprintf(" · 队列溢出丢弃 %d 条", d)
		}
	}
	switch {
	case failing > 0:
		c.Status = "fail"
		c.Summary = fmt.Sprintf("%d 条启用中的通道最近一次发送失败：安全事件此刻通知不出去", failing)
		c.Hint = "到「系统 → 消息通道」点一次「测试」拿真实错误；告警规则「消息通道发送失败」会持续报这一条"
	case live == 0:
		c.Status = "warn"
		c.Summary = fmt.Sprintf("已配 %d 条通道但全部停用：安全事件不会通知到任何人（这是显式关掉的，不是故障）", len(chans))
		c.Hint = "确认是有意为之；否则在消息通道页把需要的那条重新启用"
	case never > 0:
		// ★不判 pass：一条从没发过的通道不构成"通知链路正常"的证据。
		c.Status = "warn"
		c.Summary = fmt.Sprintf("%d 条启用中的通道从未发送过，通知是否真的送得出去还没有证据", never)
		c.Hint = "在消息通道页点一次「测试」——它是真发一条，结果就落进这一格"
	default:
		c.Status = "pass"
		c.Summary = fmt.Sprintf("%d 条启用中的通道最近一次发送均成功", live)
	}
	return c
}
