package api

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"baidi.dev/control/internal/notify"
	"baidi.dev/control/internal/store"
)

// ── 审批单的消息通知（wave11 行动 17②，PRD FR-INT-20 / ch15.2）──
//
// PRD ch15.2 逐字列了消息通道的三类用途：**认证 / 告警 / 审批**。改造前告警与
// 两类安全事件（爆破锁定、终端判定转入 block）都接了线，而「审批」这一类
// **零执行方**：三处审批单的产生点一次通知都不发——
//
//	① JIT 访问申请      handlePortalCreateAccessRequest
//	② 设备准入待批      enrollReportingDevice（首次登记且 bindMethod=approval）
//	③ 外部身份准入待批  admitExternal（RequestExtAdmission 新建单子那次）
//
// 后果不是"少一封邮件"：这三张单子在**被批准之前，当事人一步也走不下去**
// （连不上资源 / 敲不开门 / 登不进来），而管理员唯一的发现途径是自己去翻审批页。
// 于是最常见的形态是"提了申请，等了一天，没人知道"。
//
// ── 发给谁：白帝没有「审批人」这个字段 ──
//
// 三类单子的处置端点（`POST /api/v1/approvals/{id}/decide`、
// `POST /api/v1/jit/requests/{id}/decide`、准入单同款）全部收在 `PermSecurity` 上，
// 所以"该收到通知的人"= **持 PermSecurity 的管理员**——执行权在哪一权，通知就发给哪一权。
// 这不是发明一个新概念，而是把已经存在的判据（requirePerm 读的那份 scope_json）
// 原样复用一次。
//
// ★但邮箱这一维是**真的可能取不到**：`users.email` 只有外部认证源带回来的账号有值
// （本地账号至今没有采集入口）。取不到时**绝不静默**——照 notify 那条既有纪律
// （发送成败都落审计、行为人 system）落一条 fail 审计说清"这条通知没送到任何人手上"，
// 而不是让它无声消失。这正是本项目反复消灭的那种形态：功能看起来接了，
// 真出事那天一条都收不到，且没有任何报错。

// approvalRecipients 一次审批通知的收件人解析结果。
//
// ★三个字段刻意分开而不是压成一个 []string：
// 「没有任何人持 security 权」与「有 3 个人但一个邮箱都没登记」是两回事，
// 补救动作分别是"去分派角色"与"去补邮箱"，审计正文必须说得出是哪一种。
// 而 Err 那一档是**不可判定**——目录读不出来时既不能说"没人"，也不能说"发出去了"。
type approvalRecipients struct {
	// Emails 已登记邮箱的、持 PermSecurity 的管理员（去重定序）。
	Emails []string
	// Admins 持 PermSecurity 的管理员总数（含没登记邮箱的）。
	Admins int
	// Err 解析过程本身失败（目录/角色读不出来）。此时 Emails/Admins 无意义。
	Err error
}

// securityApprovers 解析「谁该收到这张待批审批单」。
//
// 判据与 requirePerm 同源：`admin_roles.scope_json` 里有没有 security 权限键
// （`AdminRole.Allows`，`*` 也算）——**不是 power、也不是页面上那个中文角色名**。
//
// ★跳过 disabled 的管理员：那是显式停用的账号，他既登不进来也不该再处置审批单，
// 给他发通知只会让"发出去了"这个结论虚高。locked（临时爆破锁定）与 idle 仍计入——
// 锁定会自己解除，而闲置账号的邮箱照样收得到信。
func (s *Server) securityApprovers(ctx context.Context) approvalRecipients {
	roles, err := s.store.AdminRoles(ctx)
	if err != nil {
		return approvalRecipients{Err: err}
	}
	byKey := make(map[string]store.AdminRole, len(roles))
	for _, r := range roles {
		byKey[r.Key] = r
	}
	sys, err := s.store.System(ctx)
	if err != nil {
		return approvalRecipients{Err: err}
	}
	want := map[string]bool{}
	for _, a := range sys.Admins {
		if a.Status == "disabled" {
			continue
		}
		if role, ok := byKey[a.RoleKey]; ok && role.Allows(store.PermSecurity) {
			want[normUser(a.Account)] = true
		}
	}
	out := approvalRecipients{Admins: len(want)}
	if out.Admins == 0 {
		return out
	}
	// 邮箱只有用户目录那张表有（AdminAccount 不带 email）。
	b, err := s.store.Users(ctx)
	if err != nil {
		return approvalRecipients{Err: err}
	}
	seen := map[string]bool{}
	for _, u := range b.Users {
		if !want[normUser(u.Account)] {
			continue
		}
		if m := strings.TrimSpace(u.Email); m != "" && !seen[strings.ToLower(m)] {
			seen[strings.ToLower(m)] = true
			out.Emails = append(out.Emails, m)
		}
	}
	sort.Strings(out.Emails) // 定序：审计正文与邮件收件人不该每次换顺序
	return out
}

// notifyApprovalPending 把一张**已经创建**的待批审批单排进通知队列。
//
// what  这类单子的中文名（进主题与审计，如「JIT 访问申请」）
// who   申请人账号（进正文；审计里也要有，管理员据此定位）
// body  正文（调用方组装，只陈述已发生的事实）
//
// ★三条纪律与 notifySecurityEvent 逐字相同：不阻塞主流程（异步入队）、不带请求 ctx、
// 措辞只记已发生的事。这里额外多一条：**收件人解析结果一律留痕**——
// 通知发不出去时，那条审计是唯一能回答"为什么没人收到"的东西。
//
// ★收件人解析是三次库读（角色表 + 管理员表 + 用户目录），**同步**跑在调用方的请求上。
// 这可以接受，因为三处调用点都只在**真的新建了一张单子**那一次触发（重复提交 /
// 重复登录 / 每 15s 的 posture 保活都不会走到这里）；它绝不能挪进热路径。
func (s *Server) notifyApprovalPending(ctx context.Context, what, who, subject, body string) {
	if s.notices == nil {
		return
	}
	rcpt := s.securityApprovers(ctx)
	switch {
	case rcpt.Err != nil:
		// 不可判定：既不说"没人该收"，也不说"发出去了"。仍然照发（通道自己配的
		// 收件人还在，那一半是有效的），只是点不了名。
		slog.Error("审批通知：收件人解析失败，本条只发给消息通道自身配置的收件人",
			"类型", what, "申请人", who, "err", rcpt.Err.Error())
		s.auditBG(ctx, "security", what+"待批（申请人 "+who+
			"）：无法解析应通知的管理员（"+rcpt.Err.Error()+"），本条通知未点名任何收件人，"+
			"只发给了消息通道自身配置的收件人", "fail")
	case rcpt.Admins == 0:
		// 系统里没有任何持 security 权的管理员——这本身就是个该被看见的事实
		// （那三类审批单此刻没有任何人有权处置）。
		s.auditBG(ctx, "security", what+"待批（申请人 "+who+
			"）：系统中没有任何持「安全策略」权限的管理员，这张单子当前无人有权处置；"+
			"本条通知未点名任何收件人", "fail")
	case len(rcpt.Emails) == 0:
		// 有人有权，但一个邮箱都没登记。★这是**默认部署下最常见的一档**：
		// users.email 只有外部认证源带回来的账号有值，本地管理员至今没有采集入口。
		s.auditBG(ctx, "security", what+"待批（申请人 "+who+"）："+
			strconv.Itoa(rcpt.Admins)+" 名持「安全策略」权限的管理员均未登记邮箱，本条通知没有送到任何人手上；"+
			"请在「用户与角色」页补齐管理员邮箱，或在消息通道里配置固定收件人", "fail")
	default:
		s.auditBG(ctx, "security", what+"待批（申请人 "+who+"）：已按持「安全策略」权限的管理员派发通知（"+
			strings.Join(rcpt.Emails, "、")+"）", "ok")
	}
	// ★无论上面哪一档都照常入队：通道自身配置的收件人（组邮箱 / 值班机器人 webhook）
	// 才是多数部署真正在用的那一路，点不到名不等于该放弃这条通知。
	s.notices.Enqueue(notify.Message{
		Event: "approval-pending", Subject: subject, Body: body, To: rcpt.Emails,
	})
}
