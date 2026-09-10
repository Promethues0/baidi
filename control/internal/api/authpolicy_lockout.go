package api

import (
	"context"
	"strconv"
	"strings"

	"baidi.dev/control/internal/authpolicy"
	"baidi.dev/control/internal/store"
)

// ── 认证加严配置的防自锁闸（PRD FR-ADMIN-20，并 FR-ADMIN-16/17）──
//
// # 改造前的形态
//
// 一条 `enhance.always=true` + `secondary=["totp"]` 的策略，只要适用范围（或它是本地目录的
// 默认策略）覆盖到全部管理员，保存下去就把**所有人**永久挡在管理台之外：
//   - handleAdminLogin 与 handlePortalLogin 走同一个 secondFactor，管理台并没有"绕过策略"的口子；
//   - 一个都没注册 passkey/TOTP 的账号在这条策略下拿到的是 needEnroll，不是会话令牌；
//   - 而注册入口（/totp/enroll、webauthn 注册）都走 requireUser——**要先登录**。
//
// 于是补救路径不存在：没有任何"管理员代为录入认证器"的接口（管理员侧只有
// ResetWebauthnCredentials，那是清空），而门户「安全设置」本身也在同一堵墙后面。
// 保存回 200、策略卡显示「已启用」，下一次登录起整套系统只能停服改库。
//
// # 闸的形态
//
// 与「最后一名超管不可降权/禁用」同一族：**在写之前判、拒绝时 409 + 说清原因**。
// 判据是「保存/删除之后，是否还存在至少一名**能登进管理台、且改得动认证策略**的管理员」。
//
// 三条刻意的取舍写在各自的实现上：
//   - 差分而不是绝对（见 guardAuthPolicyLockout）：改动**之前**就没人进得来时不拦，
//     否则修好它的那一次编辑也会被拦掉；
//   - 只认持 PermSecurity 的管理员（见 consoleReachableAdmins）：一名只能读审计的
//     管理员登得进来也解不开这条策略，把他数进去等于给出一个假的安全垫；
//   - 求值按最不利于"还有退路"的方向（见 authpolicy.EvaluateLockout）：豁免不算退路，
//     非工作时段不算锁死。

// adminLoginDirectory 管理台登录在认证策略里对应的用户目录。
//
// ★必须与 handleAdminLogin 里写死的 loginCtx{Directory: "local"} 同值：管理台没有认证域
// 路由（只查本地 bcrypt 哈希），管理员账号也不允许经外部目录换会话（externalSessionCredential）。
// 这里取错值的话，authpolicy.Match 第一刀就按目录筛，闸会对着另一批策略求值，
// 得出的结论恒为"安全"——而它不报错。
const adminLoginDirectory = "local"

// guardAuthPolicyLockout 报告「把策略集换成 next 之后，会不会没有人能登进管理台」。
//
// 返回 (拒绝理由, err)：理由非空 = 该拒绝（调用方回 409）；err != nil = 判定材料读不到，
// 调用方回 500 并**不写**（fail-closed：判不出会不会锁死自己，就别动这份配置）。
//
// ★差分判定，不是绝对判定：只有「改动前还有人进得来、改动后一个都没有」才拦。
// 绝对判定会把系统卡死在一个更坏的状态——存量部署里若已经存在一条锁死全员的策略
// （本闸上线之前保存的），绝对判定会连**把它改回去**的那次保存一起拒掉，
// 而那正是唯一能把系统救回来的操作。
func (s *Server) guardAuthPolicyLockout(ctx context.Context, current, next []store.AuthPolicy, action string) (string, error) {
	sys, err := s.store.System(ctx)
	if err != nil {
		return "", err
	}
	ix, err := s.store.SubjectIndex(ctx)
	if err != nil {
		return "", err
	}
	before := s.consoleReachableAdmins(sys, current, ix)
	if len(before) == 0 {
		return "", nil
	}
	if len(s.consoleReachableAdmins(sys, next, ix)) > 0 {
		return "", nil
	}
	return s.lockoutRefusal(before, action), nil
}

// consoleReachableAdmins 在给定策略集下，还能登进管理台**并且**改得动认证策略的管理员账号。
//
// 四道判据缺一不可，顺序无关（都是且）：
//   - 账号没被禁用/锁定（handleAdminLogin 的 accountBlocked 那道闸）；
//   - 有本地口令哈希：管理台只验本地 bcrypt，外部绑定账号 pass_hash 恒空，
//     提上去也永远登不进来（guardLocalCredentialForAdmin 的理由，这里是它的镜像）；
//   - 持 PermSecurity：**登得进来 ≠ 救得了场**。认证策略的写端点是 PermSecurity，
//     只剩一名审计管理员时，系统实际已经无人能解开这条策略，闸却会以为还安全；
//   - 过得了二次认证：已注册的第二因子无条件放行（secondFactor 的前两步），
//     否则按最不利于"还有退路"的方向求值这份策略集（authpolicy.EvaluateLockout）。
func (s *Server) consoleReachableAdmins(sys store.SystemBundle, pols []store.AuthPolicy, ix store.SubjectIndex) []string {
	roles := make(map[string]store.AdminRole, len(sys.Roles))
	for _, r := range sys.Roles {
		roles[r.Key] = r
	}
	out := []string{}
	for _, a := range sys.Admins {
		if accountBlocked(a.Status) || !a.LocalPassword {
			continue
		}
		role, ok := roles[a.RoleKey]
		if !ok || !role.Allows(store.PermSecurity) {
			continue
		}
		if s.adminHasSecondFactor(a) {
			out = append(out, a.Account)
			continue
		}
		dec := authpolicy.EvaluateLockout(pols, authpolicy.Input{
			Account:    normUser(a.Account),
			Directory:  adminLoginDirectory,
			PwStrength: a.PwStrength,
			Subjects:   ix,
		})
		if !authpolicy.Blocked(dec, s.webauthnEnabled()) {
			out = append(out, a.Account)
		}
	}
	return out
}

// adminHasSecondFactor 报告该管理员已注册的第二因子里，有没有**此刻真能用**的那一种。
//
// ★passkey 要看 RP 配没配：secondFactor 的第一步整个包在 `if s.webauthnEnabled()` 里。
// 裸 IP 部署（演示站）下 RP 恒未配置，一名只注册过 passkey 的管理员在那里等同于没有第二因子——
// 把它数成"有"，闸就会放过一条真会锁死他的策略。
func (s *Server) adminHasSecondFactor(a store.AdminAccount) bool {
	for _, f := range a.Factors {
		switch f {
		case "totp":
			return true
		case "passkey":
			if s.webauthnEnabled() {
				return true
			}
		}
	}
	return false
}

// lockoutRefusal 拒绝文案。**补救路径必须真实存在**——这是本条修复的另一半：
// 登录侧原来那两句（「可联系管理员协助录入」/「请先在门户安全设置里绑定后再登录」）
// 指的都是不存在的路，见 enrollDeadEndNote 上的说明。
func (s *Server) lockoutRefusal(lost []string, action string) string {
	enroll := "TOTP"
	if s.webauthnEnabled() {
		enroll = "passkey 或 TOTP"
	}
	var b strings.Builder
	b.WriteString("拒绝" + action + "：这样改完之后，将没有任何管理员能登进管理台。")
	b.WriteString("当前还登得进来、且有权改回认证策略的管理员共 " + strconv.Itoa(len(lost)) + " 名（" +
		strings.Join(lost, "、") + "），改完之后他们全部会被抬到二次认证，而其中没有一人注册过可用的第二因子。")
	b.WriteString("注册入口（门户「安全设置」）本身要求先登录，届时谁也进不去，只能停服改库。")
	b.WriteString("请二选一后再试：① 先让上述至少一名管理员登录门户「安全设置」注册 " + enroll + "，注册完再来保存；")
	b.WriteString("② 把他们所在的组织 / 用户组移出这条策略的适用范围。")
	if !s.webauthnEnabled() {
		b.WriteString("（本部署未配置 WebAuthn RP，浏览器规范不允许裸 IP 作 RP ID，所以能注册的第二因子只有 TOTP。）")
	}
	b.WriteString("注：「可信网络 / 授信终端」豁免不算退路——它取决于管理员届时从哪台机器、" +
		"哪个网络登录，保存这一刻无从知道，因此本闸一律按不命中判。")
	return b.String()
}

// replaceAuthPolicy 把 p 并进策略集（同 id 覆盖，否则追加），得到"保存之后"的那一份。
// 传进来的 p 必须已经过 store.NormalizeAuthPolicy——id 与 priority 都参与 Match 的挑选。
func replaceAuthPolicy(pols []store.AuthPolicy, p store.AuthPolicy) []store.AuthPolicy {
	out := make([]store.AuthPolicy, 0, len(pols)+1)
	replaced := false
	for _, cur := range pols {
		if cur.ID == p.ID {
			out, replaced = append(out, p), true
			continue
		}
		out = append(out, cur)
	}
	if !replaced {
		out = append(out, p)
	}
	return out
}

// removeAuthPolicy 从策略集里摘掉 id，得到"删除之后"的那一份。
//
// ★删除同样要过闸，这不是对称性洁癖：删掉一条**宽松的**定向策略之后，原本被它命中的
// 账号会回落到该目录的默认策略（Match 先看适用范围命中者，都不命中才回落），
// 而默认策略可能更严。「删一条策略把所有人锁在门外」是真实可达的形态。
// 默认策略本身删不掉（store.DeleteAuthPolicy 带 is_default=0），那一半不必担心。
func removeAuthPolicy(pols []store.AuthPolicy, id string) []store.AuthPolicy {
	out := make([]store.AuthPolicy, 0, len(pols))
	for _, cur := range pols {
		if cur.ID == id {
			continue
		}
		out = append(out, cur)
	}
	return out
}
