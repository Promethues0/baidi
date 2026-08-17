package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 认证域路由（wave8 行动 12，FR-AUTH-09/24 + FR-USER-01/06）──
//
// 改造前 `authenticateExternal` 的做法是「遍历全部 enabled 外部源逐个 Authenticate，
// 第一个成功者胜出」。单目录部署下没有区别，但只要接第二个外部源就同时出现两个问题：
//
//	① **凭据外溢**——A 目录员工的**明文口令**会被真实投递到排在它前面的每一台
//	   LDAP 服务器去做 simple bind（本地口令输错的那一次也算，因为本地未命中就往下问）。
//	   对方的日志里就有这次 bind 尝试与它携带的用户名；口令本身虽不入日志，
//	   但它确确实实在网络上发给了一台**不该看到它的服务器**，而那台服务器可能是
//	   另一个部门、另一家供应商、甚至一个刚被接进来还没审计过的目录。
//	   这不是理论问题：登录是高频操作，每天每人若干次。
//	② **身份归属取决于配置顺序而非用户意图**——同名账号谁先配置谁认走；
//	   后建的绑定走 `base@sourceID` 后缀分裂成第二个账号，管理员在用户页看到两行，
//	   而授权只配在其中一行上。
//
// 修法就是「命中即只问该源」。**关键不变式：一次登录只把口令交给一台服务器。**

// authDomain 一个可选的认证域（登录页的目录下拉项）。
//
// ★只暴露 id/name/kind 三样。host、baseDn、issuer 这些配置细节对登录者没有用，
// 而这个端点是**免认证**的——多一个字段就是多一分组织结构的对外暴露。
type authDomain struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"` // ldap | ad | oidc
}

// errAmbiguousDirectory 配了多个外部源、又没说要用哪一个。
//
// ★这时**拒绝**而不是挨个去问：挨个问正是凭据外溢本身。
// 单源部署走不到这里（没有歧义就没有外溢面），所以这道闸只在真有风险时才出现。
type errAmbiguousDirectory struct{ domains []authDomain }

func (e *errAmbiguousDirectory) Error() string {
	names := make([]string, 0, len(e.domains))
	for _, d := range e.domains {
		names = append(names, d.Name)
	}
	return fmt.Sprintf("本系统配置了 %d 个认证域（%s），请先选择你所属的认证域再登录",
		len(e.domains), strings.Join(names, "、"))
}

// Domains 候选目录（回给前端渲染下拉）。
func (e *errAmbiguousDirectory) Domains() []authDomain { return e.domains }

// asAmbiguousDirectory 从错误链里取歧义错误（不是则回 nil）。
func asAmbiguousDirectory(err error) *errAmbiguousDirectory {
	var d *errAmbiguousDirectory
	if errors.As(err, &d) {
		return d
	}
	return nil
}

// externalDomains 列出全部**启用中的**外部认证源（本地目录不算——它不参与外部询问）。
func externalDomains(srcs []store.AuthSourceRec) []authDomain {
	out := []authDomain{}
	for _, rec := range srcs {
		if !rec.Enabled || authsrc.Kind(rec.Kind) == authsrc.KindLocal {
			continue
		}
		out = append(out, authDomain{ID: rec.ID, Name: rec.Name, Kind: rec.Kind})
	}
	return out
}

// routeDirectory 决定这次登录该问哪些源。
//
// 判定顺序（每一档都必须让「一次登录只问一台服务器」成立）：
//  1. 显式指定了 directory 且命中 → **只问它**；
//  2. 指定了但没命中 → 拒绝（不静默回退到"问全部"——那正是要消灭的外溢，
//     而且用户明明表达了意图，替他改成另一个意思比报错糟得多）；
//  3. 没指定、只有一个启用中的外部源 → 问它（没有歧义就没有外溢面，
//     单目录部署因此完全不受影响，老客户端照常工作）；
//  4. 没指定、有多个 → 拒绝并把候选列表带回去，让前端渲染下拉。
//
// 返回的切片长度恒 ≤1：这是本函数存在的全部意义，别改成可能返回多个。
func routeDirectory(srcs []store.AuthSourceRec, directory string) ([]store.AuthSourceRec, error) {
	enabled := []store.AuthSourceRec{}
	for _, rec := range srcs {
		if !rec.Enabled || authsrc.Kind(rec.Kind) == authsrc.KindLocal {
			continue
		}
		enabled = append(enabled, rec)
	}
	// ★显式指定的判定必须排在「一个可用源都没有」之前。反过来的话，
	// 用户明明点了某个认证域、而它恰好被停用了 → 静默返回"没有源可问" →
	// 登录链路一路走到「用户名或密码错误」。他会反复确认自己的口令，
	// 而真正的原因是那个域被管理员停了，没有任何地方说得出来。
	if d := strings.TrimSpace(directory); d != "" {
		for _, rec := range enabled {
			// 按 id 匹配。**不按 kind 匹配**：两条 ldap 源的 kind 一样，
			// 按 kind 路由等于在两台服务器之间随机挑一台，外溢照旧。
			if strings.EqualFold(rec.ID, d) {
				return []store.AuthSourceRec{rec}, nil
			}
		}
		return nil, fmt.Errorf("认证域 %q 不存在或已停用", d)
	}
	if len(enabled) == 0 {
		return nil, nil
	}
	if len(enabled) == 1 {
		return enabled, nil
	}
	return nil, &errAmbiguousDirectory{domains: externalDomains(srcs)}
}

// handleAuthDomains GET /api/v1/auth/domains —— **免认证**：登录页要在登录之前拿到它。
//
// ★暴露面权衡：这确实把「本系统接了哪几个目录」的名字告诉了匿名访问者。
// 权衡下来接受——登录页的域下拉是通行做法，而替代方案（不给下拉、让用户猜）
// 会把多目录部署逼回「挨个试」，也就是把凭据外溢从服务端搬到用户手上。
// 只暴露 id/name/kind，不含任何连接细节。
//
// **只有 ≥2 个外部源时才回非空列表**：单源部署没有选择的必要，
// 也就没有必要把那一个目录的名字告诉匿名访问者。
func (s *Server) handleAuthDomains(w http.ResponseWriter, r *http.Request) {
	as := s.authSrcStore()
	if as == nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"domains": []authDomain{}})
		return
	}
	srcs, err := as.AuthSources(r.Context())
	if err != nil {
		// 读失败回空：登录页据此不显示下拉，用户仍可按单目录方式登录。
		// 这里不该 500——目录列表拿不到不代表登录不可用。
		httpx.JSON(w, http.StatusOK, map[string]any{"domains": []authDomain{}})
		return
	}
	list := externalDomains(srcs)
	if len(list) < 2 {
		list = []authDomain{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"domains": list})
}

// ensureDirectoryContext 断言路由结果满足「一次登录只问一台服务器」。
//
// ★**只有测试在调它**，这是有意的：它是本行动那条核心不变式的可执行表述。
// 写成函数而不是散在用例里的 len() 判断，是为了让下一个改 routeDirectory 的人
// 一眼看见这条约束的名字——别把它当死代码删掉。
func ensureDirectoryContext(_ context.Context, picked []store.AuthSourceRec) bool {
	return len(picked) <= 1
}
