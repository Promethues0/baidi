// routeguard_test.go 全部路由的负向鉴权守卫。
//
// 背景：授权面审计发现四条 GET 端点（/apps /overview /security /authpolicy）一道闸都
// 没有——任何 role=user 甚至 role=gateway 令牌都读得到应用后端地址、攻击源 IP、全部
// 安全基线与认证策略里的可信网段 CIDR。同时 103 条写路由里 37 条零负向鉴权用例。
// 逐条手写用例的问题是**清单会腐烂**：新加一条路由漏了闸，没有任何东西会红。
//
// 本守卫用 go/ast 解析 api.go 里 (*Server).Routes 的源码，把每一条
// `mux.HandleFunc("METHOD /path", …)` 注册都拿出来，用 role=user 与 role=gateway 两种
// 令牌各打一次，要求：
//   - 不在例外清单里的路由 → **必须 403**（新加的写路由/读路由漏了闸，CI 当场红）；
//   - 在例外清单里的路由 → **必须不是 403**，且清单条目必须是真实存在的路由
//     （只测拒绝的话，一个把所有人都拒掉的实现也能全绿；清单条目悬空则是清单腐烂）。
//
// 例外清单逐条写理由。往里加一条之前先问：这条路由是不是本来就该给非管理员用？
// 答案是「是」的只有三类——免认证的登录/票据/公开分发端点、requireUser 的自助端点、
// 网关数据面接口（compat 明文口）。
package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// nonAdminAllowedForUser role=user（门户普通账号）令牌**不该**被 403 的路由。
//
// 键是 Routes 里逐字注册的 pattern。值是理由，空理由视为清单条目无效。
var nonAdminAllowedForUser = map[string]string{
	// ── 免认证（IsOpen 白名单 / 中间件放行，身份由 handler 内票据或口令自证）──
	"GET /healthz":                         "健康检查，免认证",
	"GET /api/v1/meta":                     "产品元信息（版本号），免认证",
	"POST /api/v1/auth/login":              "管理台登录：拿到令牌之前",
	"POST /api/v1/portal/login":            "门户登录：拿到令牌之前",
	"GET /api/v1/auth/domains":             "登录页认证域候选（≥2 源才回非空，只含 id/name/kind），免认证",
	"GET /api/v1/auth/oidc/providers":      "登录页 OIDC 按钮清单，免认证",
	"GET /api/v1/auth/oidc/{id}/authorize": "OIDC 授权跳转，发生在拿到任何令牌之前",
	"GET /api/v1/auth/oidc/{id}/callback":  "OIDC 回调，发生在拿到任何令牌之前",
	"POST /api/v1/auth/oidc/session":       "OIDC 交接票据换会话，票据在 handler 内强校验",
	"POST /api/v1/webauthn/login/begin":    "passkey 登录第二回合，mfaTicket 在 handler 内强校验",
	"POST /api/v1/webauthn/login/finish":   "passkey 登录第二回合，mfaTicket 在 handler 内强校验",
	"POST /api/v1/auth/totp":               "TOTP 登录第二回合，mfaTicket 在 handler 内强校验",
	"GET /api/v1/portal/downloads":         "客户端下载清单，免认证（公开分发）",
	"GET /downloads/{file}":                "客户端安装包分发，免认证（白名单校验在 handler 内）",
	// ── 任意已登录身份 ──
	"GET /api/v1/auth/me":       "看自己的身份；角色段只对完整会话令牌下发（现算）",
	"GET /api/v1/client/update": "终端检查更新：灰度判定在服务端，任意登录身份可查自己平台的版本",
	// ── requireUser 自助端点（门户 / 桌面 / 移动客户端的终端用户面）──
	"POST /api/v1/knock-token":                 "为自己签一张短时效敲门令牌（五道闸在 handler 内）",
	"POST /api/v1/posture":                     "终端上报自己的合规状态",
	"POST /api/v1/portal/access-requests":      "JIT：为自己发起访问申请",
	"GET /api/v1/portal/access-requests":       "JIT：看自己的申请",
	"POST /api/v1/webauthn/register/begin":     "注册自己的 passkey",
	"POST /api/v1/webauthn/register/finish":    "注册自己的 passkey",
	"GET /api/v1/webauthn/credentials":         "看自己的 passkey",
	"DELETE /api/v1/webauthn/credentials/{id}": "删自己的 passkey（只删得到自己账号下的）",
	"GET /api/v1/totp":                         "看自己的 TOTP 绑定状态",
	"POST /api/v1/totp/enroll":                 "为自己注册 TOTP",
	"POST /api/v1/totp/confirm":                "确认自己的 TOTP 注册",
	"POST /api/v1/totp/disable":                "解绑自己的 TOTP（须出示当前验证码）",
	"POST /api/v1/auth/password":               "自助改密",
	"GET /api/v1/client/profile":               "客户端接入剖面：按自己的授权裁剪，不是授权凭据",
	"GET /api/v1/portal/apps":                  "门户磁贴：按自己的授权裁剪（管理台的 GET /apps 才是全量）",
	"POST /api/v1/portal/web-ticket":           "为自己换一张 B/S 访问票据（按资源鉴权后才发）",
}

// nonAdminAllowedForGateway role=gateway 令牌**不该**被 403 的路由。
//
// 网关身份只服务数据面：除免认证端点与 compat 明文口上的两条网关接口外，一切都该 403——
// 包括 requireUser 的自助端点（宽权长效的 gateway 令牌不得伪造访问申请 / 敲门令牌）。
var nonAdminAllowedForGateway = map[string]string{
	"GET /healthz":                         "健康检查，免认证",
	"GET /api/v1/meta":                     "产品元信息，免认证",
	"POST /api/v1/auth/login":              "免认证登录端点（携带令牌也不看）",
	"POST /api/v1/portal/login":            "免认证登录端点",
	"GET /api/v1/auth/domains":             "免认证",
	"GET /api/v1/auth/oidc/providers":      "免认证",
	"GET /api/v1/auth/oidc/{id}/authorize": "免认证",
	"GET /api/v1/auth/oidc/{id}/callback":  "免认证",
	"POST /api/v1/auth/oidc/session":       "票据自证，免 Bearer",
	"POST /api/v1/webauthn/login/begin":    "mfaTicket 自证，免 Bearer",
	"POST /api/v1/webauthn/login/finish":   "mfaTicket 自证，免 Bearer",
	"POST /api/v1/auth/totp":               "mfaTicket 自证，免 Bearer",
	"GET /api/v1/portal/downloads":         "免认证公开分发",
	"GET /downloads/{file}":                "免认证公开分发",
	"GET /api/v1/auth/me":                  "看自己的身份（对 gateway 只回 sub/role，无角色段）",
	"GET /api/v1/client/update":            "任意登录身份可查更新；网关拿不到比它平台名更多的东西",
	// compat 明文口：默认 false，测试服务器显式开着（New 最后一个参数），
	// 生产形态下这两条只挂 mTLS 监听、按客户端证书 CN 放行，见 mtls.go。
	"POST /api/v1/gateways/register": "网关数据面注册（requireGateway；user 令牌照样 403）",
	"GET /api/v1/gateways/policy":    "网关数据面拉策略（requireGateway；user 令牌照样 403）",
}

// TestEveryRouteRejectsNonAdminUnlessListed 双向守卫：
//
//	Routes 里的每条注册 ∖ 例外清单 → role=user / role=gateway 必 403；
//	例外清单 ⊆ Routes 且每条对相应角色必**不**是 403。
func TestEveryRouteRejectsNonAdminUnlessListed(t *testing.T) {
	routes := parseRegisteredRoutes(t)
	if len(routes) < 100 {
		t.Fatalf("只解析到 %d 条路由——守卫自身失效，请检查 parseRegisteredRoutes 对 Routes 源码的解析", len(routes))
	}
	for _, must := range []string{"GET /api/v1/apps", "POST /api/v1/resources", "POST /api/v1/pki/gateway-certs", "DELETE /api/v1/apps/{id}"} {
		if !routes[must] {
			t.Fatalf("解析结果缺少已知路由 %q——守卫自身失效", must)
		}
	}

	t.Logf("守卫覆盖 %d 条注册路由（含 compat 分支）", len(routes))
	h := newTestServer(t)
	// li.fang 是种子里的 active 普通用户：用真实存在的账号，让自助端点走到 handler 里
	// 而不是被「账号不存在」拦成另一种 403，把「该放行的没被放行」蒙混过去。
	roles := []struct {
		name    string
		token   string
		allowed map[string]string
	}{
		{"user", userToken("li.fang"), nonAdminAllowedForUser},
		{"gateway", gatewayToken(), nonAdminAllowedForGateway},
	}

	var keys []string
	for k := range routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, role := range roles {
		// 方向二·上半：清单条目必须是真实路由，且理由非空（清单腐烂 / 拼写漂移当场报）。
		for pat, why := range role.allowed {
			if strings.TrimSpace(why) == "" {
				t.Errorf("[%s] 例外清单 %q 没有写理由", role.name, pat)
			}
			if !routes[pat] {
				t.Errorf("[%s] 例外清单里的 %q 不是 Routes 里注册的路由（已删除或改名？请同步清单）", role.name, pat)
			}
		}
		for _, pat := range keys {
			method, path := splitPattern(pat)
			methods := []string{method}
			if method == "" {
				// 无方法前缀的注册对所有方法生效（目前只有 /api/v1/standby/ 的明文口显式 403）。
				methods = []string{http.MethodGet, http.MethodPost}
			}
			for _, m := range methods {
				code, out := doJSON(t, h, m, fillPlaceholders(path), role.token, nil)
				_, exempt := role.allowed[pat]
				switch {
				case !exempt && code != http.StatusForbidden:
					t.Errorf("[%s] %s %s 应 403，得 %d: %v ——这条路由对非管理员开放了。若这是有意的，把它加进 %s 的例外清单并写明理由",
						role.name, m, path, code, out, exemptListName(role.name))
				case exempt && code == http.StatusForbidden:
					t.Errorf("[%s] %s %s 在例外清单里（%s），却回了 403: %v ——要么闸加错了地方，要么这条例外该删",
						role.name, m, path, role.allowed[pat], out)
				}
			}
		}
	}
}

func exemptListName(role string) string {
	if role == "gateway" {
		return "nonAdminAllowedForGateway"
	}
	return "nonAdminAllowedForUser"
}

// parseRegisteredRoutes 从 api.go 的 (*Server).Routes 源码里解析出全部
// mux.HandleFunc 的 pattern（含 gwPlaintextCompat 分支里的两条——测试服务器开着 compat）。
//
// 只看 Routes 一个函数：mtls.go 的 MTLSHandler 另起一套 mux、按客户端证书 CN 放行，
// 不是本守卫的对象（它没有"非管理员令牌"这个概念）。
func parseRegisteredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "api.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 api.go: %v", err)
	}
	routes := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Routes" || fn.Recv == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// ★两条自检，防止注册从守卫视野里消失（守卫只认 mux.HandleFunc("字面量", …)）：
			//   (a) mux.Handle / mux.ServeHTTP 之类的非 HandleFunc 调用——mux.Handle 注册的路由
			//       这里解析不到，等于一条路由在守卫眼里不存在；
			//   (b) 把 mux 当实参传给别的函数（如 s.registerFoo(mux)）——注册发生在另一个函数体里，
			//       同样解析不到。两种都是「守卫照旧全绿、覆盖面悄悄缩水」的形态，必须当场红。
			for _, arg := range call.Args {
				if id, ok := arg.(*ast.Ident); ok && id.Name == "mux" {
					t.Errorf("Routes 里把 mux 当实参传给了别的函数（%s）：那里面的注册守卫看不到，请把注册留在 Routes 函数体内或扩展解析",
						fset.Position(call.Pos()))
				}
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "mux" {
				return true
			}
			if sel.Sel.Name != "HandleFunc" {
				t.Errorf("Routes 里出现了 mux.%s（%s）：守卫只解析 mux.HandleFunc，这条注册会从负向鉴权覆盖里消失，请改用 HandleFunc 或扩展解析",
					sel.Sel.Name, fset.Position(call.Pos()))
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				// 形如 "GET "+standby.PathBackup 的拼接只出现在 mtls.go；Routes 里出现就该显式处理。
				t.Errorf("Routes 里出现了非字面量 pattern（%s），守卫解析不到它，请改成字面量或扩展解析", fset.Position(call.Args[0].Pos()))
				return true
			}
			routes[strings.Trim(lit.Value, "\"")] = true
			return true
		})
	}
	return routes
}

// splitPattern "METHOD /path" → (METHOD, /path)；无方法前缀时 METHOD 为空。
func splitPattern(pat string) (string, string) {
	if i := strings.IndexByte(pat, ' '); i > 0 && !strings.HasPrefix(pat, "/") {
		return pat[:i], pat[i+1:]
	}
	return "", pat
}

var placeholderRe = regexp.MustCompile(`\{[^}]+\}`)

// fillPlaceholders 把 {id}/{key}/{account}… 填成占位值：闸排在路径参数解析之前，
// 目标存不存在不影响 403 判定；例外清单里的自助端点对不存在的目标回 404/400 而非 403。
func fillPlaceholders(path string) string {
	return placeholderRe.ReplaceAllString(path, "probe")
}
