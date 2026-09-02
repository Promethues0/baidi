package api

import (
	"net/http"
	"testing"
)

// 四条曾经**一道闸都没有**的管理台读端点：/apps、/overview、/security、/authpolicy。
//
// 改造前任何 role=user（门户普通账号）甚至 role=gateway 令牌都读得到：
//   - /apps        全部应用的后端地址 / 发布形态 / 关联资源 id / 已授权账号；
//   - /overview    攻击源 TOP（源 IP 明文）+ 三条防线判定计数；
//   - /security    全部安全基线（检查项 / 处置档 / 适用组织与用户组）+ 主体候选；
//   - /authpolicy  全部认证策略，含 trustedNetwork 可信网段 CIDR 与豁免条件。
//
// 消费方核对（写进用例是为了下次有人想放宽时先看见这段）：console 里这四条只被
// 管理台视图（Apps / GlobalSearch / Overview / BigScreen / Security / Auth）调用，
// 门户磁贴走 GET /portal/apps，桌面 / 移动 / 鸿蒙客户端零命中；/screen 大屏在
// console router 里对 role=user 一律重定向回 /portal/apps。故按「读端点 = 任意管理员
// 现算角色」收口（requireAdmin），不需要按角色裁字段。
//
// 三向断言：user 403 / gateway 403 / 管理员 200——只测拒绝的话，一个把所有人都拒掉
// 的实现也能全绿（参见 adminrbac_test.go 文件头）。
func TestSensitiveReadEndpointsRequireAdmin(t *testing.T) {
	h := newTestServer(t)
	// li.fang 是种子里的 active 普通用户：用真实存在的账号，排除「账号不存在」这类
	// 别的 403 来源把断言蒙混过去的可能。
	user := userToken("li.fang")
	gw := gatewayToken()
	adm := adminToken()

	paths := []string{
		"/api/v1/apps",
		"/api/v1/overview",
		"/api/v1/security",
		"/api/v1/authpolicy",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			if code, out := doJSON(t, h, "GET", p, user, nil); code != http.StatusForbidden {
				t.Errorf("role=user 读 %s 应 403，得 %d: %v", p, code, out)
			}
			if code, out := doJSON(t, h, "GET", p, gw, nil); code != http.StatusForbidden {
				t.Errorf("role=gateway 读 %s 应 403，得 %d: %v", p, code, out)
			}
			if code, out := doJSON(t, h, "GET", p, adm, nil); code != http.StatusOK {
				t.Errorf("管理员读 %s 应 200，得 %d: %v", p, code, out)
			}
		})
	}
}

// 读闸吃的是「角色现算」而不是令牌快照：撤销管理员身份后旧令牌立刻读不到这四条。
// 与 TestRemovedAdminLosesReadEndpointsImmediately 同款，只是对象换成本批补闸的端点——
// 用 requireAdmin 而不是自己比对 c.Role 的价值就在这里，少了这条它与「只看令牌」无法区分。
func TestSensitiveReadEndpointsFollowLiveAdminRole(t *testing.T) {
	h := newTestServer(t)
	tok := makeAdmin(t, h, "reader.admin", "audit")

	for _, p := range []string{"/api/v1/apps", "/api/v1/overview", "/api/v1/security", "/api/v1/authpolicy"} {
		if code, out := doJSON(t, h, "GET", p, tok, nil); code != http.StatusOK {
			t.Fatalf("在任管理员读 %s 应 200，得 %d: %v", p, code, out)
		}
	}
	if code, out := doJSON(t, h, "DELETE", "/api/v1/admins/reader.admin", adminToken(), nil); code != http.StatusOK {
		t.Fatalf("撤销管理员 http %d: %v", code, out)
	}
	for _, p := range []string{"/api/v1/apps", "/api/v1/overview", "/api/v1/security", "/api/v1/authpolicy"} {
		if code, out := doJSON(t, h, "GET", p, tok, nil); code != http.StatusForbidden {
			t.Errorf("已撤销管理员持旧令牌读 %s 应 403，得 %d: %v", p, code, out)
		}
	}
}
