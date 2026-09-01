package api

import (
	"net/http"
	"strings"
	"testing"
)

// 受控资源后端地址的**主机形态**校验（PRD FR-TUN-02）。
//
// ★缺陷原样：`net.SplitHostPort` 只把最后一个冒号后面的东西切出来，对主机部分
// 什么都不检查，于是网段 / 地址范围 / 泛域名全都 200 OK 落库过（实测三种都过）。
// 而对象库把这三种形态都当**一等对象**提供并做成种子，资源编辑器还会拿选中的对象
// 自动回填 backend——照着页面给的选项点两下就能存出一条网关永远拨不出去的资源，
// 接口回 200、列表正常、剖面里有它、客户端点开就是连不上，两侧日志都不报错。
func TestResourceBackendRejectsUndialableHosts(t *testing.T) {
	h := newTestServer(t)

	bad := []struct{ backend, wantHint string }{
		{"10.0.0.0/24:443", "网段"},
		{"192.168.0.0/16:80", "网段"},
		{"*.corp.internal:443", "泛域名"},
		{"10.1.1.1-10.1.1.99:80", "地址范围"},
		{"-bad.example.com:443", "连字符"},
		{"bad_host!:443", "非法字符"},
	}
	for i, c := range bad {
		code, out := doJSON(t, h, "POST", "/api/v1/resources", adminToken(), map[string]any{
			"id": "probe-bad-" + itoa(i), "name": "探针", "backend": c.backend,
		})
		if code != http.StatusBadRequest {
			t.Fatalf("backend=%q 应被拒（400），got %d %v —— 网关按它 net.Dial，这条资源存下来对谁都不生效",
				c.backend, code, out)
		}
		// 拒绝必须**说得出正确形态**：笼统的"格式不对"会让管理员反复换写法试，
		// 而这三种写法一种都不会成（同 IPSec peer 拒收 FQDN 那条的教训）。
		msg := errMsgOf(out)
		if !strings.Contains(msg, c.wantHint) {
			t.Fatalf("backend=%q 的拒绝理由应点名「%s」，实际是 %q", c.backend, c.wantHint, msg)
		}
	}

	// 反向：合法形态必须照收——只测拒绝的话，一个把所有人都拒掉的实现也能全绿。
	good := []string{"10.20.1.10:8080", "oa.corp.internal:443", "[::1]:8080", "db-1:5432", "host_a.corp:22"}
	for i, b := range good {
		code, out := doJSON(t, h, "POST", "/api/v1/resources", adminToken(), map[string]any{
			"id": "probe-ok-" + itoa(i), "name": "探针", "backend": b,
		})
		if code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("backend=%q 是合法拨号目标，不该被拒：%d %v", b, code, out)
		}
	}
}

// errMsgOf 取 httpx.Error 的 {"error":{"message":…}}。
func errMsgOf(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	if e == nil {
		return ""
	}
	m, _ := e["message"].(string)
	return m
}

// 建号撞已存在账号必须回 409 +「账号已存在」，而不是英文的 500（FR-USER-02）。
//
// ★改造前：CreateUser 不查重、靠唯一索引兜底，那条 UNIQUE 错误一路落到
// orgStoreErr 的 default 分支 → 500「failed to create user」。管理员看到的是一句
// 服务端故障措辞，会去重试、去找运维，而真实原因一个字都没说。
// 而同一套控制台的 CSV 批量导入对同样的输入回的是「账号已存在」——两条路两种解释。
func TestCreateUserDuplicateAccountSaysWhy(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "POST", "/api/v1/users", adminToken(), map[string]any{
		"name": "重名探针", "account": "li.fang",
	})
	if code != http.StatusConflict {
		t.Fatalf("撞已存在账号应回 409，got %d %v", code, out)
	}
	if msg := errMsgOf(out); !strings.Contains(msg, "账号已存在") {
		t.Fatalf("必须说清是账号重复（与 CSV 导入同一句话），实际是 %q", msg)
	}
	// 反向：不重复的账号照常建得出来。
	if code, out := doJSON(t, h, "POST", "/api/v1/users", adminToken(), map[string]any{
		"name": "新同事", "account": "brand.new",
	}); code != http.StatusCreated {
		t.Fatalf("不重复的账号应建得出来，got %d %v", code, out)
	}
}
