package api

import (
	"net/http"
	"strings"
	"testing"
)

// ── wave11 行动 15：应用发布的入口校验与展示地址（FR-APP-01 / FR-TUN-02）──
//
// ① `POST /apps` 的校验比后补的 `PUT` 松一大截：mode 不查白名单、addr 不查非空、
//    status 不查枚举，而 validAppMode 就放在同一个文件里。三种字典外的值都会
//    「接口回 201、页面上找不出毛病、功能静默不生效」，逐条见 normalizeAppInput 的注释。
// ② `apps.addr` 是与 `resources.backend` 并存的第二个地址真相来源：管理员手填、
//    从不校验、也永不与资源同步，而门户与移动端把它当作「这个应用的地址」展示。
//
// ★变异实测（每一条修复都能被下面某条用例变红）：
//   - 把 handleCreateApp 里那句 normalizeAppInput 删掉
//     → TestCreateAppRejectsUnknownMode / …EmptyAddr / …BadStatus 三条同时红；
//   - 把 normalizeAppInput 里的 `!validAppMode[a.Mode]` 改成恒 false
//     → TestCreateAppRejectsUnknownMode 与 TestAppUpdateRejectsUnknownMode 同时红
//     （这道校验必须两个入口共享，只修 POST 会让下一次改动重新分叉）；
//   - 把 portalAddr 的资源分支删掉（退回直发 a.Addr）
//     → TestPortalAddrComesFromResourceBackend 红；
//   - 把 global 那个提前 return 删掉
//     → TestPortalAddrBookmarkKeepsItsOwnLink 红（直连书签的「打开链接」会从此打不开东西）。

// createApp 发一次真实的 POST /apps，返回状态码与响应体。
func createApp(t *testing.T, h http.Handler, body map[string]any) (int, map[string]any) {
	t.Helper()
	return doJSON(t, h, "POST", "/api/v1/apps", adminToken(), body)
}

// baseApp 一份**除被测字段外全部合法**的发布请求体（分类取种子里真实存在的 office）。
func baseApp() map[string]any {
	return map[string]any{
		"name": "入口校验用例", "addr": "10.99.0.1:8080", "mode": "tunnel",
		"category": "office", "resourceId": "",
	}
}

func TestCreateAppRejectsUnknownMode(t *testing.T) {
	h := newTestServer(t)
	b := baseApp()
	// 大小写不同的 "Global"：判定它的三处（appAccessState 的直连书签分支、
	// 前端 modeMeta、alertSnapshot 的排除判据）全部只认小写 global，
	// 于是它会被当成受控应用、常年挂一条「未关联受控资源」告警。
	b["mode"] = "Global"
	code, out := createApp(t, h, b)
	if code != http.StatusBadRequest {
		t.Fatalf("mode=\"Global\" 应被拒（改造前回 201 并落库），得到 %d：%v", code, out)
	}
	// 拒绝要说得出原因：笼统的 "invalid app payload" 会让管理员反复换写法试。
	if msg := errMsg(out); !strings.Contains(msg, "tunnel") || !strings.Contains(msg, "Global") {
		t.Fatalf("400 正文应点名合法取值与收到的那个值，得到 %q", msg)
	}
	// 反面：合法值照常放行（校验不能把正常发布一起挡掉）。
	b["mode"] = "global"
	if code, out := createApp(t, h, b); code != http.StatusCreated {
		t.Fatalf("mode=global 应放行，得到 %d：%v", code, out)
	}
}

func TestCreateAppRejectsEmptyAddr(t *testing.T) {
	h := newTestServer(t)
	b := baseApp()
	b["addr"] = "   " // 只有空白：TrimSpace 之后就是空
	code, out := createApp(t, h, b)
	if code != http.StatusBadRequest {
		t.Fatalf("addr 全空白应被拒（发布向导里它是必填、PUT 也拒空，只有 POST 放行过），得到 %d：%v", code, out)
	}
}

func TestCreateAppRejectsBadStatus(t *testing.T) {
	h := newTestServer(t)
	b := baseApp()
	// "Running" 与 "running" 在门户/剖面那道 `status == "running"` 上分得开：
	// 这条应用对所有终端都不存在，而应用页照常列着它。
	b["status"] = "Running"
	code, out := createApp(t, h, b)
	if code != http.StatusBadRequest {
		t.Fatalf("status=\"Running\" 应被拒，得到 %d：%v", code, out)
	}
	if msg := errMsg(out); !strings.Contains(msg, "running") {
		t.Fatalf("400 正文应点名合法取值，得到 %q", msg)
	}
	// 缺席仍按 running 落定（与 SQLiteStore.CreateApp 的缺省同值，别把老客户端一起拒了）。
	b2 := baseApp()
	delete(b2, "status")
	code, out = createApp(t, h, b2)
	if code != http.StatusCreated {
		t.Fatalf("status 缺席应按 running 放行，得到 %d：%v", code, out)
	}
	if got := str(out["status"]); got != "running" {
		t.Fatalf("status 缺席应落成 running，得到 %q", got)
	}
}

// TestAppUpdateRejectsUnknownMode 编辑那一侧走的必须是同一道校验。
//
// ★两个入口各写一份校验的话，下一次改动只会改到其中一处——「发布」与「编辑」
// 对同一份请求体给出相反的答案，而这正是本行动要消灭的那种分叉。
func TestAppUpdateRejectsUnknownMode(t *testing.T) {
	h := newTestServer(t)
	a := appByName(t, h, "OA 协同办公")
	if a == nil {
		t.Fatal("种子里应有 OA 协同办公")
	}
	code, out := doJSON(t, h, "PUT", "/api/v1/apps/"+str(a["id"]), adminToken(), map[string]any{
		"name": "OA 协同办公", "addr": "10.20.1.10:8080", "mode": "WEB",
		"category": str(a["category"]), "resourceId": "oa", "status": "running",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("mode=\"WEB\" 应被拒，得到 %d：%v", code, out)
	}
}

// ── ② 展示地址 ──

// portalTiles 拉一次门户磁贴（以种子用户 zhang.wei 的身份）。
func portalTiles(t *testing.T, h http.Handler) map[string]map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/portal/apps", userToken("zhang.wei"), nil)
	if code != http.StatusOK {
		t.Fatalf("门户磁贴 %d：%v", code, out)
	}
	byID := map[string]map[string]any{}
	for _, it := range out["apps"].([]any) {
		m := it.(map[string]any)
		byID[str(m["id"])] = m
	}
	return byID
}

// TestPortalAddrComesFromResourceBackend 关联了资源的磁贴，地址取**资源的真实后端**，
// 而不是管理员在发布向导里手填的那份。
//
// 坏形态：两者分家时（填错一位数字、或后来资源改了后端），用户照着一个白帝任何地方
// 都不会去拨的地址去连——tunnel 应用尤其致命，用户要拿它填自己的 SSH/RDP 客户端——
// 而门户、剖面、网关三处全部显示正常。
func TestPortalAddrComesFromResourceBackend(t *testing.T) {
	h := newTestServer(t)
	// 种子应用 a3「研发 Git 仓库」关联资源 git；把它的 addr 改成一个明显错的值，
	// 资源侧一字不动——这就是"管理员填错了"的真实形态。
	a := appByName(t, h, "研发 Git 仓库")
	if a == nil {
		t.Fatal("种子里应有 研发 Git 仓库")
	}
	code, _ := doJSON(t, h, "PUT", "/api/v1/apps/"+str(a["id"]), adminToken(), map[string]any{
		"name": "研发 Git 仓库", "addr": "10.30.5.99:2222", "mode": "tunnel",
		"category": str(a["category"]), "resourceId": "git", "status": "running",
	})
	if code != http.StatusOK {
		t.Fatalf("改 addr %d", code)
	}
	// 资源 git 的真实后端（网关拨的就是它）。
	var backend string
	_, rs := doJSON(t, h, "GET", "/api/v1/resources", adminToken(), nil)
	for _, it := range rs["resources"].([]any) {
		m := it.(map[string]any)
		if str(m["id"]) == "git" {
			backend = str(m["backend"])
		}
	}
	if backend == "" || backend == "10.30.5.99:2222" {
		t.Fatalf("用例前提不成立：资源 git 的后端应存在且与手填值不同，得到 %q", backend)
	}

	tile := portalTiles(t, h)[str(a["id"])]
	if tile == nil {
		t.Fatal("门户里应有这张磁贴")
	}
	if got := str(tile["addr"]); got != backend {
		t.Fatalf("磁贴地址应现算成资源后端 %q（改造前直发手填的 10.30.5.99:2222），得到 %q", backend, got)
	}
	if got := str(tile["addrSource"]); got != addrSourceResource {
		t.Fatalf("addrSource 应为 %q，得到 %q", addrSourceResource, got)
	}
}

// TestPortalAddrBookmarkKeepsItsOwnLink 直连书签**不许**被一刀切。
//
// 它不经网关、没有关联资源，apps.addr 在那一档是**执行值**：门户「打开链接」
// 点下去开的就是它。一起换成资源后端（零值空串）会让那个按钮从此打不开任何东西。
func TestPortalAddrBookmarkKeepsItsOwnLink(t *testing.T) {
	h := newTestServer(t)
	a := appByName(t, h, "知网文献 (直连书签)")
	if a == nil {
		t.Fatal("种子里应有直连书签应用")
	}
	tile := portalTiles(t, h)[str(a["id"])]
	if tile == nil {
		t.Fatal("直连书签对全体登录用户可见，门户里应有它")
	}
	if got := str(tile["addr"]); got != str(a["addr"]) || got == "" {
		t.Fatalf("直连书签的地址应原样是它自己的链接 %q，得到 %q", str(a["addr"]), got)
	}
	if got := str(tile["addrSource"]); got != addrSourceBookmark {
		t.Fatalf("addrSource 应为 %q，得到 %q", addrSourceBookmark, got)
	}
}

// TestPortalAddrUnlinkedIsDeclared 没关联资源时只剩手填值，来源要如实标出来——
// 那张磁贴同时带着「配置缺口 · 不可用」，两个标记要一起读。
func TestPortalAddrUnlinkedIsDeclared(t *testing.T) {
	h := newTestServer(t)
	a := appByName(t, h, "数据库运维 (SSH)") // 种子里这条没有 resourceId
	if a == nil {
		t.Fatal("种子里应有 数据库运维 (SSH)")
	}
	tile := portalTiles(t, h)[str(a["id"])]
	if tile == nil {
		t.Fatal("门户里应有这张磁贴")
	}
	if got := str(tile["addrSource"]); got != addrSourceDeclared {
		t.Fatalf("未关联资源的磁贴 addrSource 应为 %q，得到 %q", addrSourceDeclared, got)
	}
	if got := str(tile["addr"]); got != str(a["addr"]) {
		t.Fatalf("没有资源后端可取时应回落到手填值 %q，得到 %q", str(a["addr"]), got)
	}
	if tile["unavailable"] != true {
		t.Fatalf("这张磁贴同时应是「配置缺口 · 不可用」，得到 %v", tile["unavailable"])
	}
}
