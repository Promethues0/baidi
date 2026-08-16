package api

import (
	"context"
	"net/http"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── 门户磁贴 × 客户端剖面：可访问性同构 ──
//
// 门户曾经是控制面**第四个**可访问性判定点，而且它谁都不认——不认静态 ACL、不认组织/
// 用户组、不认 JIT，只看 sensitivity（普通恒可访问、高敏恒需申请）。三种失败形态全部
// 无报错，本文件逐条钉住：
//
//	① 普通资源未授权 → 磁贴恒亮「访问」，点下去才 403（TestPortalTile_普通资源未授权不再恒亮访问）
//	② 高敏资源已授权 → 磁贴恒「需申请」，逼人为自己已有的权限走审批，而同一个人经桌面
//	   客户端立刻能进（TestPortalTile_高敏已授权不再被逼申请）
//	③ 高敏 + 未设 ACL → 磁贴锁着、点「申请权限」被 JIT 闸以「无需申请」400 顶回来的死路，
//	   而该资源经隧道对全体登录用户开放（TestPortalTile_申请权限按钮出现时JIT闸必收单）
//
// 核心用例是 TestPortalTileIsomorphicWithClientProfile：**两个端点都走真实 HTTP**，
// 同一把令牌、同一个库。只在函数层比对是自欺——两边现在调同一个 appAccessState，
// 那样的断言恒真；能验出分叉的只有「有人又在某个 handler 里加了一条特判」这件事，
// 而它只在 HTTP 出口上看得见。

// asStr / asBool JSON 解出来的弱类型取值。
func asStr(v any) string { s, _ := v.(string); return s }
func asBool(v any) bool  { b, _ := v.(bool); return b }

// portalTiles 拉一次门户磁贴，按应用 id 索引。
func (f *isoFixture) portalTiles(token string) map[string]map[string]any {
	f.t.Helper()
	code, out := doJSON(f.t, f.h, "GET", "/api/v1/portal/apps", token, nil)
	if code != http.StatusOK {
		f.t.Fatalf("portal/apps http %d: %v", code, out)
	}
	return byAppID(f.t, out["apps"])
}

// profileTiles 拉一次客户端剖面，按应用 id 索引。
func (f *isoFixture) profileTiles(token string) map[string]map[string]any {
	f.t.Helper()
	code, out := doJSON(f.t, f.h, "GET", "/api/v1/client/profile", token, nil)
	if code != http.StatusOK {
		f.t.Fatalf("client/profile http %d: %v", code, out)
	}
	return byAppID(f.t, out["apps"])
}

func byAppID(t *testing.T, v any) map[string]map[string]any {
	t.Helper()
	m := map[string]map[string]any{}
	arr, _ := v.([]any)
	for _, it := range arr {
		if tile, ok := it.(map[string]any); ok {
			m[asStr(tile["id"])] = tile
		}
	}
	return m
}

// matrixCase 一格场景：一条资源 + 一个桥接它的应用 + 对 li.fang(role=user) 的期望结论。
type matrixCase struct {
	res         map[string]any
	backend     string
	want        bool   // li.fang 此刻应否可访问
	unavailable bool   // 期望磁贴标「结构性不可用」（配置缺口，不是授权结论）
	note        string // 这一格在说什么（断言失败时原样打出来）
}

// portalMatrix 落一套覆盖「敏感度 × 是否受限 × 主体命中与否」全部组合的资源与应用。
// 返回 appID → 场景。每一格都是旧判据会答错或答对得毫无道理的场景。
func portalMatrix(f *isoFixture) map[string]matrixCase {
	f.t.Helper()
	ctx := context.Background()
	// li.fang(u2) 放进研发部：让「仅因组织被授权」这一维在门户上也能被验到。
	if err := f.st.SetUserOrg(ctx, "u2", "dev"); err != nil {
		f.t.Fatalf("SetUserOrg: %v", err)
	}
	cases := []matrixCase{
		{backend: "10.60.0.1:8080", want: true, note: "普通 + 四维全空（不限）",
			res: map[string]any{"id": "m-normal-open", "name": "普通不限", "sensitivity": store.SensitivityNormal}},
		{backend: "10.60.0.2:8080", want: false, note: "★失败形态①：普通 + 只授权给别人（旧判据恒答可访问）",
			res: map[string]any{"id": "m-normal-miss", "name": "普通仅他人", "sensitivity": store.SensitivityNormal,
				"allowUsers": []string{"zhang.wei"}}},
		{backend: "10.60.0.3:8080", want: true, note: "普通 + 点名授权本人",
			res: map[string]any{"id": "m-normal-hit", "name": "普通点名", "sensitivity": store.SensitivityNormal,
				"allowUsers": []string{"li.fang"}}},
		{backend: "10.60.0.4:8080", want: true, note: "★失败形态②：高敏 + 点名授权本人（旧判据恒答需申请）",
			res: map[string]any{"id": "m-high-hit", "name": "高敏点名", "sensitivity": store.SensitivityHigh,
				"allowUsers": []string{"li.fang"}}},
		{backend: "10.60.0.5:8080", want: false, note: "高敏 + 只授权给别人",
			res: map[string]any{"id": "m-high-miss", "name": "高敏仅他人", "sensitivity": store.SensitivityHigh,
				"allowUsers": []string{"zhang.wei"}}},
		{backend: "10.60.0.6:8080", want: true, note: "★失败形态③：高敏 + 四维全空（旧判据锁着磁贴，而隧道对全员开放）",
			res: map[string]any{"id": "m-high-open", "name": "高敏不限", "sensitivity": store.SensitivityHigh}},
		{backend: "10.60.0.7:8080", want: true, note: "普通 + 仅因所属组织被授权（含子树）",
			res: map[string]any{"id": "m-org-hit", "name": "研发部专用", "sensitivity": store.SensitivityNormal,
				"allowOrgs": []string{"dev"}}},
		{backend: "10.60.0.8:8080", want: false, note: "普通 + 授权给本人不属于的组织",
			res: map[string]any{"id": "m-org-miss", "name": "销售部专用", "sensitivity": store.SensitivityNormal,
				"allowOrgs": []string{"sales"}}},
		// ★后端缺端口：这是剖面的**第二条**丢弃路径。它必须与「未关联资源」一样被判成
		// Unavailable，否则「剖面缺席 ⟺ 门户标不可用」只单向成立，门户会继续把按钮亮着
		// （点「访问」→ 票据签得出来 → 网关拿一个没有端口的地址必然拨不通）。
		// handleSaveResource 至今不校验 backend 形态，故这一行是能真的落库的。
		{backend: "10.60.0.9", want: false, unavailable: true, note: "★后端不是 host:port（剖面的第二条丢弃路径）",
			res: map[string]any{"id": "m-badbackend", "name": "缺端口资源", "sensitivity": store.SensitivityNormal}},
	}
	out := map[string]matrixCase{}
	for _, c := range cases {
		c.res["backend"] = c.backend
		if code, o := f.saveResource(c.res); code != http.StatusOK {
			f.t.Fatalf("保存资源 %v http %d: %v", c.res["id"], code, o)
		}
		a, err := f.st.CreateApp(context.Background(), store.App{
			Name: asStr(c.res["name"]), Addr: c.backend, Mode: "web",
			Category: "office", Status: "running", ResourceID: asStr(c.res["id"]),
		})
		if err != nil {
			f.t.Fatalf("CreateApp %v: %v", c.res["id"], err)
		}
		out[a.ID] = c
	}
	// ★未关联受控资源那一格由用例**自己造**，不吃种子里的 a4。
	// 吃种子的话，「a4 哪天被补上 resourceId / 改了 id」会让断言静默失去覆盖，
	// 而本仓已经栽过这种「条件不满足就悄悄跳过 = 等同于没有这条用例」（见 notify_test.go 的同款说明）。
	un, err := f.st.CreateApp(context.Background(), store.App{
		Name: "未关联应用", Addr: "10.60.9.9:22", Mode: "tunnel",
		Category: "dev", Status: "running", ResourceID: "",
	})
	if err != nil {
		f.t.Fatalf("CreateApp 未关联应用: %v", err)
	}
	out[un.ID] = matrixCase{
		backend: "10.60.9.9:22", want: false, unavailable: true,
		note: "★未关联受控资源（配置缺口，不是授权结论）",
		res:  map[string]any{"id": "", "name": "未关联应用", "sensitivity": store.SensitivityNormal},
	}
	return out
}

// ★核心用例：门户与剖面对**每一个**应用给出同一个结论。
//
// 覆盖面刻意包含库里的种子应用（含 a4 未关联资源、a6 全网资源）——这两类不是矩阵造出来的，
// 而是真实存在的边界形态，恰恰最容易在两个 handler 里被处理成不同答案。
func TestPortalTileIsomorphicWithClientProfile(t *testing.T) {
	f := newIsoFixture(t)
	cases := portalMatrix(f)
	tok := userToken("li.fang")

	tiles := f.portalTiles(tok)
	prof := f.profileTiles(tok)
	if len(tiles) == 0 {
		t.Fatal("门户一个磁贴都没有，用例前置失败")
	}

	// ★遍历**两侧 key 的并集**，不是只遍历门户那一侧。
	// 只遍历门户的话，「门户少下发一个磁贴」这一类改动它一条都发现不了——
	// 而恰恰是「未关联的应用干脆别给磁贴了」这种看似合理的顺手改动会把 unavailable 整个抹掉，
	// 用户侧的结果是应用从门户凭空消失且没有任何解释（门户没有 warnings 通道，
	// 这正是引入 unavailable 的全部理由）。对抗式复核用真变异实测过这个盲区。
	// 另外：门户还必须覆盖库里全部 running 应用——磁贴数与 store 对齐是「没有被悄悄过滤掉」的硬证据。
	running := runningAppIDs(f)
	for id := range running {
		if _, ok := tiles[id]; !ok {
			t.Fatalf("门户漏发磁贴：应用 %s 在库里是 running，却不在 /portal/apps 里——"+
				"从门户消失且没有任何解释，比显示成不可用更糟", id)
		}
	}
	for id := range unionKeys(tiles, prof) {
		tile, inPortal := tiles[id]
		p, inProfile := prof[id]
		if !inPortal {
			t.Fatalf("应用 %s 出现在剖面里却没有门户磁贴（%v）——两侧应用集合分叉", id, p["name"])
		}
		unavailable := asBool(tile["unavailable"])
		// 结构性不可用的应用：剖面把它丢掉并给管理员一条 warning，门户则如实标在磁贴上。
		// 这个不对称是有意的（门户没有 warnings 通道），但两边的**判断**必须一致：
		// 「剖面里没有它」⟺「门户说它不可用」。★双向都要成立——剖面有两条丢弃路径
		// （未关联受控资源 / 后端不是 host:port），少覆盖一条就会让门户继续把按钮亮着。
		if unavailable != !inProfile {
			t.Fatalf("应用 %s（%v）：门户 unavailable=%v（原因 %q），剖面里%s——两边对「这个应用能不能用」的判断分叉了",
				id, tile["name"], unavailable, tile["unavailableReason"],
				map[bool]string{true: "有", false: "没有"}[inProfile])
		}
		if unavailable {
			if asBool(tile["accessible"]) {
				t.Fatalf("应用 %s 结构上不可用却标 accessible=true——按钮亮着、点了必然打不开", id)
			}
			if asStr(tile["unavailableReason"]) == "" {
				t.Fatalf("应用 %s 标了 unavailable 却没有原因——用户要拿这句话去找管理员", id)
			}
			continue
		}
		if asBool(tile["accessible"]) != asBool(p["accessible"]) {
			t.Fatalf("★同一个人同一个应用，两个界面给相反答案：%s（%v）门户 accessible=%v / 剖面 accessible=%v",
				id, tile["name"], tile["accessible"], p["accessible"])
		}
		if asBool(tile["degraded"]) != asBool(p["degraded"]) {
			t.Fatalf("应用 %s 的 degraded 两侧不一致：门户=%v 剖面=%v（「被降权」与「没授权」下一步动作不同，不能各说各话）",
				id, tile["degraded"], p["degraded"])
		}
		if asStr(tile["sensitivity"]) != asStr(p["sensitivity"]) {
			t.Fatalf("应用 %s 的 sensitivity 两侧不一致：门户=%q 剖面=%q", id, tile["sensitivity"], p["sensitivity"])
		}
	}

	// 矩阵每一格的期望结论——同构只保证「两边一样」，这一段保证「一样的那个答案是对的」。
	for id, c := range cases {
		tile, ok := tiles[id]
		// ★不能靠 nil map 取值：那会把「磁贴根本没下发」伪装成 accessible=false，
		// 与 want=false 的几格完全同形，于是「门户把磁贴藏起来」在这一段也是绿的。
		if !ok {
			t.Fatalf("磁贴缺失：%s（应用 %s）", c.note, id)
		}
		if got := asBool(tile["accessible"]); got != c.want {
			t.Fatalf("%s：期望 accessible=%v，实得 %v（资源 %v）", c.note, c.want, got, c.res["id"])
		}
		if got := asBool(tile["unavailable"]); got != c.unavailable {
			t.Fatalf("%s：期望 unavailable=%v，实得 %v（原因 %q）", c.note, c.unavailable, got, tile["unavailableReason"])
		}
	}
}

// unionKeys 两份磁贴索引的 key 并集。
func unionKeys(a, b map[string]map[string]any) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

// runningAppIDs 库里全部 status=running 的应用 id——门户磁贴必须一个不少地覆盖它们。
func runningAppIDs(f *isoFixture) map[string]bool {
	f.t.Helper()
	b, err := f.st.Apps(context.Background())
	if err != nil {
		f.t.Fatalf("Apps: %v", err)
	}
	out := map[string]bool{}
	for _, a := range b.Apps {
		if a.Status == "running" {
			out[a.ID] = true
		}
	}
	return out
}

// 失败形态①：普通资源只授权给别人时，磁贴不能再恒亮「访问」。
func TestPortalTile_普通资源未授权不再恒亮访问(t *testing.T) {
	f := newIsoFixture(t)
	if code, out := f.saveResource(map[string]any{
		"id": "r-normal-miss", "name": "普通仅他人", "backend": "10.61.0.1:8080",
		"sensitivity": store.SensitivityNormal, "allowUsers": []string{"zhang.wei"},
	}); code != http.StatusOK {
		t.Fatalf("保存资源 http %d: %v", code, out)
	}
	a, err := f.st.CreateApp(context.Background(), store.App{
		Name: "普通仅他人", Addr: "10.61.0.1:8080", Mode: "web",
		Category: "office", Status: "running", ResourceID: "r-normal-miss"})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	tile := f.portalTiles(userToken("li.fang"))[a.ID]
	if tile == nil {
		t.Fatal("磁贴缺失")
	}
	if asBool(tile["accessible"]) {
		t.Fatal("普通敏感度不等于人人可访问：未获授权的账号点下去只会拿到 403，" +
			"而磁贴上的「访问」按钮亮着——这是「按钮亮着但打不开」，不是授权结论")
	}
	if asBool(tile["degraded"]) || asBool(tile["unavailable"]) {
		t.Fatalf("这是纯粹的未授权，不该标成降权或未关联：%v", tile)
	}
}

// 失败形态②：高敏资源已静态授权给本人时，磁贴不能再显示「需申请」。
// 同时断言这不是把高敏一律放开——同一屏上未授权的高敏资源仍然锁着。
func TestPortalTile_高敏已授权不再被逼申请(t *testing.T) {
	f := newIsoFixture(t)
	for _, r := range []map[string]any{
		{"id": "r-high-hit", "name": "高敏点名", "backend": "10.62.0.1:443",
			"sensitivity": store.SensitivityHigh, "allowUsers": []string{"li.fang"}},
		{"id": "r-high-miss", "name": "高敏仅他人", "backend": "10.62.0.2:443",
			"sensitivity": store.SensitivityHigh, "allowUsers": []string{"zhang.wei"}},
	} {
		if code, out := f.saveResource(r); code != http.StatusOK {
			t.Fatalf("保存资源 %v http %d: %v", r["id"], code, out)
		}
	}
	hit, err := f.st.CreateApp(context.Background(), store.App{
		Name: "高敏点名", Addr: "10.62.0.1:443", Mode: "web",
		Category: "finance", Status: "running", ResourceID: "r-high-hit"})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	miss, err := f.st.CreateApp(context.Background(), store.App{
		Name: "高敏仅他人", Addr: "10.62.0.2:443", Mode: "web",
		Category: "finance", Status: "running", ResourceID: "r-high-miss"})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	tiles := f.portalTiles(userToken("li.fang"))
	if !asBool(tiles[hit.ID]["accessible"]) {
		t.Fatal("★已被静态授权的高敏资源不该显示「需申请」：同一个人经桌面客户端或 Web 票据" +
			"立刻就能进，逼他为自己已有的权限走一遍审批，审批就退化成纸面闸")
	}
	if asBool(tiles[miss.ID]["accessible"]) {
		t.Fatal("未授权的高敏资源必须仍然锁着——修①②不能顺手把高敏整类放开")
	}
}

// 失败形态③：磁贴让你点「申请权限」的场合，JIT 闸必须真的收单。
//
// 旧判据下「高敏 + 未设 ACL」会让磁贴显示「申请权限」，而 handlePortalCreateAccessRequest
// 的受限校验会以「目标资源未设访问限制，无需申请」400 顶回来——UI 说需申请、后端说无需申请，
// 浏览器侧是条死路。这条用例把它变成结构性不可能：不受限 ⟹ authorizeRes 放行 ⟹ 磁贴可访问 ⟹
// 根本不出现那个按钮。断言方式是**真的把申请打出去**，而不是只看代码路径。
func TestPortalTile_申请权限按钮出现时JIT闸必收单(t *testing.T) {
	f := newIsoFixture(t)
	portalMatrix(f)
	tok := userToken("li.fang")

	asked := 0
	for id, tile := range f.portalTiles(tok) {
		// 「申请权限」按钮的出现条件（见 PortalApps.vue）：不可访问 ∧ 非降权 ∧ 非未关联
		if asBool(tile["accessible"]) || asBool(tile["degraded"]) || asBool(tile["unavailable"]) {
			continue
		}
		asked++
		code, out := doJSON(t, f.h, "POST", "/api/v1/portal/access-requests", tok,
			map[string]any{"appId": id, "reason": "同构测试", "ttlMinutes": 30})
		// 201 建单、409 已有在途申请都算收单；唯独不能是 400——那意味着 UI 指了一条死路。
		if code == http.StatusBadRequest {
			t.Fatalf("磁贴 %s（%v）显示「申请权限」，JIT 闸却回 400：%v —— UI 与后端对「要不要申请」的判断相反",
				id, tile["name"], out)
		}
		if code != http.StatusCreated && code != http.StatusConflict {
			t.Fatalf("磁贴 %s 提交申请意外失败 http %d：%v", id, code, out)
		}
	}
	if asked == 0 {
		t.Fatal("矩阵里一格「需申请」都没有，用例失去意义（前置构造被改坏了）")
	}
}

// 结构性不可用的两种成因（未关联受控资源 / 后端不是 host:port）：
// 既不是「可访问」也不是「需申请」，剖面对它们都是「丢弃 + warning」。
//
// ★用例自己造这两种应用，不吃种子里的 a4——吃种子的话「a4 哪天被改」会让断言
// 静默失去覆盖，而 t.Skip 更是等同于没有这条用例（同款纪律见 notify_test.go）。
func TestPortalTile_结构性不可用不是可访问也不是需申请(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()
	tok := userToken("li.fang")

	unlinked, err := f.st.CreateApp(ctx, store.App{Name: "未关联应用", Addr: "10.64.0.1:22",
		Mode: "tunnel", Category: "dev", Status: "running", ResourceID: ""})
	if err != nil {
		t.Fatalf("CreateApp 未关联应用: %v", err)
	}
	if code, out := f.saveResource(map[string]any{
		"id": "r-badbackend", "name": "缺端口资源", "backend": "10.64.0.2",
		"sensitivity": store.SensitivityNormal,
	}); code != http.StatusOK {
		// 这里不是断言 handleSaveResource **应该**收——恰恰相反，它至今不校验 backend 形态
		// 是一处独立缺口（见 docs/charter/wave8.md 边界建议）。此处只需要它能落库，
		// 好让读侧那道兜底被验到；哪天入口真的开始拒收，这条用例会红并提醒改用例。
		t.Fatalf("保存缺端口资源 http %d: %v（若入口已加校验，本用例改用直写 store 构造）", code, out)
	}
	badBackend, err := f.st.CreateApp(ctx, store.App{Name: "缺端口应用", Addr: "10.64.0.2",
		Mode: "web", Category: "office", Status: "running", ResourceID: "r-badbackend"})
	if err != nil {
		t.Fatalf("CreateApp 缺端口应用: %v", err)
	}

	tiles := f.portalTiles(tok)
	prof := f.profileTiles(tok)
	for _, tc := range []struct{ id, what string }{
		{unlinked.ID, "未关联受控资源"},
		{badBackend.ID, "后端不是 host:port"},
	} {
		tile := tiles[tc.id]
		if tile == nil {
			t.Fatalf("前提消失：门户没有下发「%s」的磁贴——若门户改成不输出这类应用，"+
				"请连同 unavailable 这一态一起重新设计（用户会看到应用凭空消失且无解释）", tc.what)
		}
		if !asBool(tile["unavailable"]) {
			t.Fatalf("「%s」的磁贴应标 unavailable=true，实得 %v", tc.what, tile)
		}
		if asBool(tile["accessible"]) {
			t.Fatalf("「%s」标成可访问 = 按钮亮着、点了必然打不开", tc.what)
		}
		if asStr(tile["unavailableReason"]) == "" {
			t.Fatalf("「%s」没有下发原因——用户要拿这句话去找管理员", tc.what)
		}
		// 它也不该被渲染成「需申请」——JIT 闸会拒掉，那同样是死路。
		code, out := doJSON(t, f.h, "POST", "/api/v1/portal/access-requests", tok,
			map[string]any{"appId": tc.id, "reason": "验证死路", "ttlMinutes": 30})
		if code != http.StatusBadRequest {
			t.Fatalf("前提变了：「%s」的应用现在能提交申请了（http %d: %v），"+
				"那 unavailable 与「需申请」的区分就要重新设计", tc.what, code, out)
		}
		// 剖面侧同一个应用应当整条缺席，且管理员能在 warnings 里看到原因。
		if _, ok := prof[tc.id]; ok {
			t.Fatalf("剖面不该下发「%s」的应用（终端会接管一个必然连不通的地址）", tc.what)
		}
	}
}

// 降权：高敏磁贴翻不可访问且标 degraded，普通磁贴纹丝不动，两侧同真同假。
// 「被降权」与「没授权」的下一步动作完全不同（前者申请也没用），门户必须能分开说。
func TestPortalTile_降权只摘高敏且与剖面同真(t *testing.T) {
	f := newIsoFixture(t)
	cases := portalMatrix(f)
	tok := userToken("li.fang")

	f.reportPosture("li.fang", "MAC-1", store.DisposalDegrade, "系统完整性保护未开启")

	tiles := f.portalTiles(tok)
	prof := f.profileTiles(tok)
	degradedSeen, normalSeen := 0, 0
	for id, c := range cases {
		tile, p := tiles[id], prof[id]
		high := asStr(c.res["sensitivity"]) == store.SensitivityHigh
		if high {
			degradedSeen++
			if !asBool(tile["degraded"]) || asBool(tile["accessible"]) {
				t.Fatalf("降权后高敏磁贴应 degraded=true 且不可访问：%s（%v）实得 %v", id, c.note, tile)
			}
		} else {
			normalSeen++
			if asBool(tile["degraded"]) {
				t.Fatalf("★降权不是全断：普通资源不该被标降权：%s（%v）", id, c.note)
			}
			if asBool(tile["accessible"]) != c.want {
				t.Fatalf("降权不该改变普通资源的授权结论：%s 期望 %v 实得 %v", c.note, c.want, tile["accessible"])
			}
		}
		if asBool(tile["accessible"]) != asBool(p["accessible"]) || asBool(tile["degraded"]) != asBool(p["degraded"]) {
			t.Fatalf("降权态下门户与剖面分叉：%s 门户=%v 剖面=%v", id, tile, p)
		}
	}
	if degradedSeen == 0 || normalSeen == 0 {
		t.Fatalf("矩阵没同时覆盖高敏与普通（高敏 %d 条 / 普通 %d 条），本用例证不了「只摘高敏」", degradedSeen, normalSeen)
	}
}

// JIT 授予把「需申请」翻回可访问，且门户与剖面同时翻——审批批了却只有一个界面认，
// 正是本项目反复警告的那种「批了连不上 / 连得上却显示需申请」。
func TestPortalTile_JIT授予两侧同时翻真(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()
	if code, out := f.saveResource(map[string]any{
		"id": "r-jit", "name": "高敏仅他人", "backend": "10.63.0.1:443",
		"sensitivity": store.SensitivityHigh, "allowUsers": []string{"zhang.wei"},
	}); code != http.StatusOK {
		t.Fatalf("保存资源 http %d: %v", code, out)
	}
	a, err := f.st.CreateApp(ctx, store.App{Name: "高敏仅他人", Addr: "10.63.0.1:443", Mode: "web",
		Category: "finance", Status: "running", ResourceID: "r-jit"})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	tok := userToken("li.fang")
	if asBool(f.portalTiles(tok)[a.ID]["accessible"]) {
		t.Fatal("前置失败：授予之前不该可访问")
	}

	// 走真实审批链路：提交申请 → 管理员批准 → 生成有效授予
	code, out := doJSON(t, f.h, "POST", "/api/v1/portal/access-requests", tok,
		map[string]any{"appId": a.ID, "reason": "季度对账", "ttlMinutes": 30})
	if code != http.StatusCreated {
		t.Fatalf("提交申请 http %d: %v", code, out)
	}
	reqID := asStr(out["id"])
	if code, out = doJSON(t, f.h, "POST", "/api/v1/access-requests/"+reqID+"/decide", adminToken(),
		map[string]any{"decision": "approved", "reason": "同意"}); code != http.StatusOK {
		t.Fatalf("审批 http %d: %v", code, out)
	}

	tile := f.portalTiles(tok)[a.ID]
	p := f.profileTiles(tok)[a.ID]
	if !asBool(tile["accessible"]) || !asBool(p["accessible"]) {
		t.Fatalf("审批通过后两侧都应翻回可访问：门户=%v 剖面=%v", tile["accessible"], p["accessible"])
	}
}
