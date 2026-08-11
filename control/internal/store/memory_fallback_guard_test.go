// memory_fallback_guard_test.go 「以种子打底再局部覆盖」防扩散守卫。
//
// 背景：coverage_guard_test.go 盯的是**方法级**缺口（Store 接口新增方法、SQLiteStore
// 漏写实现 → 静默落回嵌入的 *Memory 种子）。它抓不到更隐蔽的**字段级**残留：
//
//	func (s *SQLiteStore) Users(ctx) (UserDirBundle, error) {
//	    b, err := s.Memory.Users(ctx)   // ← 以种子打底
//	    ...
//	    b.OrgTree = 真实组织树           // ← 只覆盖了一部分字段
//	    b.Users   = 真实用户清单
//	    return b, nil                    // ← Directories 原样带着种子回去了
//	}
//
// 这个形态在接口层面完全合规（方法有实现、返回值类型对、测试也能过），但响应里
// 真假字段混排：库里明明只有 8 个用户，页面顶部却挂着「本地目录 124 / 总部 AD 域 1160」。
// 它比整块种子更危险——整块假数据一眼能认出来，混在真数据里的那几个字段认不出来。
//
// ★判定口径是「**任何** *SQLiteStore 方法体里出现种子引用都要登记」，不再按
// 「是不是 Store 接口方法 / 是不是同名方法」筛。早先那版口径按形状开了三个口子，
// 每一个都是零成本绕过：
//
//	① 把打底挪进一个私有辅助方法（b, _ := s.Memory.Users(ctx) 写在 userDirectories 里，
//	   由 Users 调用）——辅助方法既不是接口方法、也不同名，一次都不触发；
//	② 先把 s.Memory 存进局部变量再调（m := s.Memory; m.Users(ctx)）——AST 只认
//	   CallExpr 上的 s.Memory.X(...) 形状，别名一步就绕开了；
//	③ 种子从 Memory 的方法抽成包级函数之后（seedApps() / builtinAppCategories()），
//	   打底连 s.Memory 这个形状都不再出现。
//
// 现在三种形状都登记：调用式、取值式（含别名与方法值）、包级种子构造函数调用。
// 建库播种与一次性回填确实要碰种子，它们走 memorySeeders 这份**显式**豁免名单——
// 名单本身被四条断言拴住（必须是真方法、必须真的还在碰种子、Why 不许空，
// 且**不许豁免 Store 接口方法**：读取路径没有任何理由拿种子打底）。
//
// 清单为空是理想状态，也是当前状态。登记本身不是通行证：先问一句"这个字段是不是
// 干脆不该存在"，删掉一个说不清出处的字段通常比给它配一份种子更接近正确答案。
//
// 纯测试文件，不改任何生产代码。
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// memoryFallback 一处被认可的「以 Memory 种子打底」。
type memoryFallback struct {
	// Fields 哪些字段仍来自种子（逐个列名，不许写"部分字段"）。
	Fields string
	// Why 为什么它暂时没有真实来源，以及补真实现的路径。
	Why string
}

// memoryFallbacks 已登记的「SQLiteStore 方法体内引用种子」清单，键 = 方法名。
//
// ★清单现在是空的：曾经的四处已全部逐字段脱壳——
//   - Users        —— Directories 曾原样继承种子的「本地目录 124 / 总部 AD 域 1160」，
//     现改由 auth_sources 真实行投影（SQLiteStore.userDirectories，与认证源页同源）；
//   - Overview     —— Devices/Sessions/三道防线的风险分与 TOP 实体全是编的，
//     现分别取自 trusted_devices 台账 / 网关上报（api 层注入）/ users + posture；
//   - Security     —— Spa 那张"已隐身 · 敲门正常 · G3"的卡片在控制面没有任何判据，
//     整段连同 UI 删除；真实出处是网关与隐身页（api/gatewaypage.go）；
//   - PolicyBundle —— List 那 5 条编造的策略清单删除（控制台从来没渲染过它，
//     但它照样出现在 GET /api/v1/policies 的响应里等着被人画出来）。
//
// 新增登记项必须两个字段都写满：Fields 要逐个列出字段名（写"部分字段"等于没登记），
// Why 要说清没有真实来源的原因与补真实现的路径。
var memoryFallbacks = map[string]memoryFallback{}

// memorySeeders 允许碰种子的 *SQLiteStore 方法：建库播种与一次性回填。键 = 方法名，值 = 理由。
//
// 它们把种子**写进真实表**、之后一律以库为准，与"读取时拿种子填页面"是两回事。
// 早先这条豁免是靠形状（"不是接口方法、也不同名"）结构性成立的，代价是同一个形状
// 缺口把真正的残留也一起放过了（见文件头 ①②③）。改成显式名单后，加一行是一次
// 显式且带理由的改动，且下面四条断言不允许它腐烂或被拿去豁免读取路径。
var memorySeeders = map[string]string{
	"seed":                  "首启建库播种：仅在对应表为空时把种子写进真实表，之后以库为准",
	"backfillAppResourceID": "一次性回填 apps.resource_id：按内置种子的 id 对应关系补空值，管理员改过的行不动",
	"backfillOrgUnits":      "一次性回填（org.backfill.v1）：把种子组织树建成真实 org_units 行并回填 users.org_id",
	"backfillAppCategories": "一次性回填（app.categories.backfill.v1）：把内置分类常量迁成 app_categories 真实行",
}

// TestNoUnregisteredMemorySeedFallback 未登记的种子打底 / 清单腐烂 / 清单悬空 / 豁免名单越界。
func TestNoUnregisteredMemorySeedFallback(t *testing.T) {
	ifaceMethods, sqliteMethods := collectMethodSets(t)
	files := parseStorePackage(t)
	found, totalRefs, seedFuncs := collectSeedRefs(files)

	// 守卫自检其一：包里必须至少存在一处种子引用（seed()/backfill* 那几处灌种子的正常
	// 用法）。一处都没找到，说明 AST 匹配的形状已经不成立（比如有人给 Memory 改了字段名、
	// 或改成了接口值），此时"没有发现残留"是假阴性而不是好消息。
	if totalRefs == 0 {
		t.Fatal("整个包里一处种子引用都没匹配到：要么 *Memory 嵌入与包级种子构造函数已被彻底移除（那本守卫可以退休了，连同 coverage_guard_test.go 一起），要么 collectSeedRefs 的 AST 形状假设已经失效——后者会让本守卫从此永远通过，请先确认是哪一种")
	}
	// 守卫自检其二：包级种子构造函数的识别（按名字前缀）必须还认得出东西。认不出的话，
	// 「Apps() 里写一句 apps := seedApps() 打底」这一类残留会从此隐身。
	if len(seedFuncs) == 0 {
		t.Fatalf("没有识别出任何包级种子构造函数（前缀 %v）：种子若已改名（比如 seedApps → demoApps 之外的第四种叫法），请更新 seedSourcePrefixes，否则这一路检测已经永久失效", seedSourcePrefixes)
	}

	// 方向一：引用了种子、既不在播种豁免名单、也没有登记。
	var unregistered []string
	for m := range found {
		if _, seeder := memorySeeders[m]; seeder {
			continue
		}
		if _, ok := memoryFallbacks[m]; !ok {
			unregistered = append(unregistered, m)
		}
	}
	sort.Strings(unregistered)
	for _, m := range unregistered {
		t.Errorf("*SQLiteStore.%s 在方法体里引用了种子（%s）：这是「以种子打底、再局部覆盖」的形态——被你覆盖的字段是真的，**没覆盖到的字段会原样带着演示种子返回给页面**，两者在同一个响应里混排，接口层面看不出区别，也没有任何运行期报错（Users().Directories 的「本地目录 124 / 总部 AD 域 1160」就是这么在真实部署上挂了很久）。请改成逐字段构造：缺哪一段是编译期的零值，不是一份看起来很像真的数字。确实存在没有真实来源的字段，就先考虑删掉那个字段/那块 UI；实在要留，在 memory_fallback_guard_test.go 的 memoryFallbacks 里登记，并写清 Fields（逐个列名）与 Why（为什么没有真实来源、怎么补）。若这是一处**建库播种/一次性回填**（把种子写进真实表、之后以库为准），登记到 memorySeeders 并写清理由",
			m, strings.Join(found[m], " / "))
	}

	// 方向二：登记项已经不再碰种子（清单腐烂会掩盖同名方法将来的回退）。
	var stale []string
	for m := range memoryFallbacks {
		if _, ok := found[m]; !ok {
			stale = append(stale, m)
		}
	}
	sort.Strings(stale)
	for _, m := range stale {
		t.Errorf("清单条目 %s 已经不再引用种子（该方法已逐字段脱壳）：请把它从 memory_fallback_guard_test.go 的 memoryFallbacks 删除。留着腐烂条目的代价是——将来有人重新在这个方法里写一句 s.Memory.%s(ctx) 打底时，守卫会认为「这是登记过的」而放行", m, m)
	}

	// 方向三：登记的名字压根不是 SQLiteStore 的方法（方法改名/删除后悬空）。
	var dangling []string
	for m := range memoryFallbacks {
		if !sqliteMethods[m] {
			dangling = append(dangling, m)
		}
	}
	sort.Strings(dangling)
	for _, m := range dangling {
		t.Errorf("清单条目 %s 不是 *SQLiteStore 的方法（拼写错误，或方法已改名/删除）：请修正或删除该条目", m)
	}

	// 登记内容本身必须可读：两个字段都不许空。
	for m, f := range memoryFallbacks {
		if strings.TrimSpace(f.Fields) == "" || strings.TrimSpace(f.Why) == "" {
			t.Errorf("清单条目 %s 的 Fields/Why 不能为空：不写清「哪些字段来自种子、为什么」的登记等于没登记——下一个人无从判断该字段是被认可的降级，还是又一处没人发现的残留", m)
		}
	}

	assertSeederList(t, ifaceMethods, sqliteMethods, found)
}

// assertSeederList 播种豁免名单的四条约束：不悬空、不腐烂、不越界到读取路径、理由不空。
func assertSeederList(t *testing.T, ifaceMethods, sqliteMethods map[string]bool, found map[string][]string) {
	t.Helper()
	names := make([]string, 0, len(memorySeeders))
	for m := range memorySeeders {
		names = append(names, m)
	}
	sort.Strings(names)
	for _, m := range names {
		if strings.TrimSpace(memorySeeders[m]) == "" {
			t.Errorf("播种豁免条目 %s 的理由不能为空：这份名单是本守卫唯一的人工出口，不写理由的条目下一个人无从判断该不该继续留着", m)
		}
		if !sqliteMethods[m] {
			t.Errorf("播种豁免条目 %s 不是 *SQLiteStore 的方法（拼写错误，或方法已改名/删除）：请修正或删除该条目", m)
		}
		if ifaceMethods[m] {
			t.Errorf("播种豁免条目 %s 是 Store 接口方法：接口方法是页面**读取**路径，拿种子打底正是本守卫要拦的事，不允许走播种豁免。建库播种请单独放在非接口方法里（seed / backfill*）", m)
		}
		if _, ok := found[m]; !ok {
			t.Errorf("播种豁免条目 %s 已经不再引用种子：请把它从 memorySeeders 删除。留着腐烂条目的代价与 memoryFallbacks 一样——将来有人在这个方法里写一句打底时会被静默放行", m)
		}
		if _, dup := memoryFallbacks[m]; dup {
			t.Errorf("%s 同时出现在 memorySeeders 与 memoryFallbacks 里：一处种子引用要么是建库播种、要么是待偿还的读取残留，两者不可能同时成立，请只保留一处", m)
		}
	}
}

// seedSourcePrefixes 包级「种子构造函数」的命名前缀。
//
// 种子从 Memory 的方法抽成包级函数是好事（Memory.Apps 与首启播种共用一份定义），
// 但它同时让 s.Memory 这个可检测的形状消失了：`apps := seedApps()` 打底与
// `b, _ := s.Memory.Apps(ctx)` 打底的后果完全一样，AST 却看不见。前缀识别是这里
// 唯一可行的口径（"这个函数返回的是不是编造的数据"没法从语法上判断），
// 因此上面有一条自检钉着"至少还认得出一个"。
var seedSourcePrefixes = []string{"seed", "builtin", "demo", "mock", "sample", "fake"}

// isSeedSourceName 判断包级函数名是否像一份种子构造器。
func isSeedSourceName(name string) bool {
	for _, p := range seedSourcePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// parseStorePackage 解析本包所有非测试 .go 源文件。
func parseStorePackage(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读取包目录失败: %v", err)
	}
	fset := token.NewFileSet()
	var out []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", name, err)
		}
		out = append(out, f)
	}
	return out
}

// collectSeedRefs 返回「*SQLiteStore 方法名 → 该方法体内出现的种子引用清单」、
// 全包种子引用总数、以及识别出的包级种子构造函数名集合。
//
// 登记三种形状（任一出现即登记，不再按方法名筛）：
//  1. 调用式  s.Memory.X(...)；
//  2. 取值式  s.Memory 作为值出现（m := s.Memory 别名、f := s.Memory.X 方法值、当参数传出去…）；
//  3. 包级种子构造函数调用 seedApps() / builtinAppCategories() / …（见 seedSourcePrefixes）。
func collectSeedRefs(files []*ast.File) (found map[string][]string, total int, seedFuncs map[string]bool) {
	found = map[string][]string{}
	seedFuncs = map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if isSeedSourceName(fn.Name.Name) {
				seedFuncs[fn.Name.Name] = true
			}
		}
	}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Body == nil {
				continue
			}
			if receiverTypeName(fn.Recv.List[0].Type) != "SQLiteStore" {
				continue
			}
			refs := seedRefsIn(fn.Body, receiverIdentName(fn.Recv.List[0]), seedFuncs)
			total += len(refs)
			if len(refs) > 0 {
				found[fn.Name.Name] = uniqSorted(append(found[fn.Name.Name], refs...))
			}
		}
	}
	return found, total, seedFuncs
}

// seedRefsIn 返回方法体内所有种子引用的可读描述。
// recv 为空（匿名接收者 `func (*SQLiteStore) F()`）时写不出 s.Memory，只查包级种子函数。
func seedRefsIn(body *ast.BlockStmt, recv string, seedFuncs map[string]bool) []string {
	var out []string
	// 第一趟：调用式 s.Memory.X(...)。记下内层 SelectorExpr 的位置，供第二趟去重。
	claimed := map[token.Pos]bool{}
	if recv != "" {
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			outer, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			inner, ok := outer.X.(*ast.SelectorExpr)
			if !ok || inner.Sel.Name != "Memory" {
				return true
			}
			if id, ok := inner.X.(*ast.Ident); ok && id.Name == recv {
				claimed[inner.Pos()] = true
				out = append(out, recv+".Memory."+outer.Sel.Name+"(…)")
			}
			return true
		})
		// 第二趟：取值式。别名（m := s.Memory）与方法值（f := s.Memory.X）都在这里落网——
		// 它们和直接调用等价，只是形状不同。
		ast.Inspect(body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Memory" || claimed[sel.Pos()] {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == recv {
				out = append(out, recv+".Memory（取值）")
			}
			return true
		})
	}
	// 第三趟：包级种子构造函数调用。
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && seedFuncs[id.Name] {
			out = append(out, id.Name+"()")
		}
		return true
	})
	return out
}

// uniqSorted 排序去重（同一方法里重复出现同一形状，读起来是噪声）。
func uniqSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// receiverIdentName 取接收者变量名（`func (s *SQLiteStore)` → "s"）；匿名接收者返回空串。
func receiverIdentName(field *ast.Field) string {
	if len(field.Names) == 0 {
		return ""
	}
	return field.Names[0].Name
}

// TestSeedRefDetectorCatchesEvasions 钉住检测器本身：三种绕过写法必须都被登记。
//
// ★这个测试是上面那道守卫的守卫。守卫失效不会有任何症状——它照常 PASS，
// 只是从此什么都拦不住；而"检测器认不认得这种写法"只有拿源码喂给它才知道。
// 三个正例分别对应文件头 ①②③ 三个真实存在过的口径缺口。
func TestSeedRefDetectorCatchesEvasions(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		method string // 期望被登记的方法名；空 = 期望一处都不登记
	}{{
		name: "辅助方法里打底（既不是接口方法也不同名）",
		src: `package store
func (s *SQLiteStore) userDirectories(ctx context.Context) []Directory {
	b, _ := s.Memory.Users(ctx)
	return b.Directories
}`,
		method: "userDirectories",
	}, {
		name: "先把 s.Memory 存进局部变量再调",
		src: `package store
func (s *SQLiteStore) Users(ctx context.Context) (UserDirBundle, error) {
	m := s.Memory
	return m.Users(ctx)
}`,
		method: "Users",
	}, {
		name: "取方法值（不立刻调用）",
		src: `package store
func (s *SQLiteStore) Users(ctx context.Context) (UserDirBundle, error) {
	f := s.Memory.Users
	return f(ctx)
}`,
		method: "Users",
	}, {
		name: "包级种子构造函数打底（连 s.Memory 都不出现）",
		src: `package store
func seedApps() []App { return nil }
func (s *SQLiteStore) Apps(ctx context.Context) (AppBundle, error) {
	apps := seedApps()
	return AppBundle{Apps: apps}, nil
}`,
		method: "Apps",
	}, {
		name: "反例：不碰种子的正常实现一处都不登记",
		src: `package store
func seedApps() []App { return nil }
func (s *SQLiteStore) Apps(ctx context.Context) (AppBundle, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM apps")
	_ = rows
	return AppBundle{}, err
}`,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "probe.go", c.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("解析探针源码失败: %v", err)
			}
			found, total, _ := collectSeedRefs([]*ast.File{f})
			if c.method == "" {
				if total != 0 || len(found) != 0 {
					t.Fatalf("反例被误报成种子引用：%v", found)
				}
				return
			}
			refs, ok := found[c.method]
			if !ok {
				t.Fatalf("这种写法没被检测到（守卫存在同形状缺口，会让真实残留隐身）：登记结果 %v", found)
			}
			if total == 0 {
				t.Fatal("引用总数为 0，与登记结果矛盾")
			}
			t.Logf("已登记 %s → %v", c.method, refs)
		})
	}
}
