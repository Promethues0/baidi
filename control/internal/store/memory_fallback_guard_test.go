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
// 本守卫用 go/ast 找出这一形态并要求**显式登记**：
//   - 方向一：出现了未登记的以种子打底 → 失败（防新增静默残留）；
//   - 方向二：登记项已经不再碰 Memory → 也失败（提醒删清单，防清单腐烂）；
//   - 方向三：登记项不是 SQLiteStore 的方法（改名/删除后悬空）→ 失败。
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

// memoryFallbacks 已登记的「SQLiteStore 方法体内调用 s.Memory.*」清单，键 = 方法名。
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

// TestNoUnregisteredMemorySeedFallback 三向断言：未登记的种子打底 / 清单腐烂 / 清单悬空。
func TestNoUnregisteredMemorySeedFallback(t *testing.T) {
	ifaceMethods, sqliteMethods := collectMethodSets(t)
	found, totalMemoryCalls := collectMemoryFallbacks(t, ifaceMethods)

	// 守卫自检：包里必须至少存在一处 s.Memory.<方法> 调用（seed()/backfill* 那几处灌种子的
	// 正常用法）。一处都没找到，说明 AST 匹配的形状已经不成立（比如有人给 Memory 改了
	// 字段名、或改成了接口值），此时"没有发现残留"是假阴性而不是好消息。
	if totalMemoryCalls == 0 {
		t.Fatal("整个包里一处 s.Memory.<方法> 调用都没匹配到：要么 *Memory 嵌入已被彻底移除（那本守卫可以退休了，连同 coverage_guard_test.go 一起），要么 collectMemoryFallbacks 的 AST 形状假设已经失效——后者会让本守卫从此永远通过，请先确认是哪一种")
	}

	// 方向一：以种子打底、却没有登记。
	var unregistered []string
	for m := range found {
		if _, ok := memoryFallbacks[m]; !ok {
			unregistered = append(unregistered, m)
		}
	}
	sort.Strings(unregistered)
	for _, m := range unregistered {
		t.Errorf("*SQLiteStore.%s 在方法体里调用了 %s：这是「以 Memory 种子打底、再局部覆盖」的形态——被你覆盖的字段是真的，**没覆盖到的字段会原样带着演示种子返回给页面**，两者在同一个响应里混排，接口层面看不出区别，也没有任何运行期报错（Users().Directories 的「本地目录 124 / 总部 AD 域 1160」就是这么在真实部署上挂了很久）。请改成逐字段构造：缺哪一段是编译期的零值，不是一份看起来很像真的数字。确实存在没有真实来源的字段，就先考虑删掉那个字段/那块 UI；实在要留，在 memory_fallback_guard_test.go 的 memoryFallbacks 里登记，并写清 Fields（逐个列名）与 Why（为什么没有真实来源、怎么补）",
			m, strings.Join(found[m], " / "))
	}

	// 方向二：登记项已经不再碰 Memory（清单腐烂会掩盖同名方法将来的回退）。
	var stale []string
	for m := range memoryFallbacks {
		if _, ok := found[m]; !ok {
			stale = append(stale, m)
		}
	}
	sort.Strings(stale)
	for _, m := range stale {
		t.Errorf("清单条目 %s 已经不再调用 s.Memory.*（该方法已逐字段脱壳）：请把它从 memory_fallback_guard_test.go 的 memoryFallbacks 删除。留着腐烂条目的代价是——将来有人重新在这个方法里写一句 s.Memory.%s(ctx) 打底时，守卫会认为「这是登记过的」而放行", m, m)
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
}

// collectMemoryFallbacks 解析本包非测试源码，返回
// 「方法名 → 该方法体内出现的 s.Memory.X 调用清单」与包内 s.Memory.X 调用总数。
//
// 判定口径（两者取并集）：
//  1. 该方法是 **Store 接口方法**（即页面/调用方真正读到的那条路径），且方法体里
//     出现任意 s.Memory.X(...) 调用；
//  2. 任意 SQLiteStore 方法调用了 **同名**的 s.Memory.<同名方法>(...)——那正是
//     "打底再覆盖"的标志性写法。
//
// 刻意不把 seed() / backfillAppResourceID() / backfillOrgUnits() 这类**建库灌种子**的
// 调用算进来：它们把种子写进真实表、之后以库为准，与"读取时拿种子填页面"是两回事。
// 它们不是 Store 接口方法，也不调用同名方法，自然落在口径之外——这条豁免是结构性的，
// 不需要维护一份"允许调用 Memory 的函数名单"（那种名单迟早会被顺手加一行绕过去）。
func collectMemoryFallbacks(t *testing.T, ifaceMethods map[string]bool) (found map[string][]string, totalMemoryCalls int) {
	t.Helper()
	found = map[string][]string{}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读取包目录失败: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Body == nil {
				continue
			}
			if receiverTypeName(fn.Recv.List[0].Type) != "SQLiteStore" {
				continue
			}
			recv := receiverIdentName(fn.Recv.List[0])
			calls := memoryCallsIn(fn.Body, recv)
			totalMemoryCalls += len(calls)
			if len(calls) == 0 {
				continue
			}
			var hits []string
			for _, c := range calls {
				if ifaceMethods[fn.Name.Name] || c == fn.Name.Name {
					hits = append(hits, recv+".Memory."+c)
				}
			}
			if len(hits) > 0 {
				sort.Strings(hits)
				found[fn.Name.Name] = hits
			}
		}
	}
	return found, totalMemoryCalls
}

// memoryCallsIn 返回方法体内所有 <recv>.Memory.X(...) 调用的 X 名字。
// recv 为空（匿名接收者 `func (*SQLiteStore) F()`）时不可能写出这种调用，直接返回空。
func memoryCallsIn(body *ast.BlockStmt, recv string) []string {
	if recv == "" {
		return nil
	}
	var out []string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// 形状：CallExpr{ Fun: Sel{ X: Sel{ X: Ident(recv), Sel: "Memory" }, Sel: X } }
		outer, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		inner, ok := outer.X.(*ast.SelectorExpr)
		if !ok || inner.Sel.Name != "Memory" {
			return true
		}
		if id, ok := inner.X.(*ast.Ident); ok && id.Name == recv {
			out = append(out, outer.Sel.Name)
		}
		return true
	})
	return out
}

// receiverIdentName 取接收者变量名（`func (s *SQLiteStore)` → "s"）；匿名接收者返回空串。
func receiverIdentName(field *ast.Field) string {
	if len(field.Names) == 0 {
		return ""
	}
	return field.Names[0].Name
}
