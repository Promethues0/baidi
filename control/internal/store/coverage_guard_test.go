// coverage_guard_test.go SQLiteStore 嵌入陷阱防扩散守卫。
//
// 背景（审计根因 #1）：`type SQLiteStore struct{ *Memory }` 是嵌入而非接口实现——
// Store 接口新增方法后，SQLiteStore 漏写对应的 SQLite 版**不是编译错误**，而是
// 静默落回嵌入的 *Memory 演示种子。apps.resource_id 断链、System/Gateway 页
// 长期吃种子数据，都是这个机制的产物：功能"看起来能用"，数据却不是库里那份。
//
// 本守卫用 go/ast 解析本包源码，把「Store 接口方法集合」与「SQLiteStore 显式
// 定义的方法集合」做差，要求差集与下方豁免清单**双向严格相等**：
//   - 新接口方法没写 SQLite 版又没豁免 → 失败（防新增静默缺口）；
//   - 豁免清单里的方法已经有了真实现 → 也失败（提醒删清单项，防清单腐烂）。
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

// seedExemptions 已知仍落回 Memory 种子的 Store 接口方法。
//
// ★清单现在是空的：曾经的五项已全部脱壳——
//   - System / Devices：补上了真 SQLite 实现；
//   - AuthSrc：改由 auth_sources 真实行构建（(*SQLiteStore).AuthSrc）；
//   - Gateway：整个方法从 Store 移除，网关与隐身页改由 api 层按 mTLS 注册心跳
//     的在线登记构建（api/gatewaypage.go）——真相不在库里，就不该在 Store 上留口子；
//   - OnlineSessions：整个方法从 Store 移除，无网关上报即空态（安全读数不编）。
//
// 新增接口方法若要吃种子，必须在此登记并说明理由：哪个页面在吃、为什么暂时没有
// 真实数据源、以及补真实现的路径。登记本身不是通行证——先问一句"这个页面是不是
// 干脆不该显示这块数据"，删掉一块假面板通常比给它配一份假数据更接近正确答案。
var seedExemptions = map[string]string{}

// TestSQLiteStoreCoversStoreInterface 双向断言：
// 接口方法 ∖ SQLiteStore 显式方法 == seedExemptions 的键集合。
func TestSQLiteStoreCoversStoreInterface(t *testing.T) {
	ifaceMethods, sqliteMethods := collectMethodSets(t)

	if len(ifaceMethods) == 0 {
		t.Fatal("没有解析到 Store 接口的任何方法——守卫自身失效，请检查 collectMethodSets")
	}
	if len(sqliteMethods) == 0 {
		t.Fatal("没有解析到任何 *SQLiteStore 显式方法——守卫自身失效，请检查 collectMethodSets")
	}

	// 方向一：接口方法既没有 SQLite 显式实现、也不在豁免清单 → 新的静默缺口。
	var uncovered []string
	for m := range ifaceMethods {
		if _, ok := sqliteMethods[m]; ok {
			continue
		}
		if _, exempt := seedExemptions[m]; exempt {
			continue
		}
		uncovered = append(uncovered, m)
	}
	sort.Strings(uncovered)
	for _, m := range uncovered {
		t.Errorf("Store 接口方法 %s 没有 *SQLiteStore 显式实现：嵌入 *Memory 会使该方法静默退回演示种子数据（不是编译错误、也没有任何运行期报错）。请补一份 SQLite 实现（领域文件同名 _sqlite.go），或确认它确实暂吃种子后显式加入 coverage_guard_test.go 的 seedExemptions 并注释说明是哪个页面在吃种子", m)
	}

	// 方向二：豁免清单里的方法已经有了 SQLite 显式实现 → 清单腐烂。
	var stale []string
	for m := range seedExemptions {
		if _, ok := sqliteMethods[m]; ok {
			stale = append(stale, m)
		}
	}
	sort.Strings(stale)
	for _, m := range stale {
		t.Errorf("豁免清单条目 %s 已经有 *SQLiteStore 真实现了：请把它从 coverage_guard_test.go 的 seedExemptions 删除，防止清单腐烂后掩盖未来同名方法的回退", m)
	}

	// 顺带防拼写/防漂移：豁免的名字必须仍是 Store 接口方法（接口方法改名或删除后清单条目会悬空）。
	var dangling []string
	for m := range seedExemptions {
		if _, ok := ifaceMethods[m]; !ok {
			dangling = append(dangling, m)
		}
	}
	sort.Strings(dangling)
	for _, m := range dangling {
		t.Errorf("豁免清单条目 %s 不是 Store 接口的方法（拼写错误或接口已改名/删除）：请修正或删除该条目", m)
	}
}

// collectMethodSets 解析本包所有非测试 .go 源文件，返回
// Store 接口方法名集合 与 *SQLiteStore（含值接收者 SQLiteStore）显式方法名集合。
func collectMethodSets(t *testing.T) (ifaceMethods, sqliteMethods map[string]bool) {
	t.Helper()
	ifaceMethods = map[string]bool{}
	sqliteMethods = map[string]bool{}

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
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 {
					continue
				}
				if receiverTypeName(d.Recv.List[0].Type) == "SQLiteStore" {
					sqliteMethods[d.Name.Name] = true
				}
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || ts.Name.Name != "Store" {
						continue
					}
					it, ok := ts.Type.(*ast.InterfaceType)
					if !ok {
						continue
					}
					for _, field := range it.Methods.List {
						// 具名字段才是方法；无名字段是嵌入接口（当前 Store 没有，出现了也提醒升级守卫）。
						if len(field.Names) == 0 {
							t.Fatalf("Store 接口出现嵌入接口 %v：本守卫只收集直接声明的方法，请升级 collectMethodSets 展开嵌入接口", field.Type)
						}
						for _, n := range field.Names {
							ifaceMethods[n.Name] = true
						}
					}
				}
			}
		}
	}
	return ifaceMethods, sqliteMethods
}

// receiverTypeName 取接收者的类型名（剥掉指针与泛型实参）。
func receiverTypeName(expr ast.Expr) string {
	for {
		switch e := expr.(type) {
		case *ast.StarExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.Ident:
			return e.Name
		default:
			return ""
		}
	}
}
