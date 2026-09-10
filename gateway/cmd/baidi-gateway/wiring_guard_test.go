package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 接线守卫（wave11）：cplane.Client 上每一个 Set* 都必须在 main.go 里有真实调用点。
//
// ★为什么需要这条：这些 setter 是「网关把自己的某个事实报给控制面」的唯一接线，
// 而**删掉调用行不会有任何东西变红**——代码照样编译、网关照样跑、心跳照样发，
// 只是那一项在控制面侧永远是「未上报 / 不可判定」。症状全部落在远端页面上：
//
//   - 少了 SetStealth   → 网关页那台永远显示「隐身未上报」，而 /diag 把它数进
//     「不可判定」那一栏——与"确实没开隐身"在页面上完全同形；
//   - 少了 SetMetrics   → 设备状态页那台永远「在线但未上报指标」，CPU>80% 告警
//     对它永久沉默（CLAUDE.md 里 posture 的 unknown 那条纪律，同一族）；
//   - 少了 SetTunnelIDStrict → 控制面把这台当「旧网关/不可判定」，
//     于是「隧道身份严格模式有没有真开」这件事在控制台上答不出来；
//   - 少了 SetNAT / SetIfaces → 地址转换页选不出网卡、回执恒空。
//
// 这一族在本仓的既有代码里靠注释维持（「新网关一律要调它」），而注释不是执行方。
// 本守卫是它的执行方：**新增一个 setter 却忘了接线，这条用例当场变红**。
//
// ★刻意做成「有没有调用点」而不是「调用参数对不对」：后者要跑起来才知道，
// 而这条守卫的价值恰恰在于它是编译期就能跑的、零成本的、覆盖全部 setter 的一道网。
// 参数正确性由各自的契约用例负责（例如 cplane/tunnelid_test.go）。
//
// 新增 setter 时若确实**不该**在 main.go 接线（例如只给测试或别的二进制用），
// 把它加进 wiringExempt 并写明理由——豁免清单本身也是一份可复核的记录。
// ★变异实跑记录：删掉 `cp.SetTunnelIDStrict(*tunnelIDStrict)` 那一行 → 本用例当场变红
// （「没有调用点：[SetTunnelIDStrict]」）。**把调用改名**则由编译器拦下，不归本守卫管——
// 这条守卫要防的恰恰是编译器看不见的那一种：整行删掉。
var wiringExempt = map[string]string{}

func TestEveryCplaneSetterIsWired(t *testing.T) {
	setters := cplaneSetters(t)
	if len(setters) == 0 {
		t.Fatal("一个 Set* 都没解析到——守卫本身失效了（比它要防的问题更坏）")
	}
	called := setterCallsInMain(t)

	var missing []string
	for _, name := range setters {
		if why, ok := wiringExempt[name]; ok {
			t.Logf("豁免 %s：%s", name, why)
			continue
		}
		if !called[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("这些 cplane.Client 的 setter 在 cmd/baidi-gateway/main.go 里没有调用点：%v\n"+
			"删掉接线不会有任何东西变红——网关照样跑、心跳照样发，只是那一项在控制面侧\n"+
			"永远是「未上报/不可判定」，而那与「这台确实没启用该功能」在页面上完全同形。\n"+
			"要么补上调用，要么加进 wiringExempt 并写明为什么不该接线。", missing)
	}
}

// cplaneSetters 解析 internal/cplane 包里 Client 上的全部 Set* 方法名。
func cplaneSetters(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("..", "..", "internal", "cplane")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("解析 %s：%v", dir, err)
	}
	var out []string
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || !strings.HasPrefix(fn.Name.Name, "Set") {
					continue
				}
				if !fn.Name.IsExported() || recvTypeName(fn) != "Client" {
					continue
				}
				out = append(out, fn.Name.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

func recvTypeName(fn *ast.FuncDecl) string {
	if len(fn.Recv.List) == 0 {
		return ""
	}
	switch e := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return e.Name
	}
	return ""
}

// setterCallsInMain 收集 main.go 里形如 <任意>.SetXxx(...) 的方法调用名。
//
// 按**方法名**而不是按接收者变量名匹配：接收者叫 cp 还是别的名字是无关紧要的实现细节，
// 而按名字匹配会让「改个变量名就静默失守」——那正是这类守卫最容易自己犯的错。
func setterCallsInMain(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 main.go：%v", err)
	}
	called := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.HasPrefix(sel.Sel.Name, "Set") {
			return true
		}
		called[sel.Sel.Name] = true
		return true
	})
	return called
}
