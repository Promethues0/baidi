// Package buildinfo 是服务端二进制的**版本身份**，由构建期 -ldflags -X 注入。
//
// ★为什么必须是两个字段，而不是一个「版本号」：
//
//	Semantic（语义版本 x.y.z）—— 发布方**声明**的东西。升级判定只认它：
//	    能不能升、是不是降级、够不够 minSource，全靠它排序。git 哈希排不出序。
//	Build（git 短哈希 + 构建时间）—— 这一份二进制**到底**是哪次构建产出的。
//	    出事那天要拿它去对代码，而语义版本对不上任何一次提交
//	    （同一个 0.3.0 可以被构建一百次，其中九十九次含着不同的代码）。
//
// 把两件事塞进一个字段，就必然二选一：写语义版本则永远查不到是哪次构建，
// 写 git 哈希则升级判定整个失效——后者正是本次改造前网关的真实形态：
// deploy/build.sh 注入的是 `git rev-parse --short HEAD`，
// 而 upgrade.CheckUpgrade 对它 ParseVersion 必失败 →
// **每一台按脚本装出来的网关都被判成「版本将与控制面不一致」**，
// 控制台那一栏于是恒为黄色，组件一致性校验退化成一句永远为真的告警。
//
// ★为什么「未注入」必须如实说，不能回落到源码里的常量：
//
//	改造前控制面版本是 `const Version = "0.3.0"`——而 `-ldflags -X` **对常量无效且不报错**
//	（Go 链接器只改可写的字符串变量；实测：对 const 注入后二进制里仍是旧值，退出码 0）。
//	于是「当前版本」与发布动作彻底脱钩：源码改一行才算发一版，构建脚本说了不算。
//	把缺失回落成那个常量，等于让一个**根本没经过发布流程**的二进制（go run、开发机
//	自己 go build 的、CI 里随手编的）自称 0.3.0，而升级判定会一本正经地拿它去比大小。
//	空 = 未注入 = 不可判定，这是本项目对「探不到」的一贯处置。
//
// 单一真相来源是仓库根的 VERSION 文件：deploy/build.sh 读它并注入。
// 发布动作 = 改 VERSION（而不是改一行 Go 源码），构建产物随即带上它。
package buildinfo

import "strings"

// 三个值由 deploy/build.sh 经 -ldflags -X 注入，例如：
//
//	-X baidi.dev/control/internal/buildinfo.semantic=0.4.0
//	-X baidi.dev/control/internal/buildinfo.commit=a9ae190
//	-X baidi.dev/control/internal/buildinfo.builtAt=2026-09-10T12:00:00Z
//
// ★必须是 var 不是 const：-X 对常量静默无效（见包注释）。
// ★缺省值必须是空串不是 "dev"/"0.0.0"：任何非空缺省都是一句"我知道我是哪一版"的谎，
// 而 ParseVersion 对 "dev" 失败与对 "" 失败在下游是两种措辞（前者会被读成"版本号写错了"）。
var (
	semantic = ""
	commit   = ""
	builtAt  = ""
)

// NotInjected 展示层对「未注入」的统一措辞。
//
// 后端下发的仍是空串（机读的三态判据），这一句只用于日志与 CLI 直出。
// 前端另有自己的渲染，两边都不许把它显示成 0.0.0 或 dev。
const NotInjected = "未注入"

// Info 一个服务端二进制的版本身份。三个字段各自独立缺席——
// 只注入了语义版本、没注入构建标识（例如手工 go build 时只带了 -X …semantic）
// 是完全可能的形态，不该被折成"整体未注入"。
type Info struct {
	// Semantic 语义版本 x.y.z。"" = 未注入（不可判定），**不是** 0.0.0。
	Semantic string `json:"semantic"`
	// Commit 构建自哪个提交（git 短哈希）。"" = 未注入。
	Commit string `json:"commit"`
	// BuiltAt 构建时间（RFC3339）。"" = 未注入。
	BuiltAt string `json:"builtAt"`
}

// Current 本进程的版本身份。
func Current() Info {
	return Info{
		Semantic: strings.TrimSpace(semantic),
		Commit:   strings.TrimSpace(commit),
		BuiltAt:  strings.TrimSpace(builtAt),
	}
}

// Injected 语义版本是否已注入。升级判定的前置条件——没有它就什么都判不了。
func (i Info) Injected() bool { return i.Semantic != "" }

// SemanticText 语义版本的展示文案（未注入时如实说）。
func (i Info) SemanticText() string {
	if i.Semantic == "" {
		return NotInjected
	}
	return i.Semantic
}

// BuildText 构建标识的展示文案：`短哈希 · 构建时间`。
//
// 两半各自可缺席，只有**两半都缺**才是"未注入"——
// 缺一半时如实只显示另一半，把它整体折成"未注入"会把已知的那半也丢掉。
func (i Info) BuildText() string {
	switch {
	case i.Commit != "" && i.BuiltAt != "":
		return i.Commit + " · " + i.BuiltAt
	case i.Commit != "":
		return i.Commit
	case i.BuiltAt != "":
		return i.BuiltAt
	default:
		return NotInjected
	}
}

// BuildID 构建标识的**机读**形式：两半都缺时是**空串**。
//
// ★与 BuildText 的区别就是这一点，而它是一条纪律不是风格：
// 凡是上报、落库、经 JSON 出网的地方一律用 BuildID——BuildText 会在"什么都不知道"时
// 吐出「未注入」三个字，那三个字一旦进了报文/数据库，下游就再也分不出
// 「对面明确说了它不知道」与「对面报了一个叫"未注入"的构建号」。
// 展示层（日志、-version 直出、页面）才用 BuildText。
func (i Info) BuildID() string {
	if i.Commit == "" && i.BuiltAt == "" {
		return ""
	}
	return i.BuildText()
}

// String 一行人话，给启动日志与 `-version` 用。
func (i Info) String() string {
	return "语义版本 " + i.SemanticText() + "，构建 " + i.BuildText()
}

// Note 语义版本未注入时的一句处置说明（后端下发、页面原样显示，不让前端自己编）。
//
// 措辞要点：说清「这不是坏了」也说清「因此判不了什么」。改造前这里什么都不说，
// 而升级校验会给出一句「无法解析当前版本 ""」——管理员只会去怀疑自己粘的 manifest。
const Note = "本进程的语义版本未注入：这一份二进制不是 deploy/build.sh 产出的交付件" +
	"（go run / 手工 go build 都不带版本）。因此「当前版本」不可判定，升级包校验会一律拒绝——" +
	"这是 fail-closed：拿一个猜出来的版本号去判「是不是降级」，判错的后果是数据库被旧版打开。" +
	"修法：用 deploy/build.sh 重新构建并重新部署（语义版本取自仓库根的 VERSION 文件）。"
