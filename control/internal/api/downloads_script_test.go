package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// clients/build-artifacts.sh 的**真执行**用例。
//
// ★为什么值得用 Go 用例去跑一段 shell：这个脚本产出的 manifest.json 是下载中心页面的
// 全部真相来源，而它与控制面之间有两条**只靠约定维系**的契约——
//  1. 占位文案要与 placeholderManifest() 逐字一致（manifest 缺失时页面回落到后者，
//     不一致就会让同一个平台在两种情况下说两种话）；
//  2. 工作区脏就得把溯源标成 -dirty（否则包会冒充一个它并不对应的干净 commit，
//     而 annotateProvenance 会照着说「与当前源码一致」）。
//
// 这两条都不在任何一处代码的类型系统里，只能靠真的跑一遍脚本、读它吐出来的 JSON 来守。
// 与 standby/promote_script_test.go 同一个理由：平时没人跑的脚本 = 没有的脚本。

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("拿不到当前文件路径")
	}
	// control/internal/api/ → 仓库根
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}

// 造一个只含 build-artifacts.sh 所需最小结构的**临时 git 仓库**，返回它的根。
//
// 刻意不在真仓库里跑：脚本头一句就是 `rm -rf deploy/artifacts/downloads`，
// 在真仓库跑会把本机已有的产物目录铲掉。
func fakeClientsRepo(t *testing.T) string {
	t.Helper()
	for _, bin := range []string{"bash", "git", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("本机没有 %s，跳过", bin)
		}
	}
	root := t.TempDir()
	src := filepath.Join(repoRoot(t), "clients", "build-artifacts.sh")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("读不到 %s：它是产物与 manifest 的唯一生成者，不能没有", src)
	}
	if err := os.MkdirAll(filepath.Join(root, "clients", "desktop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "clients", "build-artifacts.sh"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	// 版本号从 package.json 读（脚本不写死版本）
	if err := os.WriteFile(filepath.Join(root, "clients", "desktop", "package.json"),
		[]byte(`{"name":"baidi-desktop","version":"9.9.9"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "init", "-q")
	git(t, root, "add", "-A")
	git(t, root, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init")
	return root
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// runArtifacts 跑一次脚本，返回合并输出。
func runArtifacts(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join(root, "clients", "build-artifacts.sh"))
	cmd.Dir = root
	// 注入变量会绕过 git 取数那一段，这里要的正是那一段
	cmd.Env = append(os.Environ(), "BAIDI_CLIENT_SRC_REV=", "BAIDI_APK_SRC_REV=", "BAIDI_APK_BUILT_AT=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build-artifacts.sh 失败：%v\n%s", err, out)
	}
	return string(out)
}

func readManifest(t *testing.T, root string) map[string]ClientDownload {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "deploy", "artifacts", "downloads", "manifest.json"))
	if err != nil {
		t.Fatalf("没生成 manifest.json：%v", err)
	}
	var m downloadsManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("manifest.json 不是合法 JSON：%v\n%s", err, b)
	}
	out := map[string]ClientDownload{}
	for _, c := range m.Clients {
		out[c.Platform] = c
	}
	return out
}

// 脚本产出的占位文案必须与 placeholderManifest() **逐字一致**。
//
// 回归背景（两条，方向相反但症状同形——用户看到的都是"这一行说的话不对"）：
//   - macOS 缺 dmg 时脚本写的是 note=""，而 manifest 整体缺失时页面回落到
//     placeholderManifest 的「构建中，敬请期待」：同一个平台，某些情况下有一句解释，
//     另一些情况下空着，没有任何提示说明为什么没有包；
//   - Windows 两处都写「构建中，敬请期待」，可它缺的是实机验证（包与 wintun.dll 都齐了），
//     CI 产物也刻意不进下载中心——那是一个不会到来的版本，用户会一直等，
//     而正确的下一步（找管理员要 UNVERIFIED 包）没人告诉他。
func TestBuildArtifactsPlaceholdersMatchServer(t *testing.T) {
	root := fakeClientsRepo(t)
	runArtifacts(t, root) // 这台机器上既没有 dmg 也没有 APK → 六平台全占位
	got := readManifest(t, root)

	want := placeholderManifest()
	if len(got) != len(want.Clients) {
		t.Fatalf("平台数 %d，期望 %d", len(got), len(want.Clients))
	}
	for _, w := range want.Clients {
		g, ok := got[w.Platform]
		if !ok {
			t.Errorf("manifest 缺平台 %s", w.Platform)
			continue
		}
		if g.Available {
			t.Errorf("%s：这台机器上没有包，不该 available=true", w.Platform)
		}
		if g.Label != w.Label {
			t.Errorf("%s label = %q，placeholderManifest 是 %q（两处必须逐字一致）", w.Platform, g.Label, w.Label)
		}
		if g.Note != w.Note {
			t.Errorf("%s note 与 placeholderManifest 不一致（同一平台在两条路径上说两种话）：\n  脚本：%q\n  服务端：%q",
				w.Platform, g.Note, w.Note)
		}
		if g.Note == "" {
			t.Errorf("%s 没有包却一句解释都没有，页面上就是空着的一行", w.Platform)
		}
	}

	// 「敬请期待」只能出现在真的会被构建出来、且装了能用的平台上。
	// ★linux 在这张名单里补得晚了一步：它与 windows 同处境（CI 出得来 .deb/.AppImage、
	// 标 UNVERIFIED、刻意不下发），文案改过来了但没人守着，改回去不会有任何东西报警。
	for _, p := range []string{"ios", "harmony", "windows", "linux"} {
		if strings.Contains(got[p].Note, "敬请期待") {
			t.Errorf("%s 的占位文案不该说「敬请期待」——那是给一个不会到来的版本许诺：%q", p, got[p].Note)
		}
	}
	// Windows 那句必须给得出真实的下一步，否则与「敬请期待」是同一种没用。
	// ★还要说清验证缺口：包现在组件是齐的（wintun.dll 随包分发），只说"找管理员要"
	// 而不说为什么不上架，用户会以为这只是流程麻烦，而不是一份没验完的产物。
	// 缺口要按**此刻**的证据说（clients/BUILD.md 第十节）：ARM64 一台真机 A/B 过、C 未完，
	// x64 一次没跑——既不能退回「均未实机验证」（把已有的证据说没了），也不能只写「UNVERIFIED」
	// 这个标签（用户看不出到底缺什么）。
	n := got["windows"].Note
	for _, must := range []string{"未验", "x64", "未实机", "UNVERIFIED", "联系管理员"} {
		if !strings.Contains(n, must) {
			t.Errorf("Windows 占位要说清缺什么验证、为什么没有包、找谁（缺 %q）：%q", must, n)
		}
	}
	if strings.Contains(n, "均未实机验证") {
		t.Errorf("Windows 占位不该再说「均未实机验证」——ARM64 真机的阶段 A/B 证据已经存在（BUILD.md 10.3）：%q", n)
	}
}

// 工作区脏（含**已 add 未提交**与**未跟踪新增**）必须把溯源标成 -dirty。
//
// ★回归背景：判据曾是 `git diff --quiet -- clients/`，只比工作树与索引——
// 已 `git add` 的改动与未跟踪文件全被判成干净。而"改完先 add、构建验证一轮再提交"
// 正是最常见的节奏：那一轮出的包会写上 sourceCommit=<上一个 commit> 且不带 -dirty，
// 控制面 annotateProvenance 于是判定「与当前源码一致」，页面一片正常。
// 方向恰好是"看起来是新的"，正是这套溯源机制要消灭的谎。
func TestBuildArtifactsDirtyDetection(t *testing.T) {
	root := fakeClientsRepo(t)

	// ① 干净：不该有 dirty
	if out := runArtifacts(t, root); strings.Contains(out, "-dirty") {
		t.Fatalf("干净工作区被误判成脏：\n%s", out)
	}

	// ② 已 add 未提交（旧实现在这里判成干净）
	f := filepath.Join(root, "clients", "desktop", "新文件.ts")
	if err := os.WriteFile(f, []byte("export const x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "clients/desktop/新文件.ts")
	if out := runArtifacts(t, root); !strings.Contains(out, "-dirty") {
		t.Errorf("已 add 未提交的改动必须算脏（旧判据 git diff --quiet 只比工作树与索引）：\n%s", out)
	}

	// ③ 未跟踪新增（旧实现同样判成干净）
	git(t, root, "reset", "-q")
	if out := runArtifacts(t, root); !strings.Contains(out, "-dirty") {
		t.Errorf("未跟踪的新增文件必须算脏：\n%s", out)
	}

	// ④ 已跟踪文件被改（旧实现唯一能认出来的那种）
	os.Remove(f)
	if err := os.WriteFile(filepath.Join(root, "clients", "desktop", "package.json"),
		[]byte(`{"name":"baidi-desktop","version":"9.9.9","x":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := runArtifacts(t, root); !strings.Contains(out, "-dirty") {
		t.Errorf("工作树改动必须算脏：\n%s", out)
	}
}

// Windows / Linux 的 CI 产物必须带溯源，与安卓那份 apk-provenance.env 同一条纪律。
//
// ★回归背景：clients.yml 里「取 clients/ 子树 commit」这一步在三个平台都跑，
// 但 steps.rev.outputs.rev 只在 macOS 分支被消费——两份 UNVERIFIED artifact 里
// 只有安装包和一份 README，下载的人无从知道它出自哪个 commit、什么时候构建。
// 将来有人手工把它铺进 downloads/ 时只能靠 git log 事后猜一个，而猜错的方向
// 恰好是"看起来是新的"（671eaeb 给安卓建 apk-provenance.env 时写的就是这句）。
//
// 这条用例读的是 YAML 文本而不是解析结构：控制面不该为了一条工作流约定引 YAML 依赖，
// 而"这个文件里有没有把溯源随包发下去"用文本就能判，退回旧实现必失败。
func TestClientsWorkflowShipsProvenance(t *testing.T) {
	p := filepath.Join(repoRoot(t), ".github", "workflows", "clients.yml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("读不到 %s：%v", p, err)
	}
	y := string(b)

	// 「取 clients/ 子树 commit」那一步在三个平台都跑；它的输出必须在 macOS 之外也被消费，
	// 否则「三份产物都已盖章」只是读工作流的人的错觉。
	if n := strings.Count(y, "steps.rev.outputs.rev"); n < 2 {
		t.Errorf("steps.rev.outputs.rev 只被消费 %d 次：那一步在三个平台都跑，产物却只有一份带溯源", n)
	}
	// 生成溯源文件的那个步骤必须覆盖 macOS 之外的两个 runner
	var 写溯源步骤 string
	for _, st := range strings.Split(y, "\n      - name:") {
		if strings.Contains(st, `> "$BUNDLE/build-provenance.env"`) {
			写溯源步骤 = st
		}
	}
	if 写溯源步骤 == "" {
		t.Fatal("工作流里没有生成 build-provenance.env 的步骤")
	}
	if !strings.Contains(写溯源步骤, "runner.os != 'macOS'") {
		t.Errorf("溯源步骤要覆盖 macOS 之外的两个 runner（if: runner.os != 'macOS'）：%s", 写溯源步骤)
	}
	// 两份 UNVERIFIED artifact 的上传步骤各自要把溯源文件列进 path。
	// Windows 的产物名自 ARM64 交叉线并入后按 matrix.arch 模板化（x86_64 与 aarch64
	// 两条腿共用同一个上传步骤），所以这里钉的是模板原文而不是展开值。
	for _, name := range []string{
		"baidi-desktop-linux-x86_64-UNVERIFIED",
		"baidi-desktop-windows-${{ matrix.arch }}-UNVERIFIED",
	} {
		i := strings.Index(y, name)
		if i < 0 {
			t.Errorf("工作流里找不到 artifact %s", name)
			continue
		}
		// 从 artifact 名往后到下一个步骤（"      - name:"）之间就是它的 path 清单
		rest := y[i:]
		if j := strings.Index(rest, "\n      - name:"); j >= 0 {
			rest = rest[:j]
		}
		if !strings.Contains(rest, "build-provenance.env") {
			t.Errorf("%s 的产物里没有 build-provenance.env：下载的人无从知道它出自哪个 commit\n%s", name, rest)
		}
	}
}

// TestShippedManifestMatchesPlaceholderNotes 仓库里**已交付的那份** manifest.json，
// 其未上架平台的文案必须与 placeholderManifest() 逐字一致。
//
// ★上面那条用例守的是「脚本生成的」manifest，这条守的是「仓库里躺着的、会被 build.sh
// 拷进交付件、最终装到演示机上的」那一份——两者不是同一个东西。
// 实际踩到过：`wintun.dll` 从「需自备（本仓库不分发）」改成「构建期官方取件 + 哈希校验、
// 随包分发」之后，脚本与 placeholderManifest() 都跟着改了，**而这份产物 manifest 没有**。
// 于是演示站的下载中心对着用户说了三个月「需自备 wintun.dll」——一句已经不成立的话，
// 且它恰好会劝退唯一有可能去做实机验证的那批人。
//
// 只比未上架平台的 note：已上架条目带 file/size/sha256，本来就该与占位不同。
func TestShippedManifestMatchesPlaceholderNotes(t *testing.T) {
	path := filepath.Join(repoRoot(t), "deploy", "artifacts", "downloads", "manifest.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("仓库里没有已交付的 manifest（%v）", err)
	}
	var shipped downloadsManifest
	if err := json.Unmarshal(b, &shipped); err != nil {
		t.Fatalf("已交付的 manifest.json 解析失败: %v", err)
	}
	want := map[string]string{}
	for _, c := range placeholderManifest().Clients {
		want[c.Platform] = c.Note
	}
	for _, c := range shipped.Clients {
		if c.Available {
			continue // 已上架条目的 note 是它自己的（如「调试签名版…」），不参与比对
		}
		if w, ok := want[c.Platform]; ok && c.Note != w {
			t.Errorf("平台 %s 的占位文案与 placeholderManifest() 不一致——"+
				"这份 manifest 会被装到演示机上，它说的话必须与代码里那份相同：\n"+
				"  已交付：%s\n  代码里：%s", c.Platform, c.Note, w)
		}
	}
}
