package standby

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// deploy/promote-standby.sh 的 **dry-run 逻辑验证**。
//
// ★为什么值得用一条 Go 用例来跑一段 shell：切换脚本是这套温备唯一的"出口"，
// 而它平时永远不会被执行——真跑它的那一天，是主机已经没了的那一天。
// 一段没人跑过的恢复脚本与"写了一句请手工恢复"没有本质区别。
// 干跑覆盖到了它全部的判定分支：前置检查、完整性校验、路径映射、以及
// **校验不通过时绝不碰现网文件**这条最要紧的性质。
//
// 正式执行那一半（停服务 / 覆盖 / 起服务 / 自检）需要 systemd 与 root，本机与 CI 都不跑，
// 这条边界与 IPSec 实机互通、系统解析器配置同性质，已写进 docs/ARCHITECTURE.md 第七节。

func promoteScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("拿不到当前文件路径")
	}
	// control/internal/standby/ → 仓库根 → deploy/
	p := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "deploy", "promote-standby.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("找不到切换脚本 %s：它是温备唯一的出口，不能没有", p)
	}
	return p
}

// buildStandbyBin 编出 baidi-standby，脚本要真调它做校验与解包。
func buildStandbyBin(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("-short：跳过需要编译二进制的脚本用例")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("本机没有 bash")
	}
	bin := filepath.Join(t.TempDir(), "baidi-standby")
	cmd := exec.Command("go", "build", "-o", bin, "baidi.dev/control/cmd/baidi-standby")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("编译 baidi-standby 失败: %v\n%s", err, out)
	}
	return bin
}

// runPromote 跑一次脚本，回 (退出码, 合并输出)。
func runPromote(t *testing.T, script string, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if err != nil {
		if ok := asExitError(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("执行脚本失败: %v\n%s", err, out)
		}
	}
	return code, string(out)
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// TestPromoteDryRunOnGoodBackup 干跑通过：校验 + 解包 + 打印覆盖清单，且一个现网文件都不碰。
func TestPromoteDryRunOnGoodBackup(t *testing.T) {
	bin := buildStandbyBin(t)
	script := promoteScript(t)

	dir := t.TempDir()
	if _, err := Adopt(dir, makeBackup(t, true), testPass, "standby-1", "https://p:8092", 600, now); err != nil {
		t.Fatalf("准备本地备份: %v", err)
	}
	prefix := filepath.Join(t.TempDir(), "opt-baidi") // 刻意不预先创建：干跑不该造出任何东西

	code, out := runPromote(t, script, []string{"BAIDI_STANDBY_PASSPHRASE=" + testPass},
		"--dry-run", "--dir", dir, "--bin", bin, "--prefix", prefix)
	if code != 0 {
		t.Fatalf("干跑应成功，退出码 %d：\n%s", code, out)
	}
	for _, want := range []string{"校验备份完整性", "将要覆盖的文件", "干跑通过"} {
		if !strings.Contains(out, want) {
			t.Errorf("输出里应有 %q：\n%s", want, out)
		}
	}
	// 路径映射要出现在清单里（映射错了的表现是"恢复成功但那份材料没在起作用"）
	if !strings.Contains(out, filepath.Join(prefix, "data", "baidi.db")) {
		t.Errorf("清单里应写明 baidi.db 的落点：\n%s", out)
	}
	if !strings.Contains(out, filepath.Join(prefix, "etc", "keys", "jwt-ed25519.pem")) {
		t.Errorf("清单里应写明签名私钥的落点：\n%s", out)
	}
	// 本地同步状态要被打出来：切换前唯一该看的就是"盘上这份是什么时候的、落后多久"
	for _, want := range []string{"syncedAt", "lagSeconds", "rpo"} {
		if !strings.Contains(out, want) {
			t.Errorf("干跑应打印本地同步状态里的 %s：\n%s", want, out)
		}
	}
	if _, err := os.Stat(prefix); !os.IsNotExist(err) {
		t.Fatalf("干跑不得在目标前缀下造出任何东西（%s 竟然存在）", prefix)
	}
}

// TestPromoteRefusesBrokenBackup 备份坏掉时**在碰现网文件之前**就停住。
// 这条比"能恢复"更重要：先停服务再发现备份解不开，等于亲手制造一次停机。
func TestPromoteRefusesBrokenBackup(t *testing.T) {
	bin := buildStandbyBin(t)
	script := promoteScript(t)

	dir := t.TempDir()
	if _, err := Adopt(dir, makeBackup(t, true), testPass, "standby-1", "", 600, now); err != nil {
		t.Fatal(err)
	}
	// 直接把盘上那份改坏（模拟磁盘损坏 / 被截断）
	bak := filepath.Join(dir, BackupFile)
	b, err := os.ReadFile(bak)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bak, corrupt(b), 0o600); err != nil {
		t.Fatal(err)
	}

	prefix := filepath.Join(t.TempDir(), "opt-baidi")
	code, out := runPromote(t, script, []string{"BAIDI_STANDBY_PASSPHRASE=" + testPass},
		"--dry-run", "--dir", dir, "--bin", bin, "--prefix", prefix)
	if code == 0 {
		t.Fatalf("坏备份必须让脚本失败：\n%s", out)
	}
	if !strings.Contains(out, "校验不通过") {
		t.Errorf("失败原因要说清是校验不通过：\n%s", out)
	}
	if _, err := os.Stat(prefix); !os.IsNotExist(err) {
		t.Fatal("校验失败后不得动目标前缀")
	}
}

// TestPromoteRefusesMissingPassphraseAndBackup 两个前置检查各自给出能照做的错误。
func TestPromoteRefusesMissingPassphraseAndBackup(t *testing.T) {
	bin := buildStandbyBin(t)
	script := promoteScript(t)
	dir := t.TempDir()

	// 没口令
	code, out := runPromote(t, script, []string{"BAIDI_STANDBY_PASSPHRASE="},
		"--dry-run", "--dir", dir, "--bin", bin)
	if code == 0 || !strings.Contains(out, "BAIDI_STANDBY_PASSPHRASE") {
		t.Errorf("缺口令应失败并点名环境变量（%d）：\n%s", code, out)
	}
	// 有口令但从未同步过
	code, out = runPromote(t, script, []string{"BAIDI_STANDBY_PASSPHRASE=" + testPass},
		"--dry-run", "--dir", dir, "--bin", bin)
	if code == 0 || !strings.Contains(out, "从未成功同步") {
		t.Errorf("没有备份时应失败并说明后果（%d）：\n%s", code, out)
	}
}
