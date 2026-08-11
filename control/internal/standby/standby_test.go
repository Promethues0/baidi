package standby

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/upgrade"
)

const testPass = "standby-pass-1234"

var now = time.Date(2026, 8, 11, 12, 0, 0, 0, time.Local)

// TestEvaluateThreeStates 集群视图三态：未配置 / 新鲜 / 落后。
// 三态各自的**方向**是这套东西的全部价值——判反了的表现是"页面一直绿着"，
// 而那正是需要它的那天才会被发现。
func TestEvaluateThreeStates(t *testing.T) {
	t.Run("未配置备机", func(t *testing.T) {
		v := Evaluate(nil, now, 0)
		if v.Deployed || v.Mode != ModeSingle || v.Status != "skip" {
			t.Fatalf("未配置备机应回 single/skip/未部署，得到 %+v", v)
		}
		if !strings.Contains(v.Summary, "未配置备机") {
			t.Errorf("文案要说清是「未配置」而不是「不可用」：%q", v.Summary)
		}
		if len(v.Nodes) != 0 {
			t.Errorf("不该凭空造出节点：%+v", v.Nodes)
		}
	})

	t.Run("同步新鲜", func(t *testing.T) {
		v := Evaluate([]Node{{
			NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600,
			LastSyncAt: now.Add(-3 * time.Minute).Unix(), LastPullAt: now.Add(-3 * time.Minute).Unix(),
			LastStatus: "ok", BackupVersion: "0.3.0",
		}}, now, 15*time.Minute)
		if !v.Deployed || v.Mode != ModeWarm || v.Status != "pass" {
			t.Fatalf("新鲜备机应回 warm-standby/pass，得到 %+v", v)
		}
		if v.Nodes[0].State != StateFresh || v.Nodes[0].LagSeconds != 180 {
			t.Errorf("落后秒数应实算：%+v", v.Nodes[0])
		}
		if !strings.Contains(v.RPO, "10 分钟") {
			t.Errorf("RPO 必须原样呈现备机自报的同步间隔：%q", v.RPO)
		}
	})

	t.Run("落后超阈值", func(t *testing.T) {
		v := Evaluate([]Node{{
			NodeID: "standby-1", IntervalSec: 600, LastStatus: "ok",
			LastSyncAt: now.Add(-90 * time.Minute).Unix(),
		}}, now, 15*time.Minute)
		if v.Status != "warn" || v.Nodes[0].State != StateStale {
			t.Fatalf("落后 90 分钟（阈值 30 分钟）应判 stale/warn，得到 %+v", v)
		}
		if !strings.Contains(v.Summary, "落后") {
			t.Errorf("摘要必须说明落后多久：%q", v.Summary)
		}
	})
}

// TestEvaluateNeverSyncedIsNotZeroLag 「从未同步过」不是「落后 0 秒」。
// 补 0 会让一台从来没成功过的备机在页面上显示成刚刚同步完——
// 与「不可判定 ≠ 0」是同一条纪律。
func TestEvaluateNeverSyncedIsNotZeroLag(t *testing.T) {
	v := Evaluate([]Node{{
		NodeID: "standby-1", IntervalSec: 600,
		LastPullAt: now.Add(-time.Minute).Unix(), // 来拉过
		LastStatus: "fail", LastDetail: "校验失败：备份解密失败",
	}}, now, 15*time.Minute)
	if v.Status != "warn" {
		t.Fatalf("从未成功同步应判 warn，得到 %q", v.Status)
	}
	n := v.Nodes[0]
	if n.State != StateNever || n.LagSeconds != -1 {
		t.Fatalf("从未同步应是 never + LagSeconds=-1（不可判定），得到 %+v", n)
	}
	if n.LastSyncAt != "" {
		t.Errorf("从未同步就不该有同步时间：%q", n.LastSyncAt)
	}
	if n.LastPullAt == "" {
		t.Errorf("来拉过是另一个事实，必须照实显示（正是它能区分「拉不到」与「拉到了但校验不过」）")
	}
	if !strings.Contains(v.Summary, "从未成功同步") {
		t.Errorf("摘要要点明这台备机手上没有可用备份：%q", v.Summary)
	}
}

// TestEvaluateFreshButLastRoundFailed 盘上那份还新鲜、但最近一轮失败了：仍要 warn。
// 判成 pass 的话，"连续失败"要等到落后超阈值（默认 15 分钟起）才会被看见。
func TestEvaluateFreshButLastRoundFailed(t *testing.T) {
	v := Evaluate([]Node{{
		NodeID: "standby-1", IntervalSec: 600, LastSyncAt: now.Add(-time.Minute).Unix(),
		LastStatus: "fail", LastDetail: "主机回 503",
	}}, now, 15*time.Minute)
	if v.Status != "warn" || v.Nodes[0].State != StateFresh {
		t.Fatalf("新鲜但最近一轮失败应判 fresh+warn，得到 status=%q node=%+v", v.Status, v.Nodes[0])
	}
	if !strings.Contains(v.Summary, "503") {
		t.Errorf("失败详情要带进摘要：%q", v.Summary)
	}
}

// TestThresholdCappedAgainstSelfReportedInterval 备机自报的间隔能抬高阈值，但抬不过天花板。
// 判定材料来自被判定方时，必须有一个它够不到的上限——否则一台自报间隔 30 天的备机
// 可以让自己永远显示新鲜。
func TestThresholdCappedAgainstSelfReportedInterval(t *testing.T) {
	huge := Node{NodeID: "standby-1", IntervalSec: 30 * 24 * 3600, LastSyncAt: now.Add(-24 * time.Hour).Unix()}
	if got := thresholdFor(huge, 15*time.Minute); got != MaxStaleAfter {
		t.Fatalf("阈值应封顶到 %s，得到 %s", MaxStaleAfter, got)
	}
	v := Evaluate([]Node{huge}, now, 15*time.Minute)
	if v.Nodes[0].State != StateStale {
		t.Fatalf("自报一个巨大的间隔不该让备机免于落后判定：%+v", v.Nodes[0])
	}

	// 正常情形：3×间隔 > 全局阈值时按 3 轮算（一次抖动不刷红）
	n := Node{NodeID: "standby-1", IntervalSec: 1800, LastSyncAt: now.Add(-40 * time.Minute).Unix()}
	if got := thresholdFor(n, 15*time.Minute); got != 90*time.Minute {
		t.Fatalf("阈值应取 max(全局, 3×间隔)=90m，得到 %s", got)
	}
	if Evaluate([]Node{n}, now, 15*time.Minute).Nodes[0].State != StateFresh {
		t.Error("30 分钟间隔的备机落后 40 分钟还不到三轮，不该判落后")
	}
}

// TestUnsupportedAndUnknownAreNotPass 两种"说不出话"的情形都不许回 pass。
func TestUnsupportedAndUnknownAreNotPass(t *testing.T) {
	if v := Unsupported("纯内存演示栈"); v.Status != "skip" || v.Deployed {
		t.Errorf("后端记不下来应是 skip 且未部署：%+v", v)
	}
	if v := Unknown("库读失败"); v.Status != "warn" {
		t.Errorf("读不到备机状态必须 warn 而不是 pass：%+v", v)
	}
}

// ── 备机侧：校验与落盘 ──

// makeBackup 造一份真备份（走生产同一条 upgrade.CreateBackup）。
func makeBackup(t *testing.T, withDB bool) []byte {
	t.Helper()
	src := t.TempDir()
	var sources []upgrade.BackupSource
	if withDB {
		p := filepath.Join(src, "baidi.db")
		if err := os.WriteFile(p, []byte("SQLite format 3\x00fake"), 0o600); err != nil {
			t.Fatal(err)
		}
		sources = append(sources, upgrade.BackupSource{Name: "baidi.db", Path: p})
	}
	k := filepath.Join(src, "jwt.pem")
	if err := os.WriteFile(k, []byte("-----BEGIN PRIVATE KEY-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	sources = append(sources, upgrade.BackupSource{Name: "jwt-ed25519.pem", Path: k})

	var buf bytes.Buffer
	if err := upgrade.CreateBackup(&buf, upgrade.BackupMeta{
		Version: "0.3.0", CreatedAt: "2026-08-11 12:00:00", Note: "温备同步 → standby-1",
	}, testPass, sources); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestAdoptKeepsLocalCopyWhenVerifyFails 校验不过时**绝不覆盖本地已有的那份**。
//
// 这是整个备机侧最要紧的一条：覆盖了的话，切换那天才会发现盘上这份解不开，
// 而此前每一天页面都显示"同步正常"。
func TestAdoptKeepsLocalCopyWhenVerifyFails(t *testing.T) {
	dir := t.TempDir()
	good := makeBackup(t, true)
	if _, err := Adopt(dir, good, testPass, "standby-1", "https://p:8092", 600, now); err != nil {
		t.Fatalf("首轮同步应成功: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, BackupFile))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"密文被改一个字节": corrupt(good),
		"半截响应":     good[:len(good)/2],
		"根本不是备份":   []byte("<html>502 Bad Gateway</html>"),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Adopt(dir, bad, testPass, "standby-1", "https://p:8092", 600, now); err == nil {
				t.Fatal("坏备份必须被拒")
			}
			after, err := os.ReadFile(filepath.Join(dir, BackupFile))
			if err != nil {
				t.Fatalf("本地备份不该被删: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("校验失败却覆盖了本地备份：切换那天才会发现盘上这份解不开")
			}
		})
	}

	// 口令不对也算校验不过（GCM 认证失败时"口令错"与"文件损坏"本就无法区分）
	if _, err := Adopt(dir, good, "another-passphrase", "standby-1", "", 600, now); err == nil {
		t.Fatal("口令不对必须被拒")
	}
	after, _ := os.ReadFile(filepath.Join(dir, BackupFile))
	if !bytes.Equal(before, after) {
		t.Fatal("口令不对时也不得覆盖本地备份")
	}
}

// TestVerifyRejectsBackupWithoutDB 解得开但没有数据库 = 不完整。
// 放过它的话，恢复出来是一套能正常启动的空系统——最坏的一种"恢复成功"。
func TestVerifyRejectsBackupWithoutDB(t *testing.T) {
	if _, _, err := VerifyBackup(makeBackup(t, false), testPass); err == nil {
		t.Fatal("缺 baidi.db 的备份必须判不完整")
	}
	dir := t.TempDir()
	if _, err := Adopt(dir, makeBackup(t, false), testPass, "standby-1", "", 600, now); err == nil {
		t.Fatal("不完整的备份不该被落盘")
	}
	if _, err := os.Stat(filepath.Join(dir, BackupFile)); !os.IsNotExist(err) {
		t.Fatal("被拒的备份不得留在盘上（下次 promote 会把它当成可用备份）")
	}
}

// TestAdoptStateAndExtract 落盘状态可读，且解开的材料权限位收紧。
func TestAdoptStateAndExtract(t *testing.T) {
	dir := t.TempDir()
	if _, ok, _ := LoadLocal(dir); ok {
		t.Fatal("空目录不该报告「有备份」")
	}
	blob := makeBackup(t, true)
	st, err := Adopt(dir, blob, testPass, "standby-1", "https://p:8092", 600, now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadLocal(dir)
	if err != nil || !ok {
		t.Fatalf("状态应可读回: ok=%v err=%v", ok, err)
	}
	if got.SHA256 != st.SHA256 || got.NodeID != "standby-1" || got.IntervalSec != 600 {
		t.Errorf("状态字段对不上: %+v", got)
	}
	if got.BackupVersion != "0.3.0" || got.BackupCreatedAt != "2026-08-11 12:00:00" {
		t.Errorf("备份头信息应原样落下（页面与提升脚本都读它）: %+v", got)
	}

	out := t.TempDir()
	names, err := ExtractTo(out, blob, testPass)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("应解出 2 项材料，得到 %v", names)
	}
	fi, err := os.Stat(filepath.Join(out, "jwt-ed25519.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("私钥解出来必须是 0600，得到 %v：0644 等于把私钥暴露给同机其他用户，而系统照常运行", fi.Mode().Perm())
	}
}

// corrupt 翻掉密文尾部一个字节（头部不动，专门验"只验头部是不够的"）。
func corrupt(b []byte) []byte {
	c := append([]byte(nil), b...)
	c[len(c)-1] ^= 0xff
	return c
}

// ★「配了备机但它一次都没连上来」不得与「根本没配备机」同形。
//
// standby_nodes 的行只在备机成功连上主机 mTLS 口时才建立。运维签好了证书、备机也在跑，
// 但 mTLS 口只听回环 / 被防火墙挡住 —— 台账永远空，此前页面与 /diag 都回
// skip「未配置备机（单机形态）」，不扣分不告警，而这恰恰是"切换那天手上没有备份"的形态。
func TestNeverConnectedStandbyIsNotSilentSkip(t *testing.T) {
	now := time.Now()
	// 没签过任何备机证书：确实是单机形态，skip 是对的（不该因为"没有备机"被扣健康分）
	v := Evaluate(nil, now, 0)
	if v.Status != "skip" || v.Deployed {
		t.Fatalf("无备机证书时应 skip 单机形态，得 %+v", v)
	}

	// 签过证书却没有任何台账行：warn，且必须说清是"从未同步"而不是"未配置"
	v2 := Evaluate(nil, now, 0, "standby-1", "standby-2")
	if v2.Status != "warn" {
		t.Fatalf("★签过备机证书却零台账必须 warn，得 %q", v2.Status)
	}
	if strings.Contains(v2.Summary, "未配置备机") {
		t.Fatalf("★不得与「未配置备机」同形，得 %q", v2.Summary)
	}
	for _, want := range []string{"standby-1", "standby-2"} {
		if !strings.Contains(v2.Summary, want) {
			t.Fatalf("摘要应点名是哪几张证书，缺 %q：%q", want, v2.Summary)
		}
	}
	if strings.Contains(v2.RPO, "分钟") {
		t.Fatalf("从未同步过就没有 RPO 可言，不该给出一个数字：%q", v2.RPO)
	}
}
