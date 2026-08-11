package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.3.0", "0.3.0", 0},
		{"0.3.0", "0.4.0", -1},
		{"1.0.0", "0.9.9", 1},
		{"1.2.3", "1.2.10", -1}, // 数值序而非字典序：字典序会把 1.2.10 判成小于 1.2.3
		// 前导 v 必须被容忍：网关版本是 -ldflags 注入的（运维习惯写 v0.4.0），
		// 控制面常量写的是 0.3.0。不容忍的话组件一致性会把两种写法判成不一致。
		{"v0.4.0", "0.4.0", 0},
		{"1.0.0-rc1", "1.0.0", -1}, // 预发布 < 同号正式版
		{"1.0.0-rc1", "1.0.0-rc2", -1},
	}
	for _, c := range cases {
		a, err := ParseVersion(c.a)
		if err != nil {
			t.Fatalf("解析 %q: %v", c.a, err)
		}
		b, err := ParseVersion(c.b)
		if err != nil {
			t.Fatalf("解析 %q: %v", c.b, err)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s = %d，期望 %d", c.a, c.b, got, c.want)
		}
	}
	for _, bad := range []string{"", "1.2", "1.2.3.4", "a.b.c", "1.-2.3", "1.2.x"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("%q 应解析失败", bad)
		}
	}
}

// FR-UPG-06：禁止降级。默认规则下必须拦住，且理由要说清为什么（schema 已迁移）。
func TestDowngradeRejected(t *testing.T) {
	c := CheckUpgrade("1.2.0", "1.1.0", DefaultRules(), Components{})
	if !c.Blocked {
		t.Fatal("降级必须被拒")
	}
	if !strings.Contains(strings.Join(c.Reasons, " "), "降级") {
		t.Errorf("理由要点明是降级：%v", c.Reasons)
	}

	// 显式允许时放行，但必须留一条警告——静默放行降级等于没提醒过风险。
	r := DefaultRules()
	r.AllowDowngrade = true
	c2 := CheckUpgrade("1.2.0", "1.1.0", r, Components{})
	if c2.Blocked {
		t.Fatal("显式允许后不该再拦")
	}
	if len(c2.Warnings) == 0 {
		t.Error("允许降级也必须给出警告")
	}
}

func TestSameVersionRejected(t *testing.T) {
	if c := CheckUpgrade("0.3.0", "0.3.0", DefaultRules(), Components{}); !c.Blocked {
		t.Fatal("同版本应被拒（无需升级）")
	}
	// v 前缀不该被当成不同版本
	if c := CheckUpgrade("0.3.0", "v0.3.0", DefaultRules(), Components{}); !c.Blocked {
		t.Fatal("v0.3.0 与 0.3.0 是同一版本，应被判为无需升级")
	}
}

// FR-UPG-05：强制跳跃链路。规则由管理员配置，不写死任何版本号。
func TestForcedHopChain(t *testing.T) {
	r := DefaultRules()
	r.Hops = []Hop{{Below: "1.0.0", Next: "1.0.0"}}

	// 0.9.0 直升 2.0.0 应被拦，并告诉管理员先升到 1.0.0
	c := CheckUpgrade("0.9.0", "2.0.0", r, Components{})
	if !c.Blocked || c.NextHop != "1.0.0" {
		t.Fatalf("跨版本直升应被拦并给出下一跳，实际 blocked=%v next=%q reasons=%v",
			c.Blocked, c.NextHop, c.Reasons)
	}
	// 升到规定的那一跳本身要放行，否则管理员就被永久卡住了
	if c := CheckUpgrade("0.9.0", "1.0.0", r, Components{}); c.Blocked {
		t.Fatalf("升到强制下一跳本身必须放行：%v", c.Reasons)
	}
	// 已经过了门槛的版本不受限
	if c := CheckUpgrade("1.0.0", "2.0.0", r, Components{}); c.Blocked {
		t.Fatalf("已达门槛的版本应可直升：%v", c.Reasons)
	}
	// 出厂规则不含任何 hop：不编造白帝没有的升级约束
	if len(DefaultRules().Hops) != 0 {
		t.Error("出厂规则不该内置版本链——那是源产品的历史，不是白帝的")
	}
}

// FR-UPG-07：分离式组件一致性。旧网关不上报版本时必须**如实说不可判定**，
// 而不是当成一致（当成一致会让「网关其实是旧版」这件事永远不被发现）。
func TestComponentConsistency(t *testing.T) {
	comp := Components{Gateways: map[string]string{
		"gw-1": "0.3.0", // 升级后将落后
		"gw-2": "0.4.0", // 与目标一致
		"gw-3": "",      // 旧网关不上报
	}}
	c := CheckUpgrade("0.3.0", "0.4.0", DefaultRules(), comp)
	joined := strings.Join(c.Warnings, " | ")
	if !strings.Contains(joined, "gw-1") {
		t.Errorf("落后的网关应被点名：%v", c.Warnings)
	}
	if strings.Contains(joined, "gw-2(") {
		t.Errorf("版本已一致的网关不该被列为落后：%v", c.Warnings)
	}
	if !strings.Contains(joined, "gw-3") || !strings.Contains(joined, "无法校验") {
		t.Errorf("不上报版本的网关必须如实标为不可判定：%v", c.Warnings)
	}
	// 一致性只警告不拦截：拦住的话，一台离线的旧网关会让整个控制面永远升不了级。
	if c.Blocked {
		t.Error("组件不一致应为警告而非阻断")
	}
}

func signedManifest(t *testing.T, m Manifest) ([]byte, []byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ed25519.Sign(priv, raw), pub
}

func TestManifestValidation(t *testing.T) {
	good := Manifest{Product: "baidi", Component: "control", Version: "0.4.0",
		SHA256: strings.Repeat("ab", 32)}
	raw, _ := json.Marshal(good)
	if _, err := ParseManifest(raw); err != nil {
		t.Fatalf("合法描述应通过：%v", err)
	}

	bad := []struct {
		name string
		mut  func(*Manifest)
	}{
		{"非白帝的包", func(m *Manifest) { m.Product = "other" }},
		{"未知组件", func(m *Manifest) { m.Component = "database" }},
		{"版本号非法", func(m *Manifest) { m.Version = "1.2" }},
		{"哈希长度不对", func(m *Manifest) { m.SHA256 = "abcd" }},
		{"哈希非十六进制", func(m *Manifest) { m.SHA256 = strings.Repeat("zz", 32) }},
		{"起跳版本非法", func(m *Manifest) { m.MinSource = "not-a-version" }},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			m := good
			c.mut(&m)
			b, _ := json.Marshal(m)
			if _, err := ParseManifest(b); err == nil {
				t.Fatalf("%s 应被拒", c.name)
			}
		})
	}
}

// FR-UPG-04：校验和与签名是**两件事**，缺一不可。
func TestChecksumAndSignatureAreBothRequired(t *testing.T) {
	payload := []byte("假装这是一个升级包的字节流")
	sum := sha256.Sum256(payload)
	m := Manifest{Product: "baidi", Component: "control", Version: "0.4.0",
		SHA256: hex.EncodeToString(sum[:])}
	raw, sig, pub := signedManifest(t, m)

	if _, err := VerifyPayload(bytes.NewReader(payload), m.SHA256); err != nil {
		t.Fatalf("正确的包体应通过校验和：%v", err)
	}
	if err := VerifySignature(raw, sig, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("正确的签名应通过：%v", err)
	}

	// 包体被改（传输损坏或替换）→ 校验和必须失败
	if _, err := VerifyPayload(bytes.NewReader([]byte("被改过的包")), m.SHA256); err == nil {
		t.Error("包体不匹配时校验和必须失败")
	}
	// 描述被改（比如把 version 抬高）→ 签名必须失败
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] ^= 0xFF
	if err := VerifySignature(tampered, sig, []ed25519.PublicKey{pub}); err == nil {
		t.Error("描述被篡改时签名必须失败")
	}
	// 换一把公钥验不过
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifySignature(raw, sig, []ed25519.PublicKey{other}); err == nil {
		t.Error("用别的公钥不该验过")
	}
	// 缺签名 → 拒（FR-UPG-04：包校验失败拒绝升级）
	if err := VerifySignature(raw, nil, []ed25519.PublicKey{pub}); err == nil {
		t.Error("缺签名必须被拒")
	}
	// ★没配公钥时必须拒绝而不是跳过：跳过的话「没配公钥」与「签名有效」
	// 在结果上完全一样，而前者意味着任何人都能推一个包上来。
	if err := VerifySignature(raw, sig, nil); err == nil {
		t.Error("未配置发布公钥时必须拒绝验签，不得静默放行")
	}
	// 轮换期多把公钥：任一把验过即可
	if err := VerifySignature(raw, sig, []ed25519.PublicKey{other, pub}); err != nil {
		t.Errorf("轮换期应允许多把公钥：%v", err)
	}
}

// 包自带的 minSource 与管理员配的 Hops 是两条独立约束，都要满足。
func TestPackageMinSource(t *testing.T) {
	m := Manifest{Product: "baidi", Component: "control", Version: "2.0.0",
		MinSource: "1.5.0", SHA256: strings.Repeat("ab", 32)}
	c := CheckPackage(m, "1.0.0", DefaultRules(), Components{})
	if !c.Blocked || c.NextHop != "1.5.0" {
		t.Fatalf("低于包要求的起跳版本应被拦并指出先升到哪：blocked=%v next=%q", c.Blocked, c.NextHop)
	}
	if c := CheckPackage(m, "1.5.0", DefaultRules(), Components{}); c.Blocked {
		t.Fatalf("达到起跳版本后应放行：%v", c.Reasons)
	}
}

// ── 配置备份与恢复（FR-UPG-09/10 + 第 15.8 章的 P0 缺口）──

func writeTemp(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBackupRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db := writeTemp(t, dir, "baidi.db", "假装这是 SQLite", 0o644)
	key := writeTemp(t, dir, "pki/ca.key", "-----BEGIN PRIVATE KEY-----", 0o600)

	var buf bytes.Buffer
	meta := BackupMeta{Version: "0.3.0", CreatedAt: "2026-08-11 10:00:00", Note: "升级前"}
	src := []BackupSource{{Name: "baidi.db", Path: db}, {Name: "pki/ca.key", Path: key},
		{Name: "certs", Path: filepath.Join(dir, "不存在的目录")}} // 可选材料缺席不该失败
	if err := CreateBackup(&buf, meta, "correct-horse-battery", src); err != nil {
		t.Fatalf("备份失败：%v", err)
	}

	// 头部必须可以在**不解密**的前提下读出来
	got, _, err := ReadBackupMeta(buf.Bytes())
	if err != nil {
		t.Fatalf("读头部失败：%v", err)
	}
	if got.Version != "0.3.0" || got.Note != "升级前" || len(got.Files) != 3 {
		t.Fatalf("头部内容不符：%+v", got)
	}
	// 头部是明文的，绝不能含凭据
	head := buf.Bytes()[:bytes.IndexByte(buf.Bytes(), '\n')]
	if bytes.Contains(head, []byte("PRIVATE KEY")) {
		t.Fatal("明文头部里出现了私钥内容")
	}
	// 整个备份文件里也不该有明文私钥（证明密文确实加密了）
	if bytes.Contains(buf.Bytes(), []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("备份文件里能直接搜到明文私钥——加密没有生效")
	}

	_, files, err := OpenBackup(buf.Bytes(), "correct-horse-battery")
	if err != nil {
		t.Fatalf("恢复失败：%v", err)
	}
	if string(files["baidi.db"]) != "假装这是 SQLite" {
		t.Errorf("数据库内容对不上：%q", files["baidi.db"])
	}
	if !strings.Contains(string(files["pki/ca.key"]), "PRIVATE KEY") {
		t.Errorf("CA 私钥内容对不上")
	}
}

func TestBackupWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	db := writeTemp(t, dir, "baidi.db", "x", 0o644)
	var buf bytes.Buffer
	if err := CreateBackup(&buf, BackupMeta{Version: "0.3.0"}, "correct-horse-battery",
		[]BackupSource{{Name: "baidi.db", Path: db}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenBackup(buf.Bytes(), "wrong-horse-battery"); !errors.Is(err, ErrBackupDecrypt) {
		t.Fatalf("错口令应回解密失败，实际 %v", err)
	}
}

// 口令过短直接拒：备份里装着 CA 私钥与全部凭据，弱口令等于没加密。
func TestBackupRejectsShortPassphrase(t *testing.T) {
	var buf bytes.Buffer
	err := CreateBackup(&buf, BackupMeta{}, "short", nil)
	if !errors.Is(err, ErrBackupPassphrase) {
		t.Fatalf("短口令应被拒，实际 %v", err)
	}
}

// 头部与密文用 GCM 的 AAD 绑定：把 A 机器的头部拼到 B 机器的密文上必须失败，
// 否则管理员会以为自己在恢复 A 的配置，实际恢复的是 B 的。
func TestBackupHeaderIsBoundToCiphertext(t *testing.T) {
	dir := t.TempDir()
	db := writeTemp(t, dir, "baidi.db", "内容", 0o644)
	mk := func(note string) []byte {
		var b bytes.Buffer
		if err := CreateBackup(&b, BackupMeta{Version: "0.3.0", Note: note}, "correct-horse-battery",
			[]BackupSource{{Name: "baidi.db", Path: db}}); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	a, b := mk("A 机器"), mk("B 机器")
	// 用 A 的头部 + B 的密文
	spliced := append(append([]byte(nil), a[:bytes.IndexByte(a, '\n')+1]...), b[bytes.IndexByte(b, '\n')+1:]...)
	if _, _, err := OpenBackup(spliced, "correct-horse-battery"); err == nil {
		t.Fatal("拼接的备份必须解密失败（头部未与密文绑定）")
	}
}

// 归档内的路径穿越必须在解包时就被挡住：恢复方按名字写盘，
// 一条 ../../etc/xxx 就能覆写系统文件。
func TestBackupRejectsPathTraversal(t *testing.T) {
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	body := []byte("恶意内容")
	_ = tw.WriteHeader(&tar.Header{Name: "../../etc/passwd", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()

	if _, err := unTarGz(raw.Bytes()); err == nil || !errors.Is(err, ErrBackupFormat) {
		t.Fatalf("路径穿越必须被拒，实际 %v", err)
	}
}
