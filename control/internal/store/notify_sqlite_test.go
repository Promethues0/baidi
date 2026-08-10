package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/secret"
)

func newNotifyStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "notify.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestNotifyChannel_增删改查(t *testing.T) {
	st := newNotifyStore(t)
	ctx := context.Background()

	rec, err := st.SaveNotifyChannel(ctx, NotifyChannel{
		Name: "运维邮件组", Kind: "smtp", Enabled: true,
		Config: `{"host":"smtp.corp.example","port":587,"tlsMode":"starttls","from":"baidi@corp.example"}`,
	})
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if rec.ID == "" || !strings.HasPrefix(rec.ID, "nc-") {
		t.Fatalf("应自动生成 id，实得 %q", rec.ID)
	}
	if rec.HasSecret {
		t.Error("新建通道不该带凭据")
	}

	// 改名不改 id、不动其余列
	rec2, err := st.SaveNotifyChannel(ctx, NotifyChannel{
		ID: rec.ID, Name: "SOC 邮件组", Kind: "smtp", Enabled: false, Config: rec.Config,
	})
	if err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	if rec2.ID != rec.ID || rec2.Name != "SOC 邮件组" || rec2.Enabled {
		t.Fatalf("更新结果不对: %+v", rec2)
	}
	if rec2.CreatedAt != rec.CreatedAt {
		t.Error("created_at 不该被 upsert 覆盖")
	}

	list, err := st.NotifyChannels(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("清单应有 1 条: %v %v", list, err)
	}

	if err := st.DeleteNotifyChannel(ctx, rec.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, found, _ := st.NotifyChannelByID(ctx, rec.ID); found {
		t.Fatal("删除后仍能查到")
	}
}

// 凭据只写不读：任何读通道的路径都拿不到密文，只有存在性与指纹。
func TestNotifyChannelSecret_只写不读(t *testing.T) {
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st := newNotifyStore(t)
	ctx := context.Background()
	box, err := secret.NewFromKey(make([]byte, secret.KeyLen))
	if err != nil {
		t.Fatalf("构造加密盒: %v", err)
	}

	rec, _ := st.SaveNotifyChannel(ctx, NotifyChannel{Name: "邮件", Kind: "smtp", Enabled: true})
	const plain = "sup3r-secret-pw"
	nonce, cipher, err := box.Seal(rec.ID, []byte(plain))
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	fp := box.Fingerprint([]byte(plain))[:8]
	if err := st.SaveNotifyChannelSecret(ctx, NotifyChannelSecret{
		ChannelID: rec.ID, Nonce: nonce, Cipher: cipher, Fingerprint: fp,
	}); err != nil {
		t.Fatalf("写凭据失败: %v", err)
	}

	got, found, err := st.NotifyChannelByID(ctx, rec.ID)
	if err != nil || !found {
		t.Fatalf("查通道失败: %v", err)
	}
	if !got.HasSecret || got.SecretFingerprint != fp {
		t.Fatalf("应回显 hasSecret + 指纹，实得 %+v", got)
	}
	// 结构体里根本没有承载原文的字段，这里用整条记录的字符串化再兜一道：
	// 将来有人加了一个 Password 字段并顺手 SELECT 出来，这条会当场变红。
	if strings.Contains(dumpChannel(got), plain) {
		t.Fatalf("★通道记录里出现了凭据原文：%+v", got)
	}
	list, _ := st.NotifyChannels(ctx)
	for _, c := range list {
		if strings.Contains(dumpChannel(c), plain) {
			t.Fatalf("★列表路径泄露了凭据原文：%+v", c)
		}
	}
}

func dumpChannel(c NotifyChannel) string {
	return strings.Join([]string{c.ID, c.Name, c.Kind, c.Config, c.SecretFingerprint,
		c.LastStatus, c.LastDetail, c.LastEvent}, "|")
}

// ★AAD 绑 channel id：把密文行剪贴到另一条通道下必须解不开。
//
// 不绑的话，"能写库"就等于"能完成一次密钥转移"——把 A 通道的密文行整行拷到 B，
// B 就用上了 A 的凭据，不需要任何密码学突破（ipsec_secrets 那条注释解释的正是这个）。
func TestNotifyChannelSecret_AAD绑通道id(t *testing.T) {
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st := newNotifyStore(t)
	ctx := context.Background()
	box, _ := secret.NewFromKey(make([]byte, secret.KeyLen))

	a, _ := st.SaveNotifyChannel(ctx, NotifyChannel{Name: "A", Kind: "webhook"})
	b, _ := st.SaveNotifyChannel(ctx, NotifyChannel{Name: "B", Kind: "webhook"})

	nonce, cipher, err := box.Seal(a.ID, []byte("token-of-A"))
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	// 模拟"剪贴密文行"：同一段 nonce/cipher 写到 B 名下。
	if err := st.SaveNotifyChannelSecret(ctx, NotifyChannelSecret{
		ChannelID: b.ID, Nonce: nonce, Cipher: cipher, Fingerprint: "deadbeef",
	}); err != nil {
		t.Fatalf("写凭据失败: %v", err)
	}
	sec, found, err := st.NotifyChannelSecret(ctx, b.ID)
	if err != nil || !found {
		t.Fatalf("取密文失败: %v", err)
	}
	if _, err := box.Open(b.ID, sec.Nonce, sec.Cipher); err == nil {
		t.Fatal("★换成 B 的 id 仍然解开了：AAD 没有绑通道 id，剪贴密文行即可完成凭据转移")
	}
	// 用原主 id 解得开——证明失败确实来自 AAD 不匹配，而不是密文本身坏了。
	pt, err := box.Open(a.ID, sec.Nonce, sec.Cipher)
	if err != nil || string(pt) != "token-of-A" {
		t.Fatalf("用原通道 id 应能解开: %v %q", err, pt)
	}
}

func TestNotifyChannelSecret_空id拒绝(t *testing.T) {
	st := newNotifyStore(t)
	if err := st.SaveNotifyChannelSecret(context.Background(),
		NotifyChannelSecret{ChannelID: "  ", Cipher: []byte("x")}); err == nil {
		t.Fatal("空 channel id 必须拒绝（AAD 就是它）")
	}
}

// 删除通道必须连凭据一起删：留着孤儿密文行，同 id 重建的通道会静默继承旧凭据。
func TestNotifyChannel_删除连带清凭据(t *testing.T) {
	st := newNotifyStore(t)
	ctx := context.Background()
	rec, _ := st.SaveNotifyChannel(ctx, NotifyChannel{Name: "X", Kind: "webhook"})
	_ = st.SaveNotifyChannelSecret(ctx, NotifyChannelSecret{
		ChannelID: rec.ID, Nonce: []byte("n"), Cipher: []byte("c"), Fingerprint: "ff"})
	if err := st.DeleteNotifyChannel(ctx, rec.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, found, _ := st.NotifyChannelSecret(ctx, rec.ID); found {
		t.Fatal("★通道已删但凭据还在：同 id 重建会静默继承一条谁都不记得设过的凭据")
	}
}

// ★发送结果只由「真发过那一次」写入；保存配置不得覆盖它。
//
// 反过来的话，一条早已发不出去的通道会永远停在上一次成功的绿色上——
// 那正是"配置齐全却零报错不生效"的经典形态。
func TestNotifySend_保存配置不覆盖上次发送结果(t *testing.T) {
	st := newNotifyStore(t)
	ctx := context.Background()
	rec, _ := st.SaveNotifyChannel(ctx, NotifyChannel{Name: "X", Kind: "webhook", Enabled: true})

	if err := st.RecordNotifySend(ctx, rec.ID, NotifySendFail, "对端返回 500", "lockout", 1700000000); err != nil {
		t.Fatalf("记录发送结果失败: %v", err)
	}
	got, _, _ := st.NotifyChannelByID(ctx, rec.ID)
	if got.LastStatus != NotifySendFail || got.LastDetail != "对端返回 500" ||
		got.LastEvent != "lockout" || got.LastAt != 1700000000 {
		t.Fatalf("发送结果没落库: %+v", got)
	}

	// 改个显示名：last_* 四列必须原样保留
	if _, err := st.SaveNotifyChannel(ctx, NotifyChannel{
		ID: rec.ID, Name: "X2", Kind: "webhook", Enabled: true}); err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	got2, _, _ := st.NotifyChannelByID(ctx, rec.ID)
	if got2.Name != "X2" {
		t.Fatalf("改名没生效: %+v", got2)
	}
	if got2.LastStatus != NotifySendFail || got2.LastDetail != "对端返回 500" || got2.LastAt != 1700000000 {
		t.Fatalf("★保存配置把上次发送结果清掉/改写了：%+v", got2)
	}
}

// 失败原因过长要截断：一个返回整页 HTML 的网关能把这一列撑成几十 KB × 每次告警。
func TestNotifySend_详情截断(t *testing.T) {
	st := newNotifyStore(t)
	ctx := context.Background()
	rec, _ := st.SaveNotifyChannel(ctx, NotifyChannel{Name: "X", Kind: "webhook"})
	long := strings.Repeat("错", 2000)
	if err := st.RecordNotifySend(ctx, rec.ID, NotifySendFail, long, "test", 1); err != nil {
		t.Fatalf("记录失败: %v", err)
	}
	got, _, _ := st.NotifyChannelByID(ctx, rec.ID)
	if n := len([]rune(got.LastDetail)); n > 520 {
		t.Fatalf("详情没截断，长度 %d", n)
	}
}
