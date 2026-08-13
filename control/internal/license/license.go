// Package license License 管理（PRD ch15）：Ed25519 发行签名 + 容量/有效期判定。
//
// 这套机制演示的是「容量执行」，不是「防拷贝」——持库文件写权限的人当然能清掉
// license 行，正如持二进制的人能改代码。边界如实写在 api 层的 boundaries 里，
// 别在任何 UI 上把它说成防盗版。
//
// 与升级包验签（internal/upgrade）同一套纪律：
//   - 验签对 manifest 的**原始字节**，绝不重新序列化——JSON 键序/空白不进签名语义；
//   - 未配置发行公钥时**拒绝**而不是跳过：跳过的验签比没有验签更糟，
//     它让页面上出现一个绿色的「已验证」而实际什么都没验。
package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Manifest License 描述。字段刻意少：容量模型只有「命名用户数 + 网关数」两维，
// 那是本系统真正有执行点的两个量（建号、签发网关证书）。没有执行点的条款
// （并发数、带宽、功能开关…）一概不进模型——写进去就是又一批 config-only 字段。
type Manifest struct {
	Product  string `json:"product"`  // 必须 "baidi"
	Licensee string `json:"licensee"` // 被许可方（展示用）
	IssuedAt string `json:"issuedAt"` // YYYY-MM-DD（信息性，不参与判定）
	// ExpiresAt 到期日 YYYY-MM-DD，**含当日**。过期后的语义见 api 层 licenseAdmit：
	// 存量业务（登录/隧道/策略）照常，新增容量（建号/签网关证书）被拒。
	ExpiresAt string `json:"expiresAt"`
	// MaxUsers / MaxGateways 容量上限；0 = 该维不限。
	// 用户数含管理员与外部目录自动建的账号（占的都是命名席位）；
	// 网关数按「未吊销证书的去重 gatewayId」计（吊销即释放席位，换证不占新席位）。
	MaxUsers    int `json:"maxUsers"`
	MaxGateways int `json:"maxGateways"`
}

// File 落盘/导入格式：{"manifest": <原始 JSON>, "signature": "<base64>"}。
// Manifest 保持 RawMessage 就是为了让验签对象与传输对象是同一段字节。
type File struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature string          `json:"signature"`
}

// Sign 用私钥对 manifest 出一份 License 文件（发行方 CLI 用）。
//
// ★签名前先 json.Compact：encoding/json 在 Marshal 内嵌 RawMessage 时会重排空白
// （MarshalIndent 更是整段重新缩进），签"带缩进的原文"的话，文件一经序列化，
// 落盘字节就不再是签名字节——刚签出来的 license 自己都验不过。
// 实测踩过：CLI 用 -example 的缩进输出签发，-verify 当场失败。
// compact 是幂等的：签名对象与落盘对象自此恒为同一段字节。
func Sign(manifestRaw []byte, priv ed25519.PrivateKey) (File, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, manifestRaw); err != nil {
		return File{}, fmt.Errorf("manifest 不是合法 JSON：%w", err)
	}
	raw := append([]byte(nil), buf.Bytes()...)
	return File{
		Manifest:  json.RawMessage(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)),
	}, nil
}

// Parse 解析 License 文件并做结构校验（不验签）。
func Parse(raw []byte) (File, Manifest, error) {
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return File{}, Manifest{}, fmt.Errorf("license 文件不是合法 JSON：%w", err)
	}
	if len(f.Manifest) == 0 || strings.TrimSpace(f.Signature) == "" {
		return File{}, Manifest{}, errors.New("license 文件缺 manifest 或 signature")
	}
	var m Manifest
	if err := json.Unmarshal(f.Manifest, &m); err != nil {
		return File{}, Manifest{}, fmt.Errorf("manifest 不是合法 JSON：%w", err)
	}
	if m.Product != "baidi" {
		return File{}, Manifest{}, fmt.Errorf("这不是白帝的 license（product=%q）", m.Product)
	}
	if _, err := time.ParseInLocation("2006-01-02", m.ExpiresAt, time.Local); err != nil {
		return File{}, Manifest{}, fmt.Errorf("expiresAt 必须是 YYYY-MM-DD：%q", m.ExpiresAt)
	}
	if m.MaxUsers < 0 || m.MaxGateways < 0 {
		return File{}, Manifest{}, errors.New("容量上限不得为负（0 表示不限）")
	}
	return f, m, nil
}

// Verify 验签。多把公钥任一命中即通过（轮换期新旧并存，与升级包公钥同款）。
//
// ★签名**定义在 manifest 的 compact 形上**：Sign 先 compact 再签，Verify 先 compact
// 再验。这样空白不进签名语义（文件被 pretty-print、被编辑器重新格式化都不碎），
// 而**键序与内容仍逐字节进签名**——json.Compact 只剥空白，不重排任何东西。
// 不这么定义的话，encoding/json 序列化内嵌 RawMessage 时的空白重排会让
// "签出来的文件经一次 MarshalIndent 就验不过"（实测踩过）。
func Verify(f File, keys []ed25519.PublicKey) error {
	if len(keys) == 0 {
		// 拒绝而不是跳过：没有公钥的"验证通过"是最危险的一种绿色。
		return errors.New("未配置 License 发行公钥（BAIDI_LICENSE_PUBKEY），无法验证签名")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(f.Signature))
	if err != nil {
		return errors.New("signature 不是合法的 base64")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, f.Manifest); err != nil {
		return errors.New("manifest 不是合法 JSON，无法验签")
	}
	for _, k := range keys {
		if ed25519.Verify(k, buf.Bytes(), sig) {
			return nil
		}
	}
	return errors.New("签名验证失败：不是已配置发行方签出的 license")
}

// 状态枚举。
const (
	ModeDemo     = "demo"     // 未导入 license：演示模式，容量不限，页面如实标注
	ModeLicensed = "licensed" // 有效
	ModeExpired  = "expired"  // 已过期：存量照常，新增容量被拒
	ModeInvalid  = "invalid"  // 存了 blob 但验不过（损坏/公钥换了/伪造）：同过期一样拒新增
)

// Status 一次判定的结论。
type Status struct {
	Mode     string
	Manifest Manifest // demo/invalid 时为零值
	Reason   string   // invalid/expired 时的人话说明
}

// Evaluate 判定当前 blob 的状态。blob 为空 = 从未导入（demo）。
//
// ★invalid 的方向是 fail-closed（拒新增），与 demo（不限）刻意不同：
// demo 是「从未声称被许可」，invalid 是「声称过、但现在验不过」——后者可能是
// 公钥被人换掉或 blob 被篡改，此时放开容量正是攻击者想要的方向。
func Evaluate(blob []byte, keys []ed25519.PublicKey, now time.Time) Status {
	if len(blob) == 0 {
		return Status{Mode: ModeDemo}
	}
	f, m, err := Parse(blob)
	if err != nil {
		return Status{Mode: ModeInvalid, Reason: err.Error()}
	}
	if err := Verify(f, keys); err != nil {
		return Status{Mode: ModeInvalid, Manifest: m, Reason: err.Error()}
	}
	// 含当日：到期日当天仍有效。字符串比较对 YYYY-MM-DD 与时间序一致。
	if now.Format("2006-01-02") > m.ExpiresAt {
		return Status{Mode: ModeExpired, Manifest: m,
			Reason: "license 已于 " + m.ExpiresAt + " 到期：存量业务照常，新增用户/网关证书被拒，请导入新 license"}
	}
	return Status{Mode: ModeLicensed, Manifest: m}
}
