package upgrade

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Manifest 升级包内的元数据（包与它并排的 .json 描述，或包内首个条目）。
//
// 字段对齐 PRD 4.4「升级包（UpgradePackage）」实体里**可迁移**的那几项。
// 刻意没有 packageFormat（run/ssu/bin）与 channel（web/ssh）：那是源产品
// 三种历史包格式的分流，白帝只有一种包，编出三种格式的校验分支是假装有历史包袱。
type Manifest struct {
	Product string `json:"product"` // 固定 "baidi"，防把别的产品的包传进来
	// Component 该包升级的是哪个组件。分离式部署下控制面与网关分别出包。
	Component string `json:"component"` // control | gateway
	Version   string `json:"version"`   // 目标版本
	// MinSource 该包允许的最低起跳版本；低于它的必须先升到中间版本。
	// 空 = 不限（与 Rules.Hops 是两条独立的链路约束：这条随包走，那条由管理员配）。
	MinSource string `json:"minSource,omitempty"`
	SHA256    string `json:"sha256"`            // 包体校验和（hex）
	Notes     string `json:"notes,omitempty"`   // 版本说明
	BuiltAt   string `json:"builtAt,omitempty"` // 构建时间
}

// 组件取值。
const (
	ComponentControl = "control"
	ComponentGateway = "gateway"
)

var (
	ErrManifestInvalid = errors.New("升级包描述不合法")
	ErrChecksum        = errors.New("升级包校验和不匹配")
	ErrSignature       = errors.New("升级包签名校验失败")
	ErrUnsigned        = errors.New("升级包未随附签名")
)

// ParseManifest 解析并校验描述文件的必填项。
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	m.Product = strings.TrimSpace(m.Product)
	m.Component = strings.ToLower(strings.TrimSpace(m.Component))
	m.Version = strings.TrimSpace(m.Version)
	m.SHA256 = strings.ToLower(strings.TrimSpace(m.SHA256))

	if m.Product != "baidi" {
		return m, fmt.Errorf("%w: product 必须是 \"baidi\"（实际 %q）——防止把其他产品的包传进来", ErrManifestInvalid, m.Product)
	}
	if m.Component != ComponentControl && m.Component != ComponentGateway {
		return m, fmt.Errorf("%w: component 只能是 control 或 gateway（实际 %q）", ErrManifestInvalid, m.Component)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return m, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	if m.MinSource != "" {
		if _, err := ParseVersion(m.MinSource); err != nil {
			return m, fmt.Errorf("%w: minSource %v", ErrManifestInvalid, err)
		}
	}
	if len(m.SHA256) != 64 {
		return m, fmt.Errorf("%w: sha256 应为 64 位十六进制（实际 %d 位）", ErrManifestInvalid, len(m.SHA256))
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return m, fmt.Errorf("%w: sha256 不是合法十六进制", ErrManifestInvalid)
	}
	return m, nil
}

// VerifyPayload 流式校验包体的 SHA-256，返回实际字节数。
//
// 流式而非整包读进内存：升级包动辄上百 MB，读进内存再算会在上传并发时打爆控制面。
func VerifyPayload(r io.Reader, want string) (int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return n, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return n, fmt.Errorf("%w: 期望 %s，实际 %s", ErrChecksum, want, got)
	}
	return n, nil
}

// VerifySignature 用发布公钥验签**描述文件原文**（FR-UPG-04）。
//
// ★签的是 manifest 而不是包体：manifest 里含包体的 SHA-256，所以「签名有效 +
// 包体哈希匹配 manifest」等价于「包体被签名覆盖」，而且验签只需读几百字节，
// 不必把整个包读两遍。校验和与签名是**两件事**，缺一不可：
//   - 只校验和：攻击者换包的同时换掉 manifest 里的哈希，两边自洽；
//   - 只验签名：传输损坏的包体照样通过。
//
// pubKeys 允许多把（轮换期新旧并存）。任一把验过即通过。
func VerifySignature(manifestRaw, sig []byte, pubKeys []ed25519.PublicKey) error {
	if len(sig) == 0 {
		return ErrUnsigned
	}
	if len(pubKeys) == 0 {
		// 没配发布公钥时**拒绝**而不是跳过验签：跳过的话，「没配公钥」与
		// 「签名有效」在结果上完全一样，而前者意味着任何人都能推一个包上来。
		return fmt.Errorf("%w: 未配置升级包发布公钥（BAIDI_UPGRADE_PUBKEY），无法验签", ErrSignature)
	}
	for _, pk := range pubKeys {
		if len(pk) == ed25519.PublicKeySize && ed25519.Verify(pk, manifestRaw, sig) {
			return nil
		}
	}
	return ErrSignature
}

// CheckPackage 把包描述与当前环境合在一起判定，是上传后「即时回显校验结论」的唯一入口
// （PRD 4.5：上传即校验，不通过则禁用升级按钮并给出明确原因）。
func CheckPackage(m Manifest, currentControl string, rules Rules, comp Components) Check {
	c := CheckUpgrade(currentControl, m.Version, rules, comp)

	// 包自带的最低起跳版本（与管理员配的 Hops 是两条独立约束，都要满足）。
	if m.MinSource != "" {
		cur, err1 := ParseVersion(currentControl)
		min, err2 := ParseVersion(m.MinSource)
		if err1 == nil && err2 == nil && cur.Compare(min) < 0 {
			c.NextHop = m.MinSource
			c.block("该升级包要求起跳版本不低于 %s，当前为 %s：请先升级到 %s。",
				m.MinSource, currentControl, m.MinSource)
		}
	}
	return c
}
