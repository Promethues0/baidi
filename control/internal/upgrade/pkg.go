package upgrade

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
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
//
// ★`m.Component` 在这里**参与判定**，这是本次改造的要点。
//
// 改造前它只被解析、校验（必须是 control|gateway）、写进审计，然后就被丢掉：
// 无论包是给谁的，"当前版本"一律取控制面的。分离式部署下的后果**已实测复现**——
// 控制面 0.4.0、网关还在 0.3.0，传一个 component=gateway 的 0.4.0 网关升级包，
// 得到的结论是「升级包版本与当前运行版本相同（0.4.0），无需升级」并**阻断**：
// 一次完全必要的网关升级被系统劝退，而理由里那个"当前运行版本"说的是另一个组件。
// 方向相反的情形同样存在：控制面 0.3.0、网关已 0.4.0，同一个包会被判成一次合法升级。
//
// 于是判定按组件分流：
//
//	control  —— 当前版本 = 控制面版本（就一个，判定与改造前逐字一致）；
//	gateway  —— 当前版本 = **每一台已注册网关各自的版本**（可能有多台且各不相同，
//	            也可能一台都判不出来），逐台判定后汇总。
func CheckPackage(m Manifest, rules Rules, comp Components) Check {
	if m.Component == ComponentGateway {
		return checkGatewayPackage(m, rules, comp)
	}
	return checkControlPackage(m, rules, comp)
}

// checkControlPackage 控制面升级包：单一当前版本，判定与改造前一致。
func checkControlPackage(m Manifest, rules Rules, comp Components) Check {
	c := CheckUpgrade(comp.Control, m.Version, rules, comp)
	applyMinSource(&c, m, comp.Control, "控制面")
	return c
}

// checkGatewayPackage 网关升级包：对每一台已注册网关分别判定，再汇总成一个结论。
//
// ★为什么不能"挑一台代表"来判：分离式部署的常态就是逐台滚动升级，
// 中途必然出现"有的已升、有的没升"。挑任何一台都会让另一批的结论反着来。
//
// ★汇总规则（每一条都对应一种会真出事的形态）：
//   - 任何一台会被**降级**且规则禁止降级 → 阻断并点名。降级下去那台网关起不来，
//     而它是数据面——起不来就是那一路的业务全断，不是"页面上少个绿点"。
//   - 一台都升不动（全部已是目标版本）→ 阻断，理由说清"已经是这一版了"。
//   - 一台都判不出来（没有已注册网关，或全部未上报可解析的版本）→ **阻断**：
//     判不了就不该说"可以升"。这与本项目对"探不到"的一贯处置一致。
//   - 有的能升、有的已是目标版本 → 放行（滚动升级的正常中间态），已是目标版本的那些列进警告。
func checkGatewayPackage(m Manifest, rules Rules, comp Components) Check {
	var c Check
	tgt, err := ParseVersion(m.Version)
	if err != nil {
		c.block("无法解析升级包版本 %q：%v", m.Version, err)
		return c
	}

	ids := make([]string, 0, len(comp.Gateways))
	for id := range comp.Gateways {
		ids = append(ids, id)
	}
	sort.Strings(ids) // 文案要稳定：map 序随机会让同一份数据每次刷新都换个说法

	var upgradable, sameVer, downgrade, unknown, belowMin []string
	minV, hasMin := Version{}, false
	if m.MinSource != "" {
		if v, e := ParseVersion(m.MinSource); e == nil {
			minV, hasMin = v, true
		}
	}
	for _, id := range ids {
		raw := strings.TrimSpace(comp.Gateways[id])
		gv, e := ParseVersion(raw)
		switch {
		case raw == "":
			unknown = append(unknown, id+"（未上报版本）")
			continue
		case e != nil:
			unknown = append(unknown, fmt.Sprintf("%s（上报的是 %q，不是语义版本）", id, raw))
			continue
		}
		switch cmp := tgt.Compare(gv); {
		case cmp > 0:
			upgradable = append(upgradable, fmt.Sprintf("%s(%s)", id, raw))
		case cmp == 0:
			sameVer = append(sameVer, fmt.Sprintf("%s(%s)", id, raw))
		default:
			downgrade = append(downgrade, fmt.Sprintf("%s(%s)", id, raw))
		}
		if hasMin && gv.Compare(minV) < 0 {
			belowMin = append(belowMin, fmt.Sprintf("%s(%s)", id, raw))
		}
		// FR-UPG-05 强制跳跃链路逐台判：一台低于 Below 的网关就足以拦住这次直升，
		// 因为包是同一个、会被装到每一台上。
		for _, h := range rules.Hops {
			below, e1 := ParseVersion(h.Below)
			next, e2 := ParseVersion(h.Next)
			if e1 != nil || e2 != nil {
				continue
			}
			if gv.Compare(below) < 0 && tgt.Compare(next) > 0 {
				c.NextHop = next.String()
				c.block("禁止跨版本直升：网关 %s 当前 %s，低于 %s，必须先升级到 %s，再升更高版本。",
					id, raw, below, next)
			}
		}
	}

	switch {
	case len(comp.Gateways) == 0:
		c.block("没有任何网关注册到控制面，无法判定这个网关升级包该不该升。" +
			"先确认网关已用 mTLS 证书接上控制面（网关与隐身页能看到它），再回来校验。")
		return c
	case len(unknown) == len(ids):
		c.block("全部 %d 台网关的语义版本都不可判定（%s），无法判定这次升级："+
			"判不出当前版本就判不出这是升级还是降级。"+
			"这些网关多半不是 deploy/build.sh 产出的二进制，或版本过旧不上报语义版本。",
			len(ids), strings.Join(unknown, "、"))
		return c
	}

	if len(downgrade) > 0 {
		if !rules.AllowDowngrade {
			c.block("检测到降级：以下网关当前版本高于升级包版本 %s —— %s。已拒绝："+
				"网关降级后可能读不懂控制面下发的新字段，表现为"+`"`+"策略配了不生效"+`"`+"甚至无法启动，"+
				"而它是数据面，起不来就是那一路业务全断。确需降级请在规则里显式允许。",
				tgt, strings.Join(downgrade, "、"))
		} else {
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("这是对以下网关的降级（目标 %s）：%s，且已在规则中显式允许。务必先备份并逐台观察。",
					tgt, strings.Join(downgrade, "、")))
		}
	}
	if hasMin && len(belowMin) > 0 {
		c.NextHop = m.MinSource
		c.block("该升级包要求起跳版本不低于 %s，以下网关低于它：%s。请先把它们升到 %s。",
			m.MinSource, strings.Join(belowMin, "、"), m.MinSource)
	}
	if len(upgradable) == 0 && len(downgrade) == 0 && len(sameVer) > 0 {
		c.block("全部可判定的网关都已是 %s：%s，无需升级。", tgt, strings.Join(sameVer, "、"))
	}
	if len(sameVer) > 0 && len(upgradable) > 0 {
		c.Warnings = append(c.Warnings,
			fmt.Sprintf("以下网关已是 %s，本次无需处理：%s（滚动升级的正常中间态）。",
				tgt, strings.Join(sameVer, "、")))
	}
	if len(unknown) > 0 {
		c.Warnings = append(c.Warnings,
			fmt.Sprintf("以下网关的当前版本不可判定，本次结论**不覆盖它们**：%s。"+
				"升级前请到机器上跑一次 `baidi-gateway -version` 核对。", strings.Join(unknown, "、")))
	}
	// FR-UPG-07 的另一半：网关升上去之后，会不会反过来与控制面对不上。
	if rules.RequireComponentMatch && !c.Blocked {
		if cv, e := ParseVersion(comp.Control); e == nil && cv.Compare(tgt) != 0 {
			c.Warnings = append(c.Warnings, fmt.Sprintf(
				"升级后网关将是 %s，而控制面是 %s：两者不一致时，新增的下发字段旧的一方读不到"+
					"（表现为策略配了不生效）。请同批升级控制面。", tgt, comp.Control))
		} else if e != nil {
			c.Warnings = append(c.Warnings,
				"控制面自身的语义版本不可判定，无法校验升级后的组件一致性。")
		}
	}
	return c
}

// applyMinSource 包自带的最低起跳版本（与管理员配的 Hops 是两条独立约束，都要满足）。
func applyMinSource(c *Check, m Manifest, current, who string) {
	if m.MinSource == "" {
		return
	}
	cur, err1 := ParseVersion(current)
	min, err2 := ParseVersion(m.MinSource)
	if err1 == nil && err2 == nil && cur.Compare(min) < 0 {
		c.NextHop = m.MinSource
		c.block("该升级包要求起跳版本不低于 %s，%s当前为 %s：请先升级到 %s。",
			m.MinSource, who, current, m.MinSource)
	}
}
