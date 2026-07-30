package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"baidi.dev/gateway/internal/ipsec"
)

// 本文件是**控制台字符串 ⇄ IKEv2 Transform ID 的唯一映射入口**，外加提案的构造与选择。
//
// 为什么要有「唯一入口」这条纪律：控制台里 Enc/Hash/DH 是三个自由字符串，网关侧则是
// 一堆 uint16 码点。只要这个翻译动作散落到两处以上，迟早出现「装载时按 A 翻译、
// 构造提案时按 B 翻译」的不一致。而这类不一致**不会报错**——两端照样能谈成一个套件，
// 只是与控制台上显示的不是同一个。本项目对这种失败形态有惨痛记忆（apps.resource_id
// 静默为 NULL、-route 只接管单网段），所以：
//
//	★ 翻译只在 SpecFromPhase 里发生一次；翻译不出来**立刻拒绝**并说清「哪个字段的哪个值不认识」。
//	★ 绝不静默降级、绝不 fallback 到"默认算法"。宁可站点 failed 且界面上有中文原因，
//	  也不要一条自称 SM4 实际跑 AES128 的隧道。
//
// 国密套件（SM4-GCM/SM4-CBC、HMAC-SM3、sm2p256v1）走 IANA 私有使用段码点（1024+，见
// const.go）。**只承诺白帝↔白帝互通**，与任何第三方设备都不通，且与 GM/T 0022 无关
// （那是 IKEv1 血统 + 数字信封的另一套协议栈）。因此这些取值被 suite 字段闸住：
// 只有 suite=gm 才放行，避免有人在 suite=standard 下配出一条对外声称"标准"的私有隧道。

// suite 字段的两个合法取值。
const (
	// SuiteStandard 只允许 RFC/IANA 正式分配的码点，可以（在设计上）与第三方实现互通。
	SuiteStandard = "standard"
	// SuiteGM 额外放行白帝私有码点。**不是国密 IPSec，不可对外这么说。**
	SuiteGM = "gm"
)

// SuiteSpec 一组算法码点。它是「配置意图」与「线上提案」之间的中间表示：
// 上游只产出它（SpecFromPhase / SpecFromProposal），下游只消费它（Build / IKEProposal /
// ESPProposal / String），协议层不再碰任何算法字符串。
//
// 字段全部是 IKEv2 Transform ID 而非字符串：协商结果本来就是码点，
// 转成字符串再转回来只会多引入一次翻译错误。
//
// PRFID == 0 有明确语义：**该 spec 描述的是 ESP 提案**（ESP 不协商 PRF）。
// 用 0 做哨兵是安全的——IANA 没有为 PRF 分配过 0 号码点。
type SuiteSpec struct {
	EncrID  uint16
	KeyBits int    // 密钥长度（位）。写进提案的 Key Length 属性，AES/SM4 必带
	PRFID   uint16 // 0 = 本 spec 不含 PRF（ESP 提案）
	IntegID uint16 // IntegNone(0) = combined 模式（AEAD 自带完整性）
	DHID    uint16 // DHNone(0) = 不做 DH（无 PFS 的 Child SA）
}

// SpecError 一条「控制台配了个我不认识的值」的装载期拒绝。
//
// 单独定义类型是为了让上层能 errors.As 出 Field，原样填进 ipsec.ConfigError 回报控制面——
// 管理员在界面上要看到的是「phase1.dh=group24 本实现不支持」，
// 而不是网关默默跳过这条站点、界面永远停在 connecting。
type SpecError struct {
	Field  string // 形如 "phase1.enc" / "suite"
	Value  string // 原样带上用户填的值，别做任何美化
	Reason string
}

func (e *SpecError) Error() string {
	if e.Value == "" {
		return fmt.Sprintf("ike: 配置项 %s 不可用：%s", e.Field, e.Reason)
	}
	return fmt.Sprintf("ike: 配置项 %s=%q 不可用：%s", e.Field, e.Value, e.Reason)
}

// ── 映射表 ──
//
// 三张表就是这个包对外承诺的全部算法集合。新增一个算法 = 表里加一行；
// 表里没有的字符串一律拒绝。刻意**不**收录 AES128：控制台文档写的是 AES256-*，
// 多认一个未列入契约的取值，等于给「控制台改了但网关没改」留一条静默通道。

type encEntry struct {
	name     string
	id       uint16
	keyBits  int
	combined bool // AEAD：自带完整性，INTEG 必须为 NONE
	private  bool // 私有码点，只有 suite=gm 放行
}

var encTable = []encEntry{
	{"AES256-GCM", EncrAESGCM16, 256, true, false},
	{"AES256-CBC", EncrAESCBC, 256, false, false},
	{"SM4-GCM", EncrSM4GCM16, 128, true, true},
	{"SM4-CBC", EncrSM4CBC, 128, false, true},
}

type hashEntry struct {
	name    string
	prfID   uint16
	integID uint16
	private bool
}

var hashTable = []hashEntry{
	{"SHA256", PRFHMACSHA256, IntegHMACSHA256128, false},
	{"SM3", PRFHMACSM3, IntegHMACSM3128, true},
}

type dhEntry struct {
	name    string
	id      uint16
	private bool
}

var dhTable = []dhEntry{
	{"group14", DHModp2048, false},
	{"group19", DHEcp256, false},
	{"sm2p256", DHSm2P256, true},
}

// 查表一律 TrimSpace + 大小写不敏感。
// 这不是"宽容解析"：大小写与首尾空格不携带任何语义，让 "aes256-gcm" 因为大小写被拒、
// 换来一条永久 failed 的站点，对管理员是纯粹的折磨。真正的语义歧义（未知算法名）照拒不误。
func normSpec(s string) string { return strings.TrimSpace(s) }

func lookupEnc(name string) (encEntry, bool) {
	for _, e := range encTable {
		if strings.EqualFold(normSpec(name), e.name) {
			return e, true
		}
	}
	return encEntry{}, false
}

func lookupHash(name string) (hashEntry, bool) {
	for _, h := range hashTable {
		if strings.EqualFold(normSpec(name), h.name) {
			return h, true
		}
	}
	return hashEntry{}, false
}

func lookupDHName(name string) (dhEntry, bool) {
	for _, d := range dhTable {
		if strings.EqualFold(normSpec(name), d.name) {
			return d, true
		}
	}
	return dhEntry{}, false
}

// 供错误信息枚举「本实现支持哪些」。只回一句「不支持」等于让管理员去猜。
func encNames() string {
	out := make([]string, len(encTable))
	for i, e := range encTable {
		out[i] = e.name
	}
	return strings.Join(out, " / ")
}

func hashNames() string {
	out := make([]string, len(hashTable))
	for i, h := range hashTable {
		out[i] = h.name
	}
	return strings.Join(out, " / ")
}

func dhNames() string {
	out := make([]string, len(dhTable))
	for i, d := range dhTable {
		out[i] = d.name
	}
	return strings.Join(out, " / ")
}

// suiteAllowsPrivate 解析 suite 字段，返回是否放行私有码点。
func suiteAllowsPrivate(suite string) (bool, error) {
	switch {
	case strings.EqualFold(normSpec(suite), SuiteStandard):
		return false, nil
	case strings.EqualFold(normSpec(suite), SuiteGM):
		return true, nil
	}
	return false, &SpecError{
		Field: "suite", Value: suite,
		Reason: fmt.Sprintf("只支持 %q（RFC 码点）与 %q（白帝私有码点，仅白帝↔白帝互通）", SuiteStandard, SuiteGM),
	}
}

// SpecFromPhase 把控制台的一相配置翻译成算法码点。**这是字符串→码点的唯一入口。**
//
// forChild 区分 IKE SA 提案（false）与 Child SA/ESP 提案（true），差别有二：
//   - ESP 不协商 PRF，故 PRFID 置 0；Hash 字段此时只用来定 INTEG。
//   - IKE SA 必须做 DH，Child SA 是否带 DH 由 PFS 开关在 ESPProposal 里决定。
//
// ★注意 suite 只是**闸门**（放不放行私有码点），不强制"gm 就必须全套国密"：
// SM4-GCM 配 SHA256 在密码学上完全可用，拒绝它没有任何安全收益。为了不让 suite 标签
// 反过来骗人，界面上要显示的协商结果一律取 SuiteSpec.String()（真实算法名），
// 而不是 suite 这个标签。
func SpecFromPhase(ph ipsec.Phase, suite string, forChild bool) (SuiteSpec, error) {
	field := "phase1"
	if forChild {
		field = "phase2"
	}

	allowPrivate, err := suiteAllowsPrivate(suite)
	if err != nil {
		return SuiteSpec{}, err
	}

	enc, ok := lookupEnc(ph.Enc)
	if !ok {
		return SuiteSpec{}, &SpecError{field + ".enc", ph.Enc,
			fmt.Sprintf("不认识的加密算法；本实现支持 %s", encNames())}
	}
	if enc.private && !allowPrivate {
		return SuiteSpec{}, &SpecError{field + ".enc", ph.Enc,
			fmt.Sprintf("%s 走 IANA 私有使用段码点（%d），只有 suite=%s 才放行；当前 suite=%q",
				enc.name, enc.id, SuiteGM, normSpec(suite))}
	}

	hash, ok := lookupHash(ph.Hash)
	if !ok {
		return SuiteSpec{}, &SpecError{field + ".hash", ph.Hash,
			fmt.Sprintf("不认识的摘要算法；本实现支持 %s", hashNames())}
	}
	if hash.private && !allowPrivate {
		return SuiteSpec{}, &SpecError{field + ".hash", ph.Hash,
			fmt.Sprintf("%s 走私有码点（PRF=%d / INTEG=%d），只有 suite=%s 才放行",
				hash.name, hash.prfID, hash.integID, SuiteGM)}
	}

	dh, ok := lookupDHName(ph.DH)
	if !ok {
		// ★Child SA 即便不开 PFS 也必须填 DH 群。留空看似"反正用不到"，
		// 但管理员把 PFS 开关一打开的瞬间就没有群可用了——而那时错误发生在
		// CREATE_CHILD_SA 阶段（隧道已经建起来过），远比装载期拒绝难查。
		return SuiteSpec{}, &SpecError{field + ".dh", ph.DH,
			fmt.Sprintf("不认识的 DH 群；本实现支持 %s（group24 等其它群不实现）", dhNames())}
	}
	if dh.private && !allowPrivate {
		return SuiteSpec{}, &SpecError{field + ".dh", ph.DH,
			fmt.Sprintf("%s 走私有码点（%d），只有 suite=%s 才放行", dh.name, dh.id, SuiteGM)}
	}

	spec := SuiteSpec{EncrID: enc.id, KeyBits: enc.keyBits, DHID: dh.id}
	if !forChild {
		spec.PRFID = hash.prfID
	}
	if !enc.combined {
		// combined 模式（GCM）下 INTEG 必须是 NONE：AEAD 自带认证标签，
		// 再叠一层 HMAC 会多派生两段密钥，导致其后所有密钥整体错位。
		spec.IntegID = hash.integID
	}

	// ★装载期自检：立刻把码点真的构造成算法对象一次。
	// 目的是让「映射成功」等价于「一定跑得起来」——否则一个能通过映射但
	// LookupEncr 拒绝的组合（例如未来往表里加错 keyBits）会推迟到第一次握手才炸，
	// 那时症状是隧道建不起来而配置界面一片正常。
	if _, err := spec.Build(); err != nil {
		return SuiteSpec{}, &SpecError{field, fmt.Sprintf("%s/%s/%s", normSpec(ph.Enc), normSpec(ph.Hash), normSpec(ph.DH)),
			fmt.Sprintf("算法组合无法构造：%v", err)}
	}
	return spec, nil
}

// SpecFromProposal 从一条**协商结果**提案里读出算法码点。
//
// 典型用途：发起方收到响应方回来的 SA 载荷，确认对端到底选了什么。
// 因此校验比解析层更严——每种 Transform Type **最多只能有一个**：
// 协商结果里出现两个 ENCR 意味着两端可能各选各的，而这种分歧的症状是解密失败，
// 不是协商失败。宽容在这里没有互通收益，只有制造歧义。
func SpecFromProposal(p Proposal) (SuiteSpec, error) {
	var s SuiteSpec

	encr, ok, err := soleTransform(p, TransformEncr)
	if err != nil {
		return s, err
	}
	if !ok {
		return s, fmt.Errorf("ike: 提案 %s 没有 ENCR 变换", p)
	}
	s.EncrID = encr.ID
	s.KeyBits = int(encr.KeyLen)
	if s.KeyBits == 0 {
		// 未带 Key Length 属性。只有单一密钥长度的算法（SM4）能确定地补齐；
		// AES 补不了——猜一个长度正是「协商成功后认证失败」的经典成因，
		// 留 0 让 Build() 报出带实际值的错误。
		s.KeyBits = fixedKeyBits(encr.ID)
	}

	if prf, ok, err := soleTransform(p, TransformPRF); err != nil {
		return s, err
	} else if ok {
		s.PRFID = prf.ID
	}

	if integ, ok, err := soleTransform(p, TransformInteg); err != nil {
		return s, err
	} else if ok {
		s.IntegID = integ.ID
	}

	if dh, ok, err := soleTransform(p, TransformDH); err != nil {
		return s, err
	} else if ok {
		s.DHID = dh.ID
	}

	if esn, ok, err := soleTransform(p, TransformESN); err != nil {
		return s, err
	} else if ok && esn.ID != ESNNone {
		return s, fmt.Errorf("ike: 提案 %s 选了 ESN=%d，本实现不支持扩展序列号", p, esn.ID)
	}

	if _, err := s.Build(); err != nil {
		return SuiteSpec{}, fmt.Errorf("ike: 提案 %s 的算法组合不可用：%w", p, err)
	}
	return s, nil
}

// soleTransform 取该类型下唯一的变换。有 0 个返回 ok=false，多于 1 个返回错误。
func soleTransform(p Proposal, tt TransformType) (Transform, bool, error) {
	xs := p.TransformsOfType(tt)
	switch len(xs) {
	case 0:
		return Transform{}, false, nil
	case 1:
		return xs[0], true, nil
	}
	return Transform{}, false, fmt.Errorf("ike: 提案 %s 里有 %d 个 %s 变换（协商结果每种类型只能有一个，否则两端可能各选各的）",
		p, len(xs), tt)
}

// fixedKeyBits 对只有单一密钥长度的算法给出该长度；其余返回 0（表示"必须由 Key Length 属性给出"）。
func fixedKeyBits(encrID uint16) int {
	switch encrID {
	case EncrSM4GCM16, EncrSM4CBC:
		return 128 // SM4 只有 128 位密钥，gmsm 的 NewCipher 也只收 16 字节
	}
	return 0
}

// Build 把码点构造成可用的算法对象。
//
// PRFID==0 时 Suite.PRF 为 nil——ESP 提案不协商 PRF，这是合法状态。
// ★但 IKE SA 绝不能拿一个 PRF 为 nil 的 Suite 去派生密钥：keys.go 会明确报错，
// 别在这里"顺手补一个默认 PRF"。
func (s SuiteSpec) Build() (*Suite, error) {
	encr, err := LookupEncr(s.EncrID, s.KeyBits)
	if err != nil {
		return nil, err
	}
	var prf PRF
	if s.PRFID != 0 {
		if prf, err = LookupPRF(s.PRFID); err != nil {
			return nil, err
		}
	}
	integ, err := LookupInteg(s.IntegID)
	if err != nil {
		return nil, err
	}
	dh, err := LookupDH(s.DHID)
	if err != nil {
		return nil, err
	}
	// 与 keys.go 的 ikeKeySizes 同一条闸，在此提前一步拦住：
	// AEAD 叠 INTEG 会多派生 2×32 字节导致密钥整体错位；
	// 非 AEAD 缺 INTEG 则报文毫无完整性保护而功能一切正常（更危险，因为测试也全绿）。
	if encr.Combined() && integ != nil {
		return nil, fmt.Errorf("ike: %s 是 combined 模式（自带完整性），INTEG 必须为 NONE，实际为 %s",
			encrName(s.EncrID, s.KeyBits), integName(s.IntegID))
	}
	if !encr.Combined() && integ == nil {
		return nil, fmt.Errorf("ike: %s 不是 combined 模式，必须配 INTEG（缺了它报文没有任何完整性保护，而功能上一切正常）",
			encrName(s.EncrID, s.KeyBits))
	}
	// ESN 恒 false：本轮不实现扩展序列号，提案里也只提 ESNNone。
	return &Suite{Encr: encr, PRF: prf, Integ: integ, DH: dh, ESN: false}, nil
}

// String 给出协商结果的可读文案，形如 "AES256-GCM16/PRF-HMAC-SHA256/ECP256"。
//
// ★这是 SiteState.NegotiatedProposal 的来源。它必须显示**真实算法**而不是 suite 标签：
// 「配的是 A、谈出来 B」时能被一眼看出来，正是"真的在谈判"最直观的证据。
// 未知码点也照打（"ENCR(1234)/256"），只回一个 NO_PROPOSAL_CHOSEN 等于什么都没说。
func (s SuiteSpec) String() string {
	parts := []string{encrName(s.EncrID, s.KeyBits)}
	if s.PRFID != 0 {
		parts = append(parts, prfName(s.PRFID))
	}
	if s.IntegID != IntegNone {
		parts = append(parts, integName(s.IntegID))
	}
	if s.DHID != DHNone {
		parts = append(parts, dhName(s.DHID))
	}
	return strings.Join(parts, "/")
}

func encrName(id uint16, keyBits int) string {
	switch id {
	case EncrAESGCM16:
		return fmt.Sprintf("AES%d-GCM16", keyBits)
	case EncrAESCBC:
		return fmt.Sprintf("AES%d-CBC", keyBits)
	case EncrSM4GCM16:
		return "SM4-GCM16"
	case EncrSM4CBC:
		return "SM4-CBC"
	}
	return fmt.Sprintf("ENCR(%d)/%d", id, keyBits)
}

func prfName(id uint16) string {
	switch id {
	case PRFHMACSHA256:
		return "PRF-HMAC-SHA256"
	case PRFHMACSM3:
		return "PRF-HMAC-SM3"
	}
	return fmt.Sprintf("PRF(%d)", id)
}

func integName(id uint16) string {
	switch id {
	case IntegNone:
		return "INTEG-NONE"
	case IntegHMACSHA256128:
		return "HMAC-SHA256-128"
	case IntegHMACSM3128:
		return "HMAC-SM3-128"
	}
	return fmt.Sprintf("INTEG(%d)", id)
}

func dhName(id uint16) string {
	switch id {
	case DHNone:
		return "无DH"
	case DHModp2048:
		return "MODP2048"
	case DHEcp256:
		return "ECP256"
	case DHSm2P256:
		return "SM2P256"
	}
	return fmt.Sprintf("DH(%d)", id)
}

// IKEProposal 构造一条 IKE SA 提案。
//
// SPI 留空（长度 0）——IKE_SA_INIT 的 IKE 提案 SPI 在报文头里。
// ★CREATE_CHILD_SA 重协商 IKE SA 时调用方必须把 SPI 填成自己新生成的 8 字节，
// 否则对端按 SPI Size=0 解析，重协商会以 INVALID_SYNTAX 告终。
//
// 变换清单固定为 ENCR + PRF + INTEG + D-H（无 ESN，ESN 只属于 ESP）。
// ★关于 combined 模式下要不要发 INTEG=NONE：本实现**显式发**（照 2-ike.md §6 的定档），
// 收侧则两种形态都接受（见 matchInteg）。strongSwan 的做法是省略该变换，
// 因此这是一处**尚未实机验证过的互通风险点**——若将来对上第三方设备回
// NO_PROPOSAL_CHOSEN，这里是第一个该看的地方。
func (s SuiteSpec) IKEProposal(num uint8) Proposal {
	return Proposal{
		Num:      num,
		Protocol: ProtocolIKE,
		Transforms: []Transform{
			{Type: TransformEncr, ID: s.EncrID, KeyLen: uint16(s.KeyBits)},
			{Type: TransformPRF, ID: s.PRFID},
			{Type: TransformInteg, ID: s.IntegID},
			{Type: TransformDH, ID: s.DHID},
		},
	}
}

// ESPProposal 构造一条 Child SA（ESP）提案。
//
// inSPI 是**本端入向**的 SPI，语义是「请你用这个 SPI 发给我」——填成对端的 SPI
// 会让双方都往对方的入向 SPI 上发，两端都收不到任何东西却毫无报错。
//
// pfs=false 时**不带 D-H 变换**（RFC 允许省略，兼容性最好）。
func (s SuiteSpec) ESPProposal(num uint8, inSPI uint32, pfs bool) Proposal {
	if pfs && s.DHID == DHNone {
		// ★静默发出一条没有 D-H 的提案 = 悄悄把 PFS 关掉。对端会照单全收，
		// 隧道正常建立，界面显示 PFS 已启用，而实际前向保密根本不存在。
		// 这种"配了但没生效且无人知晓"正是本项目最忌讳的失败形态，故直接炸。
		panic("ike: 站点要求 PFS，但套件没有 DH 群（DHID=0）——发出去会静默降级成无 PFS")
	}
	tf := []Transform{
		{Type: TransformEncr, ID: s.EncrID, KeyLen: uint16(s.KeyBits)},
		{Type: TransformInteg, ID: s.IntegID},
	}
	if pfs {
		tf = append(tf, Transform{Type: TransformDH, ID: s.DHID})
	}
	// ESN 必须显式提 0：省略会让对端在"要不要用扩展序列号"上自行发挥，
	// 而本实现的反重放窗口是按 32 位序号写的。
	tf = append(tf, Transform{Type: TransformESN, ID: ESNNone})

	return Proposal{
		Num:        num,
		Protocol:   ProtocolESP,
		SPI:        binary.BigEndian.AppendUint32(nil, inSPI),
		Transforms: tf,
	}
}

// ForPFS 按 PFS 开关归一化 Child SA 的 spec：关 PFS 时把 DH 群清零。
//
// ★这个方法存在是为了消掉一个必踩的坑：SpecFromPhase(phase2, …, true) **总是**带回一个
// DH 群（配置里 Phase2.DH 是必填项，见那里的注释），但关了 PFS 的对端提案里根本不会有
// D-H 变换。不清零就会被 matchDH 判成「D-H 候选 [空] 里没有本端要的 MODP2048」——
// 一条配置完全正确的站点永远谈不拢，而错误信息还指着 DH 群，极具误导性。
//
// 正确用法是让同一个 pfs 变量贯穿选与构造两步：
//
//	sel, spec, err := SelectProposal(offered, want.ForPFS(cfg.PFS), ProtocolESP)
//	resp := spec.ESPProposal(sel.Num, myInSPI, cfg.PFS)
func (s SuiteSpec) ForPFS(pfs bool) SuiteSpec {
	if !pfs {
		s.DHID = DHNone
	}
	return s
}

// ESPSPI 读出一条 ESP 提案里的 4 字节 SPI（网络序）。
//
// 提供这个方法而不是让调用方自己 binary.BigEndian.Uint32(pr.SPI)，是因为
// 字节序写反会得到一个**完全合法**的 SPI 值：隧道照建，只是对端永远收不到包。
func (pr Proposal) ESPSPI() (uint32, error) {
	if pr.Protocol != ProtocolESP {
		return 0, fmt.Errorf("ike: 提案 %s 不是 ESP 提案，没有 4 字节 SPI", pr)
	}
	if len(pr.SPI) != 4 {
		return 0, fmt.Errorf("ike: ESP 提案的 SPI 长度为 %d（应为 4）", len(pr.SPI))
	}
	return binary.BigEndian.Uint32(pr.SPI), nil
}

// SelectProposal 在对端提上来的一组提案里挑出与本端配置相符的那一条（responder 侧）。
//
// 返回的是**对端那条提案的原样**，不是响应报文该回的提案。这样安排有两个理由：
//   - ESP 场景下调用方需要从中读出对端的 SPI（= 本端出向 SPI），见 ESPSPI；
//   - 响应提案该带**自己的** SPI，用 spec.IKEProposal(sel.Num) / spec.ESPProposal(sel.Num, myInSPI, pfs)
//     现构造即可，比在这里就地改 SPI 更难写错。
//
// ★本实现不做「每种 Type 挑第一个自己支持的」那种自由组合：站点配置已经把套件钉死了，
// 对端要么提供了完全一致的组合，要么就是谈不拢。自由组合会让实际跑的算法与控制台显示的
// 不一致——又一次「配了 A 跑了 B」。
//
// ★失败时的错误信息必须同时包含「对端提了什么」与「本端要什么」。只回一个
// NO_PROPOSAL_CHOSEN 码点，两端管理员各改各的配置能耗掉一整天。
func SelectProposal(offered []Proposal, want SuiteSpec, proto ProtocolID) (Proposal, SuiteSpec, error) {
	if len(offered) == 0 {
		return Proposal{}, SuiteSpec{}, errors.New("ike: 对端 SA 载荷里没有任何提案")
	}
	reasons := make([]string, 0, len(offered))
	for _, pr := range offered {
		if err := matchProposal(pr, want, proto); err != nil {
			reasons = append(reasons, fmt.Sprintf("%s → %v", pr, err))
			continue
		}
		return pr, want, nil
	}
	return Proposal{}, SuiteSpec{}, fmt.Errorf("ike: 没有可接受的 %s 提案（本端要求 %s）；对端各条提案的落选原因：%s",
		protocolName(proto), want, strings.Join(reasons, "；"))
}

// matchProposal 判定一条提案是否与本端配置完全相符，不符时给出**具体**原因。
func matchProposal(pr Proposal, want SuiteSpec, proto ProtocolID) error {
	if pr.Protocol != proto {
		return fmt.Errorf("协议是 %s，本次协商的是 %s", protocolName(pr.Protocol), protocolName(proto))
	}
	if proto == ProtocolESP {
		spi, err := pr.ESPSPI()
		if err != nil {
			return err
		}
		// SPI 0 在 UDP-4500 上与 non-ESP marker（4 字节全零）撞形，收侧会把 ESP 包
		// 当成 IKE 报文去解；1..255 是 IANA 保留段。两者都会表现为「隧道建好了但不通」。
		if spi < 256 {
			return fmt.Errorf("SPI=%d 落在保留区间（0 与 non-ESP marker 撞形，1..255 为 IANA 保留）", spi)
		}
	}
	if err := matchEncr(pr, want); err != nil {
		return err
	}
	if proto == ProtocolIKE {
		// ESP 提案不含 PRF，只有 IKE 提案要比。
		if !hasTransformID(pr, TransformPRF, want.PRFID) {
			return fmt.Errorf("PRF 候选 [%s] 里没有本端要的 %s", transformList(pr, TransformPRF), prfName(want.PRFID))
		}
	}
	if err := matchInteg(pr, want); err != nil {
		return err
	}
	if err := matchDH(pr, want); err != nil {
		return err
	}
	if proto == ProtocolESP {
		esn := pr.TransformsOfType(TransformESN)
		// 对端完全不提 ESN 时按「不用 ESN」处理（宽容），但只要提了就必须含 0。
		if len(esn) > 0 && !hasTransformID(pr, TransformESN, ESNNone) {
			return fmt.Errorf("只提了 ESN [%s]，本实现不支持扩展序列号", transformList(pr, TransformESN))
		}
	}
	return nil
}

func matchEncr(pr Proposal, want SuiteSpec) error {
	xs := pr.TransformsOfType(TransformEncr)
	if len(xs) == 0 {
		return errors.New("没有 ENCR 变换")
	}
	for _, x := range xs {
		if x.ID != want.EncrID {
			continue
		}
		kb := int(x.KeyLen)
		if kb == 0 {
			// 漏发 Key Length 属性。只有单一长度的算法（SM4）能无歧义补齐；
			// AES 补不了——猜一个长度就是「协商成功、AUTH 失败」的经典造法。
			kb = fixedKeyBits(x.ID)
		}
		if kb == want.KeyBits {
			return nil
		}
	}
	return fmt.Errorf("ENCR 候选 [%s] 里没有本端要的 %s（对端漏发 Key Length 属性时候选里会显示成没有 /位数）",
		transformList(pr, TransformEncr), encrName(want.EncrID, want.KeyBits))
}

func matchInteg(pr Proposal, want SuiteSpec) error {
	xs := pr.TransformsOfType(TransformInteg)
	if want.IntegID != IntegNone {
		if hasTransformID(pr, TransformInteg, want.IntegID) {
			return nil
		}
		return fmt.Errorf("INTEG 候选 [%s] 里没有本端要的 %s", transformList(pr, TransformInteg), integName(want.IntegID))
	}
	// 本端是 combined 模式（AEAD）。对端有两种合法表达：
	//   ① 完全省略 INTEG 变换（strongSwan 的做法）；
	//   ② 显式提 INTEG=NONE(0)（本实现发出去的形态，见 IKEProposal 注释）。
	// 两种都接受——只认一种就会在互通时莫名其妙地 NO_PROPOSAL_CHOSEN。
	if len(xs) == 0 || hasTransformID(pr, TransformInteg, IntegNone) {
		return nil
	}
	return fmt.Errorf("对端要求 INTEG [%s]，但本端用的是 combined 模式（%s 自带完整性，叠 HMAC 会让密钥整体错位）",
		transformList(pr, TransformInteg), encrName(want.EncrID, want.KeyBits))
}

func matchDH(pr Proposal, want SuiteSpec) error {
	xs := pr.TransformsOfType(TransformDH)
	if want.DHID != DHNone {
		if hasTransformID(pr, TransformDH, want.DHID) {
			return nil
		}
		return fmt.Errorf("D-H 候选 [%s] 里没有本端要的 %s", transformList(pr, TransformDH), dhName(want.DHID))
	}
	// 本端不要 PFS。对端若只提了非零群，"挑一个无 DH 的选项"等于**静默把 PFS 降级掉**——
	// 那是安全属性的降级，必须谈崩而不是悄悄接受。
	if len(xs) == 0 || hasTransformID(pr, TransformDH, DHNone) {
		return nil
	}
	return fmt.Errorf("对端要求 PFS（D-H [%s]），但本站点未启用 PFS；接受它等于静默降级，故不选",
		transformList(pr, TransformDH))
}

func hasTransformID(pr Proposal, tt TransformType, id uint16) bool {
	for _, x := range pr.TransformsOfType(tt) {
		if x.ID == id {
			return true
		}
	}
	return false
}

// transformList 把某类型的候选变换排成一行，专供错误信息使用。
func transformList(pr Proposal, tt TransformType) string {
	xs := pr.TransformsOfType(tt)
	if len(xs) == 0 {
		return "空"
	}
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.String()
	}
	return strings.Join(out, " ")
}
