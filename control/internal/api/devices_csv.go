// 终端设备台账的批量导出 / 导入（wave7 行动 14）。
//
// 两个端点，一条主线：**让 strict 准入模式能真正上线**。
//
// 现状是：设备只能由终端自己上报一台、管理员再逐台批准。要把准入模式切到 strict
// （非授信终端拒发敲门令牌），得先把在用终端全部纳管完——几百台机器逐台等它上报、
// 逐台点批准，这条路走不完，于是 strict 永远切不过去，设备闸实际上一直是个观察器。
// 批量预登记是补上的那条路：管理员从资产系统导出 (账号,指纹) 清单，一次预授信。
//
// ★导入路径有一条必须写在脸上的能力边界（见 deviceImportPostureNote）：
// 预登记只写设备台账，不产生 posture 环境报告。设备闸与终端合规闸是**两道各判各的闸**，
// 在 BAIDI_POSTURE_ENFORCE=strict 下，预登记为 trusted 的终端仍会因"缺报"被拒。
// 这句话必须进导入回执、进控制台、进审计——否则就是又造一个「配置齐全却连不上」，
// 而现场只看得到"设备页是绿的、就是连不上"。
package api

import (
	"context"
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 容量上限 ──

// deviceImportMaxBytes 单次导入的请求体字节上限。一个 CSV 不该能撑爆库，
// 也不该能把控制面的内存吃光——解析在内存里完成（见 handleDeviceImport 的说明）。
const deviceImportMaxBytes = 512 << 10

// deviceImportMaxRows 单次导入的数据行上限（不含表头）。
//
// 取 500 与 handleIdleLock 的批量上限同数量级，且每行都会落一条审计
// （预登记一台设备 = 一次准入授予，与在设备页点「批准」等价，不能只记一条汇总）。
// 真实上界其实更小：每账号至多 MaxDevicesPerAccount 台，超出的行会被逐行回报为超限。
const deviceImportMaxRows = 500

// deviceFingerprintMinLen / MaxLen 指纹长度区间。上界与 posture 上报入口的 128 一致
// （同一列的两个写入口，口径只能有一份）；下界挡的是 "x"、"pc" 这类形同通配的值——
// 指纹是准入判据，短到能被撞上的值不该进台账。
const (
	deviceFingerprintMinLen = 8
	deviceFingerprintMaxLen = 128
)

// deviceFingerprintUnknown 采集器探不到机器标识时上报的哨兵值（clients/desktop posture.rs 的 fmt_fp）。
//
// ★导入必须显式拒绝它：这个值在**所有**探测失败的机器上都一样。把它预登记成 trusted，
// 等于给"任何一台指纹采不出来的机器"发了准入通行证，而台账里看起来只是普通的一台设备。
const deviceFingerprintUnknown = "UNKNOWN-DEVICE"

// deviceImportPostureNote 预登记与终端合规闸的真实交互。API 回执与控制台共用这一份文本
// （照 deviceRevokeBlastRadius 的做法：界面上写一套、实际做另一套是最不该出现的错误）。
const deviceImportPostureNote = "预登记只写设备台账（trusted_devices），不产生终端环境报告（posture_reports）——" +
	"两者按 (账号,指纹) 一一对应，导入的行只有前者。因此在这些终端用客户端成功上报一次环境之前：" +
	"① 设备准入闸放行它们；② 但若控制面开着 BAIDI_POSTURE_ENFORCE=strict（缺报/过期即拒），" +
	"敲门令牌依然会被拒——设备闸与终端合规闸各判各的，预登记过不了合规闸；" +
	"③ 台账里它们的「最近合规判定」显示「从未上报」，那不是「合规」；" +
	"④ 它们的「最近上报」记的是导入时刻，若始终不上报，超过陈旧阈值后会被「清理陈旧」一并删除。"

// ── ① 导出 ──

// deviceExportStore 设备台账的流式导出能力（SQLiteStore 实现；Memory 无设备台账）。
type deviceExportStore interface {
	ExportDevices(ctx context.Context, staleDays int, fn func(store.Device) error) error
}

// handleDeviceExport GET /api/v1/devices/export：流式导出设备台账 CSV 附件。
//
// 权限比读端点更严：GET /api/v1/devices 是"任意管理员 + 角色现算"，这里要 PermSecurity。
// 理由是**动作形状不同**——页面上翻台账是查阅，整表 CSV 是把全员硬件指纹与授信状态
// 一次性搬到管理员机器上的数据出口；而"谁能改这张表的准入"正是 PermSecurity
// （批准/吊销/删除/准入设置全在这一权下）。台账的出口与台账的处置权收在同一权里。
//
// 流式逐行写、UTF-8 BOM、全列过 csvCell、审计只在写完后记——照 handleAuditExport。
func (s *Server) handleDeviceExport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	es, ok := s.store.(deviceExportStore)
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "当前存储不支持终端台账导出")
		return
	}
	// 陈旧判定的阈值先读出来：它可能失败，而响应头一旦写出去就没法改状态码了。
	st, err := s.store.DeviceTrustSetting(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "读取授信终端准入设置失败")
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="baidi-devices-`+time.Now().Format("20060102")+`.csv"`)
	w.WriteHeader(http.StatusOK)
	// UTF-8 BOM：Excel 打开含中文的 CSV 不乱码。
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	// 前七列与导入的表头识别对齐（账号/指纹/设备名/平台/状态/资产分类/标签），
	// 导出件改完能直接再导入；其余列是只读现况，导入时忽略。
	//
	// ★「资产分类」与「标签」必须**同时**出现在导出与导入两侧。只导不认的话，
	// 「导出→改分类→导入」这条最自然的用法会在分类上静默落空——而分类是准入判据，
	// 落空意味着一批本该按个人资产收紧的机器以企业资产身份进了台账，接口还回 200。
	_ = cw.Write([]string{"账号", "指纹", "设备名", "平台", "状态", "资产分类", "标签", "授信来源", "批准时间",
		"首次登记", "最近上报", "最近合规判定", "风险等级", "操作系统", "客户端版本", "是否陈旧", "吊销理由", "审批单号", "设备ID"})
	n := 0
	err = es.ExportDevices(r.Context(), st.StaleDays, func(d store.Device) error {
		n++
		// 全列过 csvCell：设备名来自终端自报的 os 字段或管理员手输、账号可能来自外部目录，
		// 都是用户可控的。逐列判断"哪列可信"没有意义——这份 CSV 就是给人用 Excel 打开的。
		return cw.Write([]string{
			csvCell(d.Account), csvCell(d.Fingerprint), csvCell(d.Name), csvCell(d.Platform),
			csvCell(deviceStatusZh(d.Status)),
			// 分类导中文（导入侧同时认中文与枚举），标签用「;」拼——逗号会被 CSV 转义成
			// 引号包裹，Excel 里看着像一整段文本，分号让人一眼看出这是多个标签。
			csvCell(store.AssetClassZh(d.AssetClass)), csvCell(strings.Join(d.Tags, deviceTagSep)),
			csvCell(deviceApproverZh(d)), csvCell(fmtUnix(d.ApprovedAt)),
			csvCell(fmtUnix(d.FirstSeen)), csvCell(fmtUnix(d.LastSeen)),
			csvCell(deviceVerdictZh(d.Verdict)), csvCell(d.Level), csvCell(d.OS), csvCell(d.ClientVersion),
			csvCell(boolZh(d.Stale)), csvCell(d.RevokeReason), csvCell(d.ApprovalID), csvCell(d.ID),
		})
	})
	cw.Flush()
	if err != nil {
		// 响应头已发出，改不了状态码；靠截断让下载侧感知失败，且不落「已导出」审计。
		return
	}
	s.audit(r, "admin", "导出终端设备台账 CSV，共 "+strconv.Itoa(n)+" 台（含归属账号、硬件指纹、授信状态）", "ok")
}

// deviceStatusZh / deviceVerdictZh / boolZh 导出用的中文值。
//
// ★导出中文而不是原始枚举，是为了让这份文件在 Excel 里直接可读；代价是导入侧
// 必须认得回来（deviceImportStatus 同时收中文与枚举），否则「导出→改→导入」这条
// 最自然的用法会在状态列上整批失败。两处的取值表挨着写就是为了不让它们分家。
func deviceStatusZh(s string) string {
	switch s {
	case store.DeviceStatusTrusted:
		return "已授信"
	case store.DeviceStatusPending:
		return "待批准"
	case store.DeviceStatusRevoked:
		return "已吊销"
	}
	return s
}

func deviceVerdictZh(v string) string {
	switch v {
	case "":
		// 空判定是「从未上报」，不是「合规」。这条纪律在设备页上已经写死，导出件同口径。
		return "从未上报"
	case "allow":
		return "合规"
	case "gray":
		return "灰度观察"
	case "degrade":
		return "已降权"
	case "block":
		return "不合规"
	}
	return v
}

func boolZh(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

// 时间列复用 jit.go 的 fmtUnix（0 → 「—」，不写成 1970 年）：同一份口径只留一处。

// deviceApproverZh 授信来源的中文说明。四种来源的可信度不同，导出件必须分得清
// （与控制台 approverText 同一份口径）：策略自动放的 / 升级前既有的 / 批量导入的 / 人批的。
func deviceApproverZh(d store.Device) string {
	switch {
	case d.ApprovedBy == "":
		return "—"
	case d.ApprovedBy == "auto":
		return "自动绑定放行"
	case d.ApprovedBy == store.DeviceApproverBackfill:
		return "升级前既有设备（按历史上报记录纳管）"
	case strings.HasPrefix(d.ApprovedBy, store.DeviceImportApproverPrefix):
		return "批量导入预登记（由 " + strings.TrimPrefix(d.ApprovedBy, store.DeviceImportApproverPrefix) + "）"
	}
	return "由 " + d.ApprovedBy + " 批准"
}

// ── ② 导入 ──

// deviceImportWriter 预登记写入能力（SQLiteStore 实现）。
type deviceImportWriter interface {
	ImportDevice(ctx context.Context, row store.DeviceImportRow, by string) (store.Device, error)
}

// deviceImportHeader CSV 表头到字段的映射。同时收中文（导出件的表头）与英文别名
// （从资产系统直接导出的清单多半是英文列名）。未识别的列一律忽略。
var deviceImportHeader = map[string]string{
	"账号": "account", "归属账号": "account", "用户": "account", "account": "account", "user": "account",
	"指纹": "fingerprint", "设备指纹": "fingerprint", "硬件指纹": "fingerprint", "fingerprint": "fingerprint", "device": "fingerprint",
	"设备名": "name", "设备名称": "name", "name": "name",
	"平台": "platform", "操作系统平台": "platform", "platform": "platform",
	"状态": "status", "授信状态": "status", "status": "status",
	// 资产分类与标签（wave7 行动 15）。★理由不是「导出→改→导入」——那条路对**存量**设备
	// 本来就改不了任何东西（ImportDevice 对已存在的 (账号,指纹) 一律跳过，回 ErrDeviceExists）。
	// 真正的理由是**批量预登记**：一次导进一批 BYOD 时可以直接标成个人资产，
	// 否则只能先导进来（默认企业资产）再逐台改，而中间那段窗口里 personalPolicy 管不到它们。
	"资产分类": "assetClass", "资产归属": "assetClass", "assetclass": "assetClass", "asset_class": "assetClass",
	"标签": "tags", "资产标签": "tags", "tags": "tags", "tag": "tags",
}

// deviceTagSep CSV 里多个标签的分隔符。导出用它拼、导入按它拆（同时也认逗号与顿号——
// 人手填的表格里这三种都会出现，只认一种等于把另外两种整批读成一个超长标签）。
const deviceTagSep = ";"

// splitDeviceTags 拆 CSV 标签单元格。归一（去空/去重/截长/截数）由 store 侧统一做。
func splitDeviceTags(cell string) []string {
	if strings.TrimSpace(cell) == "" {
		return nil
	}
	return strings.FieldsFunc(cell, func(r rune) bool {
		return r == ';' || r == '；' || r == ',' || r == '，' || r == '、'
	})
}

// deviceImportAssetClass 把 CSV 的资产分类列归一成枚举。同时认中文（导出件的写法）
// 与枚举值；**留空按企业资产**——与"新设备默认企业资产"同一个缺省，漏填一列
// 不该把一批机器悄悄划成个人资产（那在 deny 策略下等于把它们全部拒之门外）。
func deviceImportAssetClass(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "企业资产", "企业", store.AssetClassEnterprise:
		return store.AssetClassEnterprise, true
	case "个人资产", "个人", store.AssetClassPersonal:
		return store.AssetClassPersonal, true
	case "企业纳管个人", "纳管", "纳管个人", store.AssetClassManaged:
		return store.AssetClassManaged, true
	}
	return "", false
}

// deviceImportSkip 一行被跳过的记录。
//
// line 是文件里的行号（表头算第 1 行，空行照常计数——管理员是拿这个号去文件里定位那一行的，
// 跳过空行会让后面每一行都对不上）。account/fingerprint 回的是**他写的原值**而不是归一后的值，
// 同理：回一个他文件里搜不到的字符串，等于让他自己去猜是哪一行。
type deviceImportSkip struct {
	Line        int    `json:"line"`
	Account     string `json:"account,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Reason      string `json:"reason"`
}

// deviceImportOK 一行成功预登记的记录。
type deviceImportOK struct {
	Line        int    `json:"line"`
	Account     string `json:"account"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	// AssetClass/Tags 回执必须带回**落库后的实际值**（不是 CSV 里的原文）：
	// 留空按企业资产、标签被去重截断，都要让管理员在回执里当场看见，
	// 而不是导完再去台账里逐台核对。
	AssetClass string   `json:"assetClass"`
	Tags       []string `json:"tags"`
}

// handleDeviceImport POST /api/v1/devices/import（PermSecurity，body = CSV 文本）。
//
// 与「批准一台设备」同权：一行 status=trusted 的导入就是一次准入授予，
// 效果与在设备页点「批准」完全相同，不该有更低的门槛。
//
// 逐行回报、部分失败不整批回滚（照 handleIdleLock）：管理员真正要的是"哪几行没进去、为什么"，
// 整批回滚只会让 500 行里的一个拼写错误把另外 499 行也退回去。
//
// **先整体解析、再逐行落库**：行数超限必须在写任何一行之前就拒掉，否则"超限报错"
// 会变成"前 500 行已经进库了，然后报了个错"——管理员既不知道进了多少，重试还会撞上
// 已存在。请求体有 deviceImportMaxBytes 上限，所以整体解析的内存是有界的。
func (s *Server) handleDeviceImport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	iw, ok := s.writer.(deviceImportWriter)
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "当前存储不支持终端预登记导入")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, deviceImportMaxBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			httpx.Error(w, http.StatusRequestEntityTooLarge,
				"CSV 超过 "+strconv.Itoa(deviceImportMaxBytes>>10)+" KiB 上限，本批未导入任何设备，请拆分后重试")
			return
		}
		httpx.Error(w, http.StatusBadRequest, "读取上传内容失败")
		return
	}

	records, herr := parseDeviceCSV(raw)
	if herr != nil {
		httpx.Error(w, http.StatusBadRequest, herr.Error())
		return
	}
	if len(records) == 0 {
		httpx.Error(w, http.StatusBadRequest, "CSV 里没有数据行（第一行必须是表头，至少包含「账号」与「指纹」两列）")
		return
	}
	if len(records) > deviceImportMaxRows {
		httpx.Error(w, http.StatusBadRequest, "CSV 共 "+strconv.Itoa(len(records))+" 行，超过单批 "+
			strconv.Itoa(deviceImportMaxRows)+" 行上限。本批未导入任何设备，请拆分后重试")
		return
	}

	// 账号目录一次性读进 map：逐行调 lookupDirUser 会把整张用户表扫 500 遍。
	dir, err := s.accountIndex(r.Context())
	if err != nil {
		// 校验材料读不到就不导入（fail-closed）：账号存在性是这条路径唯一能挡住
		// "把设备预授信给一个根本不存在的账号"的判据，跳过它等于让台账收下任意字符串。
		httpx.Error(w, http.StatusInternalServerError, "读取用户目录失败，本批未导入任何设备")
		return
	}

	actor := actorOf(r)
	imported := []deviceImportOK{}
	skips := []deviceImportSkip{}
	trustedN := 0
	personalN := 0
	for _, rec := range records {
		row, reason := normalizeDeviceImportRow(rec, dir)
		if reason != "" {
			skips = append(skips, deviceImportSkip{Line: rec.line, Account: rec.account, Fingerprint: rec.fingerprint, Reason: reason})
			continue
		}
		d, err := iw.ImportDevice(r.Context(), row, actor)
		switch {
		case errors.Is(err, store.ErrDeviceExists):
			// 既有行一律不动（含 revoked）：导入不是"更新"，理由见 store.ErrDeviceExists。
			skips = append(skips, deviceImportSkip{Line: rec.line, Account: row.Account, Fingerprint: row.Fingerprint,
				Reason: "该账号下已登记同指纹终端，导入不修改既有设备的状态（避免一次上传静默撤销一条吊销）"})
			continue
		case errors.Is(err, store.ErrDeviceCap):
			skips = append(skips, deviceImportSkip{Line: rec.line, Account: row.Account, Fingerprint: row.Fingerprint,
				Reason: "该账号终端数已达上限（" + strconv.Itoa(store.MaxDevicesPerAccount) + " 台），请先清理后重试"})
			continue
		case err != nil:
			skips = append(skips, deviceImportSkip{Line: rec.line, Account: row.Account, Fingerprint: row.Fingerprint,
				Reason: "写入失败：" + err.Error()})
			continue
		}
		if d.Status == store.DeviceStatusTrusted {
			trustedN++
		}
		if store.IsPersonalAsset(d.AssetClass) {
			personalN++
		}
		// 逐台落审计：预登记一台 trusted 设备就是一次准入授予，与设备页点「批准」等价。
		// 只记一条汇总的话，事后想查"这台机器是谁什么时候放进来的"就只剩一个数字。
		// 资产分类一并记：它是准入判据，"当初导进来时标的是什么"事后必须查得到。
		s.audit(r, "security", "批量导入预登记终端："+d.Account+" / "+d.Name+"（指纹 "+shortFP(d.Fingerprint)+
			"，状态 "+deviceStatusZh(d.Status)+"，资产分类 "+store.AssetClassZh(d.AssetClass)+
			"）。该终端尚未上报过终端环境报告", "ok")
		imported = append(imported, deviceImportOK{Line: rec.line, Account: d.Account, Fingerprint: d.Fingerprint,
			Name: d.Name, Status: d.Status, AssetClass: d.AssetClass, Tags: d.Tags})
	}

	enforce := "observe"
	if s.postureStrict {
		enforce = "strict"
	}
	// 个人资产策略随回执下发，与 postureEnforce 同一条理由：在 deny 下，
	// 一行"个人资产 + 已授信"导进去照样连不上——不说的话，这就是又一个
	// 「台账是绿的、就是连不上」。策略读不到时如实回空串，前端不显示这一段。
	personalPolicy := ""
	if set, err := s.store.DeviceTrustSetting(r.Context()); err == nil {
		personalPolicy = set.PersonalPolicy
	}
	s.audit(r, "admin", "终端设备批量导入完成："+strconv.Itoa(len(imported))+" 台已预登记（其中 "+
		strconv.Itoa(trustedN)+" 台直接置为已授信、"+strconv.Itoa(personalN)+" 台标为个人资产）、"+
		strconv.Itoa(len(skips))+" 行跳过；"+
		"当前 BAIDI_POSTURE_ENFORCE="+enforce+"（strict 下这些终端在首次上报环境前仍会被拒发敲门令牌）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "imported": imported, "skipped": skips,
		"trusted": trustedN,
		// 回执必须带上这几项：管理员看到"导入成功 200 台"之后的下一步动作，
		// 完全取决于当前是不是 strict / 个人资产策略是哪一档——不说的话，
		// 他会以为可以切模式了。
		"postureEnforce": enforce,
		"personal":       personalN,
		"personalPolicy": personalPolicy,
		"note":           deviceImportPostureNote,
	})
}

// deviceCSVRecord 解析后的一行（保留原始行号与原始值，跳过回报要拿它对照文件）。
type deviceCSVRecord struct {
	line        int
	account     string
	fingerprint string
	name        string
	platform    string
	status      string
	assetClass  string
	tags        string
}

// parseDeviceCSV 解析上传的 CSV：剥 UTF-8 BOM → 按表头映射列 → 吐出数据行。
//
// 表头是**必需**的，且认不出「账号」「指纹」就整体拒绝：退化成按列序猜的话，
// 一份列顺序不同的表格会把设备名当指纹整批写进台账，而接口照回 200。
func parseDeviceCSV(raw []byte) ([]deviceCSVRecord, error) {
	// 我们自己导出的文件带 BOM（Excel 中文不乱码）。不剥掉的话第一列名会变成「(BOM)账号」，
	// 表头识别整体落空——「导出→改→导入」这条最自然的用法会在第一步就失败。
	body := strings.TrimPrefix(string(raw), "\ufeff")
	cr := csv.NewReader(strings.NewReader(body))
	cr.FieldsPerRecord = -1 // 容忍参差不齐的行（Excel 常在尾部留空列）
	cr.TrimLeadingSpace = true
	// ★逐条 Read 而不是 ReadAll：回执里的行号要能让管理员回 Excel 里定位，
	// 而 ReadAll 之后只剩切片下标——单元格里含换行时（引号包裹的多行文本）
	// 下标与物理行号会错开，报出去的行号指向一行无辜的数据。
	// users 侧用 FieldPos 拿的是真物理行号，这里对齐同一语义。
	var rows [][]string
	var lines []int
	var err error
	for {
		rec, rerr := cr.Read()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			err = rerr
			break
		}
		ln, _ := cr.FieldPos(0) // 只在 rerr==nil 之后调：失败那轮 FieldPos 会越界 panic
		rows = append(rows, rec)
		lines = append(lines, ln)
	}
	if err != nil {
		// 整体拒绝而不是"能解析多少算多少"：CSV 引号错位会让后续所有行整体错位，
		// 那种情况下"导入成功 N 台"里的每一台都可能是错的。
		return nil, errors.New("CSV 解析失败：" + err.Error())
	}
	var head []string
	var idx = map[string]int{}
	for _, row := range rows {
		if !isBlankRow(row) {
			head = row
			break
		}
	}
	// ★空文件要说"空"，不能说"缺账号列"——后者会把人支去改表头，而问题是压根没内容。
	// （users 侧对同一输入回的就是「CSV 内容为空」，两处口径统一。）
	if len(head) == 0 {
		return nil, errors.New("CSV 内容为空")
	}
	for i, h := range head {
		if f, ok := deviceImportHeader[strings.ToLower(strings.TrimSpace(h))]; ok {
			if _, dup := idx[f]; !dup {
				idx[f] = i
			}
		}
	}
	if _, ok := idx["account"]; !ok {
		return nil, errors.New("CSV 表头缺少「账号」列（可用列名：账号 / account / user）")
	}
	if _, ok := idx["fingerprint"]; !ok {
		return nil, errors.New("CSV 表头缺少「指纹」列（可用列名：指纹 / fingerprint / device）")
	}

	get := func(row []string, field string) string {
		i, ok := idx[field]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	out := []deviceCSVRecord{}
	seenHead := false
	for n, row := range rows {
		if isBlankRow(row) {
			continue // 空行（Excel 尾部常留一堆）不算数据行，也不占行数上限
		}
		if !seenHead {
			seenHead = true
			continue
		}
		out = append(out, deviceCSVRecord{
			line: lines[n], account: get(row, "account"), fingerprint: get(row, "fingerprint"),
			name: get(row, "name"), platform: get(row, "platform"), status: get(row, "status"),
			assetClass: get(row, "assetClass"), tags: get(row, "tags"),
		})
	}
	return out, nil
}

func isBlankRow(row []string) bool {
	for _, c := range row {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

// normalizeDeviceImportRow 单行校验 + 归一。返回空 reason 表示可以落库。
//
// 校验顺序即回报质量：先账号、再指纹、再状态、再平台——一行里有多处问题时，
// 管理员先看到的应该是最根本的那个。
func normalizeDeviceImportRow(rec deviceCSVRecord, dir map[string]store.DirUser) (store.DeviceImportRow, string) {
	account := normUser(rec.account)
	if account == "" {
		return store.DeviceImportRow{}, "账号为空"
	}
	// ★账号必须在用户目录里真实存在。设备台账按账号索引，给一个不存在的账号预登记设备，
	// 结果是一条谁也管不到的孤儿记录：它占着该"账号"的名额、出现在导出件里、
	// 却在用户页上找不到主人；等哪天真有人注册了这个名字，他会凭空继承一台已授信终端。
	u, found := dir[account]
	if !found {
		return store.DeviceImportRow{}, "账号不存在于用户目录（设备台账按账号索引，不接受凭空创建的归属）"
	}
	if err := validDeviceFingerprint(rec.fingerprint); err != nil {
		return store.DeviceImportRow{}, err.Error()
	}
	status, ok := deviceImportStatus(rec.status)
	if !ok {
		return store.DeviceImportRow{}, "状态只接受「待批准/pending」或「已授信/trusted」（留空按待批准处理）；" +
			"「已吊销」是对既有设备的处置动作，不能凭一行 CSV 凭空创建"
	}
	// 平台走 posture 上报同一张枚举表（validReportPlatform）：那是全系统对这一列的唯一口径，
	// 放任自由文本会让「按平台看合规基线」那一侧永远匹配不上，且没有任何报错。
	platform := strings.TrimSpace(rec.platform)
	if platform != "" && !validReportPlatform[platform] {
		return store.DeviceImportRow{}, "平台只接受 Windows|macOS|Linux（区分大小写）或留空"
	}
	name := strings.TrimSpace(rec.name)
	if len([]rune(name)) > store.DeviceNameMaxRunes {
		// 管理员手工准备的文件里字段过长要**拒绝**而不是截断（与 RenameDevice 同口径：
		// 他看得到这条回报，截断只会让他以为存进去的就是他写的那个名字）。
		return store.DeviceImportRow{}, "设备名过长（≤" + strconv.Itoa(store.DeviceNameMaxRunes) + " 字）"
	}
	// 资产分类**认不出就拒整行**：它是准入判据，兜成 enterprise 等于把一台管理员
	// 明确写成个人资产（只是拼错了）的机器当企业资产放进来，而回执里显示导入成功。
	assetClass, ok := deviceImportAssetClass(rec.assetClass)
	if !ok {
		return store.DeviceImportRow{}, "资产分类只接受「企业资产/enterprise」「个人资产/personal」" +
			"「企业纳管个人/managed」或留空（留空按企业资产）"
	}
	// 账号一律用目录里的规范写法落库：CSV 里大小写混写不该在台账里造出两个"看起来不同"的归属。
	return store.DeviceImportRow{
		Account: normUser(u.Account), Fingerprint: strings.TrimSpace(rec.fingerprint),
		Name: name, Platform: platform, Status: status,
		// 标签只归一不校验（没有执行方，超长/超量截断即可，见 store.NormalizeDeviceTags）。
		AssetClass: assetClass, Tags: splitDeviceTags(rec.tags),
	}, ""
}

// deviceImportStatus 把 CSV 里的状态列归一成枚举。同时认中文（导出件的写法）与枚举值，
// 留空按 pending——**默认最保守的那一档**：漏填一列就批量发出准入授权是不能接受的默认。
// revoked 明确不接受（连同它的中文写法），理由见 store.ImportDevice。
func deviceImportStatus(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "待批准", "pending":
		return store.DeviceStatusPending, true
	case "已授信", "授信", "trusted":
		return store.DeviceStatusTrusted, true
	}
	return "", false
}

// validDeviceFingerprint 指纹的基本格式校验。
//
// 指纹由客户端自报（桌面端 posture.rs 的 fmt_fp 产出 "xxxx:xxxx:xxxx:xxxx"，
// baidi-tun -device 与登录 deviceId 也走同一个值），所以这里**刻意不钉死成那一种形状**——
// 钉死会让别的合法客户端整批导不进来。但它是准入判据，不能是"任意字符串"：
//
//   - 长度 [8,128]，且至少 8 个字母数字：挡住 "pc"、"::::::::" 这类形同通配的值；
//   - 字符集限 ASCII 字母数字与 : - _ .：空格/中文/引号/控制字符进了台账，
//     只会在比对时静默对不上（客户端上报的永远是另一个字符串）；
//   - 明确拒绝 "/" "\" "." ".."：与 posture 上报入口同一道闸——那两个字符会让
//     DELETE /posture/{user}/{device} 这条按路径定位的管理接口永远删不掉这条记录；
//   - 明确拒绝哨兵值 UNKNOWN-DEVICE，理由见该常量。
func validDeviceFingerprint(fp string) error {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return errors.New("指纹为空")
	}
	if strings.EqualFold(fp, deviceFingerprintUnknown) {
		return errors.New("指纹为采集器的「探测失败」哨兵值 " + deviceFingerprintUnknown +
			"，所有采不到机器标识的终端都报这个值——预登记它等于给任意一台这样的机器发通行证")
	}
	if len(fp) < deviceFingerprintMinLen || len(fp) > deviceFingerprintMaxLen {
		return errors.New("指纹长度须在 " + strconv.Itoa(deviceFingerprintMinLen) + "~" +
			strconv.Itoa(deviceFingerprintMaxLen) + " 个字符之间")
	}
	alnum := 0
	for _, c := range fp {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			alnum++
		case c == ':' || c == '-' || c == '_' || c == '.':
		default:
			return errors.New("指纹含非法字符（只接受 ASCII 字母数字与 : - _ .）")
		}
	}
	if alnum < deviceFingerprintMinLen {
		return errors.New("指纹的有效字符太少（至少 " + strconv.Itoa(deviceFingerprintMinLen) + " 个字母数字）")
	}
	if fp == "." || fp == ".." {
		return errors.New("指纹不可为 . 或 ..")
	}
	return nil
}

// accountIndex 规范化账号 → 目录用户的索引（导入逐行校验归属用）。
func (s *Server) accountIndex(ctx context.Context) (map[string]store.DirUser, error) {
	b, err := s.store.Users(ctx)
	if err != nil {
		return nil, err
	}
	idx := make(map[string]store.DirUser, len(b.Users))
	for _, u := range b.Users {
		idx[normUser(u.Account)] = u
	}
	return idx, nil
}
