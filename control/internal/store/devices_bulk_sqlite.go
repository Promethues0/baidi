package store

// 终端设备台账的**批量出入口**（wave7 行动 14）：流式导出 + 预登记导入。
//
// 为什么另起一个文件而不是塞进 devices_sqlite.go：那边全部是**终端上报**驱动的
// 生命周期（EnrollDevice / SetDeviceStatus / PurgeStaleDevices），这边是**管理员批量**
// 驱动的出入口，两条路径对同一张表的写入纪律并不相同（见 ImportDevice 顶部）。
// 混在一起，后来人很容易把"上报路径可以做的事"顺手搬到导入路径上。

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// deviceColsD 是 deviceCols 加 "d." 前缀的形式（导出要 JOIN posture_reports，列名必须带表别名）。
// 由那个常量**派生**而不是再抄一份：抄一份就有了第二张列清单，日后加列漏掉哪一处都不报错。
var deviceColsD = "d." + strings.ReplaceAll(deviceCols, ",", ",d.")

// ErrDeviceExists 导入的 (账号,指纹) 在台账里已存在。
//
// ★这是导入路径**唯一**的处理方式：已存在即跳过，绝不改写既有行。
// 允许"导入即更新"的话，一份 CSV 就能把 revoked 的设备悄悄改回 trusted——
// 管理员点过的吊销被一次表格上传静默撤销，而页面上只显示"导入成功 N 台"。
// 这与 EnrollDevice「已登记设备状态一律不动」、PurgeStaleDevices「跳过 revoked」
// 是同一条纪律：吊销不许有任何静默的解除路径。
var ErrDeviceExists = errors.New("该账号下已登记同指纹终端")

// DeviceImportApproverPrefix 预登记设备的批准人前缀（落库形如 "import:admin"）。
//
// 与 DeviceApproverBackfill（迁移回填）同一条理由：授信来源的可信度不同，
// 页面与审计上必须分得清"人在设备页逐台批的"、"策略自动放的"、"升级前既有的"、
// "管理员用 CSV 批量预登记的"。留前缀而不是只留账号，是为了让来源和责任人都在。
const DeviceImportApproverPrefix = "import:"

// DeviceImportRow 一行待预登记的设备（格式校验由 API 层完成，这里只做落库前的最后一道）。
type DeviceImportRow struct {
	Account     string
	Fingerprint string
	Name        string
	Platform    string
	Status      string // 只接受 pending | trusted，见 ImportDevice
	// AssetClass 资产分类（enterprise|personal|managed）。**导入必须支持它**：
	// 导出件里有这一列，若导入侧忽略，「导出→改分类→导入」这条最自然的用法
	// 会在分类上静默落空——而分类是准入判据，落空的后果是一批本该按个人资产
	// 收紧的设备以企业资产身份进了台账，接口还回 200。空串按 enterprise。
	AssetClass string
	// Tags 自由标签（无执行方，纯台账属性）。同理接受导入，免得导出件里的
	// 「标签」列在回流时无声消失。
	Tags []string
}

// ExportDevices 逐行流式吐出设备台账（含 posture 现况），供 CSV 导出。
//
// ★刻意不复用 listDevices：那个函数把整表读进切片再返回，而导出的第一条纪律就是
// 不整表进内存（照 handleAuditExport 的模板）。取数形状与它逐列对齐——页面上看到
// 什么，导出的就是什么；两份口径分家的话，导出文件会变成一份"看起来像台账、
// 其实是另一个查询"的东西，而拿它做合规留档的人无从发现。
//
// 排序按 (账号, 指纹) 而不是页面的 last_seen DESC：导出件常被反复生成做 diff，
// 按最近上报排序会让同一批设备每次导出都换位置，整份文件看起来"全变了"。
func (s *SQLiteStore) ExportDevices(ctx context.Context, staleDays int, fn func(Device) error) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT `+deviceColsD+`,
       COALESCE(p.os,''),COALESCE(p.client_version,''),COALESCE(p.verdict,''),COALESCE(p.level,''),COALESCE(p.ts,0)
FROM trusted_devices d
LEFT JOIN posture_reports p ON p.user=d.account AND p.device=d.fingerprint
ORDER BY d.account, d.fingerprint`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cutoff := staleCutoff(staleDays)
	for rows.Next() {
		var d Device
		var ex deviceExtraCols
		dst := append(deviceScanDst(&d, &ex), &d.OS, &d.ClientVersion, &d.Verdict, &d.Level, &d.PostureTS)
		if err := rows.Scan(dst...); err != nil {
			return err
		}
		finishDeviceScan(&d, ex)
		d.Stale = d.LastSeen < cutoff
		if err := fn(d); err != nil {
			return err
		}
	}
	return rows.Err()
}

// ImportDevice 预登记一台设备（批量导入的单行执行方）。三条纪律：
//
//  1. **只新增，不改写**：(账号,指纹) 已存在即回 ErrDeviceExists，由调用方逐行回报。
//     理由见 ErrDeviceExists——"导入即更新"等于给吊销开一条静默解除通道。
//  2. **上限走同一个判据**：MaxDevicesPerAccount 只有一处定义，且与 EnrollDevice 一样
//     在**同一个事务**里判（DSN 带 _txlock=immediate，事务起手即持写锁）。
//     在 handler 里 check-then-act 会在批量循环 + 并发上报下越界。
//  3. **不伪造审批单**：pending 的导入行不生成 approvals 记录。审批单的语义是
//     "终端首次上报、自己进了队列"，导入是管理员的主动动作——凭空造一张
//     "某终端提交了绑定申请"的单子，等于在事后复盘唯一依据的时间线上写一件没发生的事。
//     导入的 pending 行在设备清单里照常可以「批准」。
//
// last_seen 落**导入时刻**而不是 0：那一列是陈旧判定的唯一依据（PurgeStaleDevices
// 删 last_seen<cutoff 且非 revoked 的行），置 0 的话这批预登记会在管理员下一次点
// 「清理陈旧」时当场被删光——预授信在切 strict 那天静默消失，正是本项目最怕的形态。
// 落导入时刻的副作用（这批设备若一直不上报，staleDays 之后照常会被清理）是**正确**的，
// 由 API 层如实写进导入回执。它不会被误读成"上报过"：verdict 仍为空，页面显示「从未上报」。
func (s *SQLiteStore) ImportDevice(ctx context.Context, row DeviceImportRow, by string) (Device, error) {
	key := normAccount(row.Account)
	fp := strings.TrimSpace(row.Fingerprint)
	if key == "" || fp == "" {
		return Device{}, errors.New("account/fingerprint 必填")
	}
	// 最后一道：导入路径不接受 revoked。凭一行 CSV 把一个从没见过的指纹标成"已吊销"，
	// 表面上是 fail-closed 的方向，实际是给台账塞进一批谁也解释不清来源的黑名单，
	// 而它们照样占着 MaxDevicesPerAccount 的名额。吊销是对**既有**设备的处置动作。
	if row.Status != DeviceStatusPending && row.Status != DeviceStatusTrusted {
		return Device{}, errors.New("导入状态只接受 pending|trusted")
	}
	name := ClampDeviceName(strings.TrimSpace(row.Name))
	platform := ClampDeviceName(strings.TrimSpace(row.Platform))
	now := time.Now().Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback() //nolint:errcheck // 成功路径已 Commit

	var exists string
	err = tx.QueryRowContext(ctx, `SELECT id FROM trusted_devices WHERE account=? AND fingerprint=?`, key, fp).Scan(&exists)
	switch {
	case err == nil:
		return Device{}, ErrDeviceExists
	case !errors.Is(err, sql.ErrNoRows):
		return Device{}, err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM trusted_devices WHERE account=?`, key).Scan(&n); err != nil {
		return Device{}, err
	}
	if n >= MaxDevicesPerAccount {
		return Device{}, ErrDeviceCap
	}

	d := Device{
		ID: "dev-" + uuid.NewString()[:8], Account: key, Fingerprint: fp,
		Name: pick(name, shortFingerprint(fp)), Platform: platform,
		Status: row.Status, FirstSeen: now, LastSeen: now,
		// 分类留空按 enterprise（NormalizeAssetClass 的兜底方向），与"新设备默认企业资产"一致。
		AssetClass: NormalizeAssetClass(row.AssetClass), Tags: NormalizeDeviceTags(row.Tags),
	}
	if d.Status == DeviceStatusTrusted {
		// 授信来源如实记为"导入 + 谁导的"，不冒充成某人在设备页逐台批准过。
		d.ApprovedBy, d.ApprovedAt = DeviceImportApproverPrefix+by, now
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO trusted_devices(`+deviceCols+`) VALUES(`+devicePlaceholders+`)`,
		deviceInsertArgs(d)...); err != nil {
		return Device{}, err
	}
	return d, tx.Commit()
}
