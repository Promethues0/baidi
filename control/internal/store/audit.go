package store

import "context"

// AuditBundle 审计中心页：分类聚合 + 磁盘水位 + 日志条目。
type AuditBundle struct {
	Categories []KV         `json:"categories"`
	TodayTotal int          `json:"todayTotal"`
	Disk       DiskStat     `json:"disk"`
	Logs       []AuditEntry `json:"logs"`
}

type DiskStat struct {
	UsedPct    int `json:"usedPct"`
	TotalGB    int `json:"totalGB"`
	RetainDays int `json:"retainDays"`
}

// AuditDiskStat 审计存储的实测水位（运维诊断/审计页共用）：
// 行数来自 COUNT(*)，库文件字节数来自 os.Stat（含 WAL/SHM），
// 文件系统容量来自 syscall.Statfs——全部是量出来的，没有一个字段是种子编的。
type AuditDiskStat struct {
	Rows    int64 // audit_log 当前行数
	DBBytes int64 // 库文件实际占用（主库 + -wal + -shm）
	// FSTotalBytes / FSFreeBytes 库文件所在文件系统的总容量与可用余量。
	// FSSupported=false 表示当前平台没有 Statfs（Windows 兜底），容量两项无意义。
	FSTotalBytes uint64
	FSFreeBytes  uint64
	FSSupported  bool
	// RetainDays 滚动清理天数（0=未配置）。来源见 SQLiteStore.auditRetainDays 的注释。
	RetainDays int
}

// UsedPct 文件系统占用百分比（0-100）；平台不支持时返回 0。
func (d AuditDiskStat) UsedPct() int {
	if !d.FSSupported || d.FSTotalBytes == 0 {
		return 0
	}
	return int(float64(d.FSTotalBytes-d.FSFreeBytes)/float64(d.FSTotalBytes)*100 + 0.5)
}

// ToDiskStat 折算成审计页磁贴的口径（平台不支持容量探测时两项为 0，如实示弱）。
func (d AuditDiskStat) ToDiskStat() DiskStat {
	ds := DiskStat{RetainDays: d.RetainDays}
	if d.FSSupported {
		ds.UsedPct = d.UsedPct()
		ds.TotalGB = int(d.FSTotalBytes >> 30)
	}
	return ds
}

// AuditVerifyResult 防篡改链全量校验结论（GET /api/v1/audit/verify）。
type AuditVerifyResult struct {
	OK      bool `json:"ok"`
	Checked int  `json:"checked"`
	// BrokenAt 首个断点行的链内序号 seq（1 起）；ok 时为 0。
	BrokenAt int64 `json:"brokenAt"`
}

// AuditEntry 一条审计记录。
//
// ★这个结构体是**三个出口的唯一口径**：`GET /api/v1/audit` 列表、CSV 导出、
// 以及外送给 syslog/SIEM（internal/forward 的 Record 就是它的类型别名）。
// 谁要给审计加字段，改这一处三处都跟上；各出口自建 DTO 的话，
// 同一条审计在三个地方长得不一样，而"哪个是准的"没人说得清。
type AuditEntry struct {
	Time     string `json:"time"`
	Category string `json:"category"` // access | auth | admin | security | dataplane
	User     string `json:"user"`
	SrcIP    string `json:"srcIp"`
	Event    string `json:"event"`
	Verdict  string `json:"verdict"` // allow | deny | mfa | ok | fail

	// Seq / MAC 防篡改链的链内序号与链式 MAC，由 RecordAudit 落库时算出。
	//
	// ★带出去是外送功能的**核心价值**，不是附赠：外部 SIEM 拿着这两格才能独立
	// 发现"控制面那边的第 N 条与我收到的第 N 条不是同一条"。链留在被审计方
	// 自己的库里时，整库替换（连同 HMAC 密钥）之后 verify 依然全绿。
	// 写入路径（Memory 种子、RecordAudit 的入参）不填它们，故 omitempty。
	Seq int64  `json:"seq,omitempty"`
	MAC string `json:"mac,omitempty"`
}

func (m *Memory) Audit(_ context.Context) (AuditBundle, error) {
	return AuditBundle{
		Categories: []KV{
			{Name: "访问决策", Value: 1284},
			{Name: "登录认证", Value: 642},
			{Name: "管理操作", Value: 73},
			{Name: "安全事件", Value: 41},
		},
		TodayTotal: 2040,
		Disk:       DiskStat{UsedPct: 62, TotalGB: 512, RetainDays: 180},
		Logs: []AuditEntry{
			{Time: "2026-06-22 20:11:03", Category: "access", User: "zhang.wei", SrcIP: "10.8.2.31", Event: "访问 研发 Git 仓库", Verdict: "allow"},
			{Time: "2026-06-22 20:10:48", Category: "auth", User: "li.fang", SrcIP: "10.8.5.12", Event: "SAML SSO 登录成功", Verdict: "ok"},
			{Time: "2026-06-22 20:09:55", Category: "security", User: "ext.zhou", SrcIP: "203.0.113.7", Event: "异地登录触发增强认证", Verdict: "mfa"},
			{Time: "2026-06-22 20:08:30", Category: "access", User: "wang.qiang", SrcIP: "10.8.5.40", Event: "访问 财务核算系统 被拒（无授权）", Verdict: "deny"},
			{Time: "2026-06-22 20:07:12", Category: "admin", User: "security-admin", SrcIP: "10.0.0.9", Event: "修改 销售部 用户策略", Verdict: "ok"},
			{Time: "2026-06-22 20:05:40", Category: "auth", User: "zhao.min", SrcIP: "10.8.7.9", Event: "密码连续错误 5 次，账号锁定", Verdict: "fail"},
			{Time: "2026-06-22 20:03:18", Category: "security", User: "—", SrcIP: "198.51.100.22", Event: "SPA 敲门失败，源 IP 不响应", Verdict: "deny"},
			{Time: "2026-06-22 20:01:02", Category: "access", User: "liu.yang", SrcIP: "10.8.7.21", Event: "访问 客服工单系统", Verdict: "allow"},
		},
	}, nil
}
