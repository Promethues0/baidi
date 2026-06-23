package store

import "context"

// DeviceBundle 终端管理页：信任绑定设置 + 设备清单 + 绑定审批队列。
type DeviceBundle struct {
	Settings  DeviceTrustSetting `json:"settings"`
	Devices   []Device           `json:"devices"`
	Approvals []TrustApproval    `json:"approvals"`
}

type DeviceTrustSetting struct {
	Enabled      bool   `json:"enabled"`
	BindMethod   string `json:"bindMethod"` // auto | approval
	PerUserQuota int    `json:"perUserQuota"`
}

type Device struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Fingerprint   string   `json:"fingerprint"`
	User          string   `json:"user"`
	AssetClass    string   `json:"assetClass"` // enterprise | personal | managed
	OS            string   `json:"os"`
	ClientVersion string   `json:"clientVersion"`
	Online        bool     `json:"online"`
	Tags          []string `json:"tags"`
}

// TrustApproval 设备信任绑定申请（含生命周期时间线）。
type TrustApproval struct {
	ID          string          `json:"id"`
	User        string          `json:"user"`
	Device      string          `json:"device"`
	Fingerprint string          `json:"fingerprint"`
	SubmittedAt string          `json:"submittedAt"`
	Reason      string          `json:"reason"`
	Status      string          `json:"status"` // pending | approved | rejected
	Timeline    []ApprovalEvent `json:"timeline"`
}

type ApprovalEvent struct {
	Time   string `json:"time"`
	Kind   string `json:"kind"` // submit | login | review | notify | risk
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func (m *Memory) Devices(_ context.Context) (DeviceBundle, error) {
	return DeviceBundle{
		Settings: DeviceTrustSetting{Enabled: true, BindMethod: "approval", PerUserQuota: 3},
		Devices: []Device{
			{ID: "d1", Name: "研发-张伟-PC", Fingerprint: "8F3A:11C7:9E22:4B0D", User: "zhang.wei", AssetClass: "enterprise", OS: "Windows 11", ClientVersion: "2.4.1", Online: true, Tags: []string{"已加固", "研发"}},
			{ID: "d2", Name: "销售-李芳-Mac", Fingerprint: "2D90:77AA:0C13:5F8E", User: "li.fang", AssetClass: "managed", OS: "macOS 14", ClientVersion: "2.4.1", Online: true, Tags: []string{"BYOD"}},
			{ID: "d3", Name: "客服-赵敏-PC", Fingerprint: "A1B2:C3D4:E5F6:0789", User: "zhao.min", AssetClass: "enterprise", OS: "Windows 10", ClientVersion: "2.3.8", Online: false, Tags: []string{"待升级"}},
			{ID: "d4", Name: "外包-周-未授信", Fingerprint: "FF01:2345:6789:ABCD", User: "ext.zhou", AssetClass: "personal", OS: "Android 13", ClientVersion: "2.4.0", Online: false, Tags: []string{"个人设备", "高风险"}},
		},
		Approvals: []TrustApproval{
			{ID: "ap1", User: "王强", Device: "销售-王强-iPad", Fingerprint: "3C5E:88F0:12A4:9D6B", SubmittedAt: "2026-06-22 18:40", Reason: "新配发 iPad，需访问 CRM", Status: "pending", Timeline: []ApprovalEvent{
				{Time: "2026-06-22 18:40", Kind: "submit", Title: "提交绑定申请", Detail: "王强 在未授信终端发起绑定，理由：新配发 iPad，需访问 CRM"},
				{Time: "2026-06-22 18:40", Kind: "risk", Title: "环境研判", Detail: "终端无越狱、系统版本合规、地理位置=公司网络，风险分 12（低）"},
				{Time: "2026-06-22 18:41", Kind: "review", Title: "等待管理员审批", Detail: "进入安全管理员审批队列（当前）"},
			}},
			{ID: "ap2", User: "陈静", Device: "研发-陈静-Linux", Fingerprint: "7A2B:4C6D:8E0F:1122", SubmittedAt: "2026-06-22 16:05", Reason: "更换工作站", Status: "pending", Timeline: []ApprovalEvent{
				{Time: "2026-06-22 16:05", Kind: "submit", Title: "提交绑定申请", Detail: "陈静 发起绑定，理由：更换工作站"},
				{Time: "2026-06-20 09:12", Kind: "login", Title: "历史登录", Detail: "该指纹此前以游客态登录 3 次，均触发二次认证"},
				{Time: "2026-06-22 16:06", Kind: "risk", Title: "环境研判", Detail: "Ubuntu 22.04、盘加密开启，风险分 8（低）"},
				{Time: "2026-06-22 16:06", Kind: "review", Title: "等待管理员审批", Detail: "进入审批队列（当前）"},
			}},
			{ID: "ap3", User: "外包-周", Device: "外包-周-未授信", Fingerprint: "FF01:2345:6789:ABCD", SubmittedAt: "2026-06-22 11:20", Reason: "临时访问工单系统", Status: "pending", Timeline: []ApprovalEvent{
				{Time: "2026-06-22 11:20", Kind: "submit", Title: "提交绑定申请", Detail: "外包-周 在个人 Android 发起绑定"},
				{Time: "2026-06-22 11:20", Kind: "risk", Title: "环境研判", Detail: "个人设备、非企业网络、历史异地登录，风险分 78（高）"},
				{Time: "2026-06-22 11:21", Kind: "review", Title: "等待管理员审批", Detail: "高风险，建议驳回或限授（当前）"},
			}},
		},
	}, nil
}
