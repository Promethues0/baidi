package store

import "context"

// ── 监控中心 · 在线用户（实时会话）──

// OnlineSession 一条实时在线会话。监控中心据此做"就近处置"（强制下线）。
type OnlineSession struct {
	ID         string `json:"id"`
	User       string `json:"user"`    // 显示名
	Account    string `json:"account"` // 登录账号
	Org        string `json:"org"`
	IP         string `json:"ip"`
	Location   string `json:"location"` // 接入地点（GeoIP 推断）
	Device     string `json:"device"`
	OS         string `json:"os"`
	Auth       string `json:"auth"`    // 认证方式
	App        string `json:"app"`     // 当前访问应用
	Gateway    string `json:"gateway"` // 接入网关
	LoginAt    string `json:"loginAt"`
	Duration   string `json:"duration"` // 在线时长
	Trust      string `json:"trust"`    // trusted | untrusted | unknown
	Risk       string `json:"risk"`     // none | low | high
	Status     string `json:"status"`   // online | offline（已被强制下线）
	KickReason string `json:"kickReason,omitempty"`
}

// OnlineSessions 返回演示用的实时会话清单。
func (m *Memory) OnlineSessions(_ context.Context) ([]OnlineSession, error) {
	return []OnlineSession{
		{ID: "s-1001", User: "李明", Account: "li.ming", Org: "研发中心 / 平台组", IP: "10.20.13.42", Location: "杭州 · 公司内网", Device: "MAC-研发-08", OS: "macOS 14.4", Auth: "AD 域 + 设备证书", App: "研发 Git 仓库", Gateway: "gw-east-01", LoginAt: "09:12", Duration: "3h 41m", Trust: "trusted", Risk: "none", Status: "online"},
		{ID: "s-1002", User: "王芳", Account: "wang.fang", Org: "财务中心 / 核算组", IP: "10.20.7.9", Location: "杭州 · 公司内网", Device: "WIN-财务-21", OS: "Windows 11", Auth: "本地口令 + 短信 MFA", App: "财务核算系统", Gateway: "gw-east-01", LoginAt: "08:50", Duration: "4h 03m", Trust: "trusted", Risk: "none", Status: "online"},
		{ID: "s-1003", User: "外包-赵磊", Account: "ext.zhao", Org: "外部协作 / 驻场", IP: "203.0.113.77", Location: "上海 · 公网接入", Device: "未授信-Win-3", OS: "Windows 10", Auth: "本地口令 + 短信 MFA", App: "OA 协同办公", Gateway: "gw-south-01", LoginAt: "10:31", Duration: "2h 22m", Trust: "untrusted", Risk: "high", Status: "online"},
		{ID: "s-1004", User: "陈静", Account: "chen.jing", Org: "市场中心 / 品牌组", IP: "198.51.100.14", Location: "北京 · 异地登录", Device: "MAC-市场-05", OS: "macOS 13.6", Auth: "AD 域", App: "OA 协同办公", Gateway: "gw-east-01", LoginAt: "11:05", Duration: "1h 48m", Trust: "trusted", Risk: "low", Status: "online"},
		{ID: "s-1005", User: "刘强", Account: "liu.qiang", Org: "研发中心 / 架构组", IP: "10.20.13.61", Location: "杭州 · 公司内网", Device: "WIN-研发-17", OS: "Windows 11", Auth: "AD 域 + 设备证书", App: "研发 Git 仓库", Gateway: "gw-east-01", LoginAt: "09:40", Duration: "3h 13m", Trust: "trusted", Risk: "none", Status: "online"},
		{ID: "s-1006", User: "svc-bot-04", Account: "svc.bot.04", Org: "系统账号 / 自动化", IP: "10.30.5.8", Location: "杭州 · IDC", Device: "容器节点", OS: "Linux", Auth: "API 密钥", App: "研发 Git 仓库", Gateway: "gw-east-02", LoginAt: "00:00", Duration: "13h 05m", Trust: "unknown", Risk: "low", Status: "online"},
		{ID: "s-1007", User: "周婷", Account: "zhou.ting", Org: "人力中心", IP: "10.20.9.30", Location: "杭州 · 公司内网", Device: "MAC-人力-02", OS: "macOS 14.2", Auth: "本地口令", App: "OA 协同办公", Gateway: "gw-east-01", LoginAt: "13:20", Duration: "0h 28m", Trust: "trusted", Risk: "none", Status: "online"},
		{ID: "s-1008", User: "外包-孙伟", Account: "ext.sun", Org: "外部协作 / 远程", IP: "203.0.113.122", Location: "深圳 · 公网接入", Device: "未授信-Android-3", OS: "Android 13", Auth: "本地口令 + 短信 MFA", App: "OA 协同办公", Gateway: "gw-south-01", LoginAt: "12:55", Duration: "0h 53m", Trust: "untrusted", Risk: "high", Status: "online"},
		{ID: "s-1009", User: "黄磊", Account: "huang.lei", Org: "销售中心 / 华东", IP: "10.20.11.4", Location: "杭州 · 公司内网", Device: "WIN-销售-33", OS: "Windows 11", Auth: "AD 域", App: "OA 协同办公", Gateway: "gw-east-01", LoginAt: "11:48", Duration: "1h 05m", Trust: "trusted", Risk: "none", Status: "online"},
		{ID: "s-1010", User: "吴敏", Account: "wu.min", Org: "财务中心 / 资金组", IP: "10.20.7.18", Location: "杭州 · 公司内网", Device: "WIN-财务-09", OS: "Windows 10", Auth: "本地口令 + 短信 MFA", App: "财务核算系统", Gateway: "gw-east-01", LoginAt: "10:10", Duration: "2h 43m", Trust: "trusted", Risk: "low", Status: "online"},
	}, nil
}

// ── 监控中心 · 用户状态（风险 / 异常态势）──

// UserStateBucket 状态分桶聚合（聚合头的计数卡）。
type UserStateBucket struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
	Tone  string `json:"tone"` // danger | warning | info | normal
}

// UserStateItem 一名受关注用户的当前态势。
type UserStateItem struct {
	ID        string   `json:"id"`
	User      string   `json:"user"`
	Account   string   `json:"account"`
	Org       string   `json:"org"`
	State     string   `json:"state"`   // risk-high | risk-low | locked | disabled | idle
	Risk      string   `json:"risk"`    // none | low | high
	Online    bool     `json:"online"`
	Reasons   []string `json:"reasons"` // 命中的风险 / 异常原因
	LastEvent string   `json:"lastEvent"`
	LastSeen  string   `json:"lastSeen"`
}

// UserStateBundle 用户状态页：分桶聚合 + 受关注用户清单。
type UserStateBundle struct {
	Buckets []UserStateBucket `json:"buckets"`
	Items   []UserStateItem   `json:"items"`
}

// UserStates 返回演示用的用户态势数据。
func (m *Memory) UserStates(_ context.Context) (UserStateBundle, error) {
	items := []UserStateItem{
		{ID: "u-ext-zhao", User: "外包-赵磊", Account: "ext.zhao", Org: "外部协作 / 驻场", State: "risk-high", Risk: "high", Online: true, Reasons: []string{"未授信终端接入", "公网异地登录", "短时间多次访问高敏应用"}, LastEvent: "访问财务核算系统被拒绝", LastSeen: "2 分钟前"},
		{ID: "u-ext-sun", User: "外包-孙伟", Account: "ext.sun", Org: "外部协作 / 远程", State: "risk-high", Risk: "high", Online: true, Reasons: []string{"未授信移动终端", "深圳异地接入", "口令认证强度不足"}, LastEvent: "触发自适应二次认证", LastSeen: "5 分钟前"},
		{ID: "u-svc-bot-04", User: "svc-bot-04", Account: "svc.bot.04", Org: "系统账号 / 自动化", State: "risk-low", Risk: "low", Online: true, Reasons: []string{"长连接 13 小时", "无人值守 API 账号"}, LastEvent: "API 密钥访问 Git", LastSeen: "1 分钟前"},
		{ID: "u-chen-jing", User: "陈静", Account: "chen.jing", Org: "市场中心 / 品牌组", State: "risk-low", Risk: "low", Online: true, Reasons: []string{"北京异地登录（常驻地杭州）"}, LastEvent: "登录认证成功", LastSeen: "8 分钟前"},
		{ID: "u-wu-min", User: "吴敏", Account: "wu.min", Org: "财务中心 / 资金组", State: "risk-low", Risk: "low", Online: true, Reasons: []string{"近 24h 登录失败 3 次"}, LastEvent: "访问财务核算系统", LastSeen: "12 分钟前"},
		{ID: "u-li-fang", User: "李芳", Account: "li.fang", Org: "研发中心 / 测试组", State: "locked", Risk: "high", Online: false, Reasons: []string{"连续 5 次口令错误，账号已锁定", "疑似暴力破解"}, LastEvent: "账号锁定（自动）", LastSeen: "31 分钟前"},
		{ID: "u-zhang-wei", User: "张伟", Account: "zhang.wei", Org: "销售中心 / 华南", State: "disabled", Risk: "none", Online: false, Reasons: []string{"离职流程已触发，账号被禁用"}, LastEvent: "管理员禁用账号", LastSeen: "3 天前"},
		{ID: "u-zhao-lei2", User: "赵雷", Account: "zhao.lei", Org: "人力中心", State: "disabled", Risk: "none", Online: false, Reasons: []string{"长期未登录，已临时停用"}, LastEvent: "策略自动停用", LastSeen: "21 天前"},
		{ID: "u-sun-li", User: "孙丽", Account: "sun.li", Org: "市场中心 / 活动组", State: "idle", Risk: "none", Online: false, Reasons: []string{"会话空闲超 30 分钟，已挂起"}, LastEvent: "会话空闲挂起", LastSeen: "45 分钟前"},
		{ID: "u-qian-jin", User: "钱进", Account: "qian.jin", Org: "财务中心 / 核算组", State: "idle", Risk: "none", Online: false, Reasons: []string{"会话空闲超 30 分钟，已挂起"}, LastEvent: "会话空闲挂起", LastSeen: "52 分钟前"},
	}
	count := func(states ...string) int {
		n := 0
		for _, it := range items {
			for _, st := range states {
				if it.State == st {
					n++
				}
			}
		}
		return n
	}
	buckets := []UserStateBucket{
		{Key: "risk-high", Label: "高风险用户", Count: count("risk-high"), Tone: "danger"},
		{Key: "risk-low", Label: "关注用户", Count: count("risk-low"), Tone: "warning"},
		{Key: "locked", Label: "锁定账号", Count: count("locked"), Tone: "danger"},
		{Key: "disabled", Label: "禁用账号", Count: count("disabled"), Tone: "info"},
		{Key: "idle", Label: "空闲挂起", Count: count("idle"), Tone: "normal"},
	}
	return UserStateBundle{Buckets: buckets, Items: items}, nil
}
