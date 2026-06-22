package store

import "context"

// UserDirBundle 访问者目录页：身份源 + 组织树 + 用户清单。
type UserDirBundle struct {
	Directories []Directory `json:"directories"`
	OrgTree     []OrgUnit   `json:"orgTree"`
	Users       []DirUser   `json:"users"`
}

type Directory struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Type     string `json:"type"`     // local | ad | ldap
	Users    int    `json:"users"`
	Online   int    `json:"online"`
	LastSync string `json:"lastSync"` // 外部目录上次同步（local 为空）
}

type OrgUnit struct {
	Key      string    `json:"key"`
	Title    string    `json:"title"`
	Members  int       `json:"members"`
	Children []OrgUnit `json:"children,omitempty"`
}

// DirUser 目录中的用户（含实时在线态供池化卡片展示）。
type DirUser struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Account   string   `json:"account"`
	Org       string   `json:"org"`
	OrgKey    string   `json:"orgKey"`
	Device    string   `json:"device"`
	IP        string   `json:"ip"`
	Auth      string   `json:"auth"`
	LastLogin string   `json:"lastLogin"`
	Online    bool     `json:"online"`
	Status    string   `json:"status"` // active | locked | disabled | idle
	Risk      string   `json:"risk"`   // none | low | high
	Roles     []string `json:"roles"`
}

func (m *Memory) Users(_ context.Context) (UserDirBundle, error) {
	users := []DirUser{
		{ID: "u1", Name: "张伟", Account: "zhang.wei", Org: "研发部", OrgKey: "dev", Device: "Windows 11", IP: "10.8.2.31", Auth: "密码+短信", LastLogin: "2026-06-22 19:42", Online: true, Status: "active", Risk: "none", Roles: []string{"研发", "管理员"}},
		{ID: "u2", Name: "李芳", Account: "li.fang", Org: "销售部", OrgKey: "sales", Device: "macOS 14", IP: "10.8.5.12", Auth: "SAML SSO", LastLogin: "2026-06-22 18:10", Online: true, Status: "active", Risk: "high", Roles: []string{"销售"}},
		{ID: "u3", Name: "王强", Account: "wang.qiang", Org: "销售部", OrgKey: "sales", Device: "iPhone", IP: "10.8.5.40", Auth: "密码", LastLogin: "2026-06-22 14:05", Online: true, Status: "active", Risk: "none", Roles: []string{"销售"}},
		{ID: "u4", Name: "赵敏", Account: "zhao.min", Org: "客服中心", OrgKey: "cs", Device: "Windows 10", IP: "10.8.7.9", Auth: "密码+UKey", LastLogin: "2026-06-22 09:30", Online: false, Status: "locked", Risk: "low", Roles: []string{"客服"}},
		{ID: "u5", Name: "外包-周", Account: "ext.zhou", Org: "外包人员", OrgKey: "ext", Device: "未授信终端", IP: "203.0.113.7", Auth: "密码+短信", LastLogin: "2026-06-22 11:18", Online: false, Status: "disabled", Risk: "high", Roles: []string{"外包"}},
		{ID: "u6", Name: "陈静", Account: "chen.jing", Org: "研发部", OrgKey: "dev", Device: "Ubuntu 22", IP: "10.8.2.55", Auth: "密码", LastLogin: "2026-05-20 16:00", Online: false, Status: "idle", Risk: "none", Roles: []string{"研发"}},
		{ID: "u7", Name: "刘洋", Account: "liu.yang", Org: "客服中心", OrgKey: "cs", Device: "Windows 11", IP: "10.8.7.21", Auth: "密码+短信", LastLogin: "2026-06-22 20:01", Online: true, Status: "active", Risk: "none", Roles: []string{"客服", "组长"}},
	}
	return UserDirBundle{
		Directories: []Directory{
			{Key: "local", Name: "本地目录", Type: "local", Users: 124, Online: 88},
			{Key: "ad-hq", Name: "总部 AD 域", Type: "ad", Users: 1160, Online: 1096, LastSync: "5 分钟前"},
		},
		OrgTree: []OrgUnit{
			{Key: "root", Title: "ACME 集团", Members: 1284, Children: []OrgUnit{
				{Key: "dev", Title: "研发部", Members: 210},
				{Key: "sales", Title: "销售部", Members: 86},
				{Key: "cs", Title: "客服中心", Members: 64},
				{Key: "ext", Title: "外包人员", Members: 48},
			}},
		},
		Users: users,
	}, nil
}
