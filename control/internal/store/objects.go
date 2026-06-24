package store

import "context"

// ── 对象库（PRD 第 8 章）：可被策略 / 资源 / IPSec 复用的地址 / 服务 / 时间对象 ──

// AddrObject 地址对象（主机 / 网段 / 范围 / 域名）。
type AddrObject struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`  // ip | cidr | range | domain
	Value string `json:"value"` // 10.20.1.10 / 10.20.0.0/16 / 10.20.1.1-10.20.1.99 / *.corp.com
	Desc  string `json:"desc"`
}

// ServiceObject 服务对象（协议 + 端口）。
type ServiceObject struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Proto string `json:"proto"` // tcp | udp | icmp | any
	Ports string `json:"ports"` // 443 / 8000-8100 / —
	Desc  string `json:"desc"`
}

// TimeObject 时间对象（周期 / 绝对时间段）。
type TimeObject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"` // periodic | absolute
	Spec string `json:"spec"` // 周一~周五 09:00-18:00 / 2026-01-01 ~ 2026-12-31
	Desc string `json:"desc"`
}

// ObjectBundle 对象库三类对象的集合。
type ObjectBundle struct {
	Addrs    []AddrObject    `json:"addrs"`
	Services []ServiceObject `json:"services"`
	Times    []TimeObject    `json:"times"`
}

// Objects 返回演示用的对象库（内存种子；SQLiteStore 覆盖为落库版）。
func (m *Memory) Objects(_ context.Context) (ObjectBundle, error) {
	return ObjectBundle{
		Addrs: []AddrObject{
			{ID: "addr-oa", Name: "OA 服务器", Kind: "ip", Value: "10.20.1.10", Desc: "协同办公后端"},
			{ID: "addr-fin", Name: "财务网段", Kind: "cidr", Value: "10.20.3.0/24", Desc: "财务核算系统所在子网"},
			{ID: "addr-dev", Name: "研发地址池", Kind: "range", Value: "10.30.5.1-10.30.5.99", Desc: "研发自助机段"},
			{ID: "addr-saas", Name: "企业 SaaS 域名", Kind: "domain", Value: "*.corp-saas.com", Desc: "外发 SaaS 白名单"},
		},
		Services: []ServiceObject{
			{ID: "svc-https", Name: "HTTPS", Proto: "tcp", Ports: "443", Desc: "Web 应用"},
			{ID: "svc-ssh", Name: "SSH", Proto: "tcp", Ports: "22", Desc: "运维登录"},
			{ID: "svc-rdp", Name: "RDP", Proto: "tcp", Ports: "3389", Desc: "远程桌面"},
			{ID: "svc-db", Name: "数据库端口组", Proto: "tcp", Ports: "1521,3306,5432", Desc: "Oracle/MySQL/PG"},
			{ID: "svc-ping", Name: "ICMP", Proto: "icmp", Ports: "—", Desc: "连通性探测"},
		},
		Times: []TimeObject{
			{ID: "time-work", Name: "工作时间", Kind: "periodic", Spec: "周一~周五 09:00-18:00", Desc: "标准坐班时段"},
			{ID: "time-night", Name: "非工作时段", Kind: "periodic", Spec: "每日 22:00-06:00", Desc: "高敏访问加严时段"},
			{ID: "time-audit", Name: "审计冻结期", Kind: "absolute", Spec: "2026-01-01 ~ 2026-01-07", Desc: "年初财务封账"},
		},
	}, nil
}
