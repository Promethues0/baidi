package store

import "context"

// IpsecPhase IKE 协商的一相 / 二相加密套件。
type IpsecPhase struct {
	Enc  string `json:"enc"`  // AES256-GCM / SM4-GCM ...
	Hash string `json:"hash"` // SHA256 / SM3
	DH   string `json:"dh"`   // group14 / group19 / group21
}

// IpsecSite 一条站点到站点的 IPSec 隧道（PRD 第 17 章 IPSec VPN 组网，复用烛龙 IPSEC 引擎）。
type IpsecSite struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Peer         string     `json:"peer"`         // 对端网关公网地址
	LocalSubnet  string     `json:"localSubnet"`  // 本端受保护网段
	RemoteSubnet string     `json:"remoteSubnet"` // 对端受保护网段
	IkeVersion   string     `json:"ikeVersion"`   // IKEv2（强制）
	Auth         string     `json:"auth"`         // psk | cert | sm2cert
	Suite        string     `json:"suite"`        // standard（国际） | gm（国密 SM）
	Phase1       IpsecPhase `json:"phase1"`
	Phase2       IpsecPhase `json:"phase2"`
	Pfs          bool       `json:"pfs"`      // 完美前向保密
	PqHybrid     bool       `json:"pqHybrid"` // ML-KEM 后量子混合密钥协商
	Status       string     `json:"status"`   // up | down | connecting
	RxBytes      int64      `json:"rxBytes"`
	TxBytes      int64      `json:"txBytes"`
	LastUp       string     `json:"lastUp"`
	// 对象库引用（可选）：本端 / 对端网段引用地址对象（kind=cidr/ip/range），
	// 支撑「定义一次、多处复用」与对象库「被引用」反查；网段值仍是权威配置。
	LocalRef  string `json:"localRef,omitempty"`  // 地址对象 id → localSubnet
	RemoteRef string `json:"remoteRef,omitempty"` // 地址对象 id → remoteSubnet
}

// Ipsec 返回演示用的 IPSec 站点清单（内存种子；SQLiteStore 覆盖为落库版）。
func (m *Memory) Ipsec(_ context.Context) ([]IpsecSite, error) {
	return []IpsecSite{
		{
			ID: "site-sh", Name: "上海分支", Peer: "203.0.113.21", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.40.0.0/16",
			IkeVersion: "IKEv2", Auth: "cert", Suite: "standard",
			Phase1: IpsecPhase{Enc: "AES256-GCM", Hash: "SHA384", DH: "group19"},
			Phase2: IpsecPhase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
			Pfs:    true, PqHybrid: false, Status: "up", RxBytes: 184_320_512, TxBytes: 96_337_408, LastUp: "今天 08:02",
		},
		{
			ID: "site-gz", Name: "广州分支（国密）", Peer: "203.0.113.55", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.50.0.0/16",
			IkeVersion: "IKEv2", Auth: "sm2cert", Suite: "gm",
			Phase1: IpsecPhase{Enc: "SM4-GCM", Hash: "SM3", DH: "group24"},
			Phase2: IpsecPhase{Enc: "SM4-GCM", Hash: "SM3", DH: "group24"},
			Pfs:    true, PqHybrid: true, Status: "up", RxBytes: 53_477_376, TxBytes: 41_205_760, LastUp: "今天 07:41",
		},
		{
			ID: "site-cd", Name: "成都分支", Peer: "203.0.113.88", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.60.0.0/16",
			IkeVersion: "IKEv2", Auth: "psk", Suite: "standard",
			Phase1: IpsecPhase{Enc: "AES256-CBC", Hash: "SHA256", DH: "group14"},
			Phase2: IpsecPhase{Enc: "AES256-CBC", Hash: "SHA256", DH: "group14"},
			Pfs:    false, PqHybrid: false, Status: "down", RxBytes: 0, TxBytes: 0, LastUp: "昨天 22:13",
		},
	}, nil
}
