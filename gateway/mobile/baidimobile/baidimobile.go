// Package baidimobile 是白帝移动端数据面的 gomobile 绑定层。
//
// gomobile bind 把本包编成 iOS .xcframework / 安卓 .aar，由各平台 VPN 扩展调用：
// 扩展先建立系统级 TUN（iOS NEPacketTunnelProvider / 安卓 VpnService），把 TUN 的 fd 传给 Start，
// 引擎（internal/dataplane，与桌面 baidi-tun 同一套）即在其上做 SPA 敲门 + 国密 TLCP 隧道 + gVisor 引流。
//
// 导出 API 仅用 gomobile 友好类型（string/int/bool/struct/error）。
package baidimobile

import (
	"errors"
	"os"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"golang.zx2c4.com/wireguard/tun"

	"baidi.dev/gateway/internal/dataplane"
	"baidi.dev/gateway/internal/gmcert"
)

// Config 移动端数据面配置（全 gomobile 友好类型；CA 以 PEM 字符串下发）。
type Config struct {
	SpaAddr         string // 网关 SPA 敲门 host:port
	ProxyAddr       string // 网关隧道代理 host:port
	Token           string // baidi-control 签发的会话 JWT
	Control         string // baidi-control 地址（非空=换短时效一次性令牌 + 保活）
	Gm              bool   // 国密 TLCP 隧道
	CaPEM           string // 国密 CA 根证书 PEM（空且 Gm 时退化为跳过校验，仅排障）
	ServerName      string // 校验的服务器名（须命中网关证书 SAN）
	DefaultResource string // 默认资源 id（隧道前导 CONNECT）
	Mtu             int    // 链路 MTU（默认 1420）
}

// Session 运行中的隧道句柄。
type Session struct {
	dev tun.Device
}

// Start 用平台 VPN 扩展建立的 TUN fd 启动数据面；引擎在后台 goroutine 运行。
func Start(tunFd int, c *Config) (*Session, error) {
	if c == nil {
		return nil, errors.New("nil config")
	}
	if c.Token == "" {
		return nil, errors.New("缺少身份令牌")
	}
	mtu := c.Mtu
	if mtu <= 0 {
		mtu = 1420
	}

	tlcpCfg := &tlcp.Config{ServerName: c.ServerName}
	if c.Gm {
		if c.CaPEM == "" {
			tlcpCfg.InsecureSkipVerify = true
		} else {
			pool, err := gmcert.CAPoolFromPEM([]byte(c.CaPEM))
			if err != nil {
				return nil, err
			}
			tlcpCfg.RootCAs = pool
		}
	}

	// 平台给的 TUN fd → tun.Device（linux/android 与 darwin/ios 同走 CreateTUNFromFile）
	file := os.NewFile(uintptr(tunFd), "baidi-tun")
	dev, err := tun.CreateTUNFromFile(file, mtu)
	if err != nil {
		return nil, err
	}

	cfg := &dataplane.Config{
		SpaAddr: c.SpaAddr, ProxyAddr: c.ProxyAddr, Token: c.Token, Control: c.Control,
		Gm: c.Gm, TLCPConfig: tlcpCfg, DefaultRes: c.DefaultResource,
		Reknock: 15 * time.Second, MTU: mtu,
	}
	go func() { _ = dataplane.Run(dev, cfg) }()
	return &Session{dev: dev}, nil
}

// Stop 关闭隧道（关 TUN → 引擎双向泵退出）。
func (s *Session) Stop() {
	if s != nil && s.dev != nil {
		_ = s.dev.Close()
	}
}
