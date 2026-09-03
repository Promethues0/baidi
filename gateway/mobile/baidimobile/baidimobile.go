// Package baidimobile 是白帝移动端数据面的 gomobile 绑定层。
//
// gomobile bind 把本包编成 iOS .xcframework / 安卓 .aar，由各平台 VPN 扩展调用：
// 扩展先建立系统级 TUN（iOS NEPacketTunnelProvider / 安卓 VpnService），把 TUN 的 fd 传给 Start，
// 引擎（internal/dataplane，与桌面 baidi-tun 同一套）即在其上做 SPA 敲门 + 国密 TLCP 隧道 + gVisor 引流。
//
// 导出 API 仅用 gomobile 友好类型（string/int/bool/struct/error）。
package baidimobile

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"golang.zx2c4.com/wireguard/tun"

	"baidi.dev/gateway/internal/dataplane"
	"baidi.dev/gateway/internal/gmcert"
	"baidi.dev/gateway/internal/knock"
)

// Config 移动端数据面配置（全 gomobile 友好类型；CA 以 PEM 字符串下发）。
type Config struct {
	SpaAddr         string // 网关 SPA 敲门 host:port
	ProxyAddr       string // 网关隧道代理 host:port
	Token           string // baidi-control 签发的会话 JWT
	Control         string // baidi-control 地址（必填）：换短时效一次性敲门令牌 + 保活续窗
	Gm              bool   // 国密 TLCP 隧道
	CaPEM           string // 国密 CA 根证书 PEM（空且 Gm 时退化为跳过校验，仅排障）
	ServerName      string // 校验的服务器名（须命中网关证书 SAN）
	DefaultResource string // 默认资源 id（隧道前导 CONNECT）
	Mtu             int    // 链路 MTU（默认 1420）

	// Pin 网关隧道证书的 SHA-256 指纹（hex，控制面经接入剖面下发）。
	//
	// ★此前这个字段**不存在**，于是移动端隧道对网关身份一个字节都不校验：
	// 通用 TLS 走 InsecureSkipVerify 且无回调，国密 TLCP 因 CaPEM 恒空同样跳过——
	// 而控制面剖面里明明逐网关下发了 tunnelPin。桌面端专门做的「隧道证书钉扎」
	// 在移动端结构性不存在，ARCHITECTURE 第七节那张表却把它列为已实现且不带限定。
	Pin string

	// ResmapJSON 目的地址 → 资源 id 的映射表，JSON 对象字符串（如 {"10.99.0.36:8080":"oa"}）。
	//
	// ★gomobile 不能导出 map，故用 JSON 串；解析失败**不静默忽略**，Start 直接报错——
	// 静默忽略的后果是每条连接都退化成"不发 CONNECT 前导"，而网关对无前导连接
	// 自 wave9 起 fail-closed（此前更糟：直连默认后端且完全跳过资源鉴权）。
	ResmapJSON string
}

// Session 运行中的隧道句柄。移动端 UI 轮询 Running()/Reason() 观察终态——
// 引擎因强制下线/账号禁用而停机时，Reason() 带出可显示的原因（区别于用户主动 Stop）。
type Session struct {
	dev     tun.Device
	mu      sync.Mutex
	stopped bool
	reason  string
}

// markStopped 记录引擎终止。err 非 nil（含被拒）→ 记原因；nil（正常关闭）→ 停机但无原因。
func (s *Session) markStopped(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if err != nil {
		if errors.Is(err, knock.ErrDenied) {
			s.reason = err.Error() // 定性拒绝：原文已含「接入被拒：<原因>」
		} else {
			s.reason = "隧道中断：" + err.Error()
		}
	}
}

// Running 报告引擎是否仍在运行（供移动端轮询）。
func (s *Session) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.stopped
}

// Reason 返回引擎的终止原因（运行中或正常关闭为空；被拒/异常为可显示文案）。
func (s *Session) Reason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// Start 用平台 VPN 扩展建立的 TUN fd 启动数据面；引擎在后台 goroutine 运行。
func Start(tunFd int, c *Config) (*Session, error) {
	if c == nil {
		return nil, errors.New("nil config")
	}
	if c.Token == "" {
		return nil, errors.New("缺少身份令牌")
	}
	// 与 dataplane.Run 的入口校验形成双保险：原生壳（Android/iOS）取不到配置时会回退空串，
	// 在 Start 就同步返回人话错误，好过等 goroutine 起来后经 Session.Reason() 才浮现。
	if c.Control == "" {
		return nil, errors.New("缺少控制中心地址（敲门令牌的唯一合规来源）")
	}
	// ★配置解析一律排在建 TUN **之前**：填错要在动系统状态之前失败
	//   （同 baidi-tun 里 loadGateways 那条纪律）。放在后面的话，坏配置会先
	//   建出一张 TUN、再报一个与真实成因无关的错——本用例就是这么抓到的。
	resmap, err := parseResmap(c.ResmapJSON)
	if err != nil {
		return nil, err
	}
	mtu := c.Mtu
	if mtu <= 0 {
		mtu = 1420
	}

	tlcpCfg := &tlcp.Config{ServerName: c.ServerName}
	if c.Gm {
		// 指纹钉扎与 CA 链校验并存、互不替代（gotlcp 明确写明 InsecureSkipVerify
		// 不影响 VerifyPeerCertificate 运行）。参考部署下网关证书自签、移动端手里
		// 也没有国密 CA，钉扎因此是**唯一**的服务端身份保证——桌面端同款判据。
		if c.Pin != "" {
			tlcpCfg.VerifyPeerCertificate = dataplane.PinVerifierTLCP(c.Pin)
		}
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

	// 平台给的 TUN fd → tun.Device。**建卡入口按平台分文件**（tundev_android.go /
	// tundev_other.go）：安卓必须走不碰 netlink 的 CreateUnmonitoredTUNFromFD，
	// 否则被 SELinux 拒在 netlink 绑定那一步、整条数据面起不来（详见那两个文件的注释）。
	dev, err := newTunDevice(int(tunFd), mtu)
	if err != nil {
		return nil, err
	}

	cfg := &dataplane.Config{
		SpaAddr: c.SpaAddr, ProxyAddr: c.ProxyAddr, Token: c.Token, Control: c.Control,
		Gm: c.Gm, TLCPConfig: tlcpCfg, DefaultRes: c.DefaultResource,
		TunnelPin: c.Pin, Resmap: resmap,
		Reknock: 15 * time.Second, MTU: mtu,
	}
	sess := &Session{dev: dev}
	go func() { sess.markStopped(dataplane.Run(dev, cfg)) }()
	return sess, nil
}

// parseResmap 解析 gomobile 侧传来的 JSON 映射表。空串 = 没有映射（合法：纯默认资源场景）。
// ★坏 JSON 一律报错而不是当空表：当空表的话，每条连接都不发 CONNECT 前导，
// 而网关对无前导连接 fail-closed——用户看到的会是"隧道建起来了但什么都访问不了"，
// 且两侧日志都不会说是映射表坏了。
func parseResmap(s string) (map[string]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	m := map[string]string{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, errors.New("资源映射表不是 {\"host:port\":\"资源id\"} 形式的 JSON: " + err.Error())
	}
	return m, nil
}

// Stop 关闭隧道（关 TUN → 引擎双向泵退出）。
func (s *Session) Stop() {
	if s != nil && s.dev != nil {
		_ = s.dev.Close()
	}
}
