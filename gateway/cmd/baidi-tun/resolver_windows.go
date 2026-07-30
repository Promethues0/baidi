//go:build windows

package main

// Windows 按域分流：NRPT（Name Resolution Policy Table，名称解析策略表）。
// NRPT 就是 Windows 版的「按域分流」：给某个域名后缀指定专用解析器，其余域名照旧走原出口。
//
// ★未实机验证：本机是 macOS，这段没有在 Windows 上跑过；请按「未验证代码」对待。
//
// ★★ NRPT 规则写在注册表里，**跨进程、跨重启存活**。这意味着不清理的后果比 macOS 更重：
// 卸载客户端、甚至重装系统之前，该域名都会被指向一个早已不存在的 VIP，症状是
// 「这台机器上 oa.corp.internal 永远解析不了，换台机器就好」。所以这里做了三层保险：
//   - 正常退出：cleanup（defer + 信号两条路径都会调）；
//   - 异常退出：下次启动先按 Comment 扫掉所有本客户端留下的规则；
//   - 只按 Comment=baidi-tun 匹配，绝不动管理员自己配的 NRPT 规则。
//
// 用 PowerShell 而不是 netsh：netsh 的 NRPT 子命令（netsh dnsclient add dnsserveraddress）
// 覆盖面窄且各版本行为不一致，DnsClient 模块的 *-DnsClientNrptRule 才是官方入口。

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

// applySplitDNS 见 resolver_darwin.go 的契约说明（返回的 cleanup 幂等，必须调用）。
// dev 用不上：NRPT 是按域全局生效的策略表，与具体网卡无关。
func applySplitDNS(dev, server string, domains []string) (func(), error) {
	_ = dev
	if len(domains) == 0 {
		return func() {}, nil
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			removeNrptRules()
			_ = sh("ipconfig", "/flushdns")
			slog.Info("系统解析器配置已清理（NRPT 规则已删除）")
		})
	}
	for _, d := range domains {
		// Namespace 必须以点开头才表示「该域及其子域」（见 nrptNamespace 的说明）。
		// Comment 是我们的所有权标记，也是清理时唯一的匹配依据。
		script := fmt.Sprintf(
			"Add-DnsClientNrptRule -Namespace '%s' -NameServers '%s' -Comment '%s' -DisplayName '%s split-DNS' -ErrorAction Stop",
			psQuote(nrptNamespace(d)), psQuote(server), dnsMarker, dnsMarker)
		if err := ps(script); err != nil {
			cleanup() // 半配的 NRPT 比不配更难查（部分域走隧道、部分不走）
			return nil, fmt.Errorf("添加 NRPT 规则（%s）失败: %w", d, err)
		}
	}
	_ = sh("ipconfig", "/flushdns") // 不刷的话旧应答会在缓存 TTL 内继续生效
	return cleanup, nil
}

// sweepStaleDNSConfig 见 resolver_darwin.go 的说明：启动路径无条件调用。
// NRPT 规则写在注册表里，**跨重启存活**，不清扫就是永久残留。
func sweepStaleDNSConfig() { removeNrptRules() }

// removeNrptRules 删除所有 Comment 标记为本客户端的 NRPT 规则。
// best-effort：删不掉只告警——但要**显式**告警，因为残留的后果是该域名永久解析失败。
func removeNrptRules() {
	const script = "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + dnsMarker + "' } | " +
		"ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }"
	if err := ps(script); err != nil {
		slog.Warn("清理 NRPT 规则失败（相关域名可能在断开后无法解析，可用 Get-DnsClientNrptRule 手工检查）", "err", err.Error())
	}
}

// ps 跑一段 PowerShell。-NonInteractive/-NoProfile 避免被用户 profile 或交互提示卡住
// （数据面是后台进程，一旦卡在提示上就是"接入过程无限挂起"）。
func ps(script string) error {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// psQuote PowerShell 单引号字符串转义（单引号写两遍）。域名与 IP 已经过 normalizeDomain /
// net.ParseIP 校验，理论上不含引号；这里仍然转义——「输入已被上游校验过」是注入类问题
// 最常见的开场白。
func psQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
