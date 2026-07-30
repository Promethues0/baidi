//go:build linux

package main

// Linux 按域分流：优先 systemd-resolved（resolvectl），没有才退回改写 /etc/resolv.conf。
//
// ★未实机验证：本机是 macOS，这段既没跑过也没在 Linux 上验证过；请按「未验证代码」对待。
//
// 两条路径的差距不只是「实现不同」，而是**失败后果**完全不同，故优先级是硬的：
//
//	resolvectl（首选）：per-link 配置，真正的按域分流（"~domain" 只路由该域）。
//	    接口消失时 systemd-resolved 会自动丢弃该 link 的配置——就算我们的清理没跑成，
//	    也不会留下永久损坏。这是它排第一的真正理由。
//	resolv.conf（退路）：**没有按域能力**，只能全局指定 nameserver，等于全局接管。
//	    清理没跑成时全机 DNS 指向一个已消失的 VIP，症状是「断开客户端后什么域名都解析
//	    不了」——比「某个域名不通」严重一个数量级。所以这条路径把原有 nameserver 保留在
//	    我们之后作为兜底，并且清理逻辑写得比 macOS 侧更保守。

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const resolvConfPath = "/etc/resolv.conf"

// applySplitDNS 见 resolver_darwin.go 的契约说明（返回的 cleanup 幂等，必须调用）。
func applySplitDNS(dev, server string, domains []string) (func(), error) {
	if len(domains) == 0 {
		return func() {}, nil
	}
	if _, err := exec.LookPath("resolvectl"); err == nil {
		return applyResolvectl(dev, server, domains)
	}
	slog.Warn("未找到 resolvectl（systemd-resolved），退回改写 /etc/resolv.conf：" +
		"该路径无法按域分流，会把全部 DNS 查询先发给隧道内解析器（原有解析器保留为兜底）")
	return applyResolvConf(server)
}

// applyResolvectl 走 systemd-resolved：把 server 设为本接口的解析器，并把 domains
// 声明为**仅路由域**（"~domain"）。
func applyResolvectl(dev, server string, domains []string) (func(), error) {
	if err := sh("resolvectl", "dns", dev, server); err != nil {
		return nil, fmt.Errorf("resolvectl dns 失败: %w", err)
	}
	args := append([]string{"domain", dev}, resolvectlDomainArgs(domains)...)
	if err := sh("resolvectl", args...); err != nil {
		_ = sh("resolvectl", "revert", dev) // 回滚上一步，别留半配
		return nil, fmt.Errorf("resolvectl domain 失败: %w", err)
	}
	// ★ default-route=false 是「不全局接管」的最后一道闸：没有它，systemd-resolved
	// 可能把本接口当作默认解析出口，于是**所有**域名（包括 www.example.com）都被送进
	// 隧道内解析器，而它对未知域一律回 REFUSED——症状是「接入后整机上不了外网」。
	// 老版本 resolvectl 没有这个子命令，失败只告警不中止（此时依赖 "~domain" 的语义）。
	if err := sh("resolvectl", "default-route", dev, "false"); err != nil {
		slog.Warn("resolvectl default-route 设置失败（老版本可能不支持），依赖仅路由域语义兜底", "err", err.Error())
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			// revert 把该 link 的 DNS 配置整体还原。接口此时可能已经随进程退出消失，
			// 那样 revert 会报错——这是**预期内**的，配置也随之消失，故只记 debug。
			if err := sh("resolvectl", "revert", dev); err != nil {
				slog.Debug("resolvectl revert 未成功（接口可能已消失，配置随之失效）", "dev", dev, "err", err.Error())
			}
			_ = sh("resolvectl", "flush-caches")
			slog.Info("系统解析器配置已清理（systemd-resolved）", "dev", dev)
		})
	}, nil
}

// applyResolvConf 退路：改写 /etc/resolv.conf。
//
// ★这条路径的三个已知风险，写在这里免得日后当成 bug 排查：
//  1. **不是按域分流**。resolv.conf 没有 per-domain 概念，只能整体指定 nameserver。
//     我们把自己插在最前、原有 nameserver 保留在后作兜底——glibc 收到 REFUSED/SERVFAIL
//     会把该服务器标记为失败并尝试下一个，所以外网域名仍能解析，代价是每次多一个 RTT。
//     （注意 glibc 的 MAXNS=3：原来就有 3 条时，最后一条会被挤掉。）
//  2. **随时可能被覆盖**。NetworkManager/dhclient/resolvconf 会在网络事件时重写此文件，
//     我们那行 nameserver 会无声消失，症状是「用着用着域名突然不走隧道了」。
//  3. **清理失败的代价是全机断网级别的**（全部查询指向已消失的 VIP）。故清理时只在文件
//     仍带我们标记的前提下还原备份，且备份文件在下次启动时还会被扫一遍。
func applyResolvConf(server string) (func(), error) {
	orig, err := os.ReadFile(resolvConfPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取 %s 失败: %w", resolvConfPath, err)
	}
	if isBaidiManaged(string(orig)) {
		// sweep 之后还带标记 = 还原失败，此时再叠一层会把原件彻底丢掉。
		return nil, fmt.Errorf("%s 仍是上一轮遗留的白帝配置且未能还原，拒绝继续（请手工恢复后重试）", resolvConfPath)
	}

	// 是否软链要单独记：os.WriteFile 会**跟随软链**写进目标文件（常见目标是
	// /run/systemd/resolve/stub-resolv.conf），那等于改了 systemd 的运行时文件，
	// 比改 /etc/resolv.conf 本身更糟。故先删链、再写普通文件，清理时把链接建回去。
	var wasSymlink bool
	var linkTarget string
	if fi, lerr := os.Lstat(resolvConfPath); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		wasSymlink = true
		linkTarget, _ = os.Readlink(resolvConfPath)
	}

	bak := resolvConfPath + backupSuffix
	if len(orig) > 0 && !fileExists(bak) {
		if err := os.WriteFile(bak, orig, 0o644); err != nil {
			return nil, fmt.Errorf("备份 %s 失败: %w", resolvConfPath, err)
		}
	}
	if wasSymlink {
		if err := os.Remove(resolvConfPath); err != nil {
			return nil, fmt.Errorf("移除 %s 软链失败: %w", resolvConfPath, err)
		}
	}

	var b strings.Builder
	b.WriteString("# " + dnsMarker + " 自动生成（白帝安全接入客户端）：断开接入时会还原为备份 " + bak + "\n")
	b.WriteString("nameserver " + server + "\n")
	b.Write(orig) // 原有 nameserver/search/options 保留在后作兜底
	if err := os.WriteFile(resolvConfPath, []byte(b.String()), 0o644); err != nil {
		restoreResolvConf(wasSymlink, linkTarget)
		return nil, fmt.Errorf("写 %s 失败: %w", resolvConfPath, err)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			cur, err := os.ReadFile(resolvConfPath)
			if err == nil && !isBaidiManaged(string(cur)) {
				// 已被 NetworkManager 等改回去了：不要再动，但备份要收掉。
				slog.Warn("/etc/resolv.conf 已被他方改写，保留不动", "backup", bak)
				_ = os.Remove(bak)
				return
			}
			restoreResolvConf(wasSymlink, linkTarget)
			slog.Info("系统解析器配置已清理（/etc/resolv.conf 已还原）")
		})
	}, nil
}

// restoreResolvConf 把 /etc/resolv.conf 还原成接管前的样子（软链或普通文件）。
func restoreResolvConf(wasSymlink bool, linkTarget string) {
	bak := resolvConfPath + backupSuffix
	if wasSymlink && linkTarget != "" {
		_ = os.Remove(resolvConfPath)
		if err := os.Symlink(linkTarget, resolvConfPath); err != nil {
			slog.Error("还原 /etc/resolv.conf 软链失败（全机 DNS 可能不可用，请手工恢复）",
				"target", linkTarget, "err", err.Error())
			return
		}
		_ = os.Remove(bak)
		return
	}
	b, err := os.ReadFile(bak)
	if err != nil {
		// 没有备份说明接管前本就没有这个文件：删掉我们写的那份即可。
		_ = os.Remove(resolvConfPath)
		return
	}
	if err := os.WriteFile(resolvConfPath, b, 0o644); err != nil {
		slog.Error("还原 /etc/resolv.conf 失败（全机 DNS 可能不可用，请手工恢复）", "backup", bak, "err", err.Error())
		return
	}
	_ = os.Remove(bak)
}

// sweepStaleDNSConfig 见 resolver_darwin.go 的说明：启动路径无条件调用。
//
// resolvectl 路径无需清扫：它的配置绑在 link 上，接口随进程消失时配置一并失效。
// 需要清扫的只有 resolv.conf 这条退路（那是真写进文件系统的）。
func sweepStaleDNSConfig() { sweepStaleResolvConf() }

// sweepStaleResolvConf 回收上一轮异常退出（SIGKILL/断电）留下的 resolv.conf 接管。
// ★ 软链信息只存在于上一轮的进程内存里，崩溃后无从得知，故这里只能还原成**普通文件**。
// 副作用是 systemd-resolved 的动态更新不再自动同步进来，需要管理员重建软链——
// 但这总好过让全机 DNS 指着一个不存在的 VIP。
func sweepStaleResolvConf() {
	cur, err := os.ReadFile(resolvConfPath)
	if err != nil || !isBaidiManaged(string(cur)) {
		return
	}
	bak := resolvConfPath + backupSuffix
	b, err := os.ReadFile(bak)
	if err != nil {
		slog.Warn("检出上一轮遗留的 /etc/resolv.conf 接管，但备份已丢失，无法自动还原", "backup", bak)
		return
	}
	if err := os.WriteFile(resolvConfPath, b, 0o644); err != nil {
		slog.Error("还原上一轮遗留的 /etc/resolv.conf 失败", "err", err.Error())
		return
	}
	_ = os.Remove(bak)
	slog.Warn("已还原上一轮异常退出遗留的 /etc/resolv.conf 接管（若原本是软链，请手工重建）")
}
