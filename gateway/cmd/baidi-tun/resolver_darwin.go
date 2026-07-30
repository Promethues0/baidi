//go:build darwin

package main

// macOS 按域分流：写 /etc/resolver/<domain>（见 resolver(5)）。
//
// ★未实机验证：这段要 root 且会真改系统解析配置，本机与单测都不跑它。
// 单测只覆盖 resolver.go 里的纯字符串映射（域名→文件名、文件内容、清理清单）。
// 下面的行为描述来自 resolver(5) 与 macOS 惯例，落地时请按「未验证代码」对待。
//
// 关于 /etc/resolver 的边界（写在这里免得日后误判为 bug）：
//   - 它作用于走 libresolv / mDNSResponder 的解析路径，覆盖绝大多数应用；
//   - 但**不覆盖**自己实现解析或走 DoH 的程序（浏览器的内置 DoH、部分 Go 程序的
//     纯 Go 解析器直读 /etc/resolv.conf）。症状是「大部分应用能解析，某个浏览器不行」，
//     那不是这里的 bug，是那个程序绕开了系统解析器。

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// applySplitDNS 把 domains 的解析导向隧道内解析器 server（按域分流，不全局接管）。
// 返回的 cleanup 幂等，调用方**必须**在退出前调用（defer + 信号两条路径）。
// 出错时内部已把本次写过的部分回滚干净，调用方不需要（也不应该）再调 cleanup。
//
// dev 在 macOS 用不上：/etc/resolver 是按域全局生效的，与具体接口无关
// （Linux 的 systemd-resolved 才是 per-link 配置）。
func applySplitDNS(dev, server string, domains []string) (func(), error) {
	_ = dev
	if len(domains) == 0 {
		return func() {}, nil
	}
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建 %s 失败: %w", resolverDir, err)
	}
	content := resolverFileContent(server)
	var applied []string
	var once sync.Once
	cleanup := func() {
		once.Do(func() { removeResolverFiles(applied) })
	}
	for _, path := range resolverFiles(domains) {
		if err := backupForeign(path); err != nil {
			cleanup()
			return nil, err
		}
		// 0644：解析配置不是秘密，且必须让非 root 的解析器进程读得到。
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			cleanup()
			return nil, fmt.Errorf("写 %s 失败: %w", path, err)
		}
		applied = append(applied, path)
	}
	flushDNSCache()
	return cleanup, nil
}

// backupForeign 接管一个已存在且**不是我们写的** /etc/resolver 文件前先备份。
// 直接覆盖再删掉的后果是把管理员/其他 VPN 的配置吃掉，且没人会想到是我们干的。
// 已有备份时不覆盖备份：那份来自上一次异常退出，才是真正的原件。
func backupForeign(path string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取既有解析配置 %s 失败: %w", path, err)
	}
	if isBaidiManaged(string(b)) {
		return nil // 我们自己的（上一轮残留或重复配置），直接覆盖
	}
	bak := path + backupSuffix
	if _, err := os.Stat(bak); err == nil {
		slog.Warn("既有解析配置的备份已存在，本次不再备份（保留更早的原件）", "file", path, "backup", bak)
		return nil
	}
	if err := os.WriteFile(bak, b, 0o644); err != nil {
		return fmt.Errorf("备份既有解析配置 %s 失败: %w", path, err)
	}
	slog.Warn("接管既有解析配置，已备份，断开时会还原", "file", path, "backup", bak)
	return nil
}

// removeResolverFiles 删掉我们写的解析配置并还原备份。
// 只删带标记的：如果文件在我们运行期间被他方改写，保留不动比误删安全得多。
func removeResolverFiles(paths []string) {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && !isBaidiManaged(string(b)) {
			slog.Warn("解析配置已被他方改写，保留不动", "file", p)
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			// 删不掉必须显式报出来：静默失败正是「断开后域名永久不通」的现场。
			slog.Error("清理解析配置失败（该域名可能在断开后无法解析，请手工删除）", "file", p, "err", err.Error())
			continue
		}
		if bak := p + backupSuffix; fileExists(bak) {
			if err := os.Rename(bak, p); err != nil {
				slog.Error("还原既有解析配置失败", "backup", bak, "file", p, "err", err.Error())
			}
		}
	}
	flushDNSCache()
	slog.Info("系统解析器配置已清理", "files", len(paths))
}

// sweepStaleDNSConfig 回收上一轮异常退出（SIGKILL/断电）留下的系统解析器配置。
//
// ★必须在启动路径**无条件**调用，不能挂在 applySplitDNS 里面。挂在里面时，
// 只有「本次也启用 split-DNS」的启动才会清扫：一旦控制面停用了 dns 段、或用户
// 权限收窄导致剖面不再下发搜索域，残留就再也没有回收点，那个域名在这台机器上
// 永久解析失败（查询发往已消失的 VIP），且新一次接入一切显示正常、零日志线索。
func sweepStaleDNSConfig() { sweepStaleResolverFiles() }

// sweepStaleResolverFiles 扫掉 /etc/resolver 下**带我们标记**的残留文件。
// 只认标记，不按当前域名清单：残留的往往正是「上一次配过、这一次不再需要」的那些域，
// 按当前清单删会正好漏掉它们。
func sweepStaleResolverFiles() {
	ents, err := os.ReadDir(resolverDir)
	if err != nil {
		return
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(resolverDir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil || !isBaidiManaged(string(b)) {
			continue
		}
		if err := os.Remove(p); err == nil {
			n++
			if bak := p + backupSuffix; fileExists(bak) {
				_ = os.Rename(bak, p)
			}
		}
	}
	if n > 0 {
		slog.Warn("清理上一轮异常退出遗留的解析配置", "files", n)
	}
}

// flushDNSCache 刷新系统解析缓存。不刷的话，切换前后的旧应答会在缓存 TTL 内继续生效，
// 症状是「接入成功了但前几分钟还是解析到旧地址」（断开后同理）。best-effort：
// 命令不存在或失败都不影响主流程，故不返回错误。
func flushDNSCache() {
	_ = sh("dscacheutil", "-flushcache")
	_ = sh("killall", "-HUP", "mDNSResponder")
}
