// Package darkfw 把 SPA 放行落到内核态防火墙，实现真隐身：默认 DROP 代理端口，
// 仅放行经 SPA 敲门授权的源 IP；TTL 到期即撤。相比用户态 accept+close（会回 RST、
// 可被扫描器探测为 closed），内核 DROP 让端口在网络层“不存在”（扫描器只见 filtered）。
//
// 自动适配后端：Linux 用 nftables（集合 baidi_allowed @ table inet baidi），
// macOS 用 pf（表 <baidi_allowed>）。默认拦截链/规则由各自 setup 脚本预置（需 root）：
//   - Linux： firewall/baidi-nft.sh
//   - macOS： firewall/setup-pf.sh
//
// 网关只动态增删放行集合里的 IP；pfctl/nft 操作需 root，故 -pf 模式须以 root 运行。
package darkfw

import (
	"log/slog"
	"os/exec"
	"strings"
)

// Table/Set 名称（两端一致）。
const Table = "baidi_allowed"

type backend int

const (
	none backend = iota
	pf          // macOS
	nft         // Linux
)

func detect() backend {
	if _, err := exec.LookPath("nft"); err == nil {
		return nft
	}
	if _, err := exec.LookPath("pfctl"); err == nil {
		return pf
	}
	return none
}

var be = detect()

// Available 报告是否有可用的内核防火墙后端。
func Available() bool { return be != none }

// Backend 返回当前后端名（日志用）。
func Backend() string {
	switch be {
	case pf:
		return "pf(macOS)"
	case nft:
		return "nftables(Linux)"
	default:
		return "none"
	}
}

// AllowIP 把源 IP 加入放行集合（幂等）。
func AllowIP(ip string) error {
	switch be {
	case nft:
		return run("nft", "add", "element", "inet", "baidi", Table, "{ "+ip+" }")
	case pf:
		return run("pfctl", "-t", Table, "-T", "add", ip)
	}
	return nil
}

// DenyIP 把源 IP 移出放行集合。
func DenyIP(ip string) error {
	switch be {
	case nft:
		return run("nft", "delete", "element", "inet", "baidi", Table, "{ "+ip+" }")
	case pf:
		return run("pfctl", "-t", Table, "-T", "delete", ip)
	}
	return nil
}

// Flush 清空放行集合（启动/退出归零，确保默认隐身）。
func Flush() error {
	switch be {
	case nft:
		return run("nft", "flush", "set", "inet", "baidi", Table)
	case pf:
		return run("pfctl", "-t", Table, "-T", "flush")
	}
	return nil
}

func run(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		slog.Warn("防火墙命令失败（需 root / 已 setup?）", "cmd", bin+" "+strings.Join(args, " "), "err", err.Error(), "out", strings.TrimSpace(string(out)))
		return err
	}
	return nil
}
