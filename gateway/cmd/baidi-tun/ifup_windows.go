//go:build windows

package main

import (
	"fmt"
	"os/exec"
)

// Windows wintun 适配器 cosmetic 名（= CreateTUN 传入名）。
const defaultTunName = "baidi0"

// ifup 用 netsh 配置 wintun 适配器 IP 并加受保护网段路由（需管理员）。
// dev = 适配器名；wintun.dll 需与本 exe 同目录或在 System32（见 main.go 头部）。
// 若 netsh 加路由在某些版本不稳，
// 可改 PowerShell：New-NetRoute -InterfaceAlias <dev> -DestinationPrefix <route>。
// routes 由控制面接入剖面下发，可多条（VIP 段 + 各业务后端 /32），见 ifup_darwin.go 说明。
func ifup(dev, ip string, routes []string) error {
	if err := sh("netsh", "interface", "ip", "set", "address", "name="+dev, "static", ip, "255.255.255.255"); err != nil {
		return err
	}
	for _, r := range routes {
		if err := sh("netsh", "interface", "ip", "add", "route", r, dev); err != nil {
			return fmt.Errorf("添加路由 %s → %s 失败: %w", r, dev, err)
		}
	}
	return nil
}

func sh(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil
}
