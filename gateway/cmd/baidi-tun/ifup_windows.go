//go:build windows

package main

import (
	"fmt"
	"os/exec"
)

// Windows wintun 适配器 cosmetic 名（= CreateTUN 传入名）。
const defaultTunName = "baidi0"

// ifup 用 netsh 配置 wintun 适配器 IP 并加受保护网段路由（需管理员）。
// dev = 适配器名；运行目录需有 wintun.dll。若 netsh 加路由在某些版本不稳，
// 可改 PowerShell：New-NetRoute -InterfaceAlias <dev> -DestinationPrefix <route>。
func ifup(dev, ip, route string) error {
	if err := sh("netsh", "interface", "ip", "set", "address", "name="+dev, "static", ip, "255.255.255.255"); err != nil {
		return err
	}
	return sh("netsh", "interface", "ip", "add", "route", route, dev)
}

func sh(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil
}
