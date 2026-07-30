//go:build linux

package main

import (
	"fmt"
	"os/exec"
)

// Linux tun 接口名任意（IFNAMSIZ≤15）。
const defaultTunName = "baidi0"

// ifup 用 iproute2 配置 tun 接口 IP 并把全部受保护网段路由进该接口（需 root）。
// routes 由控制面接入剖面下发，可多条（VIP 段 + 各业务后端 /32），见 ifup_darwin.go 说明。
func ifup(dev, ip string, routes []string) error {
	if err := sh("ip", "link", "set", "dev", dev, "up"); err != nil {
		return err
	}
	if err := sh("ip", "addr", "add", ip+"/32", "dev", dev); err != nil {
		return err
	}
	for _, r := range routes { // r 形如 10.99.0.0/24 或 10.20.1.10/32
		if err := sh("ip", "route", "add", r, "dev", dev); err != nil {
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
