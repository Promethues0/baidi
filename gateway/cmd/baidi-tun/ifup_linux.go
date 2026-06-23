//go:build linux

package main

import (
	"fmt"
	"os/exec"
)

// Linux tun 接口名任意（IFNAMSIZ≤15）。
const defaultTunName = "baidi0"

// ifup 用 iproute2 配置 tun 接口 IP 并把受保护网段路由进该接口（需 root）。
func ifup(dev, ip, route string) error {
	if err := sh("ip", "link", "set", "dev", dev, "up"); err != nil {
		return err
	}
	if err := sh("ip", "addr", "add", ip+"/32", "dev", dev); err != nil {
		return err
	}
	return sh("ip", "route", "add", route, "dev", dev) // route 形如 10.99.0.0/24
}

func sh(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil
}
