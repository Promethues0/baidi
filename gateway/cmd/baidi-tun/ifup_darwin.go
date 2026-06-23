//go:build darwin

package main

import (
	"fmt"
	"os/exec"
)

// macOS utun 设备名必须是 "utun" 或 "utun%d"，内核分配具体编号。
const defaultTunName = "utun"

// ifup 配置 utun 接口 IP 并把受保护网段路由进该接口（需 root）。
func ifup(dev, ip, route string) error {
	if err := sh("ifconfig", dev, "inet", ip, ip, "up"); err != nil {
		return err
	}
	return sh("route", "-q", "-n", "add", "-net", route, "-interface", dev)
}

func sh(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil
}
