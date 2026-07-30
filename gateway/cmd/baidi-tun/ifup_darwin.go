//go:build darwin

package main

import (
	"fmt"
	"os/exec"
)

// macOS utun 设备名必须是 "utun" 或 "utun%d"，内核分配具体编号。
const defaultTunName = "utun"

// ifup 配置 utun 接口 IP 并把全部受保护网段路由进该接口（需 root）。
//
// routes 由控制面接入剖面下发（VIP 段 + 各业务后端 /32），可以是多条：真实业务地址
// 通常散落在多个内网段，只接管一条网段就会出现「隧道建起来了、点开应用却直连不走隧道」。
func ifup(dev, ip string, routes []string) error {
	if err := sh("ifconfig", dev, "inet", ip, ip, "up"); err != nil {
		return err
	}
	for _, r := range routes {
		// -net 对 /32 同样有效（macOS route 按掩码自行判定主机路由）。
		// 逐条加：任一条失败即返回，让调用方带着具体网段报错，而不是留下一个
		// 「部分网段生效」的半吊子接口——那种状态排障时极难看出问题出在哪。
		if err := sh("route", "-q", "-n", "add", "-net", r, "-interface", dev); err != nil {
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
