package main

// 网关落点清单（-gateways）的装载与校验。
//
// 清单来自控制面接入剖面的 gateways 段（见 control 的 profileGateways），**顺序即优先级**：
// 客户端按序拨号、失败切下一个。终端不重排、不筛选——它没有任何能推翻控制面排序的材料
// （不知道谁负载低、不知道谁离自己近），自作主张只会把一个假信号盖在真结论上。

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"baidi.dev/gateway/internal/dataplane"
)

// gatewayEntry 落点清单文件的一行。字段名与控制面剖面的 ProfileGateway 对齐，
// 好让桌面客户端可以近乎原样地把剖面里那段写进文件。
//
// ★刻意**不收** online 字段：那是控制面视角的心跳新鲜度，只用来决定顺序，而顺序
// 在文件里已经体现了。收进来只会诱使数据面拿它做"要不要试这台"的判断——
// "控制面看不到它的心跳"与"终端连不上它"是两个独立事实，后者才是这里唯一关心的。
type gatewayEntry struct {
	ID    string `json:"id"`
	SPA   string `json:"spa"`
	Proxy string `json:"proxy"`
	Pin   string `json:"pin"`
}

// loadGateways 读落点清单；path 为空时退回 -spa/-proxy/-pin 组成的单落点。
//
// 校验从严：一条地址填错就让整次启动失败。半残地跑着的后果是"隧道显示已接入、
// 切到那个落点才连不上"，而切换是偶发的——现场几乎不可能复现出来。
func loadGateways(path, spa, proxy, pin string) ([]dataplane.Endpoint, error) {
	if strings.TrimSpace(path) == "" {
		ep := dataplane.Endpoint{SPAAddr: strings.TrimSpace(spa), ProxyAddr: strings.TrimSpace(proxy), Pin: strings.TrimSpace(pin)}
		if err := checkEndpoint(ep, 1); err != nil {
			return nil, err
		}
		return []dataplane.Endpoint{ep}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取落点清单失败: %w", err)
	}
	var raw []gatewayEntry
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("解析落点清单 %s 失败: %w", path, err)
	}
	if len(raw) == 0 {
		// 空清单不能静默退回单落点：那会让"控制面这一轮没算出任何落点"这件事
		// 被一个本地默认值盖住，用户以为连的是控制面指定的网关。
		return nil, fmt.Errorf("落点清单 %s 是空数组：控制面没有下发任何网关落点", path)
	}
	out := make([]dataplane.Endpoint, 0, len(raw))
	for i, e := range raw {
		ep := dataplane.Endpoint{
			ID:        strings.TrimSpace(e.ID),
			SPAAddr:   strings.TrimSpace(e.SPA),
			ProxyAddr: strings.TrimSpace(e.Proxy),
			Pin:       strings.TrimSpace(e.Pin),
		}
		if err := checkEndpoint(ep, i+1); err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

// checkEndpoint 单个落点的地址体检。
func checkEndpoint(ep dataplane.Endpoint, pos int) error {
	for _, f := range []struct{ name, addr string }{{"隧道地址(proxy)", ep.ProxyAddr}, {"敲门地址(spa)", ep.SPAAddr}} {
		if f.addr == "" {
			return fmt.Errorf("第 %d 个落点（%s）缺 %s", pos, ep.Label(), f.name)
		}
		if _, _, err := net.SplitHostPort(f.addr); err != nil {
			return fmt.Errorf("第 %d 个落点（%s）的 %s %q 不是合法 host:port: %v", pos, ep.Label(), f.name, f.addr, err)
		}
	}
	return nil
}
