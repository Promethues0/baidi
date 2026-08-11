package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateways.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写临时文件失败: %v", err)
	}
	return p
}

// 清单的顺序就是优先级，装载时**原样保留**：终端手里没有任何能推翻控制面排序的材料，
// 重排一次就等于拿一个假信号盖掉真结论。
func TestLoadGateways_KeepsOrderAndPerGatewayPin(t *testing.T) {
	p := writeTemp(t, `[
	  {"id":"gw-a","spa":"10.0.0.1:18201","proxy":"10.0.0.1:18443","pin":"aa"},
	  {"id":"gw-b","spa":"10.0.0.2:18201","proxy":"10.0.0.2:18443","pin":"bb"}
	]`)
	eps, err := loadGateways(p, "127.0.0.1:18201", "127.0.0.1:18443", "zz")
	if err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	if len(eps) != 2 || eps[0].ID != "gw-a" || eps[1].ID != "gw-b" {
		t.Fatalf("顺序须原样保留，实得 %+v", eps)
	}
	if eps[0].Pin != "aa" || eps[1].Pin != "bb" {
		t.Fatalf("指纹必须逐落点各带各的（共用一份会让故障转移在钉扎那步必然失败），实得 %+v", eps)
	}
	// 有清单时 -spa/-proxy/-pin 一律不参与：混用会出现"清单里是 A、实际拨的是 B"。
	for _, e := range eps {
		if e.Pin == "zz" || strings.HasPrefix(e.ProxyAddr, "127.0.0.1") {
			t.Fatalf("有清单时不该混入单落点参数，实得 %+v", e)
		}
	}
}

// 无清单时退回单落点三件套（手工起 baidi-tun 与旧桌面客户端仍走这条路）。
func TestLoadGateways_FallsBackToFlags(t *testing.T) {
	eps, err := loadGateways("", "127.0.0.1:18201", "127.0.0.1:18443", "abcd")
	if err != nil {
		t.Fatalf("单落点回退失败: %v", err)
	}
	if len(eps) != 1 || eps[0].SPAAddr != "127.0.0.1:18201" || eps[0].Pin != "abcd" {
		t.Fatalf("单落点回退结果不对：%+v", eps)
	}
}

// 空数组不能静默退回单落点：那会让"控制面这一轮没算出任何落点"被本地默认值盖住，
// 用户以为自己连的是控制面指定的网关。
func TestLoadGateways_EmptyArrayRejected(t *testing.T) {
	p := writeTemp(t, `[]`)
	if _, err := loadGateways(p, "127.0.0.1:18201", "127.0.0.1:18443", ""); err == nil {
		t.Fatal("空清单必须报错，不得静默退回单落点")
	}
}

// 地址填错要在启动期失败：半残地跑着的症状是"切到那个落点才连不上"，而切换是偶发的。
func TestLoadGateways_RejectsBadAddress(t *testing.T) {
	for name, body := range map[string]string{
		"缺端口":   `[{"id":"gw-a","spa":"10.0.0.1:18201","proxy":"10.0.0.1"}]`,
		"缺隧道地址": `[{"id":"gw-a","spa":"10.0.0.1:18201"}]`,
		"缺敲门地址": `[{"id":"gw-a","proxy":"10.0.0.1:18443"}]`,
		"不是数组":  `{"id":"gw-a"}`,
	} {
		p := writeTemp(t, body)
		if _, err := loadGateways(p, "127.0.0.1:18201", "127.0.0.1:18443", ""); err == nil {
			t.Fatalf("%s 的清单必须被拒", name)
		}
	}
}
