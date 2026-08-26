package dataplane

import (
	"strings"
	"testing"
)

// 接入态判据必须来自**真实事件**，不能是两行启动日志。
//
// ★改造前：`ready` 判 `/数据面就绪/`、`keepalive` 判 `/敲门保活/`，而这两行分别打印于
// 任何一次 knock 与任何一次拨号**之前**——纯粹是"netstack 装好了""ticker 起来了"。
// 于是三类真实故障在接入页上完全看不见，界面一律绿色「已接入 · 隧道活动」：
//   ① 全部网关落点拨不通；
//   ② config.gm 与网关模式不一致导致握手 100% 失败；
//   ③ 指纹钉扎失败（数据面自己判定为"疑似中间人"）。
// 而且业务流量一多，那两行会被挤出 4000 字节的日志尾巴 → 健康隧道反被判「未见保活」。
func TestHealthReflectsRealEvents(t *testing.T) {
	tn := &tunneler{}

	// 初始：什么都没发生过——**不能**是"就绪"
	if tn.knockOK || tn.tunnelOK {
		t.Fatal("初始状态不得声称敲门/隧道已成功")
	}

	// 拨号失败要留下原因（此前这条失败在运行中恒到不了界面）
	tn.markFail("网关证书指纹不匹配（疑似中间人）：期望 abc 实得 def")
	if tn.lastErr == "" {
		t.Error("拨号失败必须记下原因")
	}
	if tn.tunnelOK {
		t.Error("失败不该把隧道标成通")
	}

	// 敲门真的发出去了
	tn.markKnock()
	if !tn.knockOK {
		t.Error("敲门成功应被记录")
	}
	if tn.lastErr != "" {
		t.Error("成功后应清掉上一次的错误——留着会让一次早已恢复的瞬时失败永远挂在界面上")
	}

	// 隧道真的拨通了
	tn.markTunnel()
	if !tn.tunnelOK {
		t.Error("隧道拨通应被记录")
	}
}

// 健康行只在**状态变化**时打——每条流都打会把 4000 字节的日志尾巴瞬间冲满，
// 反而把该看的信息（含落点行）挤出窗口。
func TestHealthLineDedup(t *testing.T) {
	tn := &tunneler{}
	tn.markTunnel()
	first := tn.lastHealth
	if first == "" {
		t.Fatal("应记下已打印的健康行")
	}
	tn.markTunnel() // 同样的状态再来一次
	if tn.lastHealth != first {
		t.Error("状态未变时不应产生新的健康行")
	}
	tn.markFail("隧道拨号失败")
	if tn.lastHealth == first {
		t.Error("状态变了必须打新行，否则界面停在旧结论上")
	}
	// 行内必须带上客户端解析所需的三个字段（契约见 tunnel.ts 的 parseHealth）
	for _, want := range []string{"knock=", "tunnel=", "err="} {
		if !strings.Contains(tn.lastHealth, want) {
			t.Errorf("健康行缺字段 %q：%s", want, tn.lastHealth)
		}
	}
}
