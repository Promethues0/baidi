package darkfw

import (
	"os"
	"strings"
	"testing"
)

// 放行规则可达性（wave11，G33 的 pf 半边）。
//
// ★背景：baidi-pf.conf 此前把 `block drop in quick` 排在 `pass in quick` 之前，而 pf 的
// quick 语义是「命中即为最后匹配、后续规则不再求值」——放行规则永远走不到，全员连不上；
// 探针只抠得出 block 那一条，于是控制面把这台判成 armed（假绿）。
//
// 这里的输入都是 `pfctl -a baidi-gw -sr` 的**输出形状**（pf 会把 conf 规范化成
// `from any to any port = N` 这类写法），不是 conf 原文。

// 旧次序：block 在前，pass 走不到。
const pfOldOrder = `block drop in quick proto tcp from any to any port = 18443
pass in quick proto tcp from <baidi_allowed> to any port = 18443 flags S/SA keep state
pass in quick proto udp from any to any port = 18201 keep state`

// 修复后的次序：pass 在前。
const pfNewOrder = `pass in quick proto tcp from <baidi_allowed> to any port = 18443 flags S/SA keep state
block drop in quick proto tcp from any to any port = 18443
pass in quick proto udp from any to any port = 18201 keep state`

func TestPfPassShadowedByQuickBlockIsDetected(t *testing.T) {
	got := parsePfPassBeforeBlock(pfOldOrder, 18443)
	if got == nil || *got {
		t.Fatalf("block quick 排在 pass 之前时放行规则走不到，必须判 false（否则控制面会把全员连不上判成 armed），实得 %v", got)
	}
}

func TestPfPassBeforeBlockIsOK(t *testing.T) {
	got := parsePfPassBeforeBlock(pfNewOrder, 18443)
	if got == nil || !*got {
		t.Fatalf("pass 排在 block quick 之前才是正确次序，必须判 true，实得 %v", got)
	}
}

func TestPfMissingPassIsUnreachable(t *testing.T) {
	onlyBlock := "block drop in quick proto tcp from any to any port = 18443\n"
	got := parsePfPassBeforeBlock(onlyBlock, 18443)
	if got == nil || *got {
		t.Fatalf("只有默认 DROP、没有放行规则时同样是全员连不上，必须判 false，实得 %v", got)
	}
}

func TestPfPassForOtherPortDoesNotCount(t *testing.T) {
	// 放行的是另一个端口：对 18443 而言等于没有放行规则。
	out := "pass in quick proto tcp from <baidi_allowed> to any port = 18444 keep state\n" +
		"block drop in quick proto tcp from any to any port = 18443\n"
	got := parsePfPassBeforeBlock(out, 18443)
	if got == nil || *got {
		t.Fatalf("放行规则保护的是别的端口时不能算数，实得 %v", got)
	}
}

func TestPfNoBlockIsUndecidable(t *testing.T) {
	// 找不到 DROP 那一条：次序无从谈起，回 nil 交给 GuardedPort 那一支（no-drop-rule）说话。
	if got := parsePfPassBeforeBlock(pfNewOrder, 9999); got != nil {
		t.Fatalf("找不到保护该端口的 DROP 时必须回 nil（不可判定），实得 %v", *got)
	}
}

// TestShippedPfConfPutsPassBeforeBlock 随仓发布的 baidi-pf.conf 本身必须是正确次序。
//
// ★变异：把 conf 里 pass 与 block 两行对调回旧次序 → 本用例变红。这是这条修复唯一
// 落在「交付物」上的执行方——光改探针不改 conf，新装的每台 mac 网关照样全员连不上。
func TestShippedPfConfPutsPassBeforeBlock(t *testing.T) {
	raw, err := os.ReadFile("../../firewall/baidi-pf.conf")
	if err != nil {
		t.Fatalf("读不到随仓 conf：%v", err)
	}
	// conf 原文与 pfctl -sr 的输出形状不同（`to port` vs `to any port =`），
	// 这里只按行序比较两条规则的出现位置。
	passAt, blockAt := -1, -1
	for i, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if passAt < 0 && strings.HasPrefix(l, "pass in quick proto tcp from <baidi_allowed>") {
			passAt = i
		}
		if blockAt < 0 && strings.HasPrefix(l, "block drop in quick proto tcp") {
			blockAt = i
		}
	}
	if passAt < 0 || blockAt < 0 {
		t.Fatalf("conf 里找不到放行或默认丢弃规则（pass=%d block=%d）", passAt, blockAt)
	}
	if passAt > blockAt {
		t.Fatalf("baidi-pf.conf 把 block quick 排在了 pass 之前（block 第 %d 行、pass 第 %d 行）："+
			"pf 的 quick 命中即终止求值，放行规则永远走不到，全员连不上", blockAt+1, passAt+1)
	}
}
