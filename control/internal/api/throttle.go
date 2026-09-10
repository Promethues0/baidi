package api

import (
	"strconv"
	"time"
)

// 审计节流的**披露**（wave11 行动 16，NFR-OBS-02 / FR-AUDIT-05）。
//
// ★改造前控制面侧的四处节流是**丢弃式**的：水位表只记「上次落审计的时刻」，
// 窗口内被抑制的次数直接扔掉，正文里一个字都不提。于是：
//
//   - 一个终端连续接入 8 小时，审计里是 96 条一模一样的「已签发敲门令牌」，
//     而"这中间实际发生了 1920 次"这个事实不在任何地方；
//   - 审计导出页逐字写着「导出全量审计日志」——那句话在有节流的前提下不成立；
//   - **同一功能族的网关侧（gateway/internal/secevent）已经做对了**：
//     语义是"第一现场立即报、窗口内累计、到期补报"，计数不丢只聚合。
//     两种记录并排躺在同一张 audit_log 表里，而读的人分不出哪条带了聚合、哪条没带。
//
// 节流本身是对的（敲门是 15s 一次的保活热路径，不节流一个终端一天产出约 5700 条
// 内容相同的审计，真正的处置事件会被冲刷掉）。要补的只是**把被折叠的数量说出来**。
//
// ★为什么不改成"每条都记"：那会让审计表被保活流量淹没，而审计的价值恰恰在于
// 能从里面看出异常——这是 FR-AUDIT-05 与 NFR-OBS-02 之间的真实张力，
// 折中点是"聚合但不隐瞒"，与网关侧同一口径。

// throttleMark 一个节流键的水位：上次落审计的时刻 + 此后被折叠掉的次数。
type throttleMark struct {
	// At 上次真正落审计的 Unix 秒。
	At int64
	// Suppressed 自 At 以来被节流拦下、没有单独成条的次数。
	//
	// ★它是这次改造的全部要点：改造前这个数字根本不存在，被折叠的事件在系统里
	// 不留任何痕迹。落审计时把它写进正文并清零。
	Suppressed int
}

// throttleAdmit 判断这次事件是否该单独落一条审计，并返回窗口内被折叠掉的次数。
//
// due=false 时调用方直接返回（这一次被折叠，计数已经累加）。
// due=true 时 suppressed 是**上一个窗口**里被折叠的次数，应当写进正文。
//
// maxKeys 是水位表的键数上界：这些表的键往往含**客户端自报**的内容（设备指纹、账号），
// 攻击者可控，持一个合法会话每次换随机指纹就能让表无界增长。超上界整张清空——
// 最坏结果只是接下来多记几条审计，而那本来就是该被看见的。
//
// ★调用方必须**持有 s.mu**（这些水位表与 Server 的其它状态共用同一把锁）。
func throttleAdmit(tab map[string]throttleMark, key string, interval time.Duration, maxKeys int, now int64) (due bool, suppressed int) {
	if len(tab) > maxKeys {
		for k := range tab {
			delete(tab, k)
		}
	}
	mk, seen := tab[key]
	if !seen || now-mk.At >= int64(interval.Seconds()) {
		tab[key] = throttleMark{At: now}
		return true, mk.Suppressed
	}
	mk.Suppressed++
	tab[key] = mk
	return false, 0
}

// throttleNote 把被折叠的次数渲染成一句可读的正文后缀；为 0 时返回空串。
//
// ★措辞要说清这是**同一窗口内的同类事件**，而不是"发生了 N 次别的事"。
// 也要说清窗口长度——不写窗口的话，读的人无从判断 N 次是密集还是稀疏。
func throttleNote(suppressed int, interval time.Duration) string {
	if suppressed <= 0 {
		return ""
	}
	return "（上一个 " + strconv.Itoa(int(interval.Minutes())) + " 分钟窗口内另有 " +
		strconv.Itoa(suppressed) + " 次同类事件被合并，未单独成条）"
}
