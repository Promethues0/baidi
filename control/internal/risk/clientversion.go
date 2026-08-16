package risk

import (
	"fmt"
	"strings"

	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/upgrade"
)

// ── client_version：唯一一项判据在控制面的检查 ──
//
// 其余五项都是「客户端探测 + 机械布尔化」（磁盘加密、SIP、防火墙…），终端自己就能
// 给出确定答案。`client_version` 不一样：**「是不是该升级了」的判据只有控制面知道**
// （目标版本在「升级 → 灰度发布」里配），终端手里只有自己的版本号。
//
// 此前采集器对这一项写死 `Tri::Pass`，于是：
//   - 终端合规页对**跑三个版本以前客户端**的机器同样亮绿；
//   - 管理员看这一栏的目的恰恰是找出老客户端，而它对谁都说「合规」。
// 这正是本项目在桌面端自助诊断上判过死刑的「假绿」形态——假诊断比没有诊断更糟，
// 它替坏链路背书。而且这一项**不属于**「采集不到」那一类可以三态兜底的项：
// 版本号本地永远取得到（编译期常量），缺的是判据，判据本就该在控制面。
//
// 现在：采集器如实报 unknown + 原始版本号，控制面在入库前用本文件重算并写回报告，
// 于是页面渲染的那一格与风险引擎判定的那一格是同一个结论。

// minClientVersionUnset 目标版本取不到时的说明。
// 两个来源都空才会走到这里，故文案要把两个都点出来，否则管理员不知道该去哪配。
const minClientVersionUnset = "该平台既没有配置稳定版本（升级 → 灰度发布），下载中心也没有在分发安装包"

// ResolveClientVersion 用控制面认定的最低合规版本重算 client_version 这一项。
//
// 返回一份**新切片**（不改调用方持有的那份）。只在终端上报了该项时才重算——
// 没报就交给 Evaluate 按「缺失即不合规」处理，那是防选择性上报的既有设计，
// 在这里补一条出来反而会把「客户端根本没报」洗成「控制面判过了」。
//
// 三种「判不了」一律 Unknown 而非 Pass（与全项目的三态纪律同口径）：
//   - minVersion 为空：该平台没有发布计划，无从谈起「是不是最新」；
//   - reported 为空：终端没报版本；
//   - 任一侧解析不出语义化版本号。
//
// ★不能拿灰度版本当判据，只能拿稳定版：灰度是「先小范围验证」，用它判合规
// 会让全体没进灰度批次的终端一夜之间集体不合规——而他们装的恰恰是管理员让装的那版。
func ResolveClientVersion(checks []store.PostureCheckResult, reported, minVersion string) []store.PostureCheckResult {
	out := append([]store.PostureCheckResult(nil), checks...)
	for i := range out {
		if out[i].Key != store.CheckKeyClientVersion {
			continue
		}
		ok, unknown, value := judgeClientVersion(reported, minVersion)
		out[i].OK, out[i].Unknown, out[i].Value = ok, unknown, value
	}
	return out
}

// judgeClientVersion 纯判定：(合规, 不可判定, 展示值)。
func judgeClientVersion(reported, minVersion string) (ok, unknown bool, value string) {
	reported = strings.TrimSpace(reported)
	minVersion = strings.TrimSpace(minVersion)
	switch {
	case minVersion == "":
		return false, true, "无法判定：" + minClientVersionUnset
	case reported == "":
		return false, true, "无法判定：终端未上报客户端版本"
	}
	cur, err1 := upgrade.ParseVersion(reported)
	min, err2 := upgrade.ParseVersion(minVersion)
	switch {
	case err1 != nil:
		return false, true, fmt.Sprintf("无法判定：终端上报的版本号 %q 不是 x.y.z 形式", reported)
	case err2 != nil:
		return false, true, fmt.Sprintf("无法判定：稳定版本配成了 %q，不是 x.y.z 形式", minVersion)
	case cur.Compare(min) < 0:
		return false, false, fmt.Sprintf("%s，低于要求的 %s", cur, min)
	}
	return true, false, fmt.Sprintf("%s（≥ %s）", cur, min)
}
