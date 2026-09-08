package main

import (
	"crypto/tls"
	"strings"

	"baidi.dev/gateway/internal/knock"
)

// loadControlTrust 按 -control-ca 构建「调控制面」用的 TLS 配置，并回一句**启动日志回执**。
//
// 回执不是装饰：信任材料这种东西「以为配上了」与「真的生效了」在现场完全同形——
// 一个路径打错的 -control-ca 若被静默忽略，表现只是"门敲不开"，管理员会一路去查证书本身。
// 三种结局各有各的一句话：
//   - 没配 → 系统信任库（并点名自签控制面在这条路径下必然失败，因为那正是参考部署的形态）
//   - 配了且控制面是 https → 已装载，池是「系统池 ∪ 锚」
//   - 配了但控制面是 http:// → **锚不生效**，且这一跳整个没有加密。这条必须当面说：
//     配了锚的人默认以为自己已经安全了，而 http 下敲门令牌（一张短时效凭据）是明文过网的。
//
// 返回 (cfg, 回执, 是否该按 WARN 打, err)。cfg 为 nil 即"走系统信任库"（**不是**跳过校验）；
// err 一律致命，绝不静默回落——回落等于「配了却不生效」。
//
// ★回执文案里刻意不出现「失败/退出/fatal」这几个词：桌面客户端在没有健康行时会用
// /失败|未敲门成功|panic|fatal|退出/ 从日志尾巴里捞最近一次故障（tunnel.ts），
// 一句正常的启动回执被捞成故障，会让一次成功的接入在界面上显示成红的。
func loadControlTrust(path, control string) (*tls.Config, string, bool, error) {
	cfg, err := knock.ControlTLSFromFile(path)
	if err != nil {
		return nil, "", false, err
	}
	if cfg == nil {
		return nil, "控制中心信任锚：未配置 → 用系统信任库（自签控制面会栽在 x509：" +
			"参考部署正是自签，此时应当用 -control-ca 分发信任锚，而不是找一个跳过校验的开关——本程序没有）", false, nil
	}
	if isPlainHTTP(control) {
		return cfg, "控制中心信任锚：已装载 " + path + "，但 -control 是 http:// —— **锚不生效**，" +
			"且这一跳完全没有加密：敲门令牌明文过网。要么把 -control 改成 https://，要么明白自己在做什么", true, nil
	}
	return cfg, "控制中心信任锚：已装载 " + path + "（信任池 = 系统池 ∪ 该锚；" +
		"部署方换成受信证书那天照常可用）", false, nil
}

// isPlainHTTP 判断控制面地址是否是明文 http。**只认显式的 http:// 前缀**：
// 不带 scheme 的地址（如 "1.2.3.4:8090"）在 knock.Fetch 里会被 http.NewRequest 直接判非法，
// 那是一条自己会报错的路，不需要本函数替它猜。
func isPlainHTTP(control string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(control)), "http://")
}
