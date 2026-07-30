package ike

import (
	"encoding/binary"
	"io"
	"time"
)

// 重传与退避（RFC 7296 §2.1，见 2-ike.md §7.2）。
//
// ★整个协议里最容易写成"看起来对但实际是灾难"的一处：
//
//  1. **只有交换的发起方重传**。响应方永不主动重传——它无从知道自己的响应是否到达，
//     主动重发只会在丢包时制造报文风暴。
//  2. **响应方对重复请求原样回放缓存的字节**。重新计算响应会复用 GCM 显式 nonce
//     （计数器已经推进过，或者更糟：又取一次同样的计数）。nonce 复用不是"稍微弱一点"，
//     是 GCM 认证密钥可被恢复的级别。缓存实现在 IKESA.cacheResponse/replayResponse。
//  3. **抖动是必需的**，不是锦上添花：两端配置相同 → 超时时刻相同 → 同时判死、
//     同时重连、再次同时超时，形成谐振。这种故障的表现是"隧道每隔 N 分钟集体抖一次"，
//     而每条日志单看都完全正常。

// retransmitDelays 指数退避表。累计约 182 秒后放弃，满足 RFC「指数退避、
// 总时长至少几分钟」的要求，也刚好覆盖典型的对端重启窗口。
//
// 封顶 60 秒而不是继续翻倍：再长就与 DPD 判死时间重叠，两套超时互相掩盖，
// 排障时分不清是"对端没回"还是"我们还没开始重试"。
// （用数组而非切片：len 是编译期常量，maxRetransmits 才能是 const。）
var retransmitDelays = [...]time.Duration{
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
	60 * time.Second,
	60 * time.Second,
}

// maxRetransmits 首发之外的最大重传次数。tries 超过它即放弃该交换。
const maxRetransmits = len(retransmitDelays)

// retransmitDelay 给出第 attempt 次重传（attempt 从 1 开始）前应等待的时长，
// 已叠加 ±20% 抖动。
//
// rnd 取不到随机数时**不报错、退回无抖动**：抖动只是防谐振的优化，
// 为它中断一条隧道是本末倒置。（真正需要熵的地方——SPI、nonce、DH 私钥——
// 一律走 RandBytes 的 panic 路径。）
func retransmitDelay(attempt int, rnd io.Reader) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := retransmitDelays[len(retransmitDelays)-1]
	if attempt <= len(retransmitDelays) {
		base = retransmitDelays[attempt-1]
	}
	return jitter(base, rnd, 20)
}

// jitter 给 d 叠加 ±pct% 的随机偏移。
func jitter(d time.Duration, rnd io.Reader, pct int) time.Duration {
	if d <= 0 || pct <= 0 || rnd == nil {
		return d
	}
	var b [2]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return d
	}
	// 把 16 位随机数映射到 [-pct, +pct] 的百分比偏移。
	r := int64(binary.BigEndian.Uint16(b[:])) // 0..65535
	off := (r*int64(2*pct))/65535 - int64(pct)
	return d + time.Duration(int64(d)*off/100)
}

// 站点级重连退避：协商彻底失败后，多久再发起一次 IKE_SA_INIT。
//
// ★与报文级重传是两回事，不要混用同一张表。报文级重传解决的是丢包，
// 秒级即可；站点级重连解决的是"对端还没起来 / 配置错了"，必须退避到分钟级——
// 否则一条配错的站点会以每 2 秒一次的频率永久刷屏，把真正的故障淹掉。
const (
	siteRetryMin = 30 * time.Second
	siteRetryMax = 5 * time.Minute
)

// siteRetryDelay 按失败次数给出重连间隔：30s 起，翻倍到 5min 封顶，带 ±20% 抖动。
func siteRetryDelay(step int, rnd io.Reader) time.Duration {
	d := siteRetryMin
	for i := 0; i < step && d < siteRetryMax; i++ {
		d *= 2
	}
	if d > siteRetryMax {
		d = siteRetryMax
	}
	return jitter(d, rnd, 20)
}
