/**
 * 接入后的隧道存活监视 · 纯逻辑（无 Vue / 无 DOM 依赖，node --test 直接跑）。
 *
 * ★为什么要有它：原生壳（安卓 TunnelState）在被抢占 / 系统回收 / 引擎自行停机时会把
 *   stage 翻成 failed 并留下原因——但那只是**写端**。webview 侧此前只有 startTunnel 的
 *   启动期轮询（桥 BRIDGE_JS 里 400ms 一次，拿到 up 即 resolve），进入「已接入」之后再没
 *   任何人读 tunnelStatus：另一 VPN 抢占后原因确实留在 TunnelState 里，用户看到的却是
 *   纹丝不动的「已接入企业内网」，直到他自己点断开（把原因一并清掉）。这里就是那个**读端**。
 *
 * 判定口径（与安卓 TunnelState.snapshot 的四态对齐）：
 *   · null      —— 没有桥或桥没有 tunnelStatus（dev 浏览器 / iOS / 鸿蒙壳）：**不可判定，不下结论**；
 *   · up / starting —— 活着；
 *   · failed    —— 已中断，原因取原生给的那句，缺失时用一句不编造成因的通用文案；
 *   · idle      —— 我们以为在接入而原生已回 idle（服务被系统销毁却没有留下 failed 原因）：同样算中断；
 *   · 其它未知值 —— 不猜，当作活着（多显示一个「已接入」不如误报一次断开更难查？不——
 *                  误判成断开会让 UI 去 stopTunnel 把一条好好的隧道真的断掉，方向更坏）。
 */

export interface TunnelStatus {
  stage: string;
  reason?: string;
}

export type DropVerdict = { dropped: false } | { dropped: true; reason: string };

/** 中断但原生侧没给原因时的文案：只说事实，不替原生猜成因。 */
export const REASON_FAILED_UNKNOWN = '隧道已中断（原生侧未报告原因）';
export const REASON_WENT_IDLE = '隧道已停止（原生 VPN 服务已不在运行，可能被系统回收或被其它应用替换）';

export function judgeTunnelStatus(s: TunnelStatus | null | undefined): DropVerdict {
  if (!s) return { dropped: false };
  switch (s.stage) {
    case 'up':
    case 'starting':
      return { dropped: false };
    case 'failed':
      return { dropped: true, reason: s.reason?.trim() ? s.reason.trim() : REASON_FAILED_UNKNOWN };
    case 'idle':
      return { dropped: true, reason: REASON_WENT_IDLE };
    default:
      return { dropped: false };
  }
}

/** 可注入的计时器（测试用假时钟；生产用 globalThis）。 */
export interface WatchTimers {
  setInterval: (fn: () => void, ms: number) => unknown;
  clearInterval: (h: unknown) => void;
}

export interface TunnelWatch {
  /** 是否仍在监视（首次判定中断后自动停止）。 */
  readonly active: boolean;
  stop(): void;
}

/** 生产计时器：包一层是为了让 clearInterval 接受 unknown 句柄（浏览器 number / node Timeout 两种类型）。 */
const realTimers: WatchTimers = {
  setInterval: (fn, ms) => globalThis.setInterval(fn, ms),
  clearInterval: (h) => globalThis.clearInterval(h as ReturnType<typeof globalThis.setInterval>)
};

/** 接入后监视间隔：比启动期轮询（400ms）粗——那时在等一个明确终态，这时只是守着一条长连接。 */
export const WATCH_INTERVAL_MS = 2000;

/**
 * 每 intervalMs 读一次状态，判成中断即回调 onDrop **一次**并自停。
 * read 抛异常按 null（不可判定）处理——桥挂了不等于隧道断了。
 */
export function createTunnelWatch(
  read: () => TunnelStatus | null,
  onDrop: (reason: string) => void,
  intervalMs: number = WATCH_INTERVAL_MS,
  timers: WatchTimers = realTimers
): TunnelWatch {
  let handle: unknown = null;
  let active = true;
  const stop = () => {
    if (!active) return;
    active = false;
    if (handle !== null) timers.clearInterval(handle);
    handle = null;
  };
  const tick = () => {
    if (!active) return;
    let s: TunnelStatus | null;
    try { s = read(); } catch { s = null; }
    const v = judgeTunnelStatus(s);
    if (v.dropped) {
      stop();
      onDrop(v.reason);
    }
  };
  handle = timers.setInterval(tick, intervalMs);
  return { get active() { return active; }, stop };
}
