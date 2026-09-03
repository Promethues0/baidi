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
 *
 * ★wave10 起本文件回答的是**两个**问题，不是一个：
 *   judgeTunnelStatus 只回答「引擎还在不在跑」（stage），judgeReady 回答「门敲没敲开」（ready）。
 *   之所以必须分开：真机上二者会同时给出相反的答案（stage=up 而 knock=false），
 *   而处置也相反——前者判真了要断开清理，后者判真了只能等它自愈，绝不能断。
 */

export interface TunnelStatus {
  stage: string;
  reason?: string;

  /* ── 数据面健康事实（wave10 补）──────────────────────────────────────────────
   *
   * ★为什么 stage 之外还要一组键：2026-09-03 安卓真机（OPPO PKU110 / Android 16）实测，
   *   同一时刻桥回 {"stage":"up"}、startTunnel 回「数据面已就绪」，而 Go 健康行是
   *   `knock=false tunnel=false err="取敲门令牌失败：… x509: certificate signed by unknown authority"`。
   *   **引擎起来了、门没敲开，界面却显示已接入**——stage 说的是「引擎进程在不在跑」，
   *   它对「门敲没敲开」一个字都没说，而用户关心的恰恰是后者。
   *
   * ★为什么不给 stage 加第五个值（如 'unready'）：stage 的值域是跨语言契约，三处会立刻误判——
   *   ① 下面 judgeTunnelStatus 的 default 分支虽不误伤，但一旦有人图省事把新值并进 failed/idle，
   *      vpn.ts 就会去 stopTunnel，把一条**每 15s 自动重试、随时可能自愈**的隧道真的断掉
   *      （自愈性证据：gateway/internal/dataplane 的 knockOne 对非 403 失败只 warn 后 return false，
   *      Run 继续阻塞，reknock ticker 每 15s 重试）；
   *   ② vpn.ts 的 adoptRunningTunnel 只认 'up'，新值会掉进「什么都不做」，webview 重建后
   *      一条在跑的 VPN 无人监视；
   *   ③ 安卓桥 BRIDGE_JS 的 30s 轮询判 `s.stage === 'up'` 即 resolve 成功，新值会一路等到超时。
   *   于是新事实用一组**并列**的键表达：中间态是 {stage:'up', ready:false}，天然走 'up' 分支。
   *
   * ★整组键在「健康态不可判定」时**整体缺席**（不是 false、不是空串）：读不到与确定没问题的
   *   处置正好相反（前者不下结论，后者收尾成「已接入」），塌成同形正是本仓反复批判的形态。
   *   故所有读端一律先判 `typeof x === 'boolean'` 再判真假。
   *
   * ★ready **不含 tunnel 位**：tunnel 是粘性位，用户打开第一个应用之前恒 false，
   *   当必要条件会让接入死锁在「接入中」（桌面端踩过，见 clients/desktop/src/lib/tunnel.ts
   *   里 TunView.tunnel 那段注释与 docs/ARCHITECTURE.md 第七节边界①）。
   */
  /**
   * 数据面真正可用 = 引擎在跑 ∧ 敲门成功过 ∧ **敲门类**当前无失败（knockErr 为空）。
   * 缺席 = 不可判定。判定在原生壳里做（EngineHandle.judgeReady），这里只消费结论。
   *
   * ★判据用 knockErr 而不是合并后的 healthErr，是与桌面端 parseTunStatus 唯一的、刻意的分歧：
   *   healthErr 会被**每一条业务流的拨号失败**写脏、又被每 15s 的保活敲门擦掉，拿它当就绪判据，
   *   隧道类的持续故障会让接入态以 15s 为周期反复翻，每翻一次界面就弹一句「已接入企业内网」。
   *   桌面端另有 nextDataplaneNotice 那套粘性状态机吸收震荡，移动端没有。
   *   隧道类失败改由下面的 healthTunnelErr 单独承载并常驻显示，不参与「门敲没敲开」的判定。
   */
  ready?: boolean;
  /** 是否已读到过至少一行健康回报。false = 引擎刚起、还没写出健康行（此时下面几项无意义）。 */
  healthObserved?: boolean;
  healthKnock?: boolean;
  healthTunnel?: boolean;
  healthKnockErr?: string;
  healthTunnelErr?: string;
  healthErr?: string;
}

export type DropVerdict = { dropped: false } | { dropped: true; reason: string };

/** 中断但原生侧没给原因时的文案：只说事实，不替原生猜成因。 */
export const REASON_FAILED_UNKNOWN = '隧道已中断（原生侧未报告原因）';
export const REASON_WENT_IDLE = '隧道已停止（原生 VPN 服务已不在运行，可能被系统回收或被其它应用替换）';
/** 未就绪、且健康行也没给出任何错误原文时的兜底：只说结论，不猜成因。 */
export const REASON_NOT_READY_UNKNOWN = '数据面已启动但未就绪（原生侧未报告原因）';
/** 引擎在跑、但还没产生过健康回报——与「读到了健康行、里面说没错」是两件事，不能同形。 */
export const REASON_NOT_READY_UNOBSERVED = '数据面已启动，但尚未产生健康回报（引擎刚起，健康行还没写出来）';

/**
 * 判「隧道是不是断了」。**新中间态 {stage:'up', ready:false} 刻意不进这里**：
 * 它是「引擎在跑、门没敲开」，而门每 15s 自动重试、随时可能自愈；判成中断的唯一
 * 后果就是 vpn.ts 去 stopTunnel 把它真的断掉，再要恢复得用户重新点一次接入。
 * 未就绪由下面的 judgeReady 单独回答，两个判定各管各的事实，谁也不替谁下结论。
 */
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

/**
 * 判「数据面是不是真的可用」。三态：true / false / **null = 不可判定**。
 *
 * ★缺席时**不回落成 `stage === 'up'`**：那正是本波要消灭的形态——引擎起来了就报「已就绪」，
 *   而真机上恰恰是引擎起来了、敲门 403/证书校验失败。回落只在**桥内做一处**（原生壳知道
 *   自己这一版有没有健康行；webview 侧不知道，猜出来的就是一句没有依据的断言）。
 *   于是 iOS / 鸿蒙壳 / dev 浏览器这些不报 ready 的地方一律 null，UI 按「不可判定」渲染。
 */
export function judgeReady(s: TunnelStatus | null | undefined): boolean | null {
  if (!s) return null;
  if (typeof s.ready !== 'boolean') return null;
  return s.ready;
}

/**
 * 未就绪时给用户看的那句话。**优先原生健康行的原文，一个字都不改写**——
 * 「x509: certificate signed by unknown authority」指得动管理员去装 CA，
 * 换成一句自编的「网络异常」只会把人支去重启手机。
 */
export function notReadyReason(s: TunnelStatus | null | undefined): string {
  const pick = (v?: string) => (v && v.trim() ? v.trim() : '');
  // ★knockErr 必须排第一：未就绪按定义就是敲门类那一格没过（见 ready 的公式），
  //   先取 healthErr 的话，一次与就绪判定无关的隧道类失败会把它占住——界面上「未就绪」的
  //   原因写着一条拨号错误，而真正挡住门的那句 x509 被压在后面看不见。归因指向哪儿人就查哪儿。
  //   与安卓壳 EngineHandle.kt 的 notReadyReasonOf 同序。
  const first = pick(s?.healthKnockErr) || pick(s?.healthErr) || pick(s?.healthTunnelErr);
  if (first) return first;
  // 没有任何错误原文：区分「还没读到健康行」与「读到了但里面没写错误」，两者的下一步不同
  //（前者再等几秒即可，后者说明判据在别处，得看引擎日志）。
  if (s?.healthObserved === false) return REASON_NOT_READY_UNOBSERVED;
  return REASON_NOT_READY_UNKNOWN;
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

/** 监视器的两个回调。两者的语义**刻意不同**，别合并成一个「状态变了」回调。 */
export interface WatchHandlers {
  /** 判成中断：回调**一次**并自停（隧道没了，再守也没有对象）。 */
  onDrop: (reason: string) => void;
  /**
   * 每轮回报就绪判定，**双向翻转、不自停**：门没敲开是每 15s 自动重试的可恢复态，
   * 监视器必须留在原地等它翻回 true——一次性语义会让自愈之后 UI 永远停在「未就绪」。
   * 第二个参数是**同一次读到的那份快照**：结论与原因必须同源，分两次读会出现
   * 「说未就绪、却给不出原因」或「给的是上一轮的原因」。
   */
  onReady?: (ready: boolean | null, s: TunnelStatus | null) => void;
}

/**
 * 每 intervalMs 读一次状态，判成中断即回调 onDrop **一次**并自停；否则把就绪判定
 * 回报给 onReady（每轮都报，含 null=不可判定）。
 * read 抛异常按 null（不可判定）处理——桥挂了不等于隧道断了。
 */
export function createTunnelWatch(
  read: () => TunnelStatus | null,
  handlers: WatchHandlers,
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
      // 断了就不再谈"就绪不就绪"：这一轮只报中断，免得 UI 同时挂两条互相矛盾的横幅。
      stop();
      handlers.onDrop(v.reason);
      return;
    }
    handlers.onReady?.(judgeReady(s), s);
  };
  handle = timers.setInterval(tick, intervalMs);
  return { get active() { return active; }, stop };
}
