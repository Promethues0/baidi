// 隧道存活监视的单测：node --experimental-strip-types --test（无 Vue / 无 DOM，不装浏览器也能跑）。
// 守的是复核提出的那条：「onRevoke 留下的原因没有读者」——接入后必须有人轮询 tunnelStatus，
// 且判定口径不能把「不可判定」误判成「已断开」（后者会让 UI 去把一条好好的隧道真的断掉）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';
import {
  judgeTunnelStatus, judgeReady, notReadyReason, createTunnelWatch,
  REASON_FAILED_UNKNOWN, REASON_WENT_IDLE, REASON_NOT_READY_UNKNOWN, REASON_NOT_READY_UNOBSERVED,
  type TunnelStatus, type WatchTimers
} from '../src/lib/tunnelwatch.ts';

const here = dirname(fileURLToPath(import.meta.url));
const src = (rel: string) => readFileSync(join(here, '..', rel), 'utf8');

/**
 * 去掉注释后的源码——**否定式守卫必须用它**。
 * 本仓的注释习惯是把「改造前是什么形态」原文抄进注释里（那是它最有价值的部分），
 * 于是「源码里不许再出现 X」这类断言会被自己要保护的那段注释绊倒，
 * 结果只有两条出路：删掉注释，或把守卫写松。两条都是坏的。
 */
function codeOnly(s: string): string {
  return s
    .replace(/<!--[\s\S]*?-->/g, '')      // HTML/模板注释
    .replace(/\/\*[\s\S]*?\*\//g, '')     // 块注释
    .split('\n').filter((l) => !/^\s*(\/\/|\*)/.test(l)).join('\n'); // 整行的行注释
}

test('judge：不可判定与活着都不算中断', () => {
  assert.deepEqual(judgeTunnelStatus(null), { dropped: false });
  assert.deepEqual(judgeTunnelStatus(undefined), { dropped: false });
  assert.deepEqual(judgeTunnelStatus({ stage: 'up' }), { dropped: false });
  assert.deepEqual(judgeTunnelStatus({ stage: 'starting' }), { dropped: false });
  // 未知阶段不猜：误判成断开会触发 stopTunnel，把一条好隧道真的断掉
  assert.deepEqual(judgeTunnelStatus({ stage: 'whatever' }), { dropped: false });
});

test('judge：failed 原样带出原生的原因，缺失时不编造成因', () => {
  assert.deepEqual(judgeTunnelStatus({ stage: 'failed', reason: 'VPN 被系统或其它应用撤销' }),
    { dropped: true, reason: 'VPN 被系统或其它应用撤销' });
  assert.deepEqual(judgeTunnelStatus({ stage: 'failed' }), { dropped: true, reason: REASON_FAILED_UNKNOWN });
  assert.deepEqual(judgeTunnelStatus({ stage: 'failed', reason: '   ' }), { dropped: true, reason: REASON_FAILED_UNKNOWN });
});

test('judge：接入中原生回 idle 也是中断（服务被销毁却没留下失败原因）', () => {
  assert.deepEqual(judgeTunnelStatus({ stage: 'idle' }), { dropped: true, reason: REASON_WENT_IDLE });
});

// ── 新中间态 {stage:'up', ready:false}：引擎在跑、门没敲开 ──────────────────────
// 2026-09-03 安卓真机（OPPO PKU110 / Android 16）实测形态。
// ★上面那条 `{stage:'whatever'} → dropped:false` 会让这个新态**免费通过**（走 default 分支），
//   所以必须单立用例把 stage 与 ready 两条判定分别钉住，否则日后有人把新态并进
//   failed/idle 分支时，既有用例一条都不会红。
test('judge：未就绪不是中断——引擎在跑、门没敲开时绝不能去 stopTunnel', () => {
  const s: TunnelStatus = {
    stage: 'up', ready: false, healthObserved: true, healthKnock: false, healthTunnel: false,
    healthKnockErr: '取敲门令牌失败：Post "https://…/knock-token": x509: certificate signed by unknown authority',
    healthTunnelErr: '',
    healthErr: '取敲门令牌失败：Post "https://…/knock-token": x509: certificate signed by unknown authority'
  };
  // ① 不误伤：敲门每 15s 自动重试，判成中断的唯一后果是把一条可自愈的隧道真的断掉
  assert.deepEqual(judgeTunnelStatus(s), { dropped: false });
  // ② 但它确实没就绪
  assert.equal(judgeReady(s), false);
  // ③ 原因读得出，且是数据面原文——「x509: …」指得动管理员去装 CA，自编的「网络异常」不行
  assert.match(notReadyReason(s), /x509: certificate signed by unknown authority/);
});

test('judgeReady：ready 键缺席 = 不可判定（null），不是 false，更不回落成 stage==="up"', () => {
  // 旧安卓包 / iOS / 鸿蒙壳 / dev 浏览器都不报这组键
  assert.equal(judgeReady({ stage: 'up' }), null);
  assert.equal(judgeReady({ stage: 'starting' }), null);
  assert.equal(judgeReady(null), null);
  assert.equal(judgeReady(undefined), null);
  // 回落成 stage==='up' 的话，一个读不到健康态的壳会被报成"已就绪"——正是本波要消灭的断言
  assert.notEqual(judgeReady({ stage: 'up' }), true);
  // 类型不对也算不可判定（桥送来的是 JSON.parse 的结果，字段类型不受 TS 保护）
  assert.equal(judgeReady({ stage: 'up', ready: 'true' } as unknown as TunnelStatus), null);
  assert.equal(judgeReady({ stage: 'up', ready: true }), true);
});

test('notReadyReason：优先健康行原文；没有原文时区分「还没读到」与「读到了但没写原因」', () => {
  assert.equal(notReadyReason({ stage: 'up', ready: false, healthObserved: true, healthErr: '  边界空白要去掉  ' }),
    '边界空白要去掉');
  // err 为空但 knockErr 有内容（Go 侧 wave10 起把失败按 knock/tunnel 分记）
  assert.equal(notReadyReason({ stage: 'up', ready: false, healthObserved: true, healthKnockErr: '403 设备未授信' }),
    '403 设备未授信');
  // 引擎刚起、健康行还没写出来：与"读到了健康行、里面没写错误"是两件事，下一步动作不同
  assert.equal(notReadyReason({ stage: 'up', ready: false, healthObserved: false }), REASON_NOT_READY_UNOBSERVED);
  assert.equal(notReadyReason({ stage: 'up', ready: false, healthObserved: true }), REASON_NOT_READY_UNKNOWN);
});

/** 手动驱动的假时钟：fire() 触发一次 tick。 */
function fakeTimers() {
  let fn: (() => void) | null = null;
  let cleared = 0;
  const timers: WatchTimers = {
    setInterval: (f, _ms) => { fn = f; return 1; },
    clearInterval: () => { cleared++; fn = null; }
  };
  return { timers, fire: () => { fn?.(); }, get cleared() { return cleared; }, get scheduled() { return fn !== null; } };
}

test('watch：up 多轮不回调；翻成 failed 那一轮回调一次并自停', () => {
  const t = fakeTimers();
  const seq: TunnelStatus[] = [{ stage: 'up' }, { stage: 'up' }, { stage: 'failed', reason: 'VPN 被系统或其它应用撤销' }, { stage: 'failed', reason: '不该再读到' }];
  let i = 0;
  const drops: string[] = [];
  const w = createTunnelWatch(() => seq[Math.min(i++, seq.length - 1)], { onDrop: (r) => drops.push(r) }, 2000, t.timers);
  t.fire(); t.fire();
  assert.deepEqual(drops, [] as string[]);
  assert.equal(w.active, true);
  t.fire();
  assert.deepEqual(drops, ['VPN 被系统或其它应用撤销']);
  assert.equal(w.active, false);
  assert.equal(t.cleared, 1);
  // 已自停：即便有人再触发一次 tick，也不再回调
  t.fire();
  assert.deepEqual(drops, ['VPN 被系统或其它应用撤销']);
});

test('watch：读不到状态（无桥 / 桥抛异常）永远不判中断', () => {
  const t = fakeTimers();
  const drops: string[] = [];
  const w = createTunnelWatch(() => null, { onDrop: (r) => drops.push(r) }, 2000, t.timers);
  t.fire(); t.fire(); t.fire();
  assert.deepEqual(drops, [] as string[]);
  assert.equal(w.active, true);
  w.stop();
  const t2 = fakeTimers();
  createTunnelWatch(() => { throw new Error('bridge gone'); }, { onDrop: (r) => drops.push(r) }, 2000, t2.timers);
  t2.fire();
  assert.deepEqual(drops, [] as string[]);
});

test('watch：onReady 每轮回报且**双向翻转**，onDrop 仍是一次性', () => {
  const t = fakeTimers();
  const seq: TunnelStatus[] = [
    { stage: 'up', ready: false, healthObserved: true, healthKnock: false, healthErr: '取敲门令牌失败：x509 …' },
    { stage: 'up', ready: true, healthObserved: true, healthKnock: true },      // 敲门重试成功，自愈
    { stage: 'up', ready: false, healthObserved: true, healthKnock: false, healthErr: '控制面不可达' }, // 又坏了
    { stage: 'up' },                                                            // 健康态忽然读不到
    { stage: 'failed', reason: '被其它 VPN 抢占' }
  ];
  let i = 0;
  const readys: (boolean | null)[] = [];
  const reasons: string[] = [];
  const drops: string[] = [];
  const w = createTunnelWatch(
    () => seq[Math.min(i++, seq.length - 1)],
    { onDrop: (r) => drops.push(r), onReady: (v, s) => { readys.push(v); reasons.push(v === false ? notReadyReason(s) : ''); } },
    2000, t.timers
  );
  t.fire(); t.fire(); t.fire(); t.fire();
  // 一次性语义会让自愈之后 UI 永远停在「未就绪」——必须是 false→true→false 都报到
  assert.deepEqual(readys, [false, true, false, null]);
  assert.match(reasons[0], /x509/);
  assert.equal(reasons[2], '控制面不可达');
  assert.equal(w.active, true, '未就绪不是终态：监视器要留在原地等它自愈');
  assert.deepEqual(drops, [] as string[]);
  // 真断了才自停，且这一轮只报中断不再报就绪（免得 UI 同时挂两条互相矛盾的横幅）
  t.fire();
  assert.deepEqual(drops, ['被其它 VPN 抢占']);
  assert.equal(readys.length, 4, '判成中断的那一轮不该再回报就绪');
  assert.equal(w.active, false);
  t.fire();
  assert.deepEqual(drops, ['被其它 VPN 抢占'], 'onDrop 仍是一次性');
});

test('watch：不传 onReady 也不炸（旧调用方只关心中断）', () => {
  const t = fakeTimers();
  const w = createTunnelWatch(() => ({ stage: 'up', ready: false, healthObserved: true }),
    { onDrop: () => { throw new Error('不该回调'); } }, 2000, t.timers);
  t.fire(); t.fire();
  assert.equal(w.active, true);
  w.stop();
});

test('watch：stop() 清掉定时器，且幂等', () => {
  const t = fakeTimers();
  const w = createTunnelWatch(() => ({ stage: 'up' }), { onDrop: () => { throw new Error('不该回调'); } }, 2000, t.timers);
  assert.equal(t.scheduled, true);
  w.stop(); w.stop();
  assert.equal(t.cleared, 1);
  assert.equal(w.active, false);
  t.fire(); // 已清：假时钟里 fn 为 null，不会再 tick
});

// ────────────────────────────────────────────────────────────────────────────
// 接线：对 vpn.ts 做**真行为测试**（假桥 + 假计时器），不是对源码做子串匹配。
//
// ★改造前这一段只有几条 `assert.match(源码, /startTunnelWatch\(\);/)`：只查子串在不在，
//   不查条件也不查顺序。复核者做的两个破坏语义的变异——把 `if (r.ok) startTunnelWatch()`
//   改成无条件启动、把 `stopTunnel` 里的 `stopTunnelWatch()` 挪到 `await` 之后——**全绿**。
//   现在用假桥真跑：node 里没有 window/localStorage，先把这两样补上再 import vpn.ts
//   （相对导入的扩展名补全见 tests/ts-resolve.mjs）。
// ────────────────────────────────────────────────────────────────────────────
const g = globalThis as unknown as Record<string, unknown>;
g.localStorage = { getItem: () => null, setItem: () => { }, removeItem: () => { } };
g.window = globalThis;

const vpn = await import('../src/lib/vpn.ts');
const { session } = await import('../src/lib/store.ts');

/** 装一座假原生桥（只实现本条用例要用到的方法）。 */
function installBridge(b: Record<string, unknown>): void { g.__BAIDI_NATIVE__ = b; }

/**
 * 截获 vpn.ts 生产路径上的 setInterval/clearInterval（startTunnelWatch 用的是真计时器）。
 * created 计数回答「到底有没有开始监视」，fire() 手动推一轮。
 */
function captureIntervals() {
  const realSet = globalThis.setInterval, realClear = globalThis.clearInterval;
  let fn: (() => void) | null = null, created = 0, cleared = 0;
  (globalThis as unknown as Record<string, unknown>).setInterval = (f: () => void) => { fn = f; created++; return 77; };
  (globalThis as unknown as Record<string, unknown>).clearInterval = () => { cleared++; fn = null; };
  return {
    get created() { return created; },
    get cleared() { return cleared; },
    fire: () => { fn?.(); },
    restore: () => {
      (globalThis as unknown as Record<string, unknown>).setInterval = realSet;
      (globalThis as unknown as Record<string, unknown>).clearInterval = realClear;
    }
  };
}

test('接线：startTunnel 失败**不**启动监视', async () => {
  const t = captureIntervals();
  try {
    installBridge({
      startTunnel: async () => ({ ok: false, detail: '用户拒绝了 VPN 授权（系统对话框未允许）' }),
      tunnelStatus: () => ({ stage: 'failed', reason: '用户拒绝了 VPN 授权（系统对话框未允许）' })
    });
    const r = await vpn.startTunnel('tok');
    assert.equal(r.ok, false);
    // 无条件启动监视的话，下一轮 tick 就会把这次"根本没建起来"判成一次「接入已中断」并弹窗
    assert.equal(t.created, 0, 'startTunnel 失败时不该开始监视');
  } finally { t.restore(); vpn.stopTunnelWatch(); }
});

test('接线：startTunnel 成功即启动监视；原生翻 failed 那一轮翻回未接入 + 写原因 + 清原生残留', async () => {
  const t = captureIntervals();
  try {
    let stage = 'up', reason = '';
    let stopped = 0;
    installBridge({
      startTunnel: async () => ({ ok: true }),
      stopTunnel: async () => { stopped++; },
      tunnelStatus: () => ({ stage, reason })
    });
    session.connected = true;
    session.dropReason = '上一段接入的旧原因';
    const r = await vpn.startTunnel('tok');
    assert.equal(r.ok, true);
    assert.equal(t.created, 1, 'startTunnel 成功后必须开始监视');
    assert.equal(session.dropReason, '', '新一段接入必须清掉上一段的中断原因');
    t.fire();
    assert.equal(session.connected, true, 'up 不该被判成中断');
    stage = 'failed'; reason = 'VPN 被系统或其它应用撤销';
    t.fire();
    assert.equal(session.connected, false);
    assert.equal(session.dropReason, 'VPN 被系统或其它应用撤销');
    assert.equal(stopped, 1, '判成中断后要把原生侧那个引擎已死的服务清掉');
  } finally { t.restore(); vpn.stopTunnelWatch(); }
});

/** 真机形态：引擎起来了（stage=up），门没敲开（knock=false + x509）。 */
const UNREADY: TunnelStatus = {
  stage: 'up', ready: false, healthObserved: true, healthKnock: false, healthTunnel: false,
  healthKnockErr: '取敲门令牌失败：x509: certificate signed by unknown authority',
  healthTunnelErr: '',
  healthErr: '取敲门令牌失败：x509: certificate signed by unknown authority'
};

test('接线：startTunnel 回 ok:false 但**引擎真在跑** → 照样监视、写 notReady、绝不 stopTunnel', async () => {
  const t = captureIntervals();
  try {
    let stopped = 0;
    let st: TunnelStatus = UNREADY;
    installBridge({
      startTunnel: async () => ({ ok: false, detail: '数据面未就绪：取敲门令牌失败：x509: certificate signed by unknown authority' }),
      stopTunnel: async () => { stopped++; },
      tunnelStatus: () => st
    });
    session.connected = false; session.notReady = ''; session.dropReason = '';
    const r = await vpn.startTunnel('tok');
    assert.equal(r.ok, false);
    // ① 不监视的话就留下一条**无人看管**、仍以当前账号每 15s 保活续窗的孤儿 VPN
    assert.equal(t.created, 1, '引擎在跑就必须被监视，哪怕这次接入没成功');
    // ② 敲门每 15s 自动重试，随时可能自愈——主动断开等于把可自愈的隧道亲手掐死
    assert.equal(stopped, 0, '未就绪绝不能主动 stopTunnel');
    // ③ 原因写进 notReady（不是 dropReason：这次接入从来没建立过，说「已中断」是错的）
    assert.match(session.notReady, /x509: certificate signed by unknown authority/);
    assert.equal(session.dropReason, '', '未就绪不写 dropReason —— App.vue 会照它弹「接入已中断」');

    // ④ 自愈：敲门重试成功 → 下一轮把接入态翻成已接入并清掉原因
    st = { stage: 'up', ready: true, healthObserved: true, healthKnock: true, healthTunnel: false };
    t.fire();
    assert.equal(session.connected, true, 'ready 翻真必须能把 UI 翻成已接入（否则自愈了也看不见）');
    assert.equal(session.notReady, '');
    // ⑤ 再坏回去：双向翻转
    st = { ...UNREADY, healthErr: '控制面不可达', healthKnockErr: '控制面不可达' };
    t.fire();
    assert.equal(session.connected, false);
    assert.equal(session.notReady, '控制面不可达');
  } finally { t.restore(); vpn.stopTunnelWatch(); session.notReady = ''; }
});

test('接线：健康态不可判定（旧壳 / iOS / 鸿蒙）时一个字段都不动', async () => {
  const t = captureIntervals();
  try {
    installBridge({
      startTunnel: async () => ({ ok: true }),
      stopTunnel: async () => { },
      tunnelStatus: () => ({ stage: 'up' })   // 不报 ready / health*
    });
    await vpn.startTunnel('tok');
    session.connected = true; session.notReady = '';
    t.fire(); t.fire();
    // 翻成 false 会让这几端在毫无依据的情况下集体显示「未就绪」；翻成 true 则是替
    // 一份根本没读到的健康行背书。不可判定就保持调用方原来的判断。
    assert.equal(session.connected, true);
    assert.equal(session.notReady, '');
  } finally { t.restore(); vpn.stopTunnelWatch(); }
});

test('接线：startTunnel 失败且引擎**没在跑**（用户拒授权）→ 不监视、不写 notReady', async () => {
  const t = captureIntervals();
  try {
    installBridge({
      startTunnel: async () => ({ ok: false, detail: '用户拒绝了 VPN 授权（系统对话框未允许）' }),
      tunnelStatus: () => ({ stage: 'idle' })
    });
    session.notReady = '';
    const r = await vpn.startTunnel('tok');
    assert.equal(r.ok, false);
    assert.equal(t.created, 0, 'idle 就是真失败：没有任何东西在跑，监视谁？');
    assert.equal(session.notReady, '', '「未就绪」说的是引擎在跑，这里引擎压根没起来');
  } finally { t.restore(); vpn.stopTunnelWatch(); }
});

test('接线：stopTunnel 先停监视——主动断开途中原生回 idle 不该被记成一次「中断」', async () => {
  const t = captureIntervals();
  try {
    let stage = 'up';
    installBridge({
      startTunnel: async () => ({ ok: true }),
      // 原生断开是要花时间的：这期间运行态已翻回 idle。若 stopTunnelWatch() 被挪到 await 之后，
      // 此刻监视还活着 → 判成中断 → App.vue 给用户弹一条「接入已中断」，而断开正是他自己点的。
      stopTunnel: async () => { stage = 'idle'; t.fire(); },
      tunnelStatus: () => ({ stage })
    });
    await vpn.startTunnel('tok');
    session.dropReason = '';
    await vpn.stopTunnel();
    assert.equal(session.dropReason, '', '用户主动断开不是中断，不该写 dropReason');
  } finally { t.restore(); vpn.stopTunnelWatch(); }
});

test('挂载认领：up 认领并开始监视 / failed 写原因 / 读不到与 idle 一律不动', () => {
  // ① up：webview 重载后原生仍在跑——认领回「已接入」，并且必须同时开始监视
  let t = captureIntervals();
  try {
    installBridge({ tunnelStatus: () => ({ stage: 'up' }) });
    session.connected = false; session.dropReason = '';
    vpn.adoptRunningTunnel();
    assert.equal(session.connected, true);
    assert.equal(t.created, 1, '认领了却不监视 = 此后被抢占依然看不见，洞只补了一半');
  } finally { t.restore(); vpn.stopTunnelWatch(); }

  // ② failed：上一段接入不是用户断的，原因还留在原生侧——写出来给用户看
  t = captureIntervals();
  try {
    installBridge({ tunnelStatus: () => ({ stage: 'failed', reason: '引擎因终端合规阻断停机' }) });
    session.connected = false; session.dropReason = '';
    vpn.adoptRunningTunnel();
    assert.equal(session.dropReason, '引擎因终端合规阻断停机');
    assert.equal(session.connected, false, 'failed 不是「已接入」');
    assert.equal(t.created, 0, '没在跑就没什么可监视的');
  } finally { t.restore(); vpn.stopTunnelWatch(); }

  // ③ 读不到（桥抛错 / 状态不是合法 JSON）：不可判定，一个字段都不许动
  t = captureIntervals();
  try {
    installBridge({ tunnelStatus: () => { throw new Error('bridge gone'); } });
    session.connected = false; session.dropReason = '守卫：这行不该被动过'; session.notReady = '守卫：这行也不该被动过';
    vpn.adoptRunningTunnel();
    assert.equal(session.connected, false);
    assert.equal(session.dropReason, '守卫：这行不该被动过');
    assert.equal(session.notReady, '守卫：这行也不该被动过');
    assert.equal(t.created, 0);
  } finally { t.restore(); vpn.stopTunnelWatch(); session.notReady = ''; }

  // ④ idle：本就没在接入（也不是"中断"——用户可能上次就是自己断的）
  t = captureIntervals();
  try {
    installBridge({ tunnelStatus: () => ({ stage: 'idle' }) });
    session.connected = false; session.dropReason = '';
    vpn.adoptRunningTunnel();
    assert.equal(session.connected, false);
    assert.equal(session.dropReason, '');
    assert.equal(t.created, 0);
  } finally { t.restore(); vpn.stopTunnelWatch(); }

  // ⑤ up 但 ready 判假：webview 重建时数据面正卡在「引擎在跑、门没敲开」——
  //    照样认领并监视（不监视就没人看见它自愈，也没人看见它被抢占），但接入态是未就绪。
  t = captureIntervals();
  try {
    installBridge({ tunnelStatus: () => UNREADY });
    session.connected = true; session.dropReason = ''; session.notReady = '';
    vpn.adoptRunningTunnel();
    assert.equal(session.connected, false, '门没敲开就不是「已接入」——真机上这里此前显示已接入');
    assert.match(session.notReady, /x509/);
    assert.equal(t.created, 1, '未就绪的隧道同样要被监视：它可能自愈，也可能被抢占');
  } finally { t.restore(); vpn.stopTunnelWatch(); session.notReady = ''; }

  delete g.__BAIDI_NATIVE__;
});

// ────────────────────────────────────────────────────────────────────────────
// 安卓桥（MainActivity.kt 里那段 BRIDGE_JS）：把 Kotlin 常量里的 JS **原文抠出来真跑**。
// 它是 webview 与原生之间的唯一接缝，却因为嵌在 .kt 里而长期没有任何执行方——
// 「读不到状态被塌缩成 failed」这条就是在那里面。常量里没有 Kotlin 插值，抠出来即可执行。
// ────────────────────────────────────────────────────────────────────────────
interface BridgeApi {
  tunnelStatus: () => { stage: string; reason?: string } | null;
  startTunnel: (token: string, cfg: unknown) => Promise<{ ok: boolean; detail?: string }>;
}

/** 在 vm 沙箱里装起桥，并接管它的时钟与 setTimeout（轮询要能一步一步走）。 */
function bridgeSandbox(rawStatus: () => string) {
  const kt = src('native/android/app/src/main/java/dev/baidi/mobile/MainActivity.kt');
  const m = kt.match(/private const val BRIDGE_JS = """([\s\S]*?)"""/);
  assert.ok(m, 'MainActivity.kt 里找不到 BRIDGE_JS 常量（改了名就要同步改这里）');
  const js = m![1];
  assert.ok(!/stage:\s*'failed'/.test(js),
    "BRIDGE_JS 不得合成 stage:'failed'——那是把「读不到」塌缩成「确定失败」，" +
    'vpn.ts 的监视会据此把一条好隧道真的断掉');

  let now = 0;
  let pending: (() => void) | null = null;
  const sandbox: Record<string, unknown> = {
    __baidiNativeRaw: {
      apiBase: () => 'http://127.0.0.1:8090',
      tunnelStatus: rawStatus,
      startTunnel: () => { /* @JavascriptInterface 返回 Unit，JS 侧拿不到结果 */ },
      stopTunnel: () => { }
    },
    JSON, Promise,
    Date: { now: () => now },
    setTimeout: (fn: () => void) => { pending = fn; return 1; }
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(js, sandbox);
  return {
    bridge: sandbox.__BAIDI_NATIVE__ as BridgeApi,
    advance: (ms: number) => { now += ms; },
    /** 推进一轮轮询（相当于 400ms 的 setTimeout 到点）。 */
    step: () => { const f = pending; pending = null; f?.(); },
    get waiting() { return pending !== null; }
  };
}

test('安卓桥：状态解析不出来 → tunnelStatus() 回 null（不可判定），不是「已失败」', () => {
  const s = bridgeSandbox(() => '这不是 JSON');
  assert.equal(s.bridge.tunnelStatus(), null);
});

test('安卓桥：启动期读不到状态要**继续等**，随后 up 照常成功', async () => {
  let raw = '这不是 JSON';
  const s = bridgeSandbox(() => raw);
  const p = s.bridge.startTunnel('tok', {});
  assert.equal(s.waiting, true, '第一轮读不到就判失败的话，一次正常接入会在用户点「允许」之前被判死');
  s.advance(400); s.step();
  assert.equal(s.waiting, true);
  raw = '{"stage":"up","reason":""}';
  s.advance(400); s.step();
  // 逐字段断言而不是 deepEqual：回执对象是在 vm 上下文里造的，原型不同源
  const r = await p;
  assert.equal(r.ok, true);
  assert.equal(r.detail, '数据面已就绪');
});

test('安卓桥：原生给出 failed 时原样带出它的原因', async () => {
  const s = bridgeSandbox(() => '{"stage":"failed","reason":"用户拒绝了 VPN 授权（系统对话框未允许）"}');
  const r = await s.bridge.startTunnel('tok', {});
  assert.equal(r.ok, false);
  assert.equal(r.detail, '用户拒绝了 VPN 授权（系统对话框未允许）');
});

test('安卓桥：超时只报观测到的事实，不猜成因', async () => {
  // ① 一路读不到
  let s = bridgeSandbox(() => '这不是 JSON');
  let p = s.bridge.startTunnel('tok', {});
  s.advance(30001); s.step();
  let r = await p;
  assert.equal(r.ok, false);
  assert.match(r.detail!, /读不到原生运行态/);
  assert.ok(!/VPN 权限/.test(r.detail!), '成因由 onActivityResult 当场写进 failed，这里不许猜');
  // ② 读得到但一直停在 starting：说出最后读到的阶段
  s = bridgeSandbox(() => '{"stage":"starting","reason":""}');
  p = s.bridge.startTunnel('tok', {});
  s.advance(30001); s.step();
  r = await p;
  assert.equal(r.ok, false);
  assert.match(r.detail!, /最后读到的阶段：starting/);
});

// 源码级守卫：.vue 单文件组件在 node 里跑不起来，只能钉源码。
// 与 console/scripts/check-dead-ui.mjs 同一思路（删一处即红）。
test('源码守卫：Connect/App 渲染中断原因，App 挂载时认领在跑的隧道', () => {
  const connect = src('src/views/Connect.vue');
  assert.match(connect, /session\.dropReason/, 'Connect.vue 必须显示 session.dropReason');
  // wave10 起大环有四态，映射的输入也从一个信号变成两个（connected 决定 connected/idle，
  // notReady 决定 unready），故这条守卫跟着从单 watch 改成数组 watch。
  assert.match(connect, /watch\(\[\(\) => session\.connected, \(\) => session\.notReady\]/,
    'Connect.vue 必须同时监听 session.connected 与 session.notReady（前者翻回 idle，后者翻成 unready）');
  const app = src('src/App.vue');
  assert.match(app, /session\.dropReason/, 'App.vue 必须在任意页面上弹出中断原因（Connect 页未挂载时也要看得见）');
  assert.match(app, /onMounted\(\s*\(\)\s*=>\s*\{\s*adoptRunningTunnel\(\);/,
    'App.vue 必须在挂载时认领原生仍在跑的隧道（webview 重载 / Activity 重建后 session.connected 从 false 起算）');
});

test('源码守卫：Connect.vue 不再写死「已开放行窗口」，未就绪原因常驻可见', () => {
  const connect = src('src/views/Connect.vue');
  // ★真机上 knock=false，而这一行此前是 `<b class="ok">已完成 · 已开放行窗口</b>`——
  //   一句与健康行完全相反的断言，判据改对了它照样撒谎，所以必须一起摘掉。
  assert.ok(!/class="ok">\s*已完成 · 已开放行窗口/.test(codeOnly(connect)),
    'Connect.vue 不得写死「已完成 · 已开放行窗口」，必须按 healthKnock / healthErr 现算三态');
  assert.match(connect, /knockView/, 'SPA 敲门那一行必须由三态判定驱动');
  assert.match(connect, /healthObserved/, '三态必须先判「有没有读到健康行」再判真假');
  assert.match(connect, /session\.notReady/, 'Connect.vue 必须常驻显示未就绪原因（弹窗一闪而过不算「看见」）');
  assert.match(connect, /'unready'/, '大环必须有第四态');
  assert.match(connect, /stage\.value === 'connected' \|\| stage\.value === 'unready'\) return disconnect/,
    '未就绪态必须能断开，否则大环成死键（VPN 已下发、仍以当前账号保活）');
});

test('源码守卫：Profile.vue 登出守卫读原生运行态，不读 session.connected', () => {
  const pf = src('src/views/Profile.vue');
  assert.ok(!/if \(session\.connected\) \{/.test(codeOnly(pf)),
    '登出守卫不得读 session.connected：wave10 后它表达的是「门敲开没有」，'
    + '未就绪态下为 false → 跳过 stopTunnel → 留下一条仍以上一个账号每 15s 保活续窗的 VpnService');
  assert.match(pf, /function dataplaneRunning\(\)/, '登出守卫必须现算数据面运行态');
  assert.match(pf, /if \(dataplaneRunning\(\)\)/, '登出必须走那道守卫');
  assert.match(pf, /healthKnock/, '链路诊断必须如实列出 knock/tunnel/err');
  assert.match(pf, /'na'/, '诊断项必须三态（探不到 ≠ 失败 ≠ 通过）');
});

test('源码守卫：连通性探测不再打 /healthz（nginx 会把它回退成 200 的 SPA HTML）', () => {
  const apiSrc = src('src/lib/api.ts');
  assert.ok(!/origin\(\) \+ '\/healthz'/.test(codeOnly(apiSrc)),
    'ping 不得打 /healthz：它长期不是一条真实的反代通路，请求落进 `location /` 的 SPA 回退 '
    + '→ 恒回 200 HTML → 控制面整个停掉，「我的」页照样显示「连通」。'
    + '客户端装在别人的网里，前面那台 nginx 改没改我们既看不见也管不着');
  assert.match(codeOnly(apiSrc), /new AbortController\(\)/,
    '探测必须自带超时：location /api/ 的 proxy_read_timeout 是 3600s，'
    + '控制面卡死时界面会永远停在「检测中…」——那和假阳性一样看不出区别');
  assert.match(apiSrc, /PING_PATH = '\/api\/v1\/auth\/domains'/, '要打一条真实的免认证 API');
  // ★这条必须对 codeOnly 断言：上面那段注释里就写着 content-type，对原文匹配等于自己给自己盖章
  //（第一版正是这么写的，把「只看 res.ok」这个变异放了过去）。
  assert.match(codeOnly(apiSrc), /headers\.get\('content-type'\)/,
    'res.ok 挡不住 SPA 回退那张 200 HTML，必须核对 content-type 是 JSON');
});

/* ────────────────────────────────────────────────────────────────────────────
 * 桥的 ready 三分支（wave10）——**这三条是本波投入最大的那条判据的唯一执行方**。
 *
 * ★为什么必须补：复核期间做过一次变异，把 MainActivity.kt 里
 *   `if (s.ready === undefined && s.stage === 'up')` 改成 `if (!s.ready && s.stage === 'up')`
 *   ——这是这段代码最容易犯、注释里也点名警告过的那个错——`npm test` 26/26 与安卓 JVM 20/20
 *   **全绿**。而那一改精确复原了本波要修的 bug：真机形态 {stage:'up', ready:false, x509} 下
 *   `!s.ready` 为真 → 桥 resolve {ok:true,'数据面已就绪'} → Connect.vue 弹「已接入企业内网」，
 *   门根本没敲开。桥这段逻辑一年内已经被改坏过一次（600ms 无条件 resolve），
 *   在补这三条之前它的守卫强度和那时一样是零。
 *
 * 喂进去的 JSON 是安卓 TunnelState.snapshot() 的真实产出形态（扁平九键）。
 * ────────────────────────────────────────────────────────────────────────── */

test('安卓桥：ready=true 才算接入成功', async () => {
  const s = bridgeSandbox(() => '{"stage":"up","reason":"","ready":true,' +
    '"healthObserved":true,"healthKnock":true,"healthTunnel":false,' +
    '"healthKnockErr":"","healthTunnelErr":"","healthErr":""}');
  const r = await s.bridge.startTunnel('tok', {});
  assert.equal(r.ok, true);
  assert.equal(r.detail, '数据面已就绪');
});

test('安卓桥：ready=false（引擎在跑、门没敲开）绝不算成功，且超时那句要带出 x509 原文', async () => {
  const x509 = '取敲门令牌失败：本机不信任控制中心的 HTTPS 证书';
  const s = bridgeSandbox(() => '{"stage":"up","reason":"","ready":false,' +
    '"healthObserved":true,"healthKnock":false,"healthTunnel":false,' +
    `"healthKnockErr":${JSON.stringify(x509)},"healthTunnelErr":"",` +
    `"healthErr":${JSON.stringify(x509)}}`);
  const p = s.bridge.startTunnel('tok', {});
  // 连喂 30s：每一轮都必须继续等，一次都不能 resolve 成功
  for (let t = 0; t < 30000; t += 400) {
    assert.equal(s.waiting, true, `t=${t}ms 时桥不该收摊——ready=false 是可自愈态，敲门每 15s 重试`);
    s.advance(400); s.step();
  }
  s.advance(30001); s.step();
  const r = await p;
  assert.equal(r.ok, false, '真机 2026-09-03 的形态：stage=up 但 knock=false，判成功就是本波要消灭的那个 bug');
  assert.ok(String(r.detail).includes(x509),
    '超时那句必须带出原生**已知**的原因——带出已知原因 ≠ 猜一个成因。' +
    '不带的话这句 x509 就只活在 logcat 里，界面上永远看不到。得到：' + r.detail);
});

test('安卓桥：ready 键缺席（旧壳 / 旧 .aar）逐字回落到旧判据，行为不变', async () => {
  const s = bridgeSandbox(() => '{"stage":"up","reason":""}');
  const r = await s.bridge.startTunnel('tok', {});
  assert.equal(r.ok, true, '缺席 = 不可判定，此处**必须**回落成旧判据；' +
    '塌成 false 会让任何一版拿不到健康行的壳都停在「接入中」直到 30s 超时');
});

/* ────────────────────────────────────────────────────────────────────────────
 * 跨轨契约守卫：安卓壳**写端**的键名 ⇄ webview **读端**的字段名。
 *
 * ★为什么必须有：这九个键是三种语言之间唯一的接头，而每一轨的测试都只断言自己那一侧——
 *   Kotlin 单测断言 Kotlin 自己写的键名，TS 单测断言 TS 自己手写的字面量。复核期间实测过
 *   两次变异，每次都在**一条轨道内部改得自洽**（源码 + 该轨自己的测试同步改），另一轨零感知：
 *     ① "ready" → "isReady"：安卓 20/20 绿、TS 26/26 绿。运行期后果——TS 的 judgeReady 判成
 *        不可判定 → 桥落进「旧壳回落」分支 → resolve ok:true。**2026-09-03 真机上那个
 *        「引擎起来了、门没敲开、界面显示已接入」的形态原封不动地回来，没有一条测试变红。**
 *     ② "healthKnockErr" → "healthKnockError"：ready 仍判 false，但 notReadyReason 取不到原文，
 *        回落成一句通用文案——全链路上唯一那句能指导补救的 x509 原文从界面上消失。
 *   两种改法都不会被任何一轨自己的测试拦下，因为**没有人同时看两边**。这条就是那个人。
 *
 * 做法：从 TunnelState.kt 的 snapshot() 里抠出它 append 的字面量键名，与 tunnelwatch.ts 里
 * TunnelStatus 声明的字段名逐一对齐。两侧任何一边改名、加键、少键，这里立刻变红。
 * ────────────────────────────────────────────────────────────────────────── */
test('跨轨契约：安卓 snapshot() 发的键名 与 TS TunnelStatus 声明的字段名必须一一对上', () => {
  const kt = src('native/android/app/src/main/java/dev/baidi/mobile/TunnelState.kt');
  const body = kt.match(/fun snapshot\(\): String \{([\s\S]*?)\n    \}/);
  assert.ok(body, 'TunnelState.kt 里找不到 snapshot()（改了签名要同步改这里）');
  // 只取 sb.append 里的 "键": 形式，避开注释与普通字符串
  const emitted = new Set<string>();
  for (const m of body![1].matchAll(/"(\w+)"\s*:/g)) emitted.add(m[1]);

  const ts = readFileSync(new URL('../src/lib/tunnelwatch.ts', import.meta.url), 'utf8');
  const iface = ts.match(/export interface TunnelStatus \{([\s\S]*?)\n\}/);
  assert.ok(iface, 'tunnelwatch.ts 里找不到 TunnelStatus');
  // 去掉注释后取字段名（含可选 ?）
  const declared = new Set<string>();
  const cleaned = iface![1].replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const m of cleaned.matchAll(/^\s*(\w+)\??\s*:/gm)) declared.add(m[1]);

  const missingInTs = [...emitted].filter((k) => !declared.has(k));
  const missingInKt = [...declared].filter((k) => !emitted.has(k));
  assert.deepEqual(missingInTs, [],
    '安卓壳发了 webview 不认识的键（改名/加键只改了一侧）：' + missingInTs.join(', ') +
    '。后果不是少一条信息，而是读端静默回落——真机那个「显示已接入而门没敲开」的 bug 正是这么回来的');
  assert.deepEqual(missingInKt, [],
    'TS 声明了安卓壳不发的键：' + missingInKt.join(', ') +
    '。读端会永远拿到 undefined，而 undefined 在本契约里的语义是「不可判定」——' +
    '于是一条本该生效的判据变成永远不生效，且两侧都不报错');

  // 九键一个不少（防"两边一起删同一个键"这种自洽的退化）
  assert.equal(emitted.size, 9, '契约就是九个键（stage/reason/ready + 六个 health*），实得：' +
    [...emitted].sort().join(','));
});

test('源码守卫：路由必须有兜底，否则登录过的用户下次打开应用内容区是空的', () => {
  const r = src('src/router.ts');
  // 原生壳加载的是 https://appassets.local/index.html（MainActivity.loadUrl → WebViewAssetLoader），
  // vue-router 在 createWebHistory 下看到的路径就是 /index.html，五条真实路由一条都匹配不上。
  // 未登录时 beforeEach 会重定向去 /login 所以完全看不出来；登录过之后 authed() 为真 → 放行 →
  // 解析到一条不存在的路由 → <router-view> 渲染空。2026-09-03 OPPO PKU110 上实测：
  // location.pathname='/index.html'、body 只剩「接入/应用/我的」三个 tab。
  assert.match(r, /pathMatch\(\.\*\)\*/,
    'router.ts 缺少 catch-all 兜底路由。壳加载的是 /index.html，它匹配不到任何一条路由——' +
    '未登录时被 beforeEach 兜去 /login 看不出来，登录过之后就是一个只有底部导航的空白页');
  // 兜底必须排在最后：vue-router 按声明顺序匹配，放前面会吞掉所有真实路由
  const iCatch = r.indexOf('pathMatch');
  for (const p of ['/login', '/connect', '/apps', '/profile']) {
    assert.ok(r.indexOf(`'${p}'`) < iCatch,
      `catch-all 必须排在 ${p} 之后——vue-router 按声明顺序匹配，放前面会把真实路由全吞掉`);
  }
});

/* ────────────────────────────────────────────────────────────────────────────
 * 控制中心信任锚的**接线**守卫（wave10）。
 *
 * 材料只存在一处（res/raw/baidi_control_ca.pem，由 build.gradle.kts 从 -PbaidiControlCa 生成），
 * 却要同时喂给两条互不相干的链路：WebView 走 network_security_config，Go 数据面走
 * baidimobile.Config.controlCaPEM。**只接一半就会造出「网页登录得进去而隧道连不上」
 * （或反过来）——两边都不报错**，正是本仓反复批判的静默失效。这条用例把两半的接线钉住。
 *
 * 真机 A/B 已验（2026-09-03 OPPO PKU110 / 演示站 101.43.125.131 自签证书）：
 * 带锚的包 WebView 登录成功、数据面取到敲门令牌、业务流穿过隧道（healthTunnel=true、
 * 设备侧 nc 退出码 0）；同一套代码不带锚构建，同一次 fetch 在 TLS 那步失败。
 * ────────────────────────────────────────────────────────────────────────── */
test('接线守卫：控制中心信任锚必须同时接上 WebView（NSC）与数据面（controlCaPEM）', () => {
  const gradle = src('native/android/app/build.gradle.kts');
  const manifest = codeOnly(src('native/android/app/src/main/AndroidManifest.xml'));
  // ★必须剥注释：否则把接线整行注释掉、守卫照样绿（实测过，这是本文件里第二次踩同一个坑，
  //   第一次是 gateway 侧那条并集断言被自己的文档注释绊倒）。
  const svc = codeOnly(src('native/android/app/src/main/java/dev/baidi/mobile/BaidiVpnService.kt'));

  // ① 构建期从同一个入参生成两份产物
  assert.match(gradle, /baidiControlCa/, 'build.gradle.kts 缺少 -PbaidiControlCa 入参');
  assert.match(gradle, /network_security_config\.xml/, '构建期必须生成 NSC（WebView 那一半）');
  assert.match(gradle, /baidi_control_ca\.pem/, '构建期必须写出 res/raw 里的锚（数据面那一半的来源）');

  // ② WebView 那一半真的挂上了
  assert.match(manifest, /android:networkSecurityConfig="@xml\/network_security_config"/,
    'AndroidManifest 没有引用 NSC —— 生成了却没人用，WebView 那一半等于没做');

  // ③ 数据面那一半真的接上了
  assert.match(svc, /controlCaPEM\s*=/, 'BaidiVpnService 没把锚交给 baidimobile.Config.controlCaPEM');
  assert.match(svc, /readControlAnchor\(/, '锚必须经 readControlAnchor 读（它带指纹自证）');

  // ④ BuildConfig 里只放摘要、不放正文 —— 这是「两半同源」可执行的前提
  assert.match(gradle, /BAIDI_CONTROL_CA_SHA256/, 'BuildConfig 要带构建期摘要供运行期自证');
  assert.ok(!/buildConfigField\([^)]*BAIDI_CONTROL_CA_PEM/.test(gradle),
    'BuildConfig 里不许放 PEM 正文：只放摘要、运行期各自读 res/raw 再比对，' +
    '「NSC 用的那份」与「Go 用的那份」是否同源才是一件可执行的事，而不是靠约定');

  // ⑤ NSC 的域名从 apiBase 推，不另开入参（两个入参 = 两个真相来源，
  //    而它们不一致时的现场是「证书装了却不生效」）
  assert.ok(!/baidiControlHost|baidiNscDomain/.test(gradle),
    'NSC 的域名必须从 baidiApiBase 的 host 推，不许另开一个入参');
});

test('源码守卫：接入失败的原因必须常驻，不能只有一闪而过的 toast', () => {
  // ★方向此前是反的：「未就绪」（可自愈的中间态）有常驻卡片，而「接入被拒」
  //   （定性拒绝——强制下线 / 账号禁用 / 终端环境不合规，重试无用）反而只有 Message.error。
  //   2026-09-03 真机实测：li.fang 被终端合规闸拒，大环回到「未接入」、屏上什么都不剩。
  //   本页 dropReason 那条注释里早就写着「弹窗一闪而过不算「看见」」——那条纪律没覆盖到这一半。
  const code = codeOnly(src('src/views/Connect.vue'));
  assert.match(code, /lastFail/, 'Connect.vue 必须把接入失败的原因留在页面上（常驻卡片）');
  assert.match(code, /stage === 'idle' && lastFail/,
    '常驻卡片要在回到 idle 之后仍然显示——那正是用户盯着屏幕找原因的时刻');
  // 写入点：失败分支必须落库，不能只喂给 Message
  assert.match(code, /lastFail\.value\s*=\s*r\.detail/,
    '失败分支要把原生/控制面给的原文写进常驻卡片，且**原样转述不改写**');
  // 清除点：下一次接入开始时清掉，否则新一次接入的界面上挂着上一次的失败
  assert.match(code, /lastFail\.value\s*=\s*''/, '新一次接入开始时要清掉上一次的失败原因');
});
