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
  judgeTunnelStatus, createTunnelWatch, REASON_FAILED_UNKNOWN, REASON_WENT_IDLE,
  type TunnelStatus, type WatchTimers
} from '../src/lib/tunnelwatch.ts';

const here = dirname(fileURLToPath(import.meta.url));
const src = (rel: string) => readFileSync(join(here, '..', rel), 'utf8');

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
  const w = createTunnelWatch(() => seq[Math.min(i++, seq.length - 1)], (r) => drops.push(r), 2000, t.timers);
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
  const w = createTunnelWatch(() => null, (r) => drops.push(r), 2000, t.timers);
  t.fire(); t.fire(); t.fire();
  assert.deepEqual(drops, [] as string[]);
  assert.equal(w.active, true);
  w.stop();
  const t2 = fakeTimers();
  createTunnelWatch(() => { throw new Error('bridge gone'); }, (r) => drops.push(r), 2000, t2.timers);
  t2.fire();
  assert.deepEqual(drops, [] as string[]);
});

test('watch：stop() 清掉定时器，且幂等', () => {
  const t = fakeTimers();
  const w = createTunnelWatch(() => ({ stage: 'up' }), () => { throw new Error('不该回调'); }, 2000, t.timers);
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
    session.connected = false; session.dropReason = '守卫：这行不该被动过';
    vpn.adoptRunningTunnel();
    assert.equal(session.connected, false);
    assert.equal(session.dropReason, '守卫：这行不该被动过');
    assert.equal(t.created, 0);
  } finally { t.restore(); vpn.stopTunnelWatch(); }

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
  assert.match(connect, /watch\(\s*\(\)\s*=>\s*session\.connected/, 'Connect.vue 必须监听 session.connected 翻回 idle');
  const app = src('src/App.vue');
  assert.match(app, /session\.dropReason/, 'App.vue 必须在任意页面上弹出中断原因（Connect 页未挂载时也要看得见）');
  assert.match(app, /onMounted\(\s*\(\)\s*=>\s*\{\s*adoptRunningTunnel\(\);/,
    'App.vue 必须在挂载时认领原生仍在跑的隧道（webview 重载 / Activity 重建后 session.connected 从 false 起算）');
});
