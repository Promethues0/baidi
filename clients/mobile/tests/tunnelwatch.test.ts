// 隧道存活监视的单测：node --experimental-strip-types --test（无 Vue / 无 DOM，不装浏览器也能跑）。
// 守的是复核提出的那条：「onRevoke 留下的原因没有读者」——接入后必须有人轮询 tunnelStatus，
// 且判定口径不能把「不可判定」误判成「已断开」（后者会让 UI 去把一条好好的隧道真的断掉）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
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

// 接线守卫：纯逻辑对了、没人调它，用户看到的仍是「已接入」。这几条断言把接线钉在源码上，
// 与 console/scripts/check-dead-ui.mjs 同一思路（构建期守卫，删一处即红）。
test('接线：vpn.ts 在隧道就绪后启动监视、断开时停止；Connect.vue 渲染中断原因', () => {
  const vpn = src('src/lib/vpn.ts');
  /** 取某个顶层 export function 的函数体（到下一行顶格 `}` 为止）——只看定义在不在不够，要看调用点在哪个函数里。 */
  const body = (name: string) => {
    const m = vpn.match(new RegExp(`export (?:async )?function ${name}\\([^)]*\\)[^{]*\\{([\\s\\S]*?)\\n\\}`));
    assert.ok(m, `vpn.ts 缺 export function ${name}`);
    return m![1];
  };
  assert.match(vpn, /createTunnelWatch\(/, 'vpn.ts 必须用 createTunnelWatch 建监视');
  assert.match(body('startTunnel'), /startTunnelWatch\(\);/, 'startTunnel 成功分支必须启动监视');
  assert.match(body('stopTunnel'), /stopTunnelWatch\(\);/, 'stopTunnel 必须停止监视（用户主动断开不是中断）');
  assert.match(body('startTunnelWatch'), /session\.dropReason\s*=/, '中断原因必须写进 session.dropReason 供 UI 读');
  assert.match(body('startTunnelWatch'), /session\.connected\s*=\s*false/, '中断时必须把会话翻成未接入');
  const connect = src('src/views/Connect.vue');
  assert.match(connect, /session\.dropReason/, 'Connect.vue 必须显示 session.dropReason');
  assert.match(connect, /watch\(\s*\(\)\s*=>\s*session\.connected/, 'Connect.vue 必须监听 session.connected 翻回 idle');
  const app = src('src/App.vue');
  assert.match(app, /session\.dropReason/, 'App.vue 必须在任意页面上弹出中断原因（Connect 页未挂载时也要看得见）');
});
