/**
 * 侧栏角标的**真实计数**。
 *
 * ★背景：nav.ts 里那两个角标此前是写死的 '10' / '2'。写死的角标是最典型的假数据——
 * 它与真实计数在页面上完全同形，而且没人会去怀疑一个两位数。
 *
 * 三条纪律：
 *  1. 值只来自真实接口；
 *  2. 取不到（未登录 / 后端未起 / 无权限）就**不显示**角标，而不是显示 0，
 *     更不回落到任何编造值——"0 条未处理告警"和"我不知道有几条"是两回事；
 *  3. 计数不受页面上任何筛选影响（后端 counts 就是全局量）。
 */
import { reactive } from 'vue';
import { api, getToken } from '@/lib/api';
import type { BadgeKey } from '@/nav';

/** 角标值：undefined = 未知（不渲染角标）；0 也会渲染成 0（"确实没有"是有效信息）。 */
export const badgeCounts = reactive<Partial<Record<BadgeKey, number>>>({});

interface AlertsResp { counts: { pending: number; ignored: number; handled: number } }
/** source 恒为 live：会话只有网关上报这一个来源（无网关即空态）。
 *  'demo' 只可能来自尚未升级的旧后端，见下方兼容判断。 */
interface OnlineResp { sessions: unknown[]; source: 'live' | 'demo' }
interface UserStateResp { buckets: { key: string; count: number }[] }

/** 需要关注的用户档位：与风险处置四档同口径（阻断 / 降权 / 锁定）。 */
const RISK_BUCKETS = new Set(['block', 'degrade', 'locked']);

/**
 * 刷新全部角标。逐项独立 try：一个接口挂了不该把另外两个角标一起抹掉。
 * 失败的那一项**删掉**已有值（宁可不显示，也不让上一次的旧数字继续冒充现值）。
 */
export async function refreshBadges(): Promise<void> {
  if (!getToken()) return;
  await Promise.all([
    load('alerts', async () => {
      const r = await api<AlertsResp>('/alerts');
      return r.counts?.pending ?? 0;
    }),
    load('online', async () => {
      const r = await api<OnlineResp>('/online');
      // ★只认网关上报的真实会话。后端那份"无网关时回退 10 条演示会话"的种子已删除，
      // 现在无网关就是 0（"确实没有人在线"是有效信息，与"我不知道"不同）。
      // 这一行留作**旧后端兼容闸**：万一对接的是尚未升级的控制面（仍会回 demo），
      // 宁可不显示角标，也不把编造的 10 条换个地方继续画出来。
      if (r.source !== 'live') throw new Error('demo source');
      return r.sessions?.length ?? 0;
    }),
    load('risk', async () => {
      const r = await api<UserStateResp>('/userstate');
      return (r.buckets ?? []).filter((b) => RISK_BUCKETS.has(b.key)).reduce((n, b) => n + b.count, 0);
    })
  ]);
}

async function load(key: BadgeKey, fn: () => Promise<number>): Promise<void> {
  try {
    badgeCounts[key] = await fn();
  } catch {
    delete badgeCounts[key];
  }
}
