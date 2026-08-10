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
/** source=live 时 sessions 来自网关上报；demo 是无网关时的种子回退（见 api.handleOnline）。 */
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
      // ★只在**真实会话**（网关上报）时给角标。无网关时后端会回退种子演示会话
      // （source=demo，在线用户页上有标注），把那 10 条画成角标就等于换个地方
      // 继续显示写死的 '10'——本次改造要消灭的正是这个。
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
