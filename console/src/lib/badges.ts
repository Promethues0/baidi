/**
 * 侧栏角标的**真实计数**。三条纪律：
 *  1. 值只来自真实接口；
 *  2. ★取不到（未登录 / 后端未起 / 无权限）就**不显示**角标，既不显示 0 也不回落到
 *     任何常量——"0 条未处理告警"和"我不知道有几条"是两回事，而一个写死的两位数
 *     与真实计数在页面上完全同形；
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
      // ★只认网关上报的真实会话：无网关就是 0（"确实没有人在线"是有效信息，
      // 与"我不知道"不同）。旧控制面仍可能回 demo 会话，那时宁可不显示角标，
      // 也不把演示数据换个地方画出来。
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
