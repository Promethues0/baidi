/**
 * 白帝控制台 · 共享策略 store + 求值引擎 + netmap 编译下发
 * 统一策略页与策略仿真器吃同一份数据；策略变更自动编译 netmap 并 POST 到
 * 控制面演示端点（vite 中间件 /api/netmap），桌面客户端轮询拉取 → 联动演示。
 */
import { reactive, watch } from 'vue';

/* ── 策略（canonical，条件为结构化对象） ── */
export interface Cond { mfa?: boolean; posture?: boolean; workhours?: boolean; notBefore?: string; notAfter?: string; }
export interface Pol {
  id: string; subjects: string[]; resources: string[];
  action: 'allow' | 'deny'; cond: Cond; modes: string; hits: number; enabled: boolean;
}
export const policyStore = reactive<Pol[]>([
  { id: 'pol-rd-database', subjects: ['group:研发-动态', 'tag:ci-runner'], resources: ['service:db.corp:5432', 'app:gitlab'], action: 'allow', cond: { posture: true, mfa: true }, modes: 'auto', hits: 4210, enabled: true },
  { id: 'pol-oa-all', subjects: ['group:全体员工'], resources: ['app:oa.corp'], action: 'allow', cond: {}, modes: 'ssl', hits: 12880, enabled: true },
  { id: 'pol-branch-erp', subjects: ['site:上海分支'], resources: ['subnet:10.20.0.0/16'], action: 'allow', cond: {}, modes: 'ipsec', hits: 1340, enabled: true },
  { id: 'pol-finance-deny-byod', subjects: ['group:BYOD'], resources: ['app:finance'], action: 'deny', cond: {}, modes: 'auto', hits: 96, enabled: true },
  { id: 'pol-finance-fin', subjects: ['group:财务'], resources: ['app:finance'], action: 'allow', cond: { mfa: true }, modes: 'ssl', hits: 870, enabled: true },
  { id: 'pol-ops-ssh', subjects: ['group:运维'], resources: ['service:*.corp:22'], action: 'allow', cond: { mfa: true, workhours: true }, modes: 'mesh', hits: 220, enabled: false }
]);

export const condStrings = (p: Pol) => [
  ...(p.cond.posture ? ['posture: disk_encrypted'] : []),
  ...(p.cond.mfa ? ['auth: mfa'] : []),
  ...(p.cond.workhours ? ['time: workhours'] : []),
  ...(p.cond.notAfter ? ['有效期至 ' + p.cond.notAfter] : [])
];

/**
 * 从控制面 API 拉取策略并原地替换 policyStore 内容（保持 reactive 引用，
 * 让仿真器/统一策略页与 netmap watch 都指向同一份）。
 * 失败时静默保留硬编码种子（demo 降级，控制面未起时仍可演示）。
 * 必须在 startNetmapSync 之前完成，使快照基线建立在真实数据上。
 */
export async function hydratePolicies(): Promise<void> {
  try {
    const { listPolicies } = await import('@/services/policies');
    const fresh = await listPolicies();
    if (fresh.length) policyStore.splice(0, policyStore.length, ...fresh);
  } catch {
    /* 控制面不可用：保留种子数据 */
  }
}

/* ── 仿真主体与资源 ── */
export interface SimSubject { key: string; label: string; kind: 'user' | 'site'; memberOf: string[]; device?: string; }
export const simSubjects: SimSubject[] = [
  { key: 'zhang.wei', label: '张伟 · 研发', kind: 'user', memberOf: ['user:zhang.wei', 'group:研发-动态', 'group:全体员工'], device: 'MBP-7F2A' },
  { key: 'li.na', label: '李娜 · 财务', kind: 'user', memberOf: ['user:li.na', 'group:财务', 'group:全体员工'], device: 'iPhone-92' },
  { key: 'wang.qiang', label: '王强 · 运维', kind: 'user', memberOf: ['user:wang.qiang', 'group:运维', 'group:全体员工'], device: 'WS-330' },
  { key: 'byod.pad', label: 'BYOD 平板（陈静）', kind: 'user', memberOf: ['user:chen.jing', 'group:BYOD', 'group:全体员工'], device: 'Pad-1180' },
  { key: 'svc.ci', label: 'CI Runner（服务账号）', kind: 'user', memberOf: ['tag:ci-runner'], device: 'ci-runner-01' },
  { key: 'site.sh', label: '上海分支（站点）', kind: 'site', memberOf: ['site:上海分支'] }
];
export const simResources = [
  { key: 'app:oa.corp', name: 'OA 办公系统', type: 'app', modes: 'ssl', stepup: false },
  { key: 'app:gitlab', name: 'GitLab', type: 'app', modes: 'auto', stepup: false },
  { key: 'service:db.corp:5432', name: '核心数据库', type: 'service', modes: 'auto', stepup: true },
  { key: 'app:finance', name: '财务系统', type: 'app', modes: 'ssl', stepup: true },
  { key: 'subnet:10.20.0.0/16', name: '上海分支网段', type: 'subnet', modes: 'ipsec', stepup: false },
  { key: 'service:bastion.corp:22', name: '堡垒机 SSH', type: 'service', modes: 'mesh', stepup: true }
];

const resMatch = (pat: string, key: string) =>
  pat === key || (pat.includes('*') && new RegExp('^' + pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$').test(key));

/* ── 求值引擎：deny > allow > 默认拒绝（ZL-FR-104） ── */
export interface Ctx { mfa: boolean; posture: boolean; workhours: boolean; }
export interface Verdict {
  decision: 'allow' | 'deny'; matched: string; reason: string;
  trace: { tone: string; text: string }[]; effModes: string[];
}
export function evaluate(s: SimSubject, r: (typeof simResources)[number], ctx: Ctx): Verdict {
  const trace: Verdict['trace'] = [];
  trace.push({ tone: 'info', text: `主体展开：<b>${s.memberOf.join('、')}</b>${s.device ? ` · 设备 <b>${s.device}</b>` : ''}` });

  const hits = policyStore.filter((p) => p.subjects.some((ps) => s.memberOf.includes(ps)) && p.resources.some((pr) => resMatch(pr, r.key)));
  hits.filter((p) => !p.enabled).forEach((p) => trace.push({ tone: 'skip', text: `<b>${p.id}</b> 主体/资源命中，但策略<b>已停用</b> → 跳过` }));
  const active = hits.filter((p) => p.enabled);

  let decision: 'allow' | 'deny' = 'deny', matched = '', reason = '';
  const deny = active.find((p) => p.action === 'deny');
  if (deny) {
    trace.push({ tone: 'fail', text: `<b>${deny.id}</b> 显式 deny 命中（优先级最高）→ 终止求值` });
    matched = deny.id; reason = '显式拒绝策略命中（deny 优先于一切 allow）';
  } else {
    let granted = false;
    for (const p of active.filter((x) => x.action === 'allow')) {
      const failed: string[] = [];
      if (p.cond.mfa && !ctx.mfa) failed.push('auth_strength: mfa');
      if (p.cond.posture && !ctx.posture) failed.push('posture');
      if (p.cond.workhours && !ctx.workhours) failed.push('time: workhours');
      if (failed.length) trace.push({ tone: 'fail', text: `<b>${p.id}</b> 主体/资源命中，但条件 <b>${failed.join(' / ')}</b> 不满足 → 不放行` });
      else if (!granted) {
        trace.push({ tone: 'ok', text: `<b>${p.id}</b> 命中且全部条件满足 → <b>ALLOW</b>` });
        granted = true; matched = p.id;
        reason = Object.keys(p.cond).length ? '命中放行策略，条件谓词全部满足' : '命中无条件放行策略';
      }
    }
    if (granted) decision = 'allow';
    else {
      if (!hits.length) trace.push({ tone: 'skip', text: '无任何策略命中该 (主体, 资源) 组合' });
      trace.push({ tone: 'fail', text: '落入<b>默认拒绝</b>（零信任缺省）' });
      reason = matched ? '' : '无可放行策略 → 默认拒绝';
    }
  }

  const pol = policyStore.find((p) => p.id === matched);
  const effModes = pol && pol.modes !== 'auto' ? [pol.modes] : r.modes !== 'auto' ? [r.modes] : ['mesh', 'ssl'];
  return { decision, matched, reason, trace, effModes };
}

/* ── 实时审计流（ZL-FR-109：管理变更与配置下发入流，与访问事件同 schema） ── */
export interface LiveAudit {
  ts: string; kind: 'admin' | 'config';
  actor: string; device: string; resource: string; note: string;
}
export const liveAudit = reactive<LiveAudit[]>([]);
const nowTs = () => new Date().toTimeString().slice(0, 8);
function logAudit(kind: LiveAudit['kind'], resource: string, note: string) {
  liveAudit.unshift({ ts: nowTs(), kind, actor: 'admin@baidi', device: 'console', resource, note });
  if (liveAudit.length > 50) liveAudit.pop();
}

/* ── netmap 编译 + 下发（联动演示：张伟视角） ── */
// 版本号单调持久（localStorage）：避免页面重载回退，让网关跨会话拉取版本一致。
const persistedVersion = Number(localStorage.getItem('zl-netmap-version') || '218');
export const netmapState = reactive({ version: persistedVersion, lastPush: '' });
const DEMO_CTX: Ctx = { mfa: true, posture: true, workhours: true };

function compileNetmap() {
  const zw = simSubjects[0]; // zhang.wei
  return simResources
    .filter((r) => r.type !== 'subnet')
    .map((r) => {
      const v = evaluate(zw, r, DEMO_CTX);
      return { key: r.key, name: r.name, allowed: v.decision === 'allow', mode: v.effModes[0] ?? r.modes, policy: v.matched };
    });
}

let timer: ReturnType<typeof setTimeout> | null = null;
async function push() {
  netmapState.version += 1;
  localStorage.setItem('zl-netmap-version', String(netmapState.version)); // 单调持久
  const body = { version: netmapState.version, user: 'zhang.wei', ts: Date.now(), resources: compileNetmap() };
  try {
    await fetch('/api/netmap', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    netmapState.lastPush = nowTs();
    const ok = body.resources.filter((r) => r.allowed).length;
    logAudit('config', `netmap v${netmapState.version}`, `编译下发 · ${ok}/${body.resources.length} 资源可达（zhang.wei）· 在线端点 ≤2s 拉取`);
  } catch { /* 控制面端点不可用时静默（生产环境为 gRPC 推送） */ }
}

/* 策略变更 diff：启用/停用/新建 → 审计事件 */
let polSnap = new Map(policyStore.map((p) => [p.id, p.enabled]));
function diffPolicies() {
  for (const p of policyStore) {
    if (!polSnap.has(p.id)) logAudit('admin', `policy:${p.id}`, `策略创建（${p.action} · ${p.subjects.join(',')} → ${p.resources.join(',')}）`);
    else if (polSnap.get(p.id) !== p.enabled) logAudit('admin', `policy:${p.id}`, `策略${p.enabled ? '启用' : '停用'} · 触发 netmap 重编译`);
  }
  polSnap = new Map(policyStore.map((p) => [p.id, p.enabled]));
}

let started = false;
export function startNetmapSync() {
  if (started) return;
  started = true;
  push();
  watch(policyStore, () => { diffPolicies(); if (timer) clearTimeout(timer); timer = setTimeout(push, 400); }, { deep: true });
}
