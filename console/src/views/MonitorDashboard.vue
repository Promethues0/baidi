<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">安全监控大屏<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">聚合自统一审计流 + 设备 / 用户库 · 实时只读{{ d.ts ? ' · 更新于 ' + d.ts : '' }}</div>
      </div>
      <a-space>
        <a-button size="small" :loading="loading" @click="load">
          <template #icon><icon-refresh /></template>刷新
        </a-button>
      </a-space>
    </div>

    <!-- 控制面健康条：吸收原「控制面实时」的只读指示（连通 / 策略版本 / 启用数 / SSE） -->
    <div class="cp-strip">
      <span class="cp-strip__dot" :class="cp.live ? 'on' : 'off'"></span>
      <span class="cp-strip__t">控制面 <b>{{ cp.live ? '已连 zhulong-control' : '未连 · 降级演示' }}</b></span>
      <span class="cp-strip__sep">·</span>
      <span class="cp-strip__t">策略基线 <b class="data">{{ cp.live ? 'v' + cp.version : 'v—' }}</b></span>
      <span class="cp-strip__sep">·</span>
      <span class="cp-strip__t"><b class="data">{{ cp.enabled }}</b> / {{ cp.total }} 策略启用</span>
      <span class="cp-strip__sep">·</span>
      <span class="cp-strip__t">SSE 主动推送 {{ cp.live ? '就绪' : '—' }}</span>
      <router-link to="/policy" class="cp-strip__link">统一策略 →</router-link>
    </div>

    <!-- 顶部数字卡 -->
    <div class="zl-grid md-stats">
      <div class="zl-card zl-card__pad md-stat">
        <div class="md-stat__label">在线设备</div>
        <div class="md-stat__value">
          {{ d.deviceOnline }}<span class="md-stat__unit">/ {{ d.deviceTotal }}</span>
        </div>
        <div class="md-bar md-bar--track">
          <div class="md-bar__fill md-bar__fill--ok" :style="{ width: pct(d.deviceOnline, d.deviceTotal) + '%' }"></div>
        </div>
        <div class="md-stat__foot">在线率 {{ pct(d.deviceOnline, d.deviceTotal) }}%</div>
      </div>

      <div class="zl-card zl-card__pad md-stat">
        <div class="md-stat__label">用户总数</div>
        <div class="md-stat__value">{{ d.userTotal }}</div>
        <div class="md-stat__foot">纳管账号 · 含禁用</div>
      </div>

      <div class="zl-card zl-card__pad md-stat">
        <div class="md-stat__label">锁定 / 禁用</div>
        <div class="md-stat__value" :class="{ 'md-stat__value--warn': d.lockedUsers > 0 }">{{ d.lockedUsers }}</div>
        <div class="md-stat__foot">{{ d.lockedUsers > 0 ? '需关注账号状态' : '无锁定账号' }}</div>
      </div>

      <div class="zl-card zl-card__pad md-stat">
        <div class="md-stat__label">威胁事件</div>
        <div class="md-stat__value" :class="{ 'md-stat__value--danger': d.threatTotal > 0 }">{{ d.threatTotal }}</div>
        <div class="md-stat__foot">拒绝 / 失败 / 二次鉴权聚合</div>
      </div>
    </div>

    <!-- 中部两栏：审计类别分布 / 判定分布 -->
    <div class="zl-grid md-two">
      <!-- 审计类别分布 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">审计类别分布</div>
        <div class="md-sub">按事件类别聚合的统一审计流计数</div>
        <div v-if="categoryRows.length" class="md-bars">
          <div v-for="row in categoryRows" :key="row.name" class="md-brow">
            <div class="md-brow__lab">{{ row.name }}</div>
            <div class="md-brow__track">
              <div class="md-brow__fill" :style="{ width: row.w + '%' }"></div>
            </div>
            <div class="md-brow__val data">{{ row.val }}</div>
          </div>
        </div>
        <div v-else class="md-empty">暂无审计类别数据</div>
      </div>

      <!-- 判定分布 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">判定分布</div>
        <div class="md-sub">放行 / 拒绝 / 二次鉴权 / 成功 / 失败 占比</div>
        <div v-if="decisionRows.length" class="md-bars">
          <div v-for="row in decisionRows" :key="row.key" class="md-brow">
            <div class="md-brow__lab">
              <span class="zl-badge" :class="decClass(row.key)">{{ decLabel(row.key) }}</span>
            </div>
            <div class="md-brow__track">
              <div class="md-brow__fill" :class="decFill(row.key)" :style="{ width: row.w + '%' }"></div>
            </div>
            <div class="md-brow__val data">{{ row.val }}</div>
          </div>
        </div>
        <div v-else class="md-empty">暂无判定数据</div>
      </div>
    </div>

    <!-- 下部两栏：风险用户 TOP / 最近威胁事件 -->
    <div class="zl-grid md-two">
      <!-- 风险用户 TOP -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">风险用户 TOP</div>
        <div class="md-sub">按累计风险分排序的高风险账号</div>
        <div v-if="d.riskTopActor.length" class="md-risk">
          <div v-for="(r, i) in d.riskTopActor" :key="r.actor + i" class="md-risk__row">
            <div class="md-risk__rank">{{ i + 1 }}</div>
            <div class="md-risk__actor data">{{ r.actor }}</div>
            <div class="md-risk__track">
              <div class="md-risk__fill" :class="riskFill(r.risk)" :style="{ width: riskW(r.risk) + '%' }"></div>
            </div>
            <span class="zl-badge" :class="riskBadge(r.risk)">{{ r.risk }}</span>
          </div>
        </div>
        <div v-else class="md-empty">暂无高风险账号</div>
      </div>

      <!-- 最近威胁事件 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">最近威胁事件</div>
        <div class="md-sub">命中拒绝 / 失败 / 二次鉴权的最近审计事件</div>
        <div v-if="d.recentThreats.length" class="md-threats">
          <div v-for="(t, i) in d.recentThreats" :key="i" class="md-threat">
            <div class="md-threat__main">
              <span class="md-threat__act">{{ t.Action || t.Detail || t.Category || '—' }}</span>
              <span class="md-threat__actor data">{{ t.Actor || '—' }}</span>
            </div>
            <div class="md-threat__side">
              <span class="md-threat__detail">{{ t.Detail || t.Category || '' }}</span>
              <span class="zl-badge" :class="decClass(t.Decision)">{{ decLabel(t.Decision) }}</span>
            </div>
          </div>
        </div>
        <div v-else class="md-empty">暂无威胁事件 · 一切正常</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { decision } from '@/lib/status';

// 监控大屏聚合文档（只读）：控制面 /ctl/api/monitor/dashboard 聚合统一审计流 + 设备/用户库。
interface ThreatRow {
  Category: string;
  Actor: string;
  Decision: string;
  Detail: string;
  TS: string;
  Action: string;
  Risk: number;
}
interface Dashboard {
  byCategory: Record<string, number>;
  byDecision: Record<string, number>;
  riskTopActor: { actor: string; risk: number }[];
  threatTotal: number;
  recentThreats: ThreatRow[];
  deviceOnline: number;
  deviceTotal: number;
  userTotal: number;
  lockedUsers: number;
  ts: string;
}

// 前端默认（mock 降级，与后端聚合同形；加载成功后整体覆盖）。
function mockDashboard(): Dashboard {
  return {
    byCategory: { 访问决策: 1284, 登录认证: 642, 策略变更: 73, 配置变更: 41 },
    byDecision: { allow: 1106, 'step-up': 138, deny: 96, success: 588, fail: 54 },
    riskTopActor: [
      { actor: 'wang.lei@corp', risk: 82 },
      { actor: 'contractor.zhao', risk: 67 },
      { actor: 'li.fang@corp', risk: 51 },
      { actor: 'svc-backup', risk: 38 },
      { actor: 'chen.bo@corp', risk: 22 }
    ],
    threatTotal: 288,
    recentThreats: [
      { Category: '访问决策', Actor: 'contractor.zhao', Decision: 'deny', Detail: '设备未越狱检测失败 · 拒绝接入', TS: '14:21', Action: '访问内网财务系统', Risk: 67 },
      { Category: '登录认证', Actor: 'wang.lei@corp', Decision: 'fail', Detail: '连续 6 次密码错误 · 触发防爆破', TS: '14:08', Action: '账号密码登录', Risk: 82 },
      { Category: '访问决策', Actor: 'li.fang@corp', Decision: 'step-up', Detail: '异地登录 · 要求短信二次鉴权', TS: '13:55', Action: '访问运维堡垒机', Risk: 51 },
      { Category: '访问决策', Actor: 'svc-backup', Decision: 'deny', Detail: '非工作时段 · 时段策略拒绝', TS: '13:40', Action: '访问对象存储', Risk: 38 },
      { Category: '登录认证', Actor: 'chen.bo@corp', Decision: 'fail', Detail: 'TOTP 校验失败', TS: '13:22', Action: 'OTP 二次校验', Risk: 22 }
    ],
    deviceOnline: 186,
    deviceTotal: 240,
    userTotal: 312,
    lockedUsers: 4,
    ts: ''
  };
}

const d = ref<Dashboard>(mockDashboard());
const live = ref(false);
const loading = ref(false);

// 控制面健康（只读）：吸收原「控制面实时」页的连通 / 版本 / 启用数指示，无需 SSE 订阅
const cp = reactive({ live: false, version: 0, total: 0, enabled: 0 });
async function loadControlPlane() {
  try {
    const [vR, pR] = await Promise.all([fetch('/ctl/api/version'), fetch('/ctl/api/policies')]);
    if (vR.ok) { cp.version = (await vR.json()).version ?? 0; cp.live = true; }
    if (pR.ok) {
      const ps = await pR.json();
      if (Array.isArray(ps)) { cp.total = ps.length; cp.enabled = ps.filter((p: any) => p.enabled).length; }
    }
  } catch { cp.live = false; }
}

// 合并后端聚合到默认形，缺字段回落默认（向后兼容）。
function mergeDashboard(raw: any): Dashboard {
  const base = mockDashboard();
  if (!raw || typeof raw !== 'object') return base;
  return {
    byCategory: raw.byCategory && typeof raw.byCategory === 'object' ? raw.byCategory : base.byCategory,
    byDecision: raw.byDecision && typeof raw.byDecision === 'object' ? raw.byDecision : base.byDecision,
    riskTopActor: Array.isArray(raw.riskTopActor) ? raw.riskTopActor : base.riskTopActor,
    threatTotal: typeof raw.threatTotal === 'number' ? raw.threatTotal : base.threatTotal,
    recentThreats: Array.isArray(raw.recentThreats) ? raw.recentThreats : base.recentThreats,
    deviceOnline: typeof raw.deviceOnline === 'number' ? raw.deviceOnline : base.deviceOnline,
    deviceTotal: typeof raw.deviceTotal === 'number' ? raw.deviceTotal : base.deviceTotal,
    userTotal: typeof raw.userTotal === 'number' ? raw.userTotal : base.userTotal,
    lockedUsers: typeof raw.lockedUsers === 'number' ? raw.lockedUsers : base.lockedUsers,
    ts: raw.ts ?? ''
  };
}

// 聚合来自控制面 /ctl/api/monitor/dashboard（只读）；不可达时降级前端 mock。
async function load() {
  loading.value = true;
  try {
    const r = await fetch('/ctl/api/monitor/dashboard');
    if (!r.ok) { live.value = false; return; }
    d.value = mergeDashboard(await r.json());
    live.value = true;
    Message.success('监控数据已刷新 · 实时聚合');
  } catch {
    live.value = false;
  } finally {
    loading.value = false;
  }
}
onMounted(load);
onMounted(loadControlPlane);

/* —— 占比工具 —— */
const pct = (n: number, total: number) => (total > 0 ? Math.round((n / total) * 100) : 0);

// 类别分布：按占最大值的比例算条宽（最大值占满），降序展示。
const categoryRows = computed(() => {
  const e = Object.entries(d.value.byCategory || {});
  if (!e.length) return [];
  const max = Math.max(...e.map(([, v]) => v as number), 1);
  return e
    .map(([name, val]) => ({ name, val: val as number, w: Math.round(((val as number) / max) * 100) }))
    .sort((a, b) => b.val - a.val);
});

// 判定分布：固定顺序展示（allow/step-up/deny/success/fail），仅渲染有计数的项。
const DEC_ORDER = ['allow', 'step-up', 'deny', 'success', 'fail'];
const decisionRows = computed(() => {
  const m = d.value.byDecision || {};
  const known = DEC_ORDER.filter((k) => k in m);
  const extra = Object.keys(m).filter((k) => !DEC_ORDER.includes(k));
  const keys = [...known, ...extra];
  const max = Math.max(...keys.map((k) => m[k] as number), 1);
  return keys.map((key) => ({ key, val: m[key] as number, w: Math.round(((m[key] as number) / max) * 100) }));
});

/* —— 判定中文化 / 配色（与统一事件页一致） —— */
const decLabel = (k?: string) => decision(k).label;
const decClass = (k?: string) => decision(k).badge;
// 条形填充色（allow/success 绿 · deny/fail 红 · step-up 橙）。
const decFill = (k: string) =>
  k === 'allow' || k === 'success' ? 'md-brow__fill--ok' : k === 'deny' || k === 'fail' ? 'md-brow__fill--danger' : k === 'step-up' ? 'md-brow__fill--warn' : '';

/* —— 风险分阶梯（≥70 红 · ≥40 橙 · 其余中性） —— */
const riskW = (r: number) => Math.max(4, Math.min(100, Math.round((r / 100) * 100)));
const riskFill = (r: number) => (r >= 70 ? 'md-risk__fill--danger' : r >= 40 ? 'md-risk__fill--warn' : 'md-risk__fill--accent');
const riskBadge = (r: number) => (r >= 70 ? 'zl-badge--danger' : r >= 40 ? 'zl-badge--warn' : 'zl-badge--accent');
</script>

<style scoped>
/* 控制面健康条 */
.cp-strip { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 9px 14px; margin-bottom: 16px; background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--r-md); font-size: 12px; color: var(--ink-2); }
.cp-strip__dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.cp-strip__dot.on { background: var(--ok); }
.cp-strip__dot.off { background: var(--idle); }
.cp-strip__t b { color: var(--ink); font-weight: 650; }
.cp-strip__sep { color: var(--line-2); }
.cp-strip__link { margin-left: auto; color: var(--accent-2); text-decoration: none; font-weight: 600; }
.cp-strip__link:hover { text-decoration: underline; }

/* 顶部数字卡 */
.md-stats { grid-template-columns: repeat(4, 1fr); margin-bottom: 16px; }
.md-stat { display: flex; flex-direction: column; gap: 6px; }
.md-stat__label { font-size: 12.5px; color: var(--ink-3); }
.md-stat__value { font-size: 28px; font-weight: 750; color: var(--ink); line-height: 1.1; letter-spacing: -0.02em; font-family: var(--font-data); }
.md-stat__value--warn { color: var(--warn); }
.md-stat__value--danger { color: var(--danger); }
.md-stat__unit { font-size: 14px; font-weight: 500; color: var(--ink-3); margin-left: 6px; }
.md-stat__foot { font-size: 11px; color: var(--ink-3); margin-top: 2px; }

/* 数字卡内的占比小条 */
.md-bar--track { height: 6px; border-radius: 4px; background: var(--line); overflow: hidden; margin-top: 4px; }
.md-bar__fill { height: 100%; border-radius: 4px; background: var(--accent-2); transition: width .3s ease; }
.md-bar__fill--ok { background: var(--ok); }

/* 两栏布局 */
.md-two { grid-template-columns: repeat(2, 1fr); align-items: start; margin-top: 16px; }

.md-sub { font-size: 11.5px; color: var(--ink-3); margin: 4px 0 14px; line-height: 1.5; }
.md-empty { padding: 26px 8px; text-align: center; font-size: 12.5px; color: var(--ink-3); }

/* 横向条形（类别 / 判定） */
.md-bars { display: flex; flex-direction: column; gap: 12px; }
.md-brow { display: grid; grid-template-columns: 92px 1fr 56px; align-items: center; gap: 12px; }
.md-brow__lab { font-size: 12.5px; color: var(--ink-2); font-weight: 600; }
.md-brow__track { height: 14px; border-radius: 5px; background: var(--line); overflow: hidden; }
.md-brow__fill { height: 100%; border-radius: 5px; background: var(--accent-2); transition: width .3s ease; min-width: 3px; }
.md-brow__fill--ok { background: var(--ok); }
.md-brow__fill--danger { background: var(--danger); }
.md-brow__fill--warn { background: var(--warn); }
.md-brow__val { text-align: right; font-size: 13px; font-weight: 650; color: var(--ink); }

/* 风险用户 TOP */
.md-risk { display: flex; flex-direction: column; }
.md-risk__row { display: grid; grid-template-columns: 22px 150px 1fr 48px; align-items: center; gap: 12px; padding: 9px 0; }
.md-risk__row + .md-risk__row { border-top: 1px solid var(--line); }
.md-risk__rank { font-size: 12px; font-weight: 700; color: var(--ink-3); text-align: center; }
.md-risk__actor { font-size: 12.5px; color: var(--ink); font-weight: 600; overflow: hidden; text-overflow: ellipsis; }
.md-risk__track { height: 8px; border-radius: 4px; background: var(--line); overflow: hidden; }
.md-risk__fill { height: 100%; border-radius: 4px; background: var(--accent-2); transition: width .3s ease; }
.md-risk__fill--danger { background: var(--danger); }
.md-risk__fill--warn { background: var(--warn); }
.md-risk__fill--accent { background: var(--accent-2); }

/* 最近威胁事件 */
.md-threats { display: flex; flex-direction: column; }
.md-threat { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 10px 0; }
.md-threat + .md-threat { border-top: 1px solid var(--line); }
.md-threat__main { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.md-threat__act { font-size: 13px; font-weight: 600; color: var(--ink); }
.md-threat__actor { font-size: 11.5px; color: var(--ink-3); }
.md-threat__side { display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
.md-threat__detail { font-size: 11.5px; color: var(--ink-2); text-align: right; max-width: 220px; line-height: 1.4; }
</style>
