<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">主动防御<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">流水线首段「单会话检测」：基于会话元数据（指纹 / IP / 地理 / 设备）异常检测，命中按处置动作执行；命中可被<router-link to="/defense/correlate">关联规则</router-link>聚合、<router-link to="/policy/iprep">IP 信誉名单</router-link>自动加黑</div>
      </div>
    </div>

    <!-- 上半部：处置策略（5 种威胁类型，行内改动即落库） -->
    <div class="zl-card zl-card__pad">
      <div class="zl-card__title">处置策略</div>
      <div class="dp-sub">每种威胁类型一条策略，命中阈值后执行对应处置动作；启用 / 动作 / 阈值任一改动即时下发并写审计。</div>

      <div class="dp-rows">
        <div v-for="row in rows" :key="row.type" class="dp-row" :class="{ 'dp-row--off': !row.enabled }">
          <div class="dp-row__meta">
            <div class="dp-row__name">{{ typeLabel(row.type) }}</div>
            <div class="dp-row__desc">{{ typeDesc(row.type) }}</div>
          </div>

          <div class="dp-row__ctl">
            <div class="dp-field">
              <span class="dp-field__lab">启用</span>
              <a-switch v-model="row.enabled" size="small" @change="onToggle(row)" />
            </div>

            <div class="dp-field">
              <span class="dp-field__lab">处置动作</span>
              <a-select v-model="row.action" size="small" style="width:140px" :disabled="!row.enabled" @change="onChange(row)">
                <a-option v-for="a in ACTIONS" :key="a.value" :value="a.value">{{ a.label }}</a-option>
              </a-select>
            </div>

            <div class="dp-field">
              <span class="dp-field__lab">触发阈值</span>
              <a-select v-model="row.minSev" size="small" style="width:110px" :disabled="!row.enabled" @change="onChange(row)">
                <a-option v-for="s in SEVS" :key="s.value" :value="s.value">{{ s.label }}</a-option>
              </a-select>
            </div>

            <span class="zl-badge" :class="actClass(row.action)">{{ actLabel(row.action) }}</span>
          </div>
        </div>
      </div>

      <div class="dp-note">
        触发阈值 = 异常检测严重级达到该级别及以上才命中处置；处置动作从「告警」到「加入黑名单」逐级收紧。
        关闭某类型即停止该维度检测（等价旧行为，向后兼容）。
      </div>
    </div>

    <!-- 下半部：最近威胁事件 -->
    <div class="zl-card">
      <div class="zl-card__pad" style="padding-bottom:0">
        <div class="zl-card__title">最近威胁事件
          <span class="dp-evcount">最近 {{ events.length }} 条</span>
        </div>
      </div>
      <a-table :data="events" :pagination="false" :bordered="false" row-key="key">
        <template #columns>
          <a-table-column title="时间" :width="100">
            <template #cell="{ record }"><span class="data" style="color:var(--ink-3)">{{ record.ts }}</span></template>
          </a-table-column>
          <a-table-column title="账号" data-index="actor" :width="150">
            <template #cell="{ record }"><span class="data">{{ record.actor || '—' }}</span></template>
          </a-table-column>
          <a-table-column title="动作" :width="160">
            <template #cell="{ record }"><span style="font-size:12.5px;color:var(--ink-2)">{{ record.action || '—' }}</span></template>
          </a-table-column>
          <a-table-column title="处置" align="center" :width="120">
            <template #cell="{ record }">
              <span class="zl-badge" :class="decClass(record.decision)">{{ decLabel(record.decision) }}</span>
            </template>
          </a-table-column>
          <a-table-column title="详情">
            <template #cell="{ record }"><span style="font-size:12px;color:var(--ink-2)">{{ record.detail || '—' }}</span></template>
          </a-table-column>
        </template>
        <template #empty>
          <div class="dp-empty">
            <div class="dp-empty__big">暂无威胁事件</div>
            <div class="dp-empty__sub">主动防御命中处置时在此记录；当前会话元数据异常检测未触发任何策略。</div>
          </div>
        </template>
      </a-table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { defenseAction, defenseActionOptions } from '@/lib/defense';

/* —— 类型 —— */
// 处置策略文档（kind=defensepolicy，每种威胁类型一条，key=type）。
type ThreatType = 'session-hijack' | 'credential-theft' | 'mitm' | 'impossible-travel' | 'anomalous-access';
type Action = 'alert' | 'stepup' | 'logout' | 'lock' | 'blacklist';
type Sev = 'low' | 'medium' | 'high' | 'critical';
interface DefenseRow {
  type: ThreatType;
  enabled: boolean;
  action: Action;
  minSev: Sev;
}

// 威胁事件行（来自 /ctl/api/audit/events?category=主动防御）。
interface ThreatEvent {
  key: string;
  ts: string;
  actor?: string;
  action?: string;
  decision?: string;
  detail?: string;
}

/* —— 枚举中文化 —— */
const THREAT_TYPES: { value: ThreatType; label: string; desc: string }[] = [
  { value: 'session-hijack', label: '会话劫持', desc: '会话指纹突变 / Cookie 异地复用，疑似令牌被盗用' },
  { value: 'credential-theft', label: '凭据窃取', desc: '凭据在异常环境登录，疑似账号口令泄露' },
  { value: 'mitm', label: '中间人', desc: 'TLS 指纹 / 证书链异常，疑似流量被中间人截获' },
  { value: 'impossible-travel', label: '不可能旅行', desc: '短时间内跨地理位置登录，物理上不可达' },
  { value: 'anomalous-access', label: '异常访问', desc: '访问时段 / 设备 / 行为偏离基线，触发异常画像' }
];
const ACTIONS = defenseActionOptions(['alert', 'stepup', 'logout', 'lock', 'blacklist']);
const SEVS: { value: Sev; label: string }[] = [
  { value: 'low', label: '低' },
  { value: 'medium', label: '中' },
  { value: 'high', label: '高' },
  { value: 'critical', label: '严重' }
];

const typeLabel = (t: string) => THREAT_TYPES.find((x) => x.value === t)?.label ?? t;
const typeDesc = (t: string) => THREAT_TYPES.find((x) => x.value === t)?.desc ?? '';
const actLabel = (a: string) => defenseAction(a).label;
const actClass = (a: string) => defenseAction(a).badge;
// 事件处置徽标（decision 复用动作枚举 + 审计链通用判定别名 allow/deny/step-up）。
const decLabel = (d?: string) => defenseAction(d).label;
const decClass = (d?: string) => defenseAction(d).badge;

/* —— 前端默认（5 条，全部默认开启；加载后端后覆盖） —— */
function defaults(): DefenseRow[] {
  return [
    { type: 'session-hijack', enabled: true, action: 'logout', minSev: 'high' },
    { type: 'credential-theft', enabled: true, action: 'stepup', minSev: 'medium' },
    { type: 'mitm', enabled: true, action: 'logout', minSev: 'high' },
    { type: 'impossible-travel', enabled: true, action: 'stepup', minSev: 'medium' },
    { type: 'anomalous-access', enabled: true, action: 'alert', minSev: 'low' }
  ];
}

const rows = ref<DefenseRow[]>(defaults());
const events = ref<ThreatEvent[]>([]);
const live = ref(false);

/* —— 加载处置策略（kind=defensepolicy，多文档；以 type 收敛保证 5 条齐全） —— */
async function loadPolicies() {
  try {
    const r = await fetch('/ctl/api/coll?kind=defensepolicy');
    if (!r.ok) return;
    const docs = await r.json();
    if (Array.isArray(docs) && docs.length) {
      const base = defaults();
      // 后端文档按 type 覆盖默认行，缺失的 type 仍保留默认（向后兼容）。
      for (const d of docs) {
        const t = d.type ?? d.key ?? d.k;
        const row = base.find((x) => x.type === t);
        if (!row) continue;
        if (typeof d.enabled === 'boolean') row.enabled = d.enabled;
        if (ACTIONS.some((a) => a.value === d.action)) row.action = d.action;
        if (SEVS.some((s) => s.value === d.minSev)) row.minSev = d.minSev;
      }
      rows.value = base;
    }
    live.value = true;
  } catch { live.value = false; }
}

/* —— 加载最近威胁事件（category=主动防御，最多 20 条） —— */
async function loadEvents() {
  try {
    const r = await fetch('/ctl/api/audit/events?category=' + encodeURIComponent('主动防御') + '&limit=20');
    if (!r.ok) return;
    const list = await r.json();
    if (Array.isArray(list)) {
      events.value = list.map((e: any, i: number) => ({
        key: (e.seq || 'th') + '-' + i,
        ts: e.ts ?? '',
        actor: e.actor ?? '',
        action: e.action ?? '',
        decision: e.decision ?? '',
        detail: e.detail ?? e.note ?? ''
      }));
    }
  } catch { /* 控制面不可达：保留空态「暂无威胁事件」 */ }
}

onMounted(() => { loadPolicies(); loadEvents(); });

/* —— 行内持久化（POST 单条 doc，key=type；后端写审计） —— */
async function persist(row: DefenseRow): Promise<boolean> {
  if (!live.value) return true; // mock 态仅前端反馈
  try {
    const res = await fetch('/ctl/api/coll?kind=defensepolicy', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        key: row.type,
        doc: { type: row.type, enabled: row.enabled, action: row.action, minSev: row.minSev }
      })
    });
    return res.ok;
  } catch { return false; }
}

// 启用开关：即时落库，写失败回滚。
async function onToggle(row: DefenseRow) {
  const ok = await persist(row);
  if (!ok && live.value) { row.enabled = !row.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`「${typeLabel(row.type)}」检测已${row.enabled ? '开启' : '关闭'}${live.value ? ' · 已持久化' : '（mock）'}`);
}

// 动作 / 阈值改动：即时落库，写失败提示（不回滚旧值，重选即可重试）。
async function onChange(row: DefenseRow) {
  const ok = await persist(row);
  if (!ok && live.value) return Message.error('保存失败，控制面不可达');
  Message.success(`「${typeLabel(row.type)}」处置策略已更新${live.value ? ' · 已持久化 · ≤60s 下发并写审计' : '（mock）'}`);
}
</script>

<style scoped>
.dp-sub { font-size: 11.5px; color: var(--ink-3); margin: 4px 0 14px; line-height: 1.5; }

.dp-rows { display: flex; flex-direction: column; }
.dp-row { display: flex; align-items: center; justify-content: space-between; gap: 18px; padding: 14px 0; }
.dp-row + .dp-row { border-top: 1px solid var(--line); }
.dp-row--off { opacity: .6; }

.dp-row__meta { min-width: 0; flex: 1; }
.dp-row__name { font-size: 13.5px; font-weight: 650; color: var(--ink); }
.dp-row__desc { font-size: 11.5px; color: var(--ink-3); margin-top: 3px; line-height: 1.5; }

.dp-row__ctl { display: flex; align-items: center; gap: 18px; flex-shrink: 0; }
.dp-field { display: flex; flex-direction: column; gap: 5px; }
.dp-field__lab { font-size: 10.5px; color: var(--ink-3); }

.dp-note { margin-top: 14px; padding: 10px 12px; border-radius: var(--r-md); background: var(--accent-soft); font-size: 11.5px; color: var(--ink-2); line-height: 1.6; }

.zl-card .dp-evcount { font-size: 11px; font-weight: 400; color: var(--ink-3); margin-left: 10px; }

.dp-empty { padding: 30px 16px; text-align: center; }
.dp-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.dp-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 520px; margin-left: auto; margin-right: auto; }
</style>
