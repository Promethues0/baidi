<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">统一事件<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">控制面实时审计：登录/策略变更/配置变更/自适应访问决策 emit 落库 + syslog 外发 · 入 HMAC-SM3 审计链（ZL-FR-109）</div>
      </div>
      <a-button @click="exportCsv"><template #icon><icon-download /></template>导出 CSV（{{ filtered.length }}）</a-button>
    </div>

    <!-- 统计条 -->
    <div class="ev-stats">
      <button class="ev-stat" :class="{ on: !fType && !fDecision && !fCategory }" @click="fType=undefined;fDecision=undefined;fCategory=undefined">
        <b>{{ merged.length }}</b><span>全部事件</span>
      </button>
      <button class="ev-stat ok" :class="{ on: fDecision==='allow' }" @click="setDecision('allow')"><b>{{ count('allow') }}</b><span>允许</span></button>
      <button class="ev-stat warn" :class="{ on: fDecision==='step-up' }" @click="setDecision('step-up')"><b>{{ count('step-up') }}</b><span>二次鉴权</span></button>
      <button class="ev-stat danger" :class="{ on: fDecision==='deny' }" @click="setDecision('deny')"><b>{{ count('deny') }}</b><span>拒绝</span></button>
      <button class="ev-stat accent" :class="{ on: fDecision==='fail' }" @click="setDecision('fail')"><b>{{ count('fail') }}</b><span>登录失败</span></button>
    </div>

    <!-- 筛选 -->
    <div class="zl-card zl-card__pad ev-filter">
      <a-input-search v-model="q" placeholder="搜索主体 / 资源 / 策略 / 详情" allow-clear style="width: 240px" />
      <a-select v-model="fCategory" placeholder="类别" allow-clear size="small" style="width: 130px">
        <a-option value="登录认证">登录认证</a-option><a-option value="策略变更">策略变更</a-option>
        <a-option value="配置变更">配置变更</a-option><a-option value="访问决策">访问决策</a-option>
      </a-select>
      <a-select v-model="fDecision" placeholder="判定" allow-clear size="small" style="width: 120px">
        <a-option value="allow">允许</a-option><a-option value="step-up">二次鉴权</a-option>
        <a-option value="deny">拒绝</a-option><a-option value="success">成功</a-option><a-option value="fail">失败</a-option>
      </a-select>
      <span class="ev-count">{{ filtered.length }} / {{ merged.length }}</span>
      <a-button v-if="q||fMode||fDecision||fType||fCategory" size="mini" @click="q='';fMode=fDecision=fType=fCategory=undefined">重置</a-button>
    </div>

    <div class="zl-card">
      <a-table :data="filtered" :pagination="filtered.length>15?{pageSize:15}:false" :bordered="false"
               row-key="key" :row-class="(r:any)=> (r.live?'row-live ':'')+'row-click'" @row-click="openDetail">
        <template #columns>
          <a-table-column title="时间" :width="92"><template #cell="{ record }"><span class="data" style="color:var(--ink-3)">{{ record.ts }}</span></template></a-table-column>
          <a-table-column title="主体" data-index="actor" :width="130"><template #cell="{ record }"><span class="data">{{ record.actor }}</span></template></a-table-column>
          <a-table-column title="类别" :width="96"><template #cell="{ record }"><span class="zl-badge" :class="catClass(record.category)" style="font-size:10.5px">{{ record.category }}</span></template></a-table-column>
          <a-table-column title="资源/目标"><template #cell="{ record }"><span class="data" style="color:var(--ink-2)">{{ record.resource || record.action || '—' }}</span></template></a-table-column>
          <a-table-column title="信任/风险" align="center" :width="92">
            <template #cell="{ record }"><span v-if="record.category==='访问决策'" class="data" style="font-size:11.5px">{{ record.trust ?? 0 }}<span style="color:var(--ink-3)">/</span><span :style="{color:(record.risk??0)>40?'var(--danger)':'var(--ink-2)'}">{{ record.risk ?? 0 }}</span></span><span v-else style="color:var(--ink-3)">—</span></template>
          </a-table-column>
          <a-table-column title="判定" align="center" :width="84">
            <template #cell="{ record }"><span class="zl-badge" :class="decClass(record.decision)">{{ decLabel(record.decision) }}</span></template>
          </a-table-column>
          <a-table-column title="命中策略 / 详情" :width="230">
            <template #cell="{ record }">
              <span v-if="record.note" style="font-size:11.5px;color:var(--ink-2)">{{ record.note }}</span>
              <span v-else class="data" style="font-size:12px;color:var(--accent-2)">{{ record.policy }}</span>
            </template>
          </a-table-column>
        </template>
      </a-table>
    </div>

    <!-- 事件详情 -->
    <a-drawer v-model:visible="drawer" :width="460" :footer="false">
      <template #title>事件详情</template>
      <div v-if="cur" class="ed">
        <div class="ed-banner" :class="bannerClass">
          <span class="ed-banner__g">{{ bannerGlyph }}</span>
          <div>
            <div class="ed-banner__t">{{ bannerText }}</div>
            <div class="ed-banner__d">{{ cur.ts }} · {{ cur.category }}</div>
          </div>
        </div>

        <div class="ed-kv"><span>类别</span><b><span class="zl-badge" :class="catClass(cur.category)">{{ cur.category }}</span></b></div>
        <div class="ed-kv"><span>主体</span><b class="data">{{ cur.actor }}</b></div>
        <div class="ed-kv" v-if="cur.action"><span>动作</span><b>{{ cur.action }}</b></div>
        <div class="ed-kv" v-if="cur.resource"><span>资源/目标</span><b class="data">{{ cur.resource }}</b></div>
        <div class="ed-kv" v-if="cur.mode"><span>接入模式</span><b><span class="zl-mode-pill" :class="`zl-mode--${cur.mode}`">{{ cur.mode }}</span></b></div>
        <div class="ed-kv" v-if="cur.category==='访问决策'"><span>设备信任 / 风险</span><b class="data">{{ cur.trust ?? 0 }} / {{ cur.risk ?? 0 }}</b></div>
        <div class="ed-kv" v-if="cur.policy"><span>命中策略</span><b><router-link to="/policy" class="ed-link data">{{ cur.policy }}</router-link></b></div>
        <div class="ed-kv" v-if="cur.note"><span>详情</span><b style="font-weight:500">{{ cur.note }}</b></div>
        <div class="ed-kv"><span>来源</span><b class="data">{{ cur.source || srcIp }}</b></div>
        <div class="ed-kv"><span>审计链序号</span><b class="data">#{{ chainSeq }} · HMAC-SM3</b></div>

        <div class="ed-sec">原始事件（统一 schema）</div>
        <pre class="ed-json data">{{ rawJson }}</pre>

        <div class="ed-foot">
          <a-button size="small" @click="copyJson">复制 JSON</a-button>
          <router-link to="/audit/chain"><a-button type="primary" size="small">在审计链中定位 #{{ chainSeq }}</a-button></router-link>
        </div>
      </div>
    </a-drawer>
  </div>
</template>
<script setup lang="ts">
import { computed, ref, onMounted } from 'vue';
import { auditEvents } from '@/mock';
import { listAuditEvents, type AuditRow } from '@/services/audit';
import { decision } from '@/lib/status';
import { Message } from '@arco-design/web-vue';

const live = ref(false);
const mockRows: AuditRow[] = (auditEvents as any[]).map((e) => ({ ...e, category: '访问决策', kind: 'access', note: '' }));
const staticEvents = ref<AuditRow[]>(mockRows);
onMounted(async () => {
  try { staticEvents.value = await listAuditEvents(); live.value = true; } catch { /* 控制面未起：保留 mock 种子 */ }
});

const merged = computed<any[]>(() => staticEvents.value.map((e, i) => ({ ...e, live: false, key: (e.seq || 'ev') + '-' + i })));

/* —— 筛选 —— */
const q = ref('');
const fMode = ref<string>();
const fDecision = ref<string>();
const fType = ref<string>();
const fCategory = ref<string>();
const setDecision = (d: string) => { fType.value = undefined; fDecision.value = fDecision.value === d ? undefined : d; };
const setType = (t: string) => { fDecision.value = undefined; fType.value = fType.value === t ? undefined : t; };
const filtered = computed(() => merged.value.filter((e) => {
  if (fCategory.value && e.category !== fCategory.value) return false;
  if (fType.value && e.kind !== fType.value) return false;
  if (fMode.value && e.mode !== fMode.value) return false;
  if (fDecision.value && e.decision !== fDecision.value) return false;
  if (q.value) { const s = q.value.toLowerCase(); if (![e.actor, e.device, e.resource, e.policy, e.note].some((x) => String(x ?? '').toLowerCase().includes(s))) return false; }
  return true;
}));
const count = (d: string) => merged.value.filter((e) => e.decision === d).length;
const countKind = (k: string) => merged.value.filter((e) => e.kind === k).length;

const catClass = (c: string) => ({ '访问决策': 'zl-badge--accent', '策略变更': 'zl-badge--warn', '配置变更': 'zl-badge--idle', '登录认证': 'zl-badge--ok' }[c] || 'zl-badge--idle');
const decLabel = (d?: string) => decision(d).label;
const decClass = (d?: string) => decision(d).badge;

/* —— 详情 —— */
const drawer = ref(false);
const cur = ref<any>(null);
function openDetail(r: any) { cur.value = r; drawer.value = true; }

const bannerClass = computed(() => {
  const d = cur.value?.decision;
  if (d === 'allow' || d === 'success') return 'ok';
  if (d === 'step-up') return 'stepup';
  if (d === 'deny' || d === 'fail') return 'deny';
  return 'mgmt';
});
const bannerGlyph = computed(() => ({ allow: '✓', success: '✓', 'step-up': '!', deny: '✕', fail: '✕' }[cur.value?.decision as string] || '⚙'));
const bannerText = computed(() => {
  if (!cur.value) return '';
  return (cur.value.category || '事件') + ' · ' + decLabel(cur.value.decision);
});
// 演示派生（真实由网关侧带入）
const srcIp = computed(() => cur.value ? `100.${(cur.value.actor?.length ?? 3) % 64}.${(cur.value.device?.length ?? 7) % 200}.${(cur.value.ts?.replace(/\D/g, '') ?? '1').slice(-2)}` : '');
const chainSeq = computed(() => cur.value ? 4200 - merged.value.indexOf(cur.value) : 0);
const rawJson = computed(() => cur.value ? JSON.stringify({
  ts: cur.value.ts, kind: cur.value.kind, actor: cur.value.actor, device: cur.value.device,
  resource: cur.value.resource, mode: cur.value.mode ?? null,
  decision: cur.value.decision ?? null, policy: cur.value.policy || null,
  note: cur.value.note || null, src_ip: srcIp.value, chain_seq: chainSeq.value, hash_alg: 'HMAC-SM3'
}, null, 2) : '');
function copyJson() { navigator.clipboard?.writeText(rawJson.value); Message.success('原始事件 JSON 已复制'); }

/* —— CSV 导出（客户端，过滤后行）—— */
function exportCsv() {
  const head = ['时间', '类型', '主体', '设备', '资源', '模式', '判定', '命中策略/说明'];
  const rows = filtered.value.map((e) => [e.ts, e.kind, e.actor, e.device, e.resource, e.mode ?? '', e.decision ?? '', e.policy || e.note || '']);
  const csv = [head, ...rows].map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `baidi-audit-${filtered.value.length}.csv`;
  a.click(); URL.revokeObjectURL(a.href);
  Message.success(`已导出 ${filtered.value.length} 条事件`);
}
</script>
<style scoped>
.ev-stats { display: flex; gap: 12px; margin-bottom: 14px; }
.ev-stat { flex: 1; background: var(--surface); border: 1px solid var(--line); border-radius: var(--r-md); padding: 12px 16px; cursor: pointer; text-align: left; transition: all .15s; }
.ev-stat:hover { border-color: var(--accent-line); }
.ev-stat.on { border-color: var(--accent-2); background: var(--accent-soft); }
.ev-stat b { display: block; font-size: 22px; font-weight: 750; color: var(--ink); font-family: var(--font-data); line-height: 1.1; }
.ev-stat span { font-size: 11.5px; color: var(--ink-3); }
.ev-stat.ok b { color: var(--ok); } .ev-stat.danger b { color: var(--danger); }
.ev-stat.warn b { color: var(--warn); } .ev-stat.accent b { color: var(--accent-2); }
.ev-filter { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
.ev-count { font-size: 12px; color: var(--ink-3); margin-left: auto; }
:deep(.row-live) { background: var(--accent-soft); }
:deep(.row-live td) { animation: liverow 1.2s ease; }
:deep(.row-click) { cursor: pointer; }
@keyframes liverow { from { background: var(--accent-line); } to { background: transparent; } }
.ed-banner { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border-radius: var(--r-md); border: 1px solid var(--line); margin-bottom: 16px; }
.ed-banner.ok { border-color: var(--ok); } .ed-banner.deny { border-color: var(--danger); background: var(--danger-soft); }
.ed-banner.stepup { border-color: var(--warn); background: var(--warn-soft); }
.ed-banner.mgmt { border-color: var(--accent-line); background: var(--accent-soft); }
.ed-banner__g { width: 34px; height: 34px; border-radius: 50%; display: grid; place-items: center; font-size: 16px; font-weight: 800; background: var(--surface-2); }
.ed-banner.ok .ed-banner__g { background: var(--ok-soft); color: var(--ok); }
.ed-banner.deny .ed-banner__g { background: var(--danger); color: #fff; }
.ed-banner.stepup .ed-banner__g { background: var(--warn); color: #fff; }
.ed-banner.mgmt .ed-banner__g { color: var(--accent-2); }
.ed-banner__t { font-size: 14px; font-weight: 700; color: var(--ink); }
.ed-banner__d { font-size: 11.5px; color: var(--ink-3); margin-top: 2px; }
.ed-kv { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 0; border-bottom: 1px solid var(--line); font-size: 12.5px; }
.ed-kv span { color: var(--ink-3); flex: none; }
.ed-kv b { color: var(--ink); font-weight: 600; text-align: right; word-break: break-all; }
.ed-link { color: var(--accent-2); text-decoration: none; } .ed-link:hover { text-decoration: underline; }
.ed-sec { font-size: 11.5px; font-weight: 700; color: var(--ink-3); margin: 18px 0 8px; }
.ed-json { margin: 0; padding: 12px; background: var(--surface-2); border-radius: var(--r-md); font-size: 11px; line-height: 1.55; color: var(--ink-2); white-space: pre-wrap; }
.ed-foot { display: flex; justify-content: space-between; gap: 12px; margin-top: 18px; }
</style>
