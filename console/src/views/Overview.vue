<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">安全监控大屏</div>
        <div class="bd-page__sub">三道防线 · 在线会话 · 实时判定态势 · 数据时间 {{ stamp }}</div>
      </div>
      <a-space>
        <a-tag :color="live ? 'green' : 'orange'" bordered>
          <template #icon><icon-cloud /></template>
          {{ live ? '已连 baidi-control' : '降级演示 · 内置数据' }}
        </a-tag>
        <a-button :loading="loading" @click="load">
          <template #icon><icon-refresh /></template>刷新
        </a-button>
      </a-space>
    </div>

    <!-- KPI 行 -->
    <a-grid :cols="{ xs: 1, sm: 2, lg: 4 }" :col-gap="16" :row-gap="16">
      <a-grid-item>
        <a-card class="bd-kpi" :bordered="false">
          <div class="bd-kpi__label">在线设备</div>
          <div class="bd-kpi__value">{{ ov.devices.online }}<span class="bd-kpi__unit"> / {{ ov.devices.total }}</span></div>
          <a-progress :percent="ov.devices.rate" :show-text="false" size="small" :color="brand" />
          <div class="bd-kpi__foot">在线率 {{ (ov.devices.rate * 100).toFixed(0) }}%</div>
        </a-card>
      </a-grid-item>
      <a-grid-item>
        <a-card class="bd-kpi" :bordered="false">
          <div class="bd-kpi__label">纳管用户</div>
          <div class="bd-kpi__value">{{ ov.users.total }}</div>
          <div class="bd-kpi__foot">禁用 {{ ov.users.disabled }} · 锁定 {{ ov.users.locked }}</div>
        </a-card>
      </a-grid-item>
      <a-grid-item>
        <a-card class="bd-kpi" :bordered="false">
          <div class="bd-kpi__label">在线会话</div>
          <div class="bd-kpi__value">{{ ov.sessions }}</div>
          <div class="bd-kpi__foot">当前活跃接入</div>
        </a-card>
      </a-grid-item>
      <a-grid-item>
        <a-card class="bd-kpi" :bordered="false">
          <div class="bd-kpi__label">威胁事件</div>
          <div class="bd-kpi__value bd-kpi__value--danger">{{ threats }}</div>
          <div class="bd-kpi__foot">拒绝 {{ ov.threats.rejected }} · 失败 {{ ov.threats.failed }} · 二次鉴权 {{ ov.threats.secondary }}</div>
        </a-card>
      </a-grid-item>
    </a-grid>

    <!-- 三道防线 -->
    <div class="bd-section-title">三道防线</div>
    <a-grid :cols="{ xs: 1, md: 3 }" :col-gap="16" :row-gap="16">
      <a-grid-item v-for="d in ov.defense" :key="d.key">
        <a-card class="bd-line" :bordered="false">
          <div class="bd-line__head">
            <span class="bd-line__name">{{ d.name }}</span>
            <a-tag :color="riskColor(d.risk)" size="small">{{ riskLabel(d.risk) }}</a-tag>
          </div>
          <div class="bd-line__risk">
            <span class="bd-line__score" :style="{ color: riskHex(d.risk) }">{{ d.risk }}</span>
            <span class="bd-line__unit">风险分</span>
            <component :is="trendIcon(d.trend)" class="bd-line__trend" :style="{ color: trendHex(d.trend) }" />
          </div>
          <a-progress :percent="d.risk / 100" :show-text="false" size="mini" :color="riskHex(d.risk)" />
          <div class="bd-line__top">
            <div class="bd-line__top-h">TOP 风险实体</div>
            <div v-for="(e, i) in d.top" :key="e" class="bd-line__top-row">
              <span class="bd-line__rank">{{ i + 1 }}</span><span class="bd-line__ent">{{ e }}</span>
            </div>
          </div>
        </a-card>
      </a-grid-item>
    </a-grid>

    <!-- 分布 -->
    <a-grid :cols="{ xs: 1, lg: 2 }" :col-gap="16" :row-gap="16" style="margin-top: 16px">
      <a-grid-item>
        <a-card class="bd-bars" :bordered="false" title="审计类别分布">
          <div v-for="b in ov.auditByKind" :key="b.name" class="bd-bar">
            <span class="bd-bar__label">{{ b.name }}</span>
            <span class="bd-bar__track"><span class="bd-bar__fill" :style="{ width: pct(b.value, auditMax), background: brand }" /></span>
            <span class="bd-bar__val">{{ b.value }}</span>
          </div>
        </a-card>
      </a-grid-item>
      <a-grid-item>
        <a-card class="bd-bars" :bordered="false" title="访问判定分布">
          <div v-for="b in ov.verdicts" :key="b.name" class="bd-bar">
            <span class="bd-bar__label">{{ b.name }}</span>
            <span class="bd-bar__track"><span class="bd-bar__fill" :style="{ width: pct(b.value, verdictMax), background: verdictColor(b.name) }" /></span>
            <span class="bd-bar__val">{{ b.value }}</span>
          </div>
        </a-card>
      </a-grid-item>
    </a-grid>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type Overview } from '@/lib/api';

const brand = '#165DFF';

const MOCK: Overview = {
  generatedAt: '',
  devices: { online: 186, total: 240, rate: 0.775 },
  users: { total: 312, disabled: 7, locked: 4 },
  threats: { rejected: 173, failed: 62, secondary: 53 },
  sessions: 186,
  auditByKind: [
    { name: '访问决策', value: 1284 }, { name: '登录认证', value: 642 },
    { name: '策略变更', value: 73 }, { name: '配置变更', value: 41 }
  ],
  verdicts: [
    { name: '允许', value: 1102 }, { name: '二次鉴权', value: 128 },
    { name: '拒绝', value: 173 }, { name: '降权', value: 39 }
  ],
  defense: [
    { key: 'device', name: '设备防线', risk: 28, trend: 'down', top: ['203.0.113.7', '198.51.100.22', '203.0.113.91'] },
    { key: 'account', name: '账号防线', risk: 41, trend: 'up', top: ['li.fang', '外包-zhao', 'svc-bot-04'] },
    { key: 'endpoint', name: '终端防线', risk: 19, trend: 'flat', top: ['WIN-诊室-12', 'MAC-研发-08', '未授信-Android-3'] }
  ]
};

const ov = ref<Overview>(MOCK);
const live = ref(false);
const loading = ref(false);

const stamp = computed(() => (ov.value.generatedAt ? ov.value.generatedAt.replace('T', ' ').slice(0, 19) : '—'));
const threats = computed(() => ov.value.threats.rejected + ov.value.threats.failed + ov.value.threats.secondary);
const auditMax = computed(() => Math.max(...ov.value.auditByKind.map((b) => b.value), 1));
const verdictMax = computed(() => Math.max(...ov.value.verdicts.map((b) => b.value), 1));

function pct(v: number, max: number) { return `${Math.round((v / max) * 100)}%`; }
function riskColor(r: number) { return r >= 40 ? 'red' : r >= 25 ? 'orange' : 'green'; }
function riskHex(r: number) { return r >= 40 ? '#F53F3F' : r >= 25 ? '#FF7D00' : '#00B42A'; }
function riskLabel(r: number) { return r >= 40 ? '高风险' : r >= 25 ? '关注' : '良好'; }
function trendIcon(t: string) { return t === 'up' ? 'IconArrowRise' : t === 'down' ? 'IconArrowFall' : 'IconMinus'; }
function trendHex(t: string) { return t === 'up' ? '#F53F3F' : t === 'down' ? '#00B42A' : '#86909C'; }
function verdictColor(name: string) {
  return name === '拒绝' ? '#F53F3F' : name === '二次鉴权' ? '#FF7D00' : name === '降权' ? '#FF9A2E' : '#165DFF';
}

async function load() {
  loading.value = true;
  try {
    ov.value = await api<Overview>('/overview');
    live.value = true;
  } catch {
    ov.value = { ...MOCK, generatedAt: new Date().toISOString() };
    live.value = false;
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.bd-kpi { border-radius: var(--bd-radius); }
.bd-kpi__label { font-size: 13px; color: var(--color-text-3); }
.bd-kpi__value { font-size: 30px; font-weight: 700; line-height: 1.4; color: var(--color-text-1); }
.bd-kpi__value--danger { color: var(--bd-danger); }
.bd-kpi__unit { font-size: 15px; font-weight: 400; color: var(--color-text-3); }
.bd-kpi__foot { font-size: 12px; color: var(--color-text-3); margin-top: 6px; }

.bd-line { border-radius: var(--bd-radius); }
.bd-line__head { display: flex; align-items: center; justify-content: space-between; }
.bd-line__name { font-weight: 600; color: var(--color-text-1); }
.bd-line__risk { display: flex; align-items: baseline; gap: 6px; margin: 10px 0 8px; }
.bd-line__score { font-size: 28px; font-weight: 700; }
.bd-line__unit { font-size: 12px; color: var(--color-text-3); }
.bd-line__trend { margin-left: auto; font-size: 18px; }
.bd-line__top { margin-top: 14px; }
.bd-line__top-h { font-size: 12px; color: var(--color-text-3); margin-bottom: 8px; }
.bd-line__top-row { display: flex; align-items: center; gap: 8px; padding: 3px 0; font-size: 13px; }
.bd-line__rank {
  width: 18px; height: 18px; border-radius: 4px; background: var(--color-fill-2);
  color: var(--color-text-2); font-size: 11px; display: inline-flex; align-items: center; justify-content: center;
}
.bd-line__ent { color: var(--color-text-1); font-variant-numeric: tabular-nums; }

.bd-bars { border-radius: var(--bd-radius); }
.bd-bar { display: flex; align-items: center; gap: 12px; padding: 7px 0; }
.bd-bar__label { width: 72px; font-size: 13px; color: var(--color-text-2); flex-shrink: 0; }
.bd-bar__track { flex: 1; height: 10px; background: var(--color-fill-2); border-radius: 6px; overflow: hidden; }
.bd-bar__fill { display: block; height: 100%; border-radius: 6px; transition: width 0.4s ease; }
.bd-bar__val { width: 48px; text-align: right; font-size: 13px; font-variant-numeric: tabular-nums; color: var(--color-text-1); }
</style>
