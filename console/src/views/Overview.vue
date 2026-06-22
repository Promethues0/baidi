<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">运行总览</h1>
        <div class="zl-page__sub">运维 / 容量视角：流量、接入结构与 appliance 资源 · 安全态势见〈安全监控大屏〉</div>
      </div>
      <a-radio-group v-model="range" type="button" size="small">
        <a-radio value="1h">近 1 小时</a-radio>
        <a-radio value="24h">近 24 小时</a-radio>
        <a-radio value="7d">近 7 天</a-radio>
      </a-radio-group>
    </div>

    <!-- 指标卡 -->
    <div class="zl-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 16px;">
      <div v-for="s in runtimeStats" :key="s.label" class="zl-card zl-card__pad">
        <div class="zl-stat">
          <span class="zl-stat__label">{{ s.label }}</span>
          <span class="zl-stat__value data">
            {{ s.value.toLocaleString() }}<span class="unit">{{ s.unit }}</span>
          </span>
          <span v-if="s.trend" class="zl-badge" :class="s.tone === 'warn' ? 'zl-badge--warn' : 'zl-badge--ok'">
            {{ s.trend }} {{ rangeLabel }}
          </span>
        </div>
      </div>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1.5fr 1fr;">
      <!-- 流量趋势 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom: 12px;">
          三模式流量趋势 <span class="zl-page__sub" style="margin:0;">（MB/s）</span>
        </div>
        <v-chart class="chart" :option="trafficOption" autoresize style="height: 280px;" />
      </div>

      <!-- 网关清单（精简） -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom: 12px; display:flex; align-items:baseline; justify-content:space-between;">
          <span>网关健康</span>
          <router-link to="/gateway" style="font-size:12px;font-weight:400;color:var(--accent-2);text-decoration:none">查看全部 →</router-link>
        </div>
        <div v-for="g in gwList" :key="g.name" class="gw-row">
          <div class="gw-row__main">
            <span class="gw-row__name data">{{ g.name }}</span>
            <span class="gw-row__role">{{ g.role }}</span>
          </div>
          <div class="gw-row__modes">
            <span v-for="m in g.modes" :key="m" class="zl-mode-pill" :class="`zl-mode--${m}`">{{ m }}</span>
          </div>
          <span class="zl-badge" :class="statusBadge(g.status)">
            <span class="dot" :style="{ background: 'currentColor' }"></span>{{ statusText(g.status) }}
          </span>
        </div>
      </div>
    </div>

    <!-- 接入分布 / 今日判定 / 系统资源 -->
    <div class="zl-grid" style="grid-template-columns: 1fr 1.4fr; margin-top: 16px;">
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom: 8px;">接入模式分布</div>
        <div class="zl-page__sub" style="margin-bottom: 6px;">活跃会话 / 连接（{{ rangeLabel }}）</div>
        <v-chart :option="modeOption" autoresize style="height: 200px;" />
      </div>

      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom: 14px;">Appliance 系统资源 · 8C/16G</div>
        <div v-for="r in sysRes" :key="r.label" class="sysr">
          <div class="sysr__head"><span>{{ r.label }}</span><b class="data" :style="r.pct>=80?'color:var(--danger)':r.pct>=60?'color:var(--warn)':''">{{ r.val }}</b></div>
          <div class="sysr__bar"><i :style="{ width: r.pct + '%', background: r.pct>=80?'var(--danger)':r.pct>=60?'var(--warn)':'var(--accent-2)' }" /></div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import VChart from 'vue-echarts';
import { use } from 'echarts/core';
import { LineChart, PieChart } from 'echarts/charts';
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { overviewStats, gateways, trafficSeries, type Gateway } from '@/mock';
import { listGateways } from '@/services/gateways';
import { gwStatus } from '@/lib/status';

use([LineChart, PieChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer]);

const range = ref('1h');
const rangeLabel = computed(() => ({ '1h': '近 1 小时', '24h': '近 24 小时', '7d': '近 7 天' } as Record<string, string>)[range.value]);
// 时间窗放大系数：累计类指标按窗放大，瞬时类（在线/会话）保持
const mult = computed(() => ({ '1h': 1, '24h': 18, '7d': 110 } as Record<string, number>)[range.value]);

const scaledStats = computed(() => overviewStats.map((s) => {
  const cumulative = s.label.includes('命中') || s.label.includes('威胁');
  return { ...s, value: cumulative ? Math.round(s.value * mult.value) : s.value };
}));

// 网关健康卡走控制面真实清单；指标卡与流量趋势暂无对应端点，保留演示数据。
const gwList = ref<Gateway[]>([...gateways]);
onMounted(async () => {
  try {
    gwList.value = await listGateways();
  } catch {
    /* 控制面未起：保留 mock 种子 */
  }
});

const onlineGw = computed(() => gwList.value.filter((g) => g.status === 'online').length);
// 运维/容量指标：去掉与安全大屏重复的「在线设备 / 威胁事件」，避免两套 mock 口径打架；
// 保留会话/命中并补「在线网关」（由真实网关清单派生）。
const runtimeStats = computed(() => [
  ...scaledStats.value.filter((s) => s.label.includes('会话') || s.label.includes('命中')),
  { label: '在线网关', value: onlineGw.value, unit: ` / ${gwList.value.length}`, trend: '', tone: 'ok' as const }
]);

// 按时间窗生成横轴与三模式序列（1h 用真实采样；24h/7d 合成确定性序列）
const series = computed(() => {
  if (range.value === '1h') return { axis: trafficSeries.hours, ssl: trafficSeries.ssl, mesh: trafficSeries.mesh, ipsec: trafficSeries.ipsec };
  const n = range.value === '24h' ? 24 : 7;
  const axis = Array.from({ length: n }, (_, i) => range.value === '24h' ? `${String(i).padStart(2, '0')}:00` : `D-${n - i}`);
  const gen = (base: number, amp: number, ph: number) => axis.map((_, i) => +(base + amp * Math.sin(i / 2 + ph) + amp * 0.4 * Math.cos(i)).toFixed(1));
  return { axis, ssl: gen(9, 4, 0), mesh: gen(8, 2.5, 1.5), ipsec: gen(2.7, 1, 3) };
});
const trafficOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  legend: { data: ['SSL', 'Mesh', 'IPSec'], right: 0, top: 0, textStyle: { color: '#8d8579' } },
  grid: { left: 36, right: 12, top: 36, bottom: 28 },
  xAxis: { type: 'category', data: series.value.axis, axisLine: { lineStyle: { color: '#ddd6c9' } }, axisLabel: { color: '#8d8579' } },
  yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(140,128,110,0.16)' } }, axisLabel: { color: '#8d8579' } },
  series: [
    { name: 'SSL', type: 'line', smooth: true, data: series.value.ssl, areaStyle: { opacity: 0.12 }, lineStyle: { width: 2 }, itemStyle: { color: '#d99a45' } },
    { name: 'Mesh', type: 'line', smooth: true, data: series.value.mesh, areaStyle: { opacity: 0.12 }, lineStyle: { width: 2 }, itemStyle: { color: '#bd5a38' } },
    { name: 'IPSec', type: 'line', smooth: true, data: series.value.ipsec, areaStyle: { opacity: 0.1 }, lineStyle: { width: 2 }, itemStyle: { color: '#a89a86' } }
  ]
}));

const donut = (data: { name: string; value: number; color: string }[], center = ['50%', '52%']) => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c}（{d}%）' },
  legend: { bottom: 0, textStyle: { color: '#8d8579', fontSize: 11 } },
  series: [{
    type: 'pie', radius: ['52%', '74%'], center, avoidLabelOverlap: true,
    label: { show: false }, labelLine: { show: false },
    data: data.map((d) => ({ name: d.name, value: d.value, itemStyle: { color: d.color } }))
  }]
});
const modeOption = computed(() => donut([
  { name: 'SSL 会话', value: Math.round(942 * (range.value === '1h' ? 1 : range.value === '24h' ? 1.1 : 1.2)), color: '#d99a45' },
  { name: 'Mesh 连接', value: 318, color: '#bd5a38' },
  { name: 'IPSec 隧道', value: 6, color: '#a89a86' }
]));
const sysRes = computed(() => {
  const load = range.value === '7d' ? 1.15 : 1; // 演示：长窗峰值略高
  const cpu = Math.min(99, Math.round(41 * load));
  return [
    { label: 'CPU（8 核）', pct: cpu, val: cpu + '%' },
    { label: '内存（16G）', pct: 63, val: '63% · 10.1G' },
    { label: '会话表', pct: 38, val: '38% · 47.6万/125万' },
    { label: '吞吐', pct: 24, val: '2.4 / 10 Gbps' },
    { label: 'netstack goroutine', pct: 19, val: '1,920' }
  ];
});

const statusBadge = (s: string) => gwStatus(s).badge;
const statusText = (s: string) => gwStatus(s).label;
</script>

<style scoped>
.gw-row { display: flex; align-items: center; gap: 10px; padding: 11px 0; border-bottom: 1px solid var(--line); }
.gw-row:last-child { border-bottom: 0; }
.gw-row__main { flex: 1; display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.gw-row__name { font-size: 13px; font-weight: 600; color: var(--ink); }
.gw-row__role { font-size: 11.5px; color: var(--ink-3); }
.gw-row__modes { display: flex; gap: 4px; }
.sysr { margin-bottom: 12px; }
.sysr:last-child { margin-bottom: 0; }
.sysr__head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 5px; font-size: 12px; color: var(--ink-3); }
.sysr__head b { font-size: 12.5px; color: var(--ink); font-weight: 650; }
.sysr__bar { height: 6px; border-radius: 3px; background: var(--surface-3, rgba(140,128,110,0.16)); overflow: hidden; }
.sysr__bar i { display: block; height: 100%; border-radius: 3px; transition: width .3s; }
</style>
