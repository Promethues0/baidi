<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">设备状态</div>
        <div class="bd-page__sub">数据面网关宿主机的资源水位与吞吐 · 采不到的指标如实标「不可判定」，不补 0</div>
      </div>
      <div class="bd-head__right">
        <a-radio-group v-model="range" type="button" size="small" @change="load">
          <a-radio value="hour">小时</a-radio>
          <a-radio value="day">天</a-radio>
          <a-radio value="week">周</a-radio>
        </a-radio-group>
        <a-tag :color="live ? 'green' : 'red'" bordered>
          <template #icon><icon-cloud /></template>
          {{ live ? '已连 baidi-control' : '未连控制面' }}
        </a-tag>
        <a-button :loading="loading" @click="load">
          <template #icon><icon-refresh /></template>刷新
        </a-button>
      </div>
    </div>

    <!--
      ★这一页刻意**没有降级演示数据**（与控制台其余页不同）。
      设备状态的全部意义是「这台机器现在什么水位」——编一组好看的曲线出来，
      读者无从分辨它是真实采集还是占位，而这正是最坏的一种误导。
      连不上控制面就说连不上，一条线都不画。
    -->
    <div v-if="err" class="bd-tip bd-tip--err">
      <icon-exclamation-circle-fill class="bd-tip__ic" />
      <span>无法从控制面读取设备状态：{{ err }}。本页不提供演示数据——编造的曲线无法与真实采集区分。</span>
    </div>

    <template v-else>
      <!-- 时间窗被留存期截断：如实说明，否则左侧一大片空白看起来像采集坏了 -->
      <div v-if="resp && resp.truncated" class="bd-tip">
        <icon-info-circle class="bd-tip__ic" />
        <span>{{ resp.rangeLabel }}的窗口已按留存策略截断到最近 {{ resp.retentionHours }} 小时（BAIDI_METRICS_RETENTION_HOURS）：更早的采样点已被清理。</span>
      </div>

      <!-- 空态一：一台上报指标的网关都没有 -->
      <div v-if="!series.length" class="bd-card bd-empty bd-empty--lg">
        <icon-storage />
        <div class="bd-empty__main">无数据面上报</div>
        <div class="bd-empty__sub">
          <template v-if="silent.length">
            当前有 {{ resp?.onlineGateways ?? 0 }} 台网关在线，但它们都没有上报宿主机指标：
            <b class="bd-mono">{{ silent.join('、') }}</b>。
            设备状态采集是新版本网关才有的能力，升级 baidi-gateway 后本页即有数据。
          </template>
          <template v-else>
            还没有任何数据面网关向控制面注册并上报指标。网关需以 mTLS 客户端证书接入
            （<span class="bd-mono">-control</span> + <span class="bd-mono">-mtls-*</span>），心跳会自动带上设备状态。
          </template>
        </div>
      </div>

      <!-- 空态二：有网关在报，但另有网关在线却不报——两种处境要分开讲 -->
      <div v-else-if="silent.length" class="bd-tip bd-tip--warn">
        <icon-exclamation-circle class="bd-tip__ic" />
        <span>
          另有 {{ silent.length }} 台在线网关未上报设备指标（<span class="bd-mono">{{ silent.join('、') }}</span>）：
          多半是网关版本过旧。它们不会出现在下方图表里——这里不为它们补零线。
        </span>
      </div>

      <!-- 每台网关一块 -->
      <a-card v-for="g in series" :key="g.gatewayId" class="bd-card bd-gw" :bordered="false">
        <div class="bd-gw__head">
          <div class="bd-gw__id">
            <icon-storage />
            <span class="bd-mono">{{ g.gatewayId }}</span>
          </div>
          <div class="bd-gw__ts">
            <span v-if="!g.latest">该网关在本窗口内无采样</span>
            <template v-else>
              <a-tag v-if="isStale(g.latest.ts)" color="orangered" size="small" bordered>数据陈旧</a-tag>
              最后上报 {{ agoText(g.latest.ts) }}（{{ clockText(g.latest.ts) }}）
            </template>
          </div>
        </div>

        <!-- 当前值：取的是最新一条**原始采样**，不是最后一个桶的均值 -->
        <div class="bd-tiles">
          <div v-for="t in tiles(g)" :key="t.key" class="bd-tile">
            <div class="bd-tile__label">{{ t.label }}</div>
            <div class="bd-tile__value" :class="{ unknown: t.text === UNKNOWN }" :style="{ color: t.text === UNKNOWN ? '' : t.color }">
              {{ t.text }}
            </div>
            <div v-if="t.pct !== null" class="bd-tile__bar">
              <span :style="{ width: t.pct + '%', background: t.color }" />
            </div>
            <div v-else class="bd-tile__hint">{{ t.hint }}</div>
          </div>
        </div>

        <!-- 趋势图 -->
        <div class="bd-charts">
          <div v-for="c in CHARTS" :key="c.title" class="bd-chart">
            <div class="bd-chart__head">
              <span class="bd-chart__title">{{ c.title }}</span>
              <span class="bd-chart__legend">
                <span v-for="ln in c.lines" :key="ln.key" class="bd-lg">
                  <i :style="{ background: ln.color }" />{{ ln.label }}
                </span>
              </span>
            </div>
            <ChartBody :chart="c" :series="g" :view="viewBox" />
          </div>
        </div>
      </a-card>
    </template>
  </div>
</template>

<script setup lang="ts">
/**
 * 监控中心 · 设备状态（PRD ch5 FR-MON-01/02）。
 *
 * 三条不能破的规矩，全部对应本项目踩过的坑：
 *
 *  ① **不可判定 ≠ 0**。后端把采不到的指标下发成 null，这里渲染成「—」并写明原因。
 *     写成 `v ?? 0` 就会让一台采集失明的网关显示成「CPU 0%」的健康机器。
 *  ② **不画假的平线**。后端不返回空桶；折线遇到 null 或桶间跨度超过一个桶宽即断开，
 *     掉线段在图上是空白，不是一条贴地的直线。
 *  ③ **当前值来自最新那条原始采样**，不是最后一个桶的均值——桶均值会把刚冲到 95%
 *     的机器摊平成 60%，而这一页存在的意义就是看现在。
 *
 * 图表用内联 SVG 手绘：package.json 里虽然挂着 echarts，但全仓一处未用（等于未落地的依赖），
 * 为一页折线把它拉进包体不划算，也不符合「不引新依赖」。
 */
import { ref, computed, onMounted, h, type PropType, type VNode } from 'vue';
import { api, type DeviceStatResp, type DeviceMetricSeries, type DeviceStatRange, type MetricValue } from '@/lib/api';

/** 不可判定的统一呈现。整页只有这一处字面量，避免有人某处写成 0。 */
const UNKNOWN = '—';

type MetricKey = 'cpu' | 'mem' | 'disk' | 'load' | 'rxBps' | 'txBps';
interface ChartLine { key: MetricKey; label: string; color: string }
interface ChartSpec {
  title: string;
  /** 固定纵轴上界（百分比图恒 0-100，免得两台机器的图不能横向比）；不填即按数据自适应。 */
  fixedMax?: number;
  format: (v: number) => string;
  lines: ChartLine[];
}

const CHARTS: ChartSpec[] = [
  {
    title: '资源占用（%）', fixedMax: 100, format: (v) => v.toFixed(0) + '%',
    lines: [
      { key: 'cpu', label: 'CPU', color: '#165DFF' },
      { key: 'mem', label: '内存', color: '#00B42A' },
      { key: 'disk', label: '磁盘', color: '#FF7D00' }
    ]
  },
  {
    title: '网络吞吐', format: fmtBps,
    lines: [
      { key: 'rxBps', label: '接收', color: '#722ED1' },
      { key: 'txBps', label: '发送', color: '#F53F3F' }
    ]
  },
  {
    title: '系统负载', format: (v) => v.toFixed(2),
    lines: [{ key: 'load', label: '1 分钟平均', color: '#0E42D2' }]
  }
];

/** SVG 画布坐标（viewBox 单位，不是像素——外层按容器宽度缩放）。 */
const viewBox = { w: 480, h: 120, padL: 34, padR: 6, padT: 8, padB: 16 };

const range = ref<DeviceStatRange>('hour');
const resp = ref<DeviceStatResp | null>(null);
const loading = ref(false);
const live = ref(false);
const err = ref('');

const series = computed<DeviceMetricSeries[]>(() => resp.value?.gateways ?? []);
const silent = computed<string[]>(() => resp.value?.silentGateways ?? []);

/** 网关心跳新鲜度窗口，与控制面 gatewayOnlineWindow 同为 120s。 */
const STALE_SEC = 120;
function isStale(ts: number) {
  const now = resp.value?.until ?? Math.floor(Date.now() / 1000);
  return now - ts > STALE_SEC;
}

function agoText(ts: number) {
  const now = resp.value?.until ?? Math.floor(Date.now() / 1000);
  const s = Math.max(0, now - ts);
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}
function clockText(ts: number) {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** 横轴刻度：窗口跨度超过一天就带上日期，否则只给时分（周档全是 hh:mm 会分不清哪天）。 */
function axisTime(ts: number): string {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, '0');
  const hm = `${p(d.getHours())}:${p(d.getMinutes())}`;
  const span = (resp.value?.until ?? 0) - (resp.value?.since ?? 0);
  return span > 86400 ? `${p(d.getMonth() + 1)}-${p(d.getDate())} ${hm}` : hm;
}

function fmtBps(v: number): string {
  if (v < 1024) return `${v.toFixed(0)} B/s`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
  if (v < 1024 * 1024 * 1024) return `${(v / 1024 / 1024).toFixed(2)} MB/s`;
  return `${(v / 1024 / 1024 / 1024).toFixed(2)} GB/s`;
}

/** 水位配色：越接近满越红。只影响观感，不参与任何判定。 */
function pctColor(v: number) {
  if (v >= 90) return '#F53F3F';
  if (v >= 75) return '#FF7D00';
  return '#165DFF';
}

interface Tile { key: string; label: string; text: string; color: string; pct: number | null; hint: string }

/**
 * 当前值磁贴。★数据源固定是 latest（最新原始采样），并且 null 一律走 UNKNOWN 分支——
 * 这里是全页最容易被顺手写成 `?? 0` 的地方。
 */
function tiles(g: DeviceMetricSeries): Tile[] {
  const l = g.latest;
  const pct = (key: 'cpu' | 'mem' | 'disk', label: string, hint: string): Tile => {
    const v: MetricValue = l ? l[key] : null;
    if (v === null || v === undefined) {
      return { key, label, text: UNKNOWN, color: '', pct: null, hint };
    }
    return { key, label, text: v.toFixed(1) + '%', color: pctColor(v), pct: Math.min(100, Math.max(0, v)), hint: '' };
  };
  const plain = (key: 'load' | 'rxBps' | 'txBps', label: string, fmt: (v: number) => string, hint: string): Tile => {
    const v: MetricValue = l ? l[key] : null;
    if (v === null || v === undefined) {
      return { key, label, text: UNKNOWN, color: '', pct: null, hint };
    }
    return { key, label, text: fmt(v), color: 'var(--bd-t1)', pct: null, hint: '' };
  };
  return [
    pct('cpu', 'CPU 使用率', '该网关采不到 CPU（如 macOS 宿主机：取 CPU 时间片需 cgo）'),
    pct('mem', '内存使用率', '该网关采不到内存'),
    pct('disk', '磁盘使用率', '该网关采不到磁盘水位'),
    plain('load', '1 分钟负载', (v) => v.toFixed(2), '该网关采不到系统负载'),
    plain('rxBps', '接收速率', fmtBps, '需要连续两次心跳才算得出速率'),
    plain('txBps', '发送速率', fmtBps, '需要连续两次心跳才算得出速率')
  ];
}

/**
 * 折线渲染组件（函数式，就近定义：它只服务这一页，抽到 components/ 属于过早通用化）。
 *
 * ★断线规则是本组件的全部要点：
 *   - 值为 null（不可判定）→ 抬笔；
 *   - 相邻两个桶的时间跨度 > 1.5 个桶宽（中间有空桶 = 网关掉线）→ 抬笔重新起笔。
 * 少了任何一条，图上都会出现一条跨越空洞的直线，而它是纯粹虚构的。
 */
const ChartBody = (props: {
  chart: ChartSpec;
  series: DeviceMetricSeries;
  view: typeof viewBox;
}) => {
  const { chart, series: g, view } = props;
  const r = resp.value;
  const pts = g.points;

  // 该图涉及的指标在窗内是否有任何一个真值
  const values: number[] = [];
  for (const p of pts) {
    for (const ln of chart.lines) {
      const v = p[ln.key];
      if (v !== null && v !== undefined) values.push(v);
    }
  }
  if (!values.length) {
    return h('div', { class: 'bd-chart__empty' },
      `窗口内没有可用的${chart.title}采样（网关未采集到，或此段时间未上报）`);
  }

  const t0 = r?.since ?? pts[0].ts;
  const t1 = r?.until ?? pts[pts.length - 1].ts + 1;
  const bucket = r?.bucketSec ?? 60;
  // 自适应上界向上留 10% 余量；全 0 时给 1，免得除零（rx=0 B/s 是真实读数，要画在底线上）
  const rawMax = Math.max(...values);
  const max = chart.fixedMax ?? (rawMax > 0 ? rawMax * 1.1 : 1);

  const innerW = view.w - view.padL - view.padR;
  const innerH = view.h - view.padT - view.padB;
  const xOf = (ts: number) => view.padL + (t1 > t0 ? ((ts - t0) / (t1 - t0)) * innerW : 0);
  const yOf = (v: number) => view.padT + innerH - Math.min(1, Math.max(0, v / max)) * innerH;

  const children: VNode[] = [];

  // 网格与纵轴刻度（3 档：0 / 中 / 上界）
  for (const frac of [0, 0.5, 1]) {
    const y = view.padT + innerH - frac * innerH;
    children.push(h('line', {
      x1: view.padL, y1: y, x2: view.w - view.padR, y2: y,
      stroke: 'var(--bd-border)', 'stroke-width': 0.6, 'stroke-dasharray': frac === 0 ? '' : '3 3'
    }));
    children.push(h('text', {
      x: view.padL - 4, y: y + 3, 'text-anchor': 'end',
      'font-size': 8, fill: 'var(--bd-t3)'
    }, chart.format(max * frac)));
  }

  // 逐条线：断线 + 孤点补圆点（孤点只有 M 指令，不画点就完全看不见）
  for (const ln of chart.lines) {
    let d = '';
    let penDown = false;
    let lastTs = 0;
    let lastPlotted: { x: number; y: number } | null = null;
    let segLen = 0;
    const dots: Array<{ x: number; y: number }> = [];
    const flushSeg = () => {
      if (segLen === 1 && lastPlotted) dots.push(lastPlotted);
      segLen = 0;
    };
    for (const p of pts) {
      const v = p[ln.key];
      if (v === null || v === undefined) { flushSeg(); penDown = false; continue; }
      const x = xOf(p.ts);
      const y = yOf(v);
      const gap = penDown && p.ts - lastTs > bucket * 1.5;
      if (gap) flushSeg();
      if (!penDown || gap) {
        d += `M${x.toFixed(1)} ${y.toFixed(1)}`;
        penDown = true;
        segLen = 1;
      } else {
        d += ` L${x.toFixed(1)} ${y.toFixed(1)}`;
        segLen++;
      }
      lastTs = p.ts;
      lastPlotted = { x, y };
    }
    flushSeg();
    if (d) {
      children.push(h('path', {
        d, fill: 'none', stroke: ln.color, 'stroke-width': 1.6,
        'stroke-linejoin': 'round', 'stroke-linecap': 'round'
      }));
    }
    for (const dot of dots) {
      children.push(h('circle', { cx: dot.x, cy: dot.y, r: 1.8, fill: ln.color }));
    }
  }

  // 横轴两端标出窗口起止时刻：数据只覆盖窗口一小段时，看得出「是数据少」而不是「图坏了」
  children.push(h('text', {
    x: view.padL, y: view.h - 4, 'text-anchor': 'start', 'font-size': 8, fill: 'var(--bd-t3)'
  }, axisTime(t0)));
  children.push(h('text', {
    x: view.w - view.padR, y: view.h - 4, 'text-anchor': 'end', 'font-size': 8, fill: 'var(--bd-t3)'
  }, axisTime(t1)));

  return h('svg', {
    class: 'bd-chart__svg', viewBox: `0 0 ${view.w} ${view.h}`,
    width: '100%', preserveAspectRatio: 'none', role: 'img',
    'aria-label': `${g.gatewayId} 的${chart.title}趋势`
  }, children);
};
ChartBody.props = {
  chart: { type: Object as PropType<ChartSpec>, required: true },
  series: { type: Object as PropType<DeviceMetricSeries>, required: true },
  view: { type: Object as PropType<typeof viewBox>, required: true }
};

async function load() {
  loading.value = true;
  try {
    resp.value = await api<DeviceStatResp>(`/monitor/device-stat?range=${range.value}`);
    live.value = true;
    err.value = '';
  } catch (e) {
    // 不回退演示数据：连不上就说连不上（见文件头 ①/②）
    resp.value = null;
    live.value = false;
    err.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.bd-tip {
  display: flex; align-items: flex-start; gap: 8px; margin-bottom: 16px;
  padding: 10px 14px; border-radius: var(--bd-radius);
  background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b);
  font-size: 12.5px; color: var(--bd-t2); line-height: 1.6;
}
.bd-tip__ic { color: var(--bd-primary); font-size: 16px; flex: none; margin-top: 2px; }
.bd-tip--warn { background: var(--bd-tag-gold-bg); border-color: #FFCF8B; }
.bd-tip--warn .bd-tip__ic { color: var(--bd-warning); }
.bd-tip--err { background: var(--bd-tag-red-bg); border-color: #FBACA3; }
.bd-tip--err .bd-tip__ic { color: var(--bd-danger); }

.bd-empty {
  display: flex; flex-direction: column; align-items: center; gap: 6px;
  padding: 44px 24px; text-align: center; color: var(--bd-t3);
}
.bd-empty :deep(svg) { font-size: 30px; color: var(--bd-t4); }
.bd-empty__main { font-size: 15px; font-weight: 600; color: var(--bd-t2); }
.bd-empty__sub { font-size: 12.5px; line-height: 1.7; max-width: 620px; }

.bd-gw { margin-bottom: 14px; border-radius: var(--bd-radius); }
.bd-gw__head {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap; margin-bottom: 14px;
}
.bd-gw__id { display: flex; align-items: center; gap: 7px; font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-gw__id :deep(svg) { color: var(--bd-primary); }
.bd-gw__ts { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--bd-t3); }

/* 当前值磁贴 */
.bd-tiles {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px; margin-bottom: 16px;
}
.bd-tile { padding: 10px 12px; border-radius: var(--bd-radius-s); background: var(--bd-fill-1); }
.bd-tile__label { font-size: 12px; color: var(--bd-t3); }
.bd-tile__value {
  font-size: 20px; font-weight: 700; line-height: 1.5;
  font-variant-numeric: tabular-nums; color: var(--bd-t1);
}
/* 不可判定：灰、细、明显不是一个读数——绝不让它长得像 0 */
.bd-tile__value.unknown { color: var(--bd-t4); font-weight: 500; }
.bd-tile__bar { height: 4px; border-radius: 2px; background: var(--bd-fill-2); overflow: hidden; }
.bd-tile__bar span { display: block; height: 100%; border-radius: 2px; transition: width .2s; }
.bd-tile__hint { font-size: 11px; color: var(--bd-t4); line-height: 1.5; }

/* 趋势图 */
.bd-charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
.bd-chart { border: 1px solid var(--bd-border); border-radius: var(--bd-radius-s); padding: 10px 12px 6px; }
.bd-chart__head { display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; margin-bottom: 4px; }
.bd-chart__title { font-size: 12.5px; font-weight: 600; color: var(--bd-t2); }
.bd-chart__legend { display: flex; gap: 10px; }
.bd-lg { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; color: var(--bd-t3); }
.bd-lg i { width: 8px; height: 2.5px; border-radius: 2px; display: inline-block; }
.bd-chart__svg { display: block; height: 120px; }
.bd-chart__empty { padding: 34px 8px; text-align: center; font-size: 12px; color: var(--bd-t4); line-height: 1.6; }

.bd-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
</style>
