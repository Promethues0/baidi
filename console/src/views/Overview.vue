<template>
  <div class="bd-page">
    <PageHeader title="安全监控大屏" :live="live" off-text="降级演示">
      <template #subtitle>三道防线 · 在线会话 · 数据时间 {{ stamp }}</template>
      <!-- 时间窗：审计派生统计与攻击源共用它。★对账号/终端两条防线不生效，
           逐卡片标出（见 DefenseLine.scope）——悄悄不生效的筛选比没有更坏。 -->
      <a-radio-group v-model="hours" type="button" size="small" @change="load">
        <a-radio :value="24">24 小时</a-radio>
        <a-radio :value="168">7 天</a-radio>
        <a-radio :value="720">30 天</a-radio>
      </a-radio-group>
      <a-button :loading="loading" @click="load">
        <template #icon><icon-refresh /></template>刷新
      </a-button>
    </PageHeader>

    <!-- 首屏骨架：第一次 load() 回来之前不画 MOCK——那一瞬间 240 台终端闪一下再变成真数，显示的是假数。 -->
    <template v-if="!loaded">
      <div class="bd-ov__kpis">
        <div v-for="i in 4" :key="i" class="bd-card"><SkeletonBlock kind="stat" /></div>
      </div>
      <div class="bd-section-title">三道防线</div>
      <div class="bd-ov__lines">
        <div v-for="i in 3" :key="i" class="bd-card"><SkeletonBlock kind="card" :rows="4" /></div>
      </div>
    </template>

    <template v-else>
    <!-- ★读取失败时，后端那句原话必须在页面上有地方看。改造前唯一的线索是页头右上
         那枚橙色「降级演示」标签：用户看得出"出事了"，却看不到"是什么事"——而
         /overview 的失败有两种截然不同的处境（连不上控制面 / 403 权限拒绝），
         下一步动作完全相反。归因一律来自 failReason(e)，前端不猜。 -->
    <div v-if="live === false" class="bd-notice bd-notice--warn">
      <icon-exclamation-circle-fill />
      <div class="bd-notice__body">
        本页数据未读取（后端原话：<b>{{ loadErr }}</b>），下面的 KPI、三道防线与分布图
        是<b>内置演示数据</b>，<b>不代表现场情况</b>。
      </div>
    </div>

    <!-- 口径说明：后端下发，前端不自己编——它要说清「哪些数按窗口算、
         哪些是当前状态、实际能回溯多久」，任何一处与后端脱节都会变成误导。 -->
    <div v-if="ov.windowNote" class="bd-notice" :class="ov.truncated ? 'bd-notice--warn' : 'bd-notice--plain'">
      <icon-info-circle-fill /><span>{{ ov.windowNote }}</span>
    </div>

    <!-- KPI 行 -->
    <div class="bd-ov__kpis">
      <StatCard label="授信终端" :value="ov.devices.trusted" :unit="`/ ${ov.devices.total}`"
        :foot="`纳管率 ${(ov.devices.rate * 100).toFixed(0)}% · 待审批 ${ov.devices.pending} · 已吊销 ${ov.devices.revoked}`">
        <template #extra><a-progress :percent="ov.devices.rate" :show-text="false" size="small" :color="brand" /></template>
      </StatCard>
      <StatCard label="纳管用户" :value="ov.users.total" :foot="`禁用 ${ov.users.disabled} · 锁定 ${ov.users.locked}`" />
      <!-- ★三态：sessions 缺席 = 控制面收不到任何网关心跳，"有谁接入"没有数据源。
           改造前后端那句 `if n >= 0` 的 -1 分支等于白写（store 侧恒 0），
           于是「不可判定」与「确实 0 个」在这一格上是同一个字，底下还标着
           「当前活跃接入」。渲染口径与 DeviceStat 的不可判定磁贴一致——StatCard 对
           null/undefined 画「—」，脚注换成 unknownText，绝不写 `?? 0`。 -->
      <StatCard label="在线会话" :value="sessionsUnknown ? null : ov.sessions" foot="当前活跃接入"
        unknown-text="无网关上报心跳，接入数不可判定（隧道可能仍在转发）" />
      <StatCard label="威胁事件" :value="threats" tone="danger"
        :foot="`拒绝 ${ov.threats.rejected} · 失败 ${ov.threats.failed} · 二次鉴权 ${ov.threats.secondary}`" />
    </div>

    <!-- 三道防线 -->
    <div class="bd-section-title">三道防线</div>
    <div class="bd-ov__lines">
      <div v-for="d in ov.defense" :key="d.key" class="bd-card bd-line">
        <div class="bd-line__head">
          <span class="bd-line__name">{{ d.name }}</span>
          <span class="bd-line__tags">
            <!-- 口径标签：window = 按所选时间窗；current = 当前状态，与时间窗无关。 -->
            <a-tag size="small" :color="d.scope === 'window' ? 'arcoblue' : 'gray'">
              {{ d.scope === 'window' ? scopeText : '当前状态' }}
            </a-tag>
            <a-tag :color="riskColor(d.risk)" size="small">{{ riskLabel(d.risk) }}</a-tag>
          </span>
        </div>
        <div class="bd-line__risk">
          <span class="bd-line__score" :class="`bd-line__score--${riskTone(d.risk)}`">{{ d.risk }}</span>
          <span class="bd-line__unit">风险分</span>
        </div>
        <a-progress :percent="d.risk / 100" :show-text="false" size="mini" :color="riskHex(d.risk)" />
        <div class="bd-line__top">
          <div class="bd-line__top-h">TOP 风险实体</div>
          <div v-for="(e, i) in d.top" :key="e" class="bd-line__top-row">
            <span class="bd-line__rank">{{ i + 1 }}</span><span class="bd-line__ent">{{ e }}</span>
          </div>
          <div v-if="!d.top.length" class="bd-line__none">暂无风险实体</div>
        </div>
        <div v-if="d.note" class="bd-line__note">{{ d.note }}</div>
      </div>
    </div>

    <!-- 分布 -->
    <div class="bd-ov__dist">
      <div class="bd-card">
        <div class="bd-card__h">审计类别分布</div>
        <div class="bd-card__b">
          <div v-for="b in ov.auditByKind" :key="b.name" class="bd-bar">
            <span class="bd-bar__label">{{ b.name }}</span>
            <span class="bd-bar__track"><span class="bd-bar__fill" :style="{ width: pct(b.value, auditMax), background: brand }" /></span>
            <span class="bd-bar__val">{{ b.value }}</span>
          </div>
        </div>
      </div>
      <div class="bd-card">
        <div class="bd-card__h">访问判定分布</div>
        <div class="bd-card__b">
          <div v-for="b in ov.verdicts" :key="b.name" class="bd-bar">
            <span class="bd-bar__label">{{ b.name }}</span>
            <span class="bd-bar__track"><span class="bd-bar__fill" :style="{ width: pct(b.value, verdictMax), background: verdictColor(b.name) }" /></span>
            <span class="bd-bar__val">{{ b.value }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 攻击源：数据面拒绝事件的真实聚合（网关心跳上报，attack_sources 表）。
         后端没有该字段（内存种子模式）就整块不画——绝不造种子攻击。
         ★标题里的窗口跟随选择器：写死「24 小时」而数据按 30 天算，就是又一次口径错标。 -->
    <div v-if="ov.attack" class="bd-card bd-atk">
      <div class="bd-card__h">
        SPA 攻击源（{{ scopeText.replace('近 ', '') }}）
        <span class="bd-card__h-sub">隐身在挡谁——敲门 / 隧道 / Web 三个面的拒绝聚合</span>
      </div>
      <div class="bd-card__b bd-atk__grid">
        <div class="bd-atk__kpis">
          <div class="bd-atk__kpi"><b>{{ ov.attack.sources }}</b><span>攻击来源</span></div>
          <div class="bd-atk__kpi"><b>{{ ov.attack.denies }}</b><span>拒绝次数</span></div>
        </div>
        <div class="bd-atk__trend">
          <div class="bd-atk__cols">
            <div v-for="(kv, i) in ov.attack.trend" :key="i" class="bd-atk__col" :title="`${kv.name} · ${kv.value} 次`">
              <span class="bd-atk__colfill" :class="{ 'bd-atk__colfill--hit': kv.value > 0 }" :style="{ height: colH(kv.value) }" />
            </div>
          </div>
          <div class="bd-atk__axis">
            <span>{{ ov.attack.trend[0]?.name }}</span><span>{{ ov.attack.trend[ov.attack.trend.length - 1]?.name }}</span>
          </div>
        </div>
        <div class="bd-atk__top">
          <div class="bd-atk__toph">TOP 攻击源</div>
          <div v-for="(t2, i) in ov.attack.top" :key="t2.ip" class="bd-atk__toprow">
            <span class="bd-line__rank">{{ i + 1 }}</span>
            <span class="bd-mono bd-atk__ip">{{ t2.ip }}</span>
            <span class="bd-atk__cat">{{ t2.cat }}</span>
            <span class="bd-atk__cnt">×{{ t2.count }}</span>
          </div>
          <EmptyState v-if="!ov.attack.top.length" size="sm" tone="ok" :title="`${scopeText}内没有任何拒绝——面上很安静`" />
        </div>
      </div>
    </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, failReason, type Overview } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import StatCard from '@/components/StatCard.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';
import EmptyState from '@/components/EmptyState.vue';

const brand = '#165DFF';

const MOCK: Overview = {
  generatedAt: '',
  devices: { total: 240, trusted: 186, pending: 8, revoked: 3, rate: 0.775 },
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
  windowHours: 24,
  windowNote: '（降级演示数据）审计派生统计按最近 24 小时聚合；账号与终端两条防线是当前状态，与时间窗无关',
  defense: [
    { key: 'attack', name: '隐身防线', risk: 28, top: ['203.0.113.7 · 敲门令牌无效 ×41', '198.51.100.4 · 未敲门直连隧道口 ×9'] , scope: 'window', note: '按所选时间窗聚合' },
    { key: 'account', name: '账号防线', risk: 41, top: ['li.fang', '外包-zhao', 'svc-bot-04'] , scope: 'current', note: '当前状态，与所选时间窗无关' },
    { key: 'endpoint', name: '终端防线', risk: 19, top: ['WIN-诊室-12', 'MAC-研发-08'] , scope: 'current', note: '当前状态，与所选时间窗无关' }
  ],
  attack: {
    sources: 6, denies: 87,
    top: [
      { ip: '203.0.113.7', count: 41, cat: '敲门令牌无效' },
      { ip: '198.51.100.4', count: 9, cat: '未敲门直连隧道口' }
    ],
    trend: Array.from({ length: 24 }, (_, i) => ({ name: `${String(i).padStart(2, '0')}:00`, value: [0, 2, 0, 5, 12, 3][i % 6] }))
  }
};

const ov = ref<Overview>(MOCK);
/** 连接态三态：undefined = 首轮请求还在路上（判不出来，PageHeader 此时不画标签）/
 *  true 已连 / false 降级演示。★初值写 false 的话，首屏那一瞬页头就挂上一枚橙色
 *  「降级演示」——把"还没探过"说成"确定离线"，而那一刻什么都还没发生。 */
const live = ref<boolean | undefined>(undefined);
/** 读取失败时后端那句原话（failReason 收口，前端不编造归因）。 */
const loadErr = ref('');
const loading = ref(false);
/** 首屏是否已完成第一次加载：只决定骨架屏何时让位（成功 / 降级都算完成），不改任何数据流。 */
const loaded = ref(false);

/* sessionsUnknown 后端把 sessions 整个字段缺席下发 = 一台在线网关都没在上报，
 * 控制面**不知道**有谁接入（与 /diag 的「在线 —（无网关上报）」同一口径）。
 * ★绝不能写 `ov.sessions ?? 0`：那把后端如实的缺席在前端塌回一个确定的 0，
 *   而此刻隧道可能正在转发——KPI 底下那句「当前活跃接入」会直接把人带偏。 */
const sessionsUnknown = computed(() => ov.value.sessions === undefined || ov.value.sessions === null);

/* hours 态势统计的时间窗（默认 24h，钳制在后端 store.ClampOverviewWindow 一处）。 */
const hours = ref(24);
/* scopeText 窗口标签文案（跟随 hours，不写死）。 */
const scopeText = computed(() =>
  hours.value >= 720 ? '近 30 天' : hours.value >= 168 ? '近 7 天' : '近 24 小时'
);

const stamp = computed(() => (ov.value.generatedAt ? ov.value.generatedAt.replace('T', ' ').slice(0, 19) : '—'));
const threats = computed(() => ov.value.threats.rejected + ov.value.threats.failed + ov.value.threats.secondary);
const auditMax = computed(() => Math.max(...ov.value.auditByKind.map((b) => b.value), 1));
const verdictMax = computed(() => Math.max(...ov.value.verdicts.map((b) => b.value), 1));

function pct(v: number, max: number) { return `${Math.round((v / max) * 100)}%`; }
/** 攻击趋势柱高（相对窗口内最大桶；零桶给 2px 底线示意"这一小时确实没有"）。 */
const atkMax = computed(() => Math.max(...(ov.value.attack?.trend ?? []).map((k) => k.value), 1));
function colH(v: number) { return v ? `${Math.max(8, Math.round((v / atkMax.value) * 100))}%` : '2px'; }
function riskColor(r: number) { return r >= 40 ? 'red' : r >= 25 ? 'orange' : 'green'; }
function riskHex(r: number) { return r >= 40 ? '#F53F3F' : r >= 25 ? '#FF7D00' : '#00B42A'; }
/** 风险分的语义档（与 riskColor / riskLabel 同阈值），供 class 走 --bd-* 语义色而不写十六进制。 */
function riskTone(r: number) { return r >= 40 ? 'danger' : r >= 25 ? 'warning' : 'success'; }
function riskLabel(r: number) { return r >= 40 ? '高风险' : r >= 25 ? '关注' : '良好'; }
function verdictColor(name: string) {
  return name === '拒绝' ? '#F53F3F' : name === '二次鉴权' ? '#FF7D00' : name === '降权' ? '#FF9A2E' : '#165DFF';
}

async function load() {
  loading.value = true;
  try {
    ov.value = await api<Overview>(`/overview?hours=${hours.value}`);
    live.value = true;
    loadErr.value = '';
  } catch (e) {
    ov.value = { ...MOCK, generatedAt: new Date().toISOString() };
    live.value = false;
    loadErr.value = failReason(e);
  } finally {
    loading.value = false;
    loaded.value = true;
  }
}

onMounted(load);
</script>

<style scoped>
/* 本页独有的布局与两块自绘图表。页头 / KPI 卡 / 卡片头 / 提示条 / 区块标题都在共享件与 app.css 里。 */
.bd-ov__kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--bd-sp-4); }
.bd-ov__lines { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--bd-sp-4); }
.bd-ov__dist { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--bd-sp-4); margin-top: var(--bd-sp-4); }
@media (max-width: 1320px) {
  .bd-ov__kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 960px) {
  .bd-ov__lines, .bd-ov__dist { grid-template-columns: 1fr; }
}

/* 三道防线卡 */
.bd-line { padding: var(--bd-sp-4) var(--bd-sp-5); }
.bd-line__head { display: flex; align-items: center; justify-content: space-between; gap: var(--bd-sp-2); }
.bd-line__name { font-weight: 600; color: var(--bd-t1); font-size: var(--bd-fs-base); }
.bd-line__tags { display: inline-flex; gap: var(--bd-sp-1); }
.bd-line__risk { display: flex; align-items: baseline; gap: 6px; margin: 10px 0 var(--bd-sp-2); }
.bd-line__score { font-size: var(--bd-fs-2xl); font-weight: 700; line-height: 1.2; }
.bd-line__score--danger { color: var(--bd-danger); }
.bd-line__score--warning { color: var(--bd-warning); }
.bd-line__score--success { color: var(--bd-success); }
.bd-line__unit { font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-line__none { font-size: var(--bd-fs-sm); color: var(--bd-t3); padding: 3px 0; }
.bd-line__top { margin-top: 14px; }
.bd-line__top-h { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-bottom: var(--bd-sp-2); }
.bd-line__top-row { display: flex; align-items: center; gap: var(--bd-sp-2); padding: 3px 0; font-size: var(--bd-fs-md); }
.bd-line__rank {
  width: 18px; height: 18px; border-radius: var(--bd-radius-xs); background: var(--bd-fill-2);
  color: var(--bd-t2); font-size: var(--bd-fs-xs); display: inline-flex; align-items: center; justify-content: center; flex: none;
}
.bd-line__ent { color: var(--bd-t1); font-variant-numeric: tabular-nums; }
.bd-line__note { margin-top: var(--bd-sp-2); font-size: var(--bd-fs-xs); color: var(--bd-t3); line-height: var(--bd-lh-loose); }

/* 分布条 */
.bd-bar { display: flex; align-items: center; gap: var(--bd-sp-3); padding: 7px 0; }
.bd-bar__label { width: 72px; font-size: var(--bd-fs-md); color: var(--bd-t2); flex-shrink: 0; }
.bd-bar__track { flex: 1; height: 10px; background: var(--bd-fill-2); border-radius: 6px; overflow: hidden; }
.bd-bar__fill { display: block; height: 100%; border-radius: 6px; transition: width var(--bd-dur-slow) var(--bd-ease); }
.bd-bar__val { width: 48px; text-align: right; font-size: var(--bd-fs-md); font-variant-numeric: tabular-nums; color: var(--bd-t1); }

/* 攻击源面板 */
.bd-atk { margin-top: var(--bd-sp-4); }
.bd-atk__grid { display: grid; grid-template-columns: 150px 1fr 300px; gap: var(--bd-sp-6); align-items: stretch; }
@media (max-width: 960px) { .bd-atk__grid { grid-template-columns: 1fr; } }
.bd-atk__kpis { display: flex; flex-direction: column; gap: 14px; justify-content: center; }
.bd-atk__kpi b { display: block; font-size: 26px; font-weight: 700; color: var(--bd-t1); line-height: 1.2; }
.bd-atk__kpi span { font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-atk__trend { display: flex; flex-direction: column; justify-content: flex-end; min-width: 0; }
.bd-atk__cols { display: flex; align-items: flex-end; gap: 3px; height: 84px; }
.bd-atk__col { flex: 1; display: flex; align-items: flex-end; min-width: 0; }
.bd-atk__colfill { width: 100%; border-radius: 2px 2px 0 0; background: var(--bd-fill-3); transition: height var(--bd-dur-base) var(--bd-ease); }
.bd-atk__colfill--hit { background: var(--bd-danger); }
.bd-atk__axis { display: flex; justify-content: space-between; font-size: var(--bd-fs-xs); color: var(--bd-t3); margin-top: 6px; }
.bd-atk__top { min-width: 0; }
.bd-atk__toph { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-bottom: var(--bd-sp-2); }
.bd-atk__toprow { display: flex; align-items: center; gap: var(--bd-sp-2); padding: 4px 0; font-size: var(--bd-fs-md); }
.bd-atk__ip { color: var(--bd-t1); font-weight: 600; }
.bd-atk__cat { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.bd-atk__cnt { color: var(--bd-danger); font-weight: 600; }
</style>
