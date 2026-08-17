<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">安全监控大屏</div>
        <div class="bd-page__sub">三道防线 · 在线会话 · 数据时间 {{ stamp }}</div>
      </div>
      <a-space>
        <!-- 时间窗：审计派生统计与攻击源共用它。★对账号/终端两条防线不生效，
             逐卡片标出（见 DefenseLine.scope）——悄悄不生效的筛选比没有更坏。 -->
        <a-radio-group v-model="hours" type="button" size="small" @change="load">
          <a-radio :value="24">24 小时</a-radio>
          <a-radio :value="168">7 天</a-radio>
          <a-radio :value="720">30 天</a-radio>
        </a-radio-group>
        <a-tag :color="live ? 'green' : 'orange'" bordered>
          <template #icon><icon-cloud /></template>
          {{ live ? '已连 baidi-control' : '降级演示 · 内置数据' }}
        </a-tag>
        <a-button :loading="loading" @click="load">
          <template #icon><icon-refresh /></template>刷新
        </a-button>
      </a-space>
    </div>

    <!-- 口径说明：后端下发，前端不自己编——它要说清「哪些数按窗口算、
         哪些是当前状态、实际能回溯多久」，任何一处与后端脱节都会变成误导。 -->
    <div v-if="ov.windowNote" class="bd-scopebar" :class="{ 'bd-scopebar--warn': ov.truncated }">
      <icon-info-circle-fill /><span>{{ ov.windowNote }}</span>
    </div>

    <!-- KPI 行 -->
    <a-grid :cols="{ xs: 1, sm: 2, lg: 4 }" :col-gap="16" :row-gap="16">
      <a-grid-item>
        <a-card class="bd-kpi" :bordered="false">
          <div class="bd-kpi__label">授信终端</div>
          <div class="bd-kpi__value">{{ ov.devices.trusted }}<span class="bd-kpi__unit"> / {{ ov.devices.total }}</span></div>
          <a-progress :percent="ov.devices.rate" :show-text="false" size="small" :color="brand" />
          <div class="bd-kpi__foot">纳管率 {{ (ov.devices.rate * 100).toFixed(0) }}% · 待审批 {{ ov.devices.pending }} · 已吊销 {{ ov.devices.revoked }}</div>
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
            <!-- 口径标签：window = 按所选时间窗；current = 当前状态，与时间窗无关。 -->
            <a-tag size="small" :color="d.scope === 'window' ? 'arcoblue' : 'gray'">
              {{ d.scope === 'window' ? scopeText : '当前状态' }}
            </a-tag>
            <a-tag :color="riskColor(d.risk)" size="small">{{ riskLabel(d.risk) }}</a-tag>
          </div>
          <div class="bd-line__risk">
            <span class="bd-line__score" :style="{ color: riskHex(d.risk) }">{{ d.risk }}</span>
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

    <!-- 攻击源：数据面拒绝事件的真实聚合（网关心跳上报，attack_sources 表）。
         后端没有该字段（内存种子模式）就整块不画——绝不造种子攻击。
         ★标题里的窗口跟随选择器：写死「24 小时」而数据按 30 天算，就是又一次口径错标。 -->
    <a-card v-if="ov.attack" class="bd-atk" :bordered="false" style="margin-top: 16px">
      <template #title>
        SPA 攻击源（{{ scopeText.replace('近 ', '') }}）
        <span class="bd-atk__sub">隐身在挡谁——敲门 / 隧道 / Web 三个面的拒绝聚合</span>
      </template>
      <div class="bd-atk__grid">
        <div class="bd-atk__kpis">
          <div class="bd-atk__kpi"><b>{{ ov.attack.sources }}</b><span>攻击来源</span></div>
          <div class="bd-atk__kpi"><b>{{ ov.attack.denies }}</b><span>拒绝次数</span></div>
        </div>
        <div class="bd-atk__trend">
          <div class="bd-atk__cols">
            <div v-for="(kv, i) in ov.attack.trend" :key="i" class="bd-atk__col" :title="`${kv.name} · ${kv.value} 次`">
              <span class="bd-atk__colfill" :style="{ height: colH(kv.value), background: kv.value ? '#F53F3F' : 'var(--color-fill-3)' }" />
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
          <div v-if="!ov.attack.top.length" class="bd-line__none">{{ scopeText }}内没有任何拒绝——面上很安静</div>
        </div>
      </div>
    </a-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type Overview } from '@/lib/api';

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
const live = ref(false);
const loading = ref(false);

/* hours 态势统计的时间窗。默认 24h——与改造前"攻击源 24h"那一半口径一致，
   页面不会在升级那一刻突然换语义。 */
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
function riskLabel(r: number) { return r >= 40 ? '高风险' : r >= 25 ? '关注' : '良好'; }
function verdictColor(name: string) {
  return name === '拒绝' ? '#F53F3F' : name === '二次鉴权' ? '#FF7D00' : name === '降权' ? '#FF9A2E' : '#165DFF';
}

async function load() {
  loading.value = true;
  try {
    ov.value = await api<Overview>(`/overview?hours=${hours.value}`);
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
.bd-line__none { font-size: 12px; color: var(--color-text-3); padding: 3px 0; }

/* 攻击源面板 */
.bd-atk { border-radius: var(--bd-radius); }
.bd-atk__sub { font-size: 12px; font-weight: 400; color: var(--color-text-3); margin-left: 10px; }
.bd-atk__grid { display: grid; grid-template-columns: 150px 1fr 300px; gap: 22px; align-items: stretch; }
@media (max-width: 960px) { .bd-atk__grid { grid-template-columns: 1fr; } }
.bd-atk__kpis { display: flex; flex-direction: column; gap: 14px; justify-content: center; }
.bd-atk__kpi b { display: block; font-size: 26px; font-weight: 700; color: var(--color-text-1); }
.bd-atk__kpi span { font-size: 12px; color: var(--color-text-3); }
.bd-atk__trend { display: flex; flex-direction: column; justify-content: flex-end; min-width: 0; }
.bd-atk__cols { display: flex; align-items: flex-end; gap: 3px; height: 84px; }
.bd-atk__col { flex: 1; display: flex; align-items: flex-end; min-width: 0; }
.bd-atk__colfill { width: 100%; border-radius: 2px 2px 0 0; transition: height .2s; }
.bd-atk__axis { display: flex; justify-content: space-between; font-size: 11px; color: var(--color-text-3); margin-top: 6px; }
.bd-atk__top { min-width: 0; }
.bd-atk__toph { font-size: 12px; color: var(--color-text-3); margin-bottom: 8px; }
.bd-atk__toprow { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 13px; }
.bd-atk__ip { color: var(--color-text-1); font-weight: 600; }
.bd-atk__cat { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; color: var(--color-text-3); }
.bd-atk__cnt { color: var(--bd-danger); font-weight: 600; }
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

/* 口径说明条：常态是中性提示，被留存期截断时转警示色。 */
.bd-scopebar {
  display: flex; align-items: flex-start; gap: 8px; margin: 12px 0; padding: 9px 12px;
  border-radius: 8px; font-size: 12.5px; line-height: 1.6;
  color: var(--bd-t2); background: var(--bd-fill2); border: 1px solid var(--bd-border);
}
.bd-scopebar--warn { color: #A8620E; background: #FFF7E8; border-color: #FFD08A; }
.bd-scopebar > :first-child { flex: none; margin-top: 2px; font-size: 14px; }
.bd-line__note { margin-top: 8px; font-size: 11.5px; color: var(--bd-t3); line-height: 1.55; }
</style>
