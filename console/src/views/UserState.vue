<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">用户状态</div>
        <div class="bd-page__sub">风险用户与异常账号态势 · 最小误杀，最大可恢复</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>
          <template #icon><icon-cloud /></template>
          {{ live ? '已连 baidi-control' : '降级演示' }}
        </a-tag>
        <a-button :loading="loading" @click="load">
          <template #icon><icon-refresh /></template>刷新
        </a-button>
      </div>
    </div>

    <!-- 灰度处置提示条（呼应 P9） -->
    <div class="bd-tip">
      <icon-info-circle class="bd-tip__ic" />
      <span>处置遵循灰度原则：先建议（立即 / 30 分钟后 / 待审批），再执行；高风险不等于自动断网。</span>
    </div>

    <!-- P10 聚合头 -->
    <a-grid :cols="{ xs: 2, sm: 3, lg: 5 }" :col-gap="12" :row-gap="12">
      <a-grid-item>
        <a-card class="bd-bk" :class="{ on: filter === '' }" :bordered="false" @click="filter = ''">
          <span class="bd-bk__bar" :style="{ background: '#86909C' }" />
          <div class="bd-bk__label">全部</div>
          <div class="bd-bk__count">{{ bundle.items.length }}</div>
        </a-card>
      </a-grid-item>
      <a-grid-item v-for="b in bundle.buckets" :key="b.key">
        <a-card class="bd-bk" :class="{ on: filter === b.key }" :bordered="false" @click="toggle(b.key)">
          <span class="bd-bk__bar" :style="{ background: toneHex(b.tone) }" />
          <div class="bd-bk__label">{{ b.label }}</div>
          <div class="bd-bk__count" :style="{ color: toneHex(b.tone) }">{{ b.count }}</div>
        </a-card>
      </a-grid-item>
    </a-grid>

    <!-- 受关注用户清单 -->
    <div class="bd-section-title">受关注用户 <em>{{ shown.length }}</em></div>

    <div v-if="!shown.length" class="bd-card bd-empty bd-empty--lg">
      <icon-check-circle-fill />当前筛选条件下没有受关注用户
    </div>

    <a-card v-for="u in shown" :key="u.id" class="bd-card bd-row" :bordered="false">
      <!-- 左：身份 -->
      <div class="bd-row__id">
        <span class="bd-avatar" :style="{ background: avatarBg(u.user) }">{{ u.user.slice(0, 1) }}</span>
        <div class="bd-row__who">
          <div class="bd-row__name">{{ u.user }}</div>
          <div class="bd-row__meta">{{ u.account }} · {{ u.org }}</div>
          <span class="bd-st">
            <span class="d" :style="{ background: u.online ? 'var(--bd-success)' : 'var(--bd-t4)' }" />{{ u.online ? '在线' : '离线' }}
          </span>
        </div>
      </div>

      <!-- 中：状态 + 风险 + 命中原因 -->
      <div class="bd-row__mid">
        <div class="bd-row__tags">
          <span class="bd-tg" :style="tagStyle(stateMeta(u.state).color)">{{ stateMeta(u.state).label }}</span>
          <!-- 风险标签仅在比状态标签多给信息时出现：risk-high/low 状态本身已含风险级别，不再重复一枚同名标签 -->
          <span v-if="u.risk !== 'none' && riskLabel(u.risk) !== stateMeta(u.state).label" class="bd-tg" :style="tagStyle(riskHex(u.risk))">{{ riskLabel(u.risk) }}</span>
        </div>
        <div v-if="u.reasons.length" class="bd-row__reasons">
          <span v-for="(r, i) in u.reasons" :key="i" class="bd-tg bd-tg--grey">{{ r }}</span>
        </div>
      </div>

      <!-- 右：最近事件 + 处置入口 -->
      <div class="bd-row__right">
        <div class="bd-row__event">{{ u.lastEvent }}</div>
        <div class="bd-row__time bd-mono">{{ u.lastSeen }}</div>
        <div class="bd-row__acts">
          <span class="bd-link" @click="goUsers"><icon-user />查看用户</span>
          <span class="bd-link bd-link--grey" @click="goAudit"><icon-file />查审计</span>
        </div>
      </div>
    </a-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { api, type UserStateBundle, type UserStateItem } from '@/lib/api';

const router = useRouter();

const MOCK: UserStateBundle = {
  buckets: [
    { key: 'risk-high', label: '高风险', count: 2, tone: 'danger' },
    { key: 'risk-low', label: '关注', count: 3, tone: 'warning' },
    { key: 'locked', label: '已锁定', count: 1, tone: 'danger' },
    { key: 'disabled', label: '已禁用', count: 1, tone: 'info' },
    { key: 'idle', label: '空闲挂起', count: 2, tone: 'normal' }
  ],
  items: [
    { id: 'u1', user: '赵磊', account: 'zhao.lei', org: '研发中心', state: 'risk-high', risk: 'high', online: true, reasons: ['境外 IP 登录', '新设备指纹', '非工作时段'], lastEvent: '触发异地登录策略 · 已要求二次鉴权', lastSeen: '2026-06-24 09:42' },
    { id: 'u2', user: '孙浩', account: 'sun.hao', org: '财务部', state: 'risk-high', risk: 'high', online: false, reasons: ['连续 5 次认证失败', '密码喷洒特征'], lastEvent: '认证失败超阈值 · 建议 30 分钟后临时锁定', lastSeen: '2026-06-24 08:17' },
    { id: 'u3', user: '周婷', account: 'zhou.ting', org: '法务部', state: 'risk-low', risk: 'low', online: true, reasons: ['访问敏感资源频次上升'], lastEvent: '高敏资源访问偏离基线 · 建议观察', lastSeen: '2026-06-24 10:05' },
    { id: 'u4', user: '王芳', account: 'wang.fang', org: 'IT 运维', state: 'risk-low', risk: 'low', online: true, reasons: ['新地点登录', '夜间活跃'], lastEvent: '换城市登录 · 已完成短信确认', lastSeen: '2026-06-24 07:33' },
    { id: 'u5', user: '李伟', account: 'li.wei', org: '市场部', state: 'risk-low', risk: 'low', online: false, reasons: ['BYOD 终端未托管'], lastEvent: '个人设备接入 · 建议引导纳管', lastSeen: '2026-06-23 18:51' },
    { id: 'u6', user: '陈强', account: 'chen.qiang', org: '运维堡垒', state: 'locked', risk: 'high', online: false, reasons: ['暴力破解触发自动锁定', '需管理员解锁'], lastEvent: '账号已临时锁定 · 等待人工核验后恢复', lastSeen: '2026-06-24 06:02' },
    { id: 'u7', user: '外包-张', account: 'ext.zhang', org: '外包供应商', state: 'disabled', risk: 'none', online: false, reasons: ['合同到期', '账号已停用'], lastEvent: '到期自动停用 · 可按需重新启用', lastSeen: '2026-06-20 17:40' },
    { id: 'u8', user: '张敏', account: 'zhang.min', org: '行政部', state: 'idle', risk: 'none', online: false, reasons: ['30 天未活跃'], lastEvent: '长期未登录 · 建议挂起回收授权', lastSeen: '2026-05-22 14:12' },
    { id: 'u9', user: 'svc-bot-04', account: 'svc.bot.04', org: '服务账号', state: 'idle', risk: 'low', online: true, reasons: ['服务账号长期高频', '凭据未轮换'], lastEvent: '机器账号凭据超期 · 建议轮换密钥', lastSeen: '2026-06-24 10:11' }
  ]
};

const bundle = ref<UserStateBundle>(MOCK);
const live = ref(false);
const loading = ref(false);
const filter = ref<string>('');

const shown = computed<UserStateItem[]>(() =>
  filter.value ? bundle.value.items.filter((i) => i.state === filter.value) : bundle.value.items
);

function toggle(key: string) { filter.value = filter.value === key ? '' : key; }
function tagStyle(c: string) { return { color: c, background: c + '14' }; }
function toneHex(t: string) {
  return t === 'danger' ? '#F53F3F' : t === 'warning' ? '#FF7D00' : t === 'info' ? '#165DFF' : '#86909C';
}
function riskHex(r: string) { return r === 'high' ? '#F53F3F' : r === 'low' ? '#FF7D00' : '#86909C'; }
function riskLabel(r: string) { return r === 'high' ? '高风险' : r === 'low' ? '关注' : ''; }
function stateMeta(s: string) {
  const m: Record<string, { label: string; color: string }> = {
    'risk-high': { label: '高风险', color: '#F53F3F' },
    'risk-low': { label: '关注', color: '#FF7D00' },
    locked: { label: '已锁定', color: '#F53F3F' },
    disabled: { label: '已禁用', color: '#86909C' },
    idle: { label: '空闲挂起', color: '#5E7CE0' }
  };
  // 后端若返回未知状态值，回退为中性灰标签而非渲染时抛错。
  return m[s] ?? { label: s, color: '#86909C' };
}
function avatarBg(name: string) {
  const palette = ['#165DFF', '#722ED1', '#00B42A', '#FF7D00', '#F53F3F'];
  let h = 0;
  for (const ch of name) h = (h + ch.charCodeAt(0)) % palette.length;
  return palette[h];
}

function goUsers() { router.push('/business/users'); }
function goAudit() { router.push('/security/audit'); }

async function load() {
  loading.value = true;
  try {
    bundle.value = await api<UserStateBundle>('/userstate');
    live.value = true;
  } catch {
    bundle.value = MOCK;
    live.value = false;
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
/* 提示条 */
.bd-tip {
  display: flex; align-items: center; gap: 8px; margin-bottom: 16px;
  padding: 10px 14px; border-radius: var(--bd-radius);
  background: var(--bd-primary-1); border: 1px solid var(--bd-primary-b);
  font-size: 12.5px; color: var(--bd-t2); line-height: 1.6;
}
.bd-tip__ic { color: var(--bd-primary); font-size: 16px; flex: none; }

/* P10 聚合卡 */
.bd-bk {
  position: relative; border-radius: var(--bd-radius); cursor: pointer;
  overflow: hidden; transition: box-shadow .15s, transform .12s;
}
.bd-bk:hover { box-shadow: 0 4px 12px rgba(0, 0, 0, .06); }
.bd-bk.on { box-shadow: 0 0 0 1.5px var(--bd-primary); }
.bd-bk__bar { position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
.bd-bk__label { font-size: 13px; color: var(--bd-t3); padding-left: 6px; }
.bd-bk__count { font-size: 26px; font-weight: 700; line-height: 1.4; padding-left: 6px; color: var(--bd-t1); font-variant-numeric: tabular-nums; }

/* section 标题 */
.bd-section-title { font-size: 14px; font-weight: 600; color: var(--bd-t1); margin: 22px 0 12px; }
.bd-section-title em { font-style: normal; font-size: 12px; color: var(--bd-t3); margin-left: 6px; }

/* 用户行卡 */
.bd-row { border-radius: var(--bd-radius); margin-bottom: 12px; }
.bd-row :deep(.arco-card-body) { display: flex; align-items: flex-start; gap: 20px; padding: 16px 18px; }

.bd-row__id { display: flex; align-items: center; gap: 12px; width: 220px; flex: none; }
.bd-row__who { min-width: 0; }
.bd-row__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-row__meta { font-size: 12px; color: var(--bd-t3); margin: 2px 0 6px; }

.bd-row__mid { flex: 1; min-width: 0; }
.bd-row__tags { display: flex; flex-wrap: wrap; gap: 6px; }
.bd-row__reasons { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.bd-tg--grey { background: var(--bd-fill-2); color: var(--bd-t3); font-weight: 400; }

.bd-row__right { width: 230px; flex: none; text-align: right; }
.bd-row__event { font-size: 12.5px; color: var(--bd-t2); line-height: 1.5; }
.bd-row__time { font-size: 11.5px; color: var(--bd-t3); margin-top: 4px; }
.bd-row__acts { display: flex; justify-content: flex-end; gap: 14px; margin-top: 10px; }
.bd-row__acts .bd-link { display: inline-flex; align-items: center; gap: 4px; font-size: 12.5px; }

/* 空态 */
.bd-empty { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--bd-t3); padding: 16px 12px; }
.bd-empty :deep(svg) { color: var(--bd-success); }
.bd-empty--lg { justify-content: center; min-height: 200px; flex-direction: column; gap: 12px; color: var(--bd-t4); }
.bd-empty--lg :deep(svg) { font-size: 28px; color: var(--bd-t4); }
</style>
