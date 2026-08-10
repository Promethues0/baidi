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
      <span>风险处置四档均有真实执行方：<b>灰度观察</b>不改访问权、只记 observing 审计；<b>已降权</b>仅摘除高敏资源，隧道与普通资源照常；<b>已阻断</b>才是撤窗断隧道。收缩优先于全断。</span>
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

    <!-- 爆破锁定 IP（login_lockouts · kind=ip）：同一源 IP 换账号爆破触发的锁，与账号锁分开列 -->
    <div class="bd-section-title">爆破锁定 IP <em>{{ ipLocks.length }}</em></div>
    <div v-if="!ipLocks.length" class="bd-card bd-empty">
      <icon-check-circle-fill />当前没有被防爆破锁定的来源 IP
    </div>
    <a-card v-else class="bd-card" :bordered="false">
      <div v-for="lk in ipLocks" :key="lk.key" class="bd-iplock">
        <span class="bd-mono bd-iplock__ip">{{ lk.key }}</span>
        <span class="bd-iplock__reason">{{ lk.reason }}</span>
        <span class="bd-iplock__until">锁定至 {{ fmtUntil(lk.until) }}</span>
        <a-button size="mini" @click="unlockIP(lk)">解锁</a-button>
      </div>
    </a-card>

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
          <!-- 风险标签仅在比档位标签多给信息时出现，不重复一枚同名标签 -->
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
          <!-- 就地解锁：按锁的种类选路——爆破锁走 /security/lockouts/unlock，目录锁走 /users/{id}/status -->
          <span v-if="u.state === 'locked' || u.bruteLocked" class="bd-link" @click="unlockUser(u)"><icon-unlock />就地解锁</span>
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
import { Message } from '@arco-design/web-vue';
import { api, type UserStateBundle, type UserStateItem, type LoginLockout, type LockoutsResp } from '@/lib/api';

const router = useRouter();

const MOCK: UserStateBundle = {
  buckets: [
    { key: 'block', label: '已阻断', count: 1, tone: 'danger' },
    { key: 'degrade', label: '已降权', count: 2, tone: 'warning' },
    { key: 'gray', label: '灰度观察', count: 2, tone: 'info' },
    { key: 'locked', label: '锁定账号', count: 1, tone: 'danger' },
    { key: 'disabled', label: '禁用账号', count: 1, tone: 'normal' }
  ],
  items: [
    { id: 'u1', user: '赵磊', account: 'zhao.lei', org: '研发中心', state: 'block', risk: 'high', online: true, reasons: ['磁盘未加密', '终端防护未在线'], lastEvent: '终端环境不合规 · 接入已阻断（撤窗 + 断隧道）', lastSeen: '2026-06-24 09:42' },
    { id: 'u2', user: '孙浩', account: 'sun.hao', org: '财务部', state: 'degrade', risk: 'high', online: false, reasons: ['系统完整性保护未开启'], lastEvent: '高敏资源已暂停访问 · 普通资源与隧道不受影响', lastSeen: '2026-06-24 08:17' },
    { id: 'u3', user: '周婷', account: 'zhou.ting', org: '法务部', state: 'degrade', risk: 'high', online: true, reasons: ['客户端版本过低'], lastEvent: '高敏资源已暂停访问 · 普通资源与隧道不受影响', lastSeen: '2026-06-24 10:05' },
    { id: 'u4', user: '王芳', account: 'wang.fang', org: 'IT 运维', state: 'gray', risk: 'low', online: true, reasons: ['主机防火墙未开启'], lastEvent: '灰度观察中 · 访问权未变更', lastSeen: '2026-06-24 07:33' },
    { id: 'u5', user: '李伟', account: 'li.wei', org: '市场部', state: 'gray', risk: 'low', online: false, reasons: ['操作系统版本落后'], lastEvent: '灰度观察中 · 访问权未变更', lastSeen: '2026-06-23 18:51' },
    { id: 'u6', user: '陈强', account: 'chen.qiang', org: '运维堡垒', state: 'locked', risk: 'high', online: false, bruteLocked: true, reasons: ['暴力破解触发自动锁定', '需管理员解锁'], lastEvent: '账号已临时锁定 · 等待人工核验后恢复', lastSeen: '2026-06-24 06:02' },
    { id: 'u7', user: '外包-张', account: 'ext.zhang', org: '外包供应商', state: 'disabled', risk: 'none', online: false, reasons: ['合同到期', '账号已停用'], lastEvent: '到期自动停用 · 可按需重新启用', lastSeen: '2026-06-20 17:40' }
  ]
};

/** 降级演示用的锁定清单（与 MOCK 里 chen.qiang 的 bruteLocked 呼应）。 */
const MOCK_LOCKS: LoginLockout[] = [
  { kind: 'ip', key: '203.0.113.77', until: Math.floor(Date.now() / 1000) + 540, reason: '10 分钟内连续 5 次登录失败', createdAt: '2026-06-24 06:02:11' },
  { kind: 'account', key: 'chen.qiang', until: Math.floor(Date.now() / 1000) + 540, reason: '10 分钟内连续 5 次登录失败', createdAt: '2026-06-24 06:02:11' }
];

const bundle = ref<UserStateBundle>(MOCK);
const lockouts = ref<LoginLockout[]>(MOCK_LOCKS);
const live = ref(false);
const loading = ref(false);
const filter = ref<string>('');

const shown = computed<UserStateItem[]>(() => {
  if (!filter.value) return bundle.value.items;
  // locked 桶与后端计数口径一致：目录锁定 ∪ 爆破锁定
  if (filter.value === 'locked') return bundle.value.items.filter((i) => i.state === 'locked' || i.bruteLocked);
  return bundle.value.items.filter((i) => i.state === filter.value);
});

const ipLocks = computed(() => lockouts.value.filter((l) => l.kind === 'ip'));

function fmtUntil(ts: number) {
  const d = new Date(ts * 1000);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

/** 就地解锁：按锁的种类选路，两种锁都有就都解（意图是让该用户能重新登录）。 */
async function unlockUser(u: UserStateItem) {
  try {
    if (u.bruteLocked) {
      await api('/security/lockouts/unlock', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind: 'account', key: u.account })
      });
    }
    if (u.state === 'locked' && u.id) {
      await api(`/users/${u.id}/status`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'active' })
      });
    }
    Message.success(`已解锁 ${u.account}`);
    await load();
  } catch {
    Message.error('解锁失败，请检查后端连接');
  }
}

async function unlockIP(lk: LoginLockout) {
  try {
    await api('/security/lockouts/unlock', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind: 'ip', key: lk.key })
    });
    Message.success(`已解锁 IP ${lk.key}`);
    await load();
  } catch {
    Message.error('解锁失败，请检查后端连接');
  }
}

function toggle(key: string) { filter.value = filter.value === key ? '' : key; }
function tagStyle(c: string) { return { color: c, background: c + '14' }; }
function toneHex(t: string) {
  return t === 'danger' ? '#F53F3F' : t === 'warning' ? '#FF7D00' : t === 'info' ? '#165DFF' : '#86909C';
}
function riskHex(r: string) { return r === 'high' ? '#F53F3F' : r === 'low' ? '#FF7D00' : '#86909C'; }
function riskLabel(r: string) { return r === 'high' ? '高风险' : r === 'low' ? '关注' : ''; }
/**
 * 档位标签。★与风险处置四档同名同义：这里显示的就是网关此刻正在执行的那一档，
 * 不是另起一套"高风险/关注"的模糊说法。文案直接写清各档到底做了什么，
 * 免得管理员把「已降权」误当成「已断网」而去做多余的处置。
 */
function stateMeta(s: string) {
  const m: Record<string, { label: string; color: string }> = {
    block: { label: '已阻断', color: '#F53F3F' },
    degrade: { label: '已降权', color: '#FF7D00' },
    gray: { label: '灰度观察', color: '#165DFF' },
    locked: { label: '已锁定', color: '#F53F3F' },
    disabled: { label: '已禁用', color: '#86909C' }
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
    const [b, lo] = await Promise.all([
      api<UserStateBundle>('/userstate'),
      api<LockoutsResp>('/security/lockouts')
    ]);
    bundle.value = b;
    lockouts.value = lo.lockouts;
    live.value = true;
  } catch {
    bundle.value = MOCK;
    lockouts.value = MOCK_LOCKS;
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

/* 爆破锁定 IP 行 */
.bd-iplock { display: flex; align-items: center; gap: 14px; padding: 8px 0; border-bottom: 1px solid var(--bd-fill-1); }
.bd-iplock:last-child { border-bottom: none; }
.bd-iplock__ip { font-size: 13px; font-weight: 600; color: var(--bd-t1); min-width: 130px; }
.bd-iplock__reason { flex: 1; font-size: 12.5px; color: var(--bd-t2); }
.bd-iplock__until { font-size: 12px; color: var(--bd-t3); font-variant-numeric: tabular-nums; }

/* 空态 */
.bd-empty { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--bd-t3); padding: 16px 12px; }
.bd-empty :deep(svg) { color: var(--bd-success); }
.bd-empty--lg { justify-content: center; min-height: 200px; flex-direction: column; gap: 12px; color: var(--bd-t4); }
.bd-empty--lg :deep(svg) { font-size: 28px; color: var(--bd-t4); }
</style>
