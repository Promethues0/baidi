<template>
  <div class="bd-page">
    <!-- 页头 -->
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">在线用户</div>
        <div class="bd-page__sub">实时接入会话 · 就近处置（强制下线）· 数据时间 {{ stamp }}</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <a-button @click="load">
          <template #icon><icon-refresh /></template>刷新
        </a-button>
      </div>
    </div>

    <!-- P10 聚合头 -->
    <a-grid :cols="{ xs: 1, sm: 2, lg: 4 }" :col-gap="16" :row-gap="16">
      <a-grid-item>
        <a-card class="bd-kpi" :class="{ 'bd-kpi--on': filter === 'all' }" :bordered="false" hoverable @click="setFilter('all')">
          <div class="bd-kpi__label">在线会话总数</div>
          <div class="bd-kpi__value">{{ onlineCount }}</div>
          <div class="bd-kpi__foot">当前活跃接入会话</div>
        </a-card>
      </a-grid-item>
      <a-grid-item>
        <a-card class="bd-kpi" :class="{ 'bd-kpi--on': filter === 'high' }" :bordered="false" hoverable @click="setFilter('high')">
          <div class="bd-kpi__label">高风险会话</div>
          <div class="bd-kpi__value" :style="{ color: C.danger }">{{ highCount }}</div>
          <div class="bd-kpi__foot">risk = high · 建议优先处置</div>
        </a-card>
      </a-grid-item>
      <a-grid-item>
        <a-card class="bd-kpi" :class="{ 'bd-kpi--on': filter === 'geo' }" :bordered="false" hoverable @click="setFilter('geo')">
          <div class="bd-kpi__label">异地·公网接入</div>
          <div class="bd-kpi__value" :style="{ color: C.warning }">{{ geoCount }}</div>
          <div class="bd-kpi__foot">非常用地点 / 公网来源</div>
        </a-card>
      </a-grid-item>
      <a-grid-item>
        <a-card class="bd-kpi" :class="{ 'bd-kpi--on': filter === 'untrusted' }" :bordered="false" hoverable @click="setFilter('untrusted')">
          <div class="bd-kpi__label">未授信终端</div>
          <div class="bd-kpi__value" :style="{ color: C.warning }">{{ untrustedCount }}</div>
          <div class="bd-kpi__foot">trust = untrusted</div>
        </a-card>
      </a-grid-item>
    </a-grid>

    <!-- 会话表 -->
    <div class="bd-tablecard">
      <!-- 过滤条 -->
      <div class="bd-toolbar">
        <a-radio-group v-model="filter" type="button" size="small">
          <a-radio value="all">全部</a-radio>
          <a-radio value="high">高风险</a-radio>
          <a-radio value="untrusted">未授信</a-radio>
          <a-radio value="geo">异地公网</a-radio>
        </a-radio-group>
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 260px">
          <icon-search />
          <input v-model="keyword" class="bd-searchbox__in" placeholder="按用户 / 账号 / IP / 应用搜索" />
        </div>
      </div>

      <table class="bd-table">
        <thead>
          <tr>
            <th>用户</th>
            <th>组织</th>
            <th>接入地点</th>
            <th>终端</th>
            <th>认证方式</th>
            <th>当前应用</th>
            <th>网关</th>
            <th>在线时长</th>
            <th>信任 &amp; 风险</th>
            <th class="r">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in shown" :key="s.id" :class="{ 'bd-row--off': s.status === 'offline' }">
            <td>
              <div class="bd-cellname">
                <span class="bd-avatar" :style="{ background: avatarColor(s.user) }">{{ initial(s.user) }}</span>
                <span>
                  <b>{{ s.user }}</b>
                  <i>{{ s.account }}</i>
                </span>
              </div>
            </td>
            <td>{{ s.org || '—' }}</td>
            <td>
              <div><span class="bd-mono">{{ s.ip }}</span></div>
              <div class="bd-cellsub" :style="isRemote(s.location) ? { color: C.warning } : {}">{{ s.location }}</div>
            </td>
            <td>
              <div>{{ s.device }}</div>
              <div class="bd-cellsub">{{ s.os }}</div>
            </td>
            <td>{{ s.auth }}</td>
            <td>{{ s.app || '—' }}</td>
            <td><span class="bd-mono">{{ s.gateway }}</span></td>
            <td>
              <div class="bd-cellsub">{{ loginStamp(s.loginAt) }} 起</div>
              <div>· {{ s.duration }}</div>
            </td>
            <td>
              <span class="bd-tg" :style="tagStyle(trustColor(s.trust))">{{ trustLabel(s.trust) }}</span>
              <span v-if="s.risk !== 'none'" class="bd-tg" :style="[tagStyle(riskColor(s.risk)), { marginLeft: '6px' }]">{{ riskLabel(s.risk) }}</span>
            </td>
            <td class="r">
              <template v-if="s.status === 'online'">
                <a-popconfirm content="确认强制下线该会话？将立即断开隧道并要求重新认证。" type="warning" @ok="kick(s)">
                  <span class="bd-link bd-link--danger">强制下线</span>
                </a-popconfirm>
              </template>
              <template v-else>
                <span class="bd-tg" :style="tagStyle(C.grey)">已下线</span>
                <div v-if="s.kickReason" class="bd-cellsub">{{ s.kickReason }}</div>
              </template>
            </td>
          </tr>
          <tr v-if="!shown.length">
            <td colspan="10" class="bd-empty">无匹配会话</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type OnlineSession, type OnlineResp } from '@/lib/api';

type Filter = 'all' | 'high' | 'untrusted' | 'geo';

const C = {
  brand: '#165DFF',
  success: '#00B42A',
  warning: '#FF7D00',
  danger: '#F53F3F',
  purple: '#722ED1',
  grey: '#86909C'
} as const;

const PALETTE = [C.brand, C.success, C.warning, C.danger, C.purple, '#0FC6C2'];

const MOCK: OnlineResp = {
  generatedAt: '2026-06-24T10:42:18',
  sessions: [
    { id: 'sess-1001', user: '李明', account: 'li.ming', org: '研发中心 / 平台组', ip: '10.20.3.14', location: '杭州 · 内网', device: 'MacBook Pro', os: 'macOS 15.4', auth: '口令 + 短信', app: 'OA 协同办公', gateway: 'gw-hz-01', loginAt: '2026-06-24T08:55:02', duration: '1h47m', trust: 'trusted', risk: 'none', status: 'online' },
    { id: 'sess-1002', user: '赵磊', account: 'waibao-zhao', org: '外包 / 实施', ip: '203.0.113.77', location: '上海 · 公网（异地）', device: 'Surface Laptop', os: 'Windows 11', auth: '口令', app: '运维堡垒机', gateway: 'gw-sh-02', loginAt: '2026-06-24T10:31:40', duration: '10m', trust: 'untrusted', risk: 'high', status: 'online' },
    { id: 'sess-1003', user: '王芳', account: 'wang.fang', org: '财务部', ip: '10.20.5.31', location: '杭州 · 内网', device: 'ThinkPad X1', os: 'Windows 11', auth: '口令 + UKey', app: '财务核算系统', gateway: 'gw-hz-01', loginAt: '2026-06-24T09:12:55', duration: '1h29m', trust: 'trusted', risk: 'low', status: 'online' },
    { id: 'sess-1004', user: '陈晨', account: 'chen.chen', org: '研发中心 / 算法组', ip: '198.51.100.22', location: '深圳 · 公网（异地）', device: 'iPad Air', os: 'iPadOS 18', auth: '口令', app: '代码评审平台', gateway: 'gw-sz-03', loginAt: '2026-06-24T10:05:11', duration: '37m', trust: 'unknown', risk: 'high', status: 'online' },
    { id: 'sess-1005', user: '孙倩', account: 'sun.qian', org: '市场部', ip: '10.20.8.66', location: '杭州 · 内网', device: 'HUAWEI MateBook', os: 'Windows 11', auth: '口令 + 短信', app: 'CRM 客户管理', gateway: 'gw-hz-01', loginAt: '2026-06-24T08:30:19', duration: '2h11m', trust: 'trusted', risk: 'none', status: 'online' },
    { id: 'sess-1006', user: '周强', account: 'zhou.qiang', org: '研发中心 / 测试组', ip: '172.16.4.9', location: '北京 · 分支专线', device: 'Android Phone', os: 'Android 14', auth: '口令', app: '缺陷跟踪系统', gateway: 'gw-bj-04', loginAt: '2026-06-24T10:38:02', duration: '4m', trust: 'untrusted', risk: 'low', status: 'online' },
    { id: 'sess-1007', user: '吴霜', account: 'wu.shuang', org: '人力资源部', ip: '203.0.113.140', location: '广州 · 公网（异地）', device: 'iPhone 15', os: 'iOS 18.3', auth: '口令 + 短信', app: 'HR 自助门户', gateway: 'gw-gz-05', loginAt: '2026-06-24T09:48:27', duration: '53m', trust: 'unknown', risk: 'none', status: 'online' },
    { id: 'sess-1008', user: '郑昊', account: 'svc-bot-04', org: '系统 / 服务账号', ip: '10.20.1.200', location: '杭州 · 内网', device: 'Linux Host', os: 'Ubuntu 24.04', auth: '证书', app: '数据同步服务', gateway: 'gw-hz-01', loginAt: '2026-06-24T07:10:00', duration: '—', trust: 'trusted', risk: 'none', status: 'offline', kickReason: '管理员手动下线 · 09:55' }
  ]
};

const sessions = ref<OnlineSession[]>(MOCK.sessions);
const generatedAt = ref<string>(MOCK.generatedAt);
const live = ref<boolean>(false);
const filter = ref<Filter>('all');
const keyword = ref<string>('');

const stamp = computed<string>(() => (generatedAt.value ? generatedAt.value.replace('T', ' ').slice(0, 19) : '—'));

function isRemote(loc: string): boolean {
  return loc.includes('异地') || loc.includes('公网');
}

const onlineCount = computed<number>(() => sessions.value.filter((s) => s.status === 'online').length);
const highCount = computed<number>(() => sessions.value.filter((s) => s.risk === 'high').length);
const geoCount = computed<number>(() => sessions.value.filter((s) => isRemote(s.location)).length);
const untrustedCount = computed<number>(() => sessions.value.filter((s) => s.trust === 'untrusted').length);

const shown = computed<OnlineSession[]>(() => {
  const kw = keyword.value.trim().toLowerCase();
  return sessions.value.filter((s) => {
    if (filter.value === 'high' && s.risk !== 'high') return false;
    if (filter.value === 'untrusted' && s.trust !== 'untrusted') return false;
    if (filter.value === 'geo' && !isRemote(s.location)) return false;
    if (kw) {
      const hay = `${s.user} ${s.account} ${s.ip} ${s.app}`.toLowerCase();
      if (!hay.includes(kw)) return false;
    }
    return true;
  });
});

function setFilter(f: Filter): void {
  filter.value = f;
}

function tagStyle(c: string): { color: string; background: string } {
  return { color: c, background: c + '14' };
}
function initial(name: string): string {
  return name ? name.trim().charAt(0).toUpperCase() : '?';
}
function avatarColor(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return PALETTE[h % PALETTE.length];
}
function trustColor(t: OnlineSession['trust']): string {
  return t === 'trusted' ? C.success : t === 'untrusted' ? C.danger : C.grey;
}
function trustLabel(t: OnlineSession['trust']): string {
  return t === 'trusted' ? '已授信' : t === 'untrusted' ? '未授信' : '未知';
}
function riskColor(r: OnlineSession['risk']): string {
  return r === 'high' ? C.danger : C.warning;
}
function riskLabel(r: OnlineSession['risk']): string {
  return r === 'high' ? '高风险' : '低风险';
}
function loginStamp(t: string): string {
  return t ? t.replace('T', ' ').slice(11, 16) : '—';
}

async function load(): Promise<void> {
  try {
    const r = await api<OnlineResp>('/online');
    sessions.value = r.sessions;
    generatedAt.value = r.generatedAt;
    live.value = true;
  } catch {
    sessions.value = MOCK.sessions;
    generatedAt.value = MOCK.generatedAt;
    live.value = false;
  }
}

async function kick(s: OnlineSession): Promise<void> {
  try {
    await api(`/online/${s.id}/kick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: '管理员强制下线' })
    });
    Message.success('已强制下线：' + s.user);
    await load();
  } catch {
    Message.error('下线失败，请检查管理员权限');
  }
}

onMounted(load);
</script>

<style scoped>
.bd-kpi { border-radius: var(--bd-radius); cursor: pointer; transition: box-shadow .15s, transform .15s; }
.bd-kpi--on { box-shadow: 0 0 0 2px var(--bd-primary) inset; }
.bd-kpi__label { font-size: 13px; color: var(--bd-t3); }
.bd-kpi__value { font-size: 30px; font-weight: 700; line-height: 1.4; color: var(--bd-t1); }
.bd-kpi__foot { font-size: 12px; color: var(--bd-t3); margin-top: 6px; }

.bd-tablecard { margin-top: 16px; }
.bd-searchbox__in { border: none; outline: none; background: transparent; flex: 1; min-width: 0; font-size: 13px; color: var(--bd-t1); }
.bd-searchbox__in::placeholder { color: var(--bd-t3); }
.bd-cellsub { font-size: 11px; color: var(--bd-t3); margin-top: 2px; }
.bd-row--off { opacity: .5; }
.bd-row--off:hover { background: transparent; }
</style>
