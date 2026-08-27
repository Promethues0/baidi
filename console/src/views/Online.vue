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
        <!-- source 恒为 live：后端只有网关上报这一个来源，无网关即空态（演示种子已删除）。
             留着这个标记是为了在对接旧后端时仍能看出数据从哪来。 -->
        <a-tag v-if="live" :color="source === 'live' ? 'arcoblue' : 'gray'" bordered>
          {{ source === 'live' ? '真实接入 · 网关上报' : '旧版后端演示数据' }}
        </a-tag>
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
      <!-- ★这一格原来是「异地·公网接入」，判据是 location 含「异地」或「公网」——
           而 location 对每条真实会话恒为 "—"，于是它**结构性恒为 0**、筛选页签永远空。
           一个永远匹配不到东西的筛选比没有筛选更坏：它让人以为「查过了，没有异地接入」。
           白帝没有 GeoIP 库（SCOPE 也不打算做），故整格换成一个真有数的读数。 -->
      <a-grid-item>
        <a-card class="bd-kpi" :class="{ 'bd-kpi--on': filter === 'unknown' }" :bordered="false" hoverable @click="setFilter('unknown')">
          <div class="bd-kpi__label">风险不可判定</div>
          <div class="bd-kpi__value" :style="{ color: C.warning }">{{ unknownCount }}</div>
          <div class="bd-kpi__foot">未登记终端 / 从未上报环境</div>
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
          <a-radio value="unknown">不可判定</a-radio>
        </a-radio-group>
        <div style="flex: 1" />
        <div class="bd-searchbox" style="width: 260px">
          <icon-search />
          <input v-model="keyword" class="bd-searchbox__in" placeholder="按用户 / 账号 / 组织 / IP / 网关搜索" />
        </div>
      </div>

      <table class="bd-table">
        <thead>
          <tr>
            <!-- ★删掉了「接入地点 / 终端 / 当前应用」三列：网关按会话上报的只有
                 {IP, 账号, 角色, 建立时刻}，这三格此前对每条真实会话都渲染成 "—"。
                 三列永远空着的表头不是"暂无数据"，是在暗示这些维度存在而恰好没取到。
                 「认证方式」同理改名为「接入方式」：会话经 SPA 敲门 + 隧道建立是它唯一
                 确定的事实，登录因子（口令/MFA/证书）发生在控制面登录时，网关不知道。 -->
            <th>用户</th>
            <th>组织</th>
            <th>来源 IP</th>
            <th>接入方式</th>
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
            <td><span class="bd-mono">{{ s.ip }}</span></td>
            <td>{{ s.auth }}</td>
            <td><span class="bd-mono">{{ s.gateway }}</span></td>
            <td>
              <div class="bd-cellsub">{{ loginStamp(s.loginAt) }} 起</div>
              <div>· {{ s.duration }}</div>
            </td>
            <td>
              <!-- ★依据挂 title：这两格是**账号级**结论（会话上报里没有设备指纹），
                   只给结论不给依据，管理员没法判断该不该处置。
                   ★risk=unknown 也必须显示——此前只在 risk!=='none' 时渲染，
                   于是「不可判定」与「无风险」在页面上长得一模一样。 -->
              <span class="bd-tg" :style="tagStyle(trustColor(s.trust))" :title="s.trustNote">{{ trustLabel(s.trust) }}</span>
              <span v-if="s.risk !== 'none'" class="bd-tg" :style="[tagStyle(riskColor(s.risk)), { marginLeft: '6px' }]" :title="s.riskNote">{{ riskLabel(s.risk) }}</span>
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
          <!-- 空态要区分"筛没了"和"根本没有人在线"：后者是安全读数，
               含义是数据面此刻没有任何接入，不该和筛选结果为空混为一谈。 -->
          <tr v-if="!shown.length">
            <td colspan="10" class="bd-empty">
              <template v-if="sessions.length">无匹配会话（当前筛选条件下）</template>
              <template v-else-if="live">尚无网关上报在线会话：数据面网关未注册，或当前无人接入</template>
              <template v-else>无匹配会话</template>
            </td>
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

type Filter = 'all' | 'high' | 'untrusted' | 'unknown';

const C = {
  brand: '#165DFF',
  success: '#00B42A',
  warning: '#FF7D00',
  danger: '#F53F3F',
  purple: '#722ED1',
  grey: '#86909C'
} as const;

const PALETTE = [C.brand, C.success, C.warning, C.danger, C.purple, '#0FC6C2'];

// 降级演示数据（仅在**连不上后端**时渲染，页头会打「降级演示」标）。
// 字段与真实响应同构：location/device/os/app 四列已随后端一并删除——
// 演示数据比真实响应多几列的话，页面会按演示数据的形状设计，而真机上那几列永远空着。
const MOCK: OnlineResp = {
  generatedAt: '2026-06-24T10:42:18',
  sessions: [
    { id: 'sess-1001', user: '李明', account: 'li.ming', org: '研发中心 / 平台组', ip: '10.20.3.14', auth: 'SPA 敲门 + 隧道', gateway: 'gw-hz-01', loginAt: '2026-06-24T08:55:02', duration: '1h47m', trust: 'trusted', risk: 'none', trustNote: '该账号名下 2 台终端：2 台已授信', riskNote: '终端合规判定 allow：无失败项', status: 'online' },
    { id: 'sess-1002', user: '赵磊', account: 'waibao-zhao', org: '外包 / 实施', ip: '203.0.113.77', auth: 'SPA 敲门 + 隧道', gateway: 'gw-sh-02', loginAt: '2026-06-24T10:31:40', duration: '10m', trust: 'untrusted', risk: 'high', trustNote: '该账号名下 1 台终端：1 台已吊销', riskNote: '终端合规判定 block（已拒发敲门令牌 / 撤窗断隧道）：磁盘已加密 未通过', status: 'online' },
    { id: 'sess-1003', user: '王芳', account: 'wang.fang', org: '财务部', ip: '10.20.5.31', auth: 'SPA 敲门 + 隧道', gateway: 'gw-hz-01', loginAt: '2026-06-24T09:12:55', duration: '1h29m', trust: 'trusted', risk: 'low', trustNote: '该账号名下 1 台终端：1 台已授信', riskNote: '终端合规判定 gray（观察中，访问权未变更）：EDR 终端防护在线 未通过', status: 'online' },
    { id: 'sess-1004', user: '陈晨', account: 'chen.chen', org: '研发中心 / 算法组', ip: '198.51.100.22', auth: 'SPA 敲门 + 隧道', gateway: 'gw-sz-03', loginAt: '2026-06-24T10:05:11', duration: '37m', trust: 'unknown', risk: 'unknown', trustNote: '该账号名下没有任何已登记终端', riskNote: '该账号从未上报过终端环境（observe 模式下仍可接入）', status: 'online' },
    { id: 'sess-1005', user: '孙倩', account: 'sun.qian', org: '市场部', ip: '10.20.8.66', auth: 'SPA 敲门 + 隧道', gateway: 'gw-hz-01', loginAt: '2026-06-24T08:30:19', duration: '2h11m', trust: 'trusted', risk: 'none', status: 'online' },
    { id: 'sess-1006', user: '周强', account: 'zhou.qiang', org: '研发中心 / 测试组', ip: '172.16.4.9', auth: 'SPA 敲门 + 隧道', gateway: 'gw-bj-04', loginAt: '2026-06-24T10:38:02', duration: '4m', trust: 'untrusted', risk: 'low', trustNote: '该账号名下 2 台终端：1 台已授信 / 1 台待审批', status: 'online' },
    { id: 'sess-1007', user: '吴霜', account: 'wu.shuang', org: '人力资源部', ip: '203.0.113.140', auth: 'SPA 敲门 + 隧道', gateway: 'gw-gz-05', loginAt: '2026-06-24T09:48:27', duration: '53m', trust: 'unknown', risk: 'unknown', status: 'online' },
    { id: 'sess-1008', user: '郑昊', account: 'svc-bot-04', org: '系统 / 服务账号', ip: '10.20.1.200', auth: 'SPA 敲门 + 隧道', gateway: 'gw-hz-01', loginAt: '2026-06-24T07:10:00', duration: '—', trust: 'trusted', risk: 'none', status: 'offline', kickReason: '管理员手动下线 · 09:55' }
  ]
};

const sessions = ref<OnlineSession[]>(MOCK.sessions);
const generatedAt = ref<string>(MOCK.generatedAt);
const live = ref<boolean>(false);
const source = ref<'live' | 'demo'>('demo'); // live=数据面网关上报的真实敲门会话；demo=演示种子
const filter = ref<Filter>('all');
const keyword = ref<string>('');

const stamp = computed<string>(() => (generatedAt.value ? generatedAt.value.replace('T', ' ').slice(0, 19) : '—'));

const onlineCount = computed<number>(() => sessions.value.filter((s) => s.status === 'online').length);
const highCount = computed<number>(() => sessions.value.filter((s) => s.risk === 'high').length);
const untrustedCount = computed<number>(() => sessions.value.filter((s) => s.trust === 'untrusted').length);
/** 风险不可判定：账号一台终端都没登记，或从未上报过终端环境。
 *  ★这两种恰恰是 observe 准入模式下最常见的形态——他们照样能接入，而控制面对他们
 *  的终端一无所知。此前这一格显示成「授信 / 无风险」，等于替一台完全未知的机器背书。 */
const unknownCount = computed<number>(() =>
  sessions.value.filter((s) => s.trust === 'unknown' || s.risk === 'unknown').length);

const shown = computed<OnlineSession[]>(() => {
  const kw = keyword.value.trim().toLowerCase();
  return sessions.value.filter((s) => {
    if (filter.value === 'high' && s.risk !== 'high') return false;
    if (filter.value === 'untrusted' && s.trust !== 'untrusted') return false;
    if (filter.value === 'unknown' && s.trust !== 'unknown' && s.risk !== 'unknown') return false;
    if (kw) {
      // 检索维度必须覆盖页面在显示的列（含 org），且与占位文案一致。
      const hay = `${s.user} ${s.account} ${s.org ?? ''} ${s.ip} ${s.gateway}`.toLowerCase();
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
  return t === 'trusted' ? '已授信' : t === 'untrusted' ? '未授信' : '终端不可判定';
}
/** ★unknown 用灰色而不是橙色：它不是"低风险"，是"我们不知道"。
 *  用暖色会让人以为已经评估过、只是不严重。 */
function riskColor(r: OnlineSession['risk']): string {
  return r === 'high' ? C.danger : r === 'unknown' ? C.grey : C.warning;
}
function riskLabel(r: OnlineSession['risk']): string {
  return r === 'high' ? '高风险' : r === 'unknown' ? '风险不可判定' : '低风险';
}
function loginStamp(t: string): string {
  return t ? t.replace('T', ' ').slice(11, 16) : '—';
}

async function load(): Promise<void> {
  try {
    const r = await api<OnlineResp>('/online');
    sessions.value = r.sessions;
    generatedAt.value = r.generatedAt;
    source.value = r.source ?? 'demo';
    live.value = true;
  } catch {
    sessions.value = MOCK.sessions;
    generatedAt.value = MOCK.generatedAt;
    source.value = 'demo';
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
