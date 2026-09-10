<template>
  <div class="bd-page">
    <PageHeader title="在线用户" :live="live" off-text="降级演示">
      <template #subtitle>实时接入会话 · 就近处置（强制下线）· 数据时间 {{ stamp }}</template>
      <!-- source 恒为 live：后端只有网关上报这一个来源，无网关即空态（演示种子已删除）。
           留着这个标记是为了在对接旧后端时仍能看出数据从哪来。 -->
      <a-tag v-if="live" :color="source === 'live' ? 'arcoblue' : 'gray'" bordered>
        {{ source === 'live' ? '真实接入 · 网关上报' : '旧版后端演示数据' }}
      </a-tag>
      <a-button @click="load">
        <template #icon><icon-refresh /></template>刷新
      </a-button>
    </PageHeader>

    <!-- 首屏骨架：第一次 load() 回来之前不画 MOCK——那一瞬间 8 条演示会话闪一下再变成真数，显示的是假数。 -->
    <template v-if="!loaded">
      <div class="bd-ol__kpis">
        <div v-for="i in 4" :key="i" class="bd-card"><SkeletonBlock kind="stat" /></div>
      </div>
      <div class="bd-tablecard bd-ol__table"><SkeletonBlock kind="table" :rows="5" :cols="8" /></div>
    </template>

    <template v-else>
    <!-- ★读取失败时，后端那句原话必须在页面上有地方看。改造前唯一的线索是页头右上
         那枚橙色「降级演示」标签——看得出"出事了"，看不到"是什么事"。而这一页的
         八条演示会话与真实会话在结构上一模一样，误当成现场就会去处置不存在的人。 -->
    <div v-if="live === false" class="bd-notice bd-notice--warn">
      <icon-exclamation-circle-fill />
      <div class="bd-notice__body">
        在线会话未读取（后端原话：<b>{{ loadErr }}</b>），下面这些会话是<b>内置演示数据</b>，
        <b>不代表现场情况</b>——此刻真实的接入既不在这张表里，也不受这里的「强制下线」影响。
      </div>
    </div>

    <!-- ★「B/S 0 人」在两种情况下长得完全一样：确实没人用浏览器，和一台网关根本没在报。
         后者意味着这一页正在漏人，必须当面说出来而不是让那个 0 被当成结论。 -->
    <div v-if="webBlind.length" class="bd-notice bd-notice--warn">
      <icon-exclamation-circle-fill />
      <div class="bd-notice__body">
        网关 <b>{{ webBlind.join('、') }}</b> 没有上报<b>浏览器（B/S）会话</b>——它们可能未开启七层 Web 代理（<code>-web</code>），
        也可能版本较旧。这一页<b>可能漏掉</b>经这些网关接入的浏览器用户，对他们的「强制下线」也点不到。
      </div>
    </div>

    <!-- P10 聚合头：四张 KPI 同时是筛选入口，选中态由 StatCard 的 :active 承接 -->
    <div class="bd-ol__kpis">
      <StatCard label="在线会话总数" :value="onlineCount" foot="当前活跃接入会话" clickable
        :active="filter === 'all'" @click="setFilter('all')" />
      <StatCard label="高风险会话" :value="highCount" foot="risk = high · 建议优先处置" tone="danger" clickable
        :active="filter === 'high'" @click="setFilter('high')" />
      <!-- ★这一格原来是「异地·公网接入」，判据是 location 含「异地」或「公网」——
           而 location 对每条真实会话恒为 "—"，于是它**结构性恒为 0**、筛选页签永远空。
           一个永远匹配不到东西的筛选比没有筛选更坏：它让人以为「查过了，没有异地接入」。
           白帝没有 GeoIP 库（SCOPE 也不打算做），故整格换成一个真有数的读数。 -->
      <StatCard label="风险不可判定" :value="unknownCount" foot="未登记终端 / 从未上报环境" tone="warning" clickable
        :active="filter === 'unknown'" @click="setFilter('unknown')" />
      <StatCard label="未授信终端" :value="untrustedCount" foot="trust = untrusted" tone="warning" clickable
        :active="filter === 'untrusted'" @click="setFilter('untrusted')" />
    </div>

    <!-- 会话表 -->
    <div class="bd-tablecard bd-ol__table">
      <!-- 过滤条 -->
      <div class="bd-toolbar">
        <a-radio-group v-model="filter" type="button" size="small">
          <a-radio value="all">全部</a-radio>
          <!-- 接入形态是这一页最基本的分组：两种会话的处置粒度与判据都不同 -->
          <a-radio value="tunnel">客户端隧道</a-radio>
          <a-radio value="web">浏览器</a-radio>
          <a-radio value="high">高风险</a-radio>
          <a-radio value="untrusted">未授信</a-radio>
          <a-radio value="unknown">不可判定</a-radio>
        </a-radio-group>
        <div class="bd-toolbar__spacer" />
        <div class="bd-searchbox bd-ol__search">
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
                 「认证方式」同理改名为「接入方式」：会话经 SPA 敲门 + 隧道（C/S）或
                 门户票据 + 浏览器会话（B/S）建立，这是它唯一确定的事实；登录因子
                 （口令/MFA/证书）发生在控制面登录时，网关不知道。 -->
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
            <td>
              <span class="bd-tg" :class="kindOf(s) === 'web' ? 'bd-tg--gold' : 'bd-tg--blue'">
                {{ kindOf(s) === 'web' ? 'B/S 浏览器' : 'C/S 隧道' }}
              </span>
              <div class="bd-cellsub">{{ s.auth }}</div>
              <!-- 只有 B/S 会话有这两格：L7 会话本就绑单个资源、逐请求鉴权天然带活跃度。
                   隧道那侧填任何值都是假的（一条隧道可路由到多个资源，活跃时刻是三态）。 -->
              <div v-if="kindOf(s) === 'web'" class="bd-cellsub">
                资源 <span class="bd-mono">{{ s.resource || '—' }}</span>
                <template v-if="s.idleSec != null"> · 空闲 {{ humanIdle(s.idleSec) }}</template>
              </div>
            </td>
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
              <span class="bd-ol__tags">
                <span class="bd-tg" :class="`bd-tg--${trustTg(s.trust)}`" :title="s.trustNote">{{ trustLabel(s.trust) }}</span>
                <span v-if="s.risk !== 'none'" class="bd-tg" :class="`bd-tg--${riskTg(s.risk)}`" :title="s.riskNote">{{ riskLabel(s.risk) }}</span>
              </span>
            </td>
            <td class="r">
              <template v-if="s.status === 'online'">
                <!-- ★文案必须说清真实影响面：强制下线是**账号维度**的（撤销通道本就没有
                     会话维度），点一条 B/S 会话同样会把这个人的隧道一起断掉。
                     写成「断开这条会话」会让管理员以为只影响他正开着的那个浏览器页面。 -->
                <a-popconfirm :content="kickHint(s)" type="warning" @ok="kick(s)">
                  <button type="button" class="bd-link bd-link--danger">强制下线</button>
                </a-popconfirm>
              </template>
              <template v-else>
                <span class="bd-tg bd-tg--grey">已下线</span>
                <div v-if="s.kickReason" class="bd-cellsub">{{ s.kickReason }}</div>
              </template>
            </td>
          </tr>
          <!-- 空态要区分"筛没了"和"根本没有人在线"：后者是安全读数，
               含义是数据面此刻没有任何接入，不该和筛选结果为空混为一谈。 -->
          <tr v-if="!shown.length" class="bd-table__emptyrow">
            <td colspan="8">
              <EmptyState v-if="sessions.length" size="md" title="无匹配会话（当前筛选条件下）" />
              <EmptyState v-else-if="live" size="md" tone="warn" title="尚无网关上报在线会话" desc="数据面网关未注册，或当前无人接入" />
              <EmptyState v-else size="md" title="无匹配会话" />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type OnlineSession, type OnlineResp, failReason } from '@/lib/api';
import PageHeader from '@/components/PageHeader.vue';
import StatCard from '@/components/StatCard.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

type Filter = 'all' | 'tunnel' | 'web' | 'high' | 'untrusted' | 'unknown';

/* 头像底色色板（按用户名哈希取色，只服务头像；KPI / 标签的语义色一律走 --bd-* 类）。 */
const PALETTE = ['#165DFF', '#00B42A', '#FF7D00', '#F53F3F', '#722ED1', '#0FC6C2'];

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
    { id: 'sess-1007', user: '吴霜', account: 'wu.shuang', org: '人力资源部', ip: '203.0.113.140', auth: '门户票据 + 浏览器会话', kind: 'web', resource: 'oa', idleSec: 138, gateway: 'gw-gz-05', loginAt: '2026-06-24T09:48:27', duration: '53m', trust: 'unknown', risk: 'unknown', status: 'online' },
    { id: 'sess-1008', user: '郑昊', account: 'svc-bot-04', org: '系统 / 服务账号', ip: '10.20.1.200', auth: 'SPA 敲门 + 隧道', gateway: 'gw-hz-01', loginAt: '2026-06-24T07:10:00', duration: '—', trust: 'trusted', risk: 'none', status: 'offline', kickReason: '管理员手动下线 · 09:55' }
  ]
};

const sessions = ref<OnlineSession[]>(MOCK.sessions);
const generatedAt = ref<string>(MOCK.generatedAt);
/** 连接态三态：undefined = 首轮请求还在路上（判不出来，PageHeader 此时不画标签）/
 *  true 已连 / false 降级演示。★初值写 false 的话，首屏那一瞬页头就挂上一枚橙色
 *  「降级演示」——把"还没探过"说成"确定离线"，而那一刻什么都还没发生。 */
const live = ref<boolean | undefined>(undefined);
/** 读取失败时后端那句原话（failReason 收口，前端不编造归因）。 */
const loadErr = ref('');
const source = ref<'live' | 'demo'>('demo'); // live=数据面网关上报的真实敲门会话；demo=演示种子
/** 在线、但没上报七层会话的网关（这一页可能正在漏掉它们上面的浏览器接入）。 */
const webBlind = ref<string[]>([]);
const filter = ref<Filter>('all');
const keyword = ref<string>('');
/** 首屏是否已完成第一次加载：只决定骨架屏何时让位（成功 / 降级都算完成），不改任何数据流。 */
const loaded = ref(false);

const stamp = computed<string>(() => (generatedAt.value ? generatedAt.value.replace('T', ' ').slice(0, 19) : '—'));

const onlineCount = computed<number>(() => sessions.value.filter((s) => s.status === 'online').length);
const highCount = computed<number>(() => sessions.value.filter((s) => s.risk === 'high').length);
const untrustedCount = computed<number>(() => sessions.value.filter((s) => s.trust === 'untrusted').length);
/** 风险不可判定：账号一台终端都没登记，或从未上报过终端环境。
 *  ★这两种恰恰是 observe 准入模式下最常见的形态——他们照样能接入，而控制面对他们
 *  的终端一无所知。此前这一格显示成「授信 / 无风险」，等于替一台完全未知的机器背书。 */
const unknownCount = computed<number>(() =>
  sessions.value.filter((s) => s.trust === 'unknown' || s.risk === 'unknown').length);

/** 接入形态。★旧后端不发 kind 时按 tunnel 渲染——那时这一页本来就只有隧道会话，
 *  默认成 'web' 会把一整页 C/S 会话说成浏览器接入，而两者的处置粒度完全不同。 */
function kindOf(s: OnlineSession): 'tunnel' | 'web' {
  return s.kind === 'web' ? 'web' : 'tunnel';
}
/** 强制下线的确认文案：把**账号维度**这件事说在前面。
 *  后端 handleKickSession 把该账号记进封禁名单 + 注销其控制面令牌，网关随下一轮策略
 *  同时切隧道、切七层长连接、注销全部 Web 会话——不存在"只踢这一条"。 */
function kickHint(s: OnlineSession): string {
  return kindOf(s) === 'web'
    ? `确认强制下线 ${s.user}？处置是账号维度的：他的浏览器会话与客户端隧道会一起被切断，并需重新认证。`
    : `确认强制下线 ${s.user}？处置是账号维度的：他的隧道与浏览器会话会一起被切断，并需重新认证。`;
}
/** 空闲时长的人话。0 秒是「刚刚还有流量」，不是「不可判定」——不可判定时字段整个缺席。 */
function humanIdle(sec: number): string {
  if (sec < 60) return `${sec} 秒`;
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟`;
  return `${Math.floor(sec / 3600)} 小时`;
}

const shown = computed<OnlineSession[]>(() => {
  const kw = keyword.value.trim().toLowerCase();
  return sessions.value.filter((s) => {
    if (filter.value === 'tunnel' && kindOf(s) !== 'tunnel') return false;
    if (filter.value === 'web' && kindOf(s) !== 'web') return false;
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

function initial(name: string): string {
  return name ? name.trim().charAt(0).toUpperCase() : '?';
}
function avatarColor(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return PALETTE[h % PALETTE.length];
}
/** 标签语义色走 .bd-tg--* 浅色对：trusted 绿 / untrusted 红 / 不可判定 灰。 */
function trustTg(t: OnlineSession['trust']): string {
  return t === 'trusted' ? 'green' : t === 'untrusted' ? 'red' : 'grey';
}
function trustLabel(t: OnlineSession['trust']): string {
  return t === 'trusted' ? '已授信' : t === 'untrusted' ? '未授信' : '终端不可判定';
}
/** ★unknown 用灰色而不是橙色：它不是"低风险"，是"我们不知道"。
 *  用暖色会让人以为已经评估过、只是不严重。 */
function riskTg(r: OnlineSession['risk']): string {
  return r === 'high' ? 'red' : r === 'unknown' ? 'grey' : 'gold';
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
    webBlind.value = r.webBlindGateways ?? [];
    live.value = true;
    loadErr.value = '';
  } catch (e) {
    sessions.value = MOCK.sessions;
    generatedAt.value = MOCK.generatedAt;
    source.value = 'demo';
    // 降级演示时不挂那条提示：它说的是"真实数据源有一块盲区"，
    // 而此刻整页都不是真实数据（页顶那条 warn 已经把这件事说清了）。
    webBlind.value = [];
    live.value = false;
    loadErr.value = failReason(e);
  } finally {
    loaded.value = true;
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
  } catch (e) {
    Message.error(`强制下线失败：${failReason(e)}`);
  }
}

onMounted(load);
</script>

<style scoped>
/* 本页独有的布局。页头 / KPI 卡 / 表格卡 / 搜索框 / 标签 / 空态 / 骨架都在共享件与 app.css 里。 */
.bd-ol__kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: var(--bd-sp-4); }
/* KPI 卡兼作筛选入口：选中态主色描边 */
.bd-ol__table { margin-top: var(--bd-sp-4); }
.bd-ol__search { width: 260px; }
.bd-ol__tags { display: inline-flex; flex-wrap: wrap; gap: 6px; }
.bd-cellsub { font-size: var(--bd-fs-xs); color: var(--bd-t3); margin-top: 2px; }
.bd-row--off { opacity: .5; }
.bd-row--off:hover td { background: transparent; }
@media (max-width: 1320px) {
  .bd-ol__kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .bd-ol__search { width: 220px; }
}
</style>
