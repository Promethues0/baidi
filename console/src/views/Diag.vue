<template>
  <div class="dg">
    <!-- 顶栏：独立页（不在管理台壳里），自带一条与门户栏同规格的细 bar -->
    <header class="dg-top">
      <div class="dg-logo">
        <span class="dg-logo__mark">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <div class="dg-logo__txt"><b>运维诊断</b><i>白帝 · 系统自检与健康巡检</i></div>
      </div>
      <div class="dg-top__spacer" />
      <!-- 连接态三态（与 PageHeader 同一条契约，本页手写头故不能复用那个组件）：
           live == null（首屏还没体检过一次）→ **不画标签**。此前初值是 false，于是页面一挂载
           就当场断言「降级演示 · 内置数据」——那一刻请求还在飞，控制面可能好得很。
           data-tone 给机器断言用（CDP 探针核不到 Arco 的颜色类名）。 -->
      <a-tag v-if="live != null" :color="live ? 'green' : denied ? 'red' : 'orange'"
        :data-tone="live ? 'green' : denied ? 'red' : 'orange'" bordered>
        <template #icon><icon-cloud /></template>
        {{ live ? '已连 baidi-control' : denied ? '需管理员权限' : '降级演示 · 内置数据' }}
      </a-tag>
      <a-button type="primary" :loading="loading" @click="load">
        <template #icon><icon-refresh /></template>重新体检
      </a-button>
      <a-button @click="exportReport"><template #icon><icon-download /></template>导出报告</a-button>
      <a-button @click="back"><template #icon><icon-export /></template>返回控制台</a-button>
    </header>

    <!-- 非管理员（后端 403）：如实告知，不展示演示数据。
         desc 里带上 failReason(e) 的后端原话——403 有好几种成因（不是管理员 / 是管理员但角色
         没有该权限键），后端那句「角色「审计管理员」无权执行该操作（需要权限：system）」
         才是唯一能指导下一步动作的信息。 -->
    <div v-if="denied" class="dg-body dg-body--center">
      <EmptyState size="lg" tone="danger" title="需要管理员权限" :desc="deniedDesc">
        <template #icon><icon-lock /></template>
        <template #action>
          <a-button type="primary" @click="back"><template #icon><icon-export /></template>返回控制台</a-button>
        </template>
      </EmptyState>
    </div>

    <!-- 首屏骨架：第一次 load() 回来之前不画 MOCK——那一瞬间「健康分 81」闪一下再变成真数，显示的是假数。 -->
    <div v-else-if="!loaded" class="dg-body">
      <section class="bd-card dg-hero dg-hero--sk">
        <SkeletonBlock kind="stat" />
        <SkeletonBlock kind="text" :rows="3" />
        <SkeletonBlock kind="text" :rows="4" />
      </section>
      <section class="dg-grid">
        <div v-for="i in 6" :key="i" class="bd-card"><SkeletonBlock kind="card" :rows="3" /></div>
      </section>
    </div>

    <div v-else class="dg-body">
      <!-- ★这一页是全站最后一处「页面主动说反话」：MOCK 的第一张卡就是
           「控制面 baidi-control · 正常 · 控制中心进程运行正常，API 响应中」，而这一屏出现的
           前提恰恰是本次 /diag 请求没有应答——用一张绿卡替一台没应答的控制面背书，
           比什么都不显示更坏。归因一律来自 failReason(e)，前端不猜。
           同批把健康分改成「—」、把九张卡的状态徽标改成「演示占位」：
           横幅在屏幕顶上，而检查卡才是这一页的正文，只加横幅拦不住往下滚的人。
           **MOCK 回落本身没动**（卡片、结论、指标一条不少），改的只是"它们被当成实测"这件事。 -->
      <div v-if="degraded" class="bd-notice bd-notice--warn">
        <icon-exclamation-circle-fill />
        <div class="bd-notice__body">
          体检未执行（后端原话：<b>{{ loadErr || '控制面未返回体检数据' }}</b>），下面的健康分、
          {{ bundle.checks.length }} 张检查卡与全部数字都是<b>内置演示数据</b>，<b>不代表本机现状</b>——
          每张卡的状态徽标已按此标成「演示占位」，健康分显示为「—」。
          控制面恢复后点右上角「重新体检」；此刻导出的报告也会带同一句标注（与本条同源）。
        </div>
      </div>

      <!-- 健康总览 -->
      <section class="bd-card dg-hero">
        <div class="dg-score">
          <svg viewBox="0 0 120 120" class="dg-score__svg">
            <circle cx="60" cy="60" r="52" class="dg-score__track" />
            <!-- 判不出来时把进度环整圈让位给底轨（offset = 整个周长）：留着 81% 那道弧，
                 光看颜色和长度的人照样会读成"这台机器 81 分"。 -->
            <circle
              cx="60" cy="60" r="52" class="dg-score__val" :class="degraded ? 'is-unknown' : `is-${scoreTone}`"
              :stroke-dasharray="scoreCirc" :stroke-dashoffset="degraded ? scoreCirc : scoreOffset"
            />
          </svg>
          <div class="dg-score__c">
            <b :class="degraded ? 'is-unknown' : `is-${scoreTone}`">{{ degraded ? '—' : bundle.score }}</b>
            <i>健康分</i>
          </div>
        </div>
        <div class="dg-hero__mid">
          <div class="dg-hero__verdict" :class="degraded ? 'is-unknown' : `is-${scoreTone}`">{{ verdictText }}</div>
          <template v-if="!degraded">
            <div class="dg-hero__stats">
              <span class="dg-stat dg-stat--pass"><b>{{ bundle.pass }}</b>正常</span>
              <span class="dg-stat dg-stat--warn"><b>{{ bundle.warn }}</b>关注</span>
              <span class="dg-stat dg-stat--fail"><b>{{ bundle.fail }}</b>异常</span>
              <span v-if="bundle.skip" class="dg-stat dg-stat--skip"><b>{{ bundle.skip }}</b>跳过</span>
            </div>
            <div class="dg-hero__bar">
              <span v-if="bundle.pass" class="seg pass" :style="{ flex: bundle.pass }" />
              <span v-if="bundle.warn" class="seg warn" :style="{ flex: bundle.warn }" />
              <span v-if="bundle.fail" class="seg fail" :style="{ flex: bundle.fail }" />
            </div>
          </template>
          <!-- 「5 正常 / 3 关注 / 0 异常」这一行同样是对本机的正面断言，判不出来时不许画。 -->
          <div v-else class="dg-hero__unknown">
            检查项计数与健康分本次都<b>不可判定</b>：控制面没有返回任何体检结果，页面退回内置演示占位。
          </div>
        </div>
        <div class="dg-hero__meta">
          <div class="mrow"><span>组件</span><b>{{ bundle.component }}</b></div>
          <!-- ★不再硬拼 "v" 前缀：未注入时那会渲染成一个孤零零的 "v"，
               看起来像取数出了 bug，而事实是这个二进制没有版本身份（见 checkVersion 那一项）。 -->
          <div class="mrow"><span>版本</span><b>{{ versionText }} · {{ envLabel }}</b></div>
          <div class="mrow"><span>构建</span><b>{{ bundle.build || '未注入' }}</b></div>
          <div class="mrow"><span>运行时长</span><b>{{ bundle.uptime }}</b></div>
          <div class="mrow"><span>体检时间</span><b>{{ bundle.generatedAt || '—' }}</b></div>
        </div>
      </section>

      <!-- 检查项（问题优先：异常 → 关注 → 正常） -->
      <section class="dg-grid">
        <!-- 判不出来时状态徽标与左侧色边一律走中性的 demo 档：绿色的「正常」是一句断言，
             而这一屏的前提是"一次检查都没跑过"。徽标文案 badgeLabel() 与导出报告同一处实现。 -->
        <article v-for="c in sortedChecks" :key="c.key" class="bd-card dg-card" :class="'is-' + (degraded ? 'demo' : c.status)">
          <div class="dg-card__head">
            <span class="dg-card__icon"><component :is="catIcon(c.category)" /></span>
            <div class="dg-card__t">
              <div class="dg-card__name">{{ c.name }}</div>
              <div class="dg-card__cat">{{ catLabel(c.category) }}</div>
            </div>
            <span class="dg-badge" :class="degraded ? 'demo' : c.status">{{ badgeLabel(c) }}</span>
          </div>
          <div class="dg-card__summary">{{ c.summary }}</div>
          <div v-if="c.metric" class="dg-card__metric"><icon-info-circle />{{ c.metric }}</div>
          <div v-if="c.hint" class="dg-card__hint"><icon-bulb />{{ c.hint }}</div>
          <div v-if="c.items?.length" class="dg-card__more">
            <!-- 真 button：明细折叠是键盘可达的 -->
            <button type="button" class="dg-card__more-h" :aria-expanded="openItems.has(c.key)" @click="toggleItems(c.key)">
              <icon-down :class="{ up: openItems.has(c.key) }" />{{ c.items.length }} 项明细
            </button>
            <ul v-if="openItems.has(c.key)" class="dg-items">
              <li v-for="it in c.items" :key="it.label" class="dg-item">
                <span class="dg-item__dot" :class="'is-' + (it.status || 'pass')" />
                <span class="dg-item__l">{{ it.label }}</span>
                <span class="dg-item__v">{{ it.value }}</span>
              </li>
            </ul>
          </div>
        </article>
      </section>

      <!-- 数据面网关明细（诊断联动真实上报指标） -->
      <section v-if="gateways.length" class="dg-gws">
        <div class="bd-section-title">
          <icon-link /> 数据面网关明细
          <span class="bd-section-title__sub">{{ gateways.length }} 台已注册 · 网关每 15s 上报活性</span>
        </div>
        <div class="dg-gws__grid">
          <div v-for="g in gateways" :key="g.id" class="bd-card dg-gw" :class="{ off: !gwOnline(g) }">
            <div class="dg-gw__top">
              <span class="dg-gw__dot" :class="{ on: gwOnline(g) }" />
              <b class="dg-gw__id">{{ g.id }}</b>
              <span class="dg-gw__state">{{ gwOnline(g) ? '在线' : '心跳超时' }}</span>
            </div>
            <div class="dg-gw__nums">
              <div class="dg-gw__n"><b>{{ g.clients }}</b><i>已授权客户端</i></div>
              <div class="dg-gw__n"><b>{{ g.tunnels }}</b><i>活跃隧道</i></div>
              <div class="dg-gw__n"><b>{{ fmtUptime(g.uptime) }}</b><i>运行时长</i></div>
            </div>
            <div class="dg-gw__meta">
              <span class="bd-mono">代理 {{ g.proxy }}</span>
              <span class="bd-mono">SPA {{ g.spa }}</span>
              <span>心跳 {{ fmtAgo(g.lastSeen) }}</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, type DiagBundle, type DiagCheck, type DiagCategory, type DiagStatus, type GatewaysResp, type GatewayReg, failStatus, failReason } from '@/lib/api';
import { FIRST_PATH } from '@/nav';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

const router = useRouter();

/* 数据面网关明细（诊断联动：/gateways 上报的真实活性指标） */
const gateways = ref<GatewayReg[]>([]);
const GW_ONLINE_WINDOW = 120; // 秒，与后端一致
function gwOnline(g: GatewayReg): boolean { return Date.now() / 1000 - g.lastSeen <= GW_ONLINE_WINDOW; }
function fmtAgo(sec: number): string {
  const d = Math.max(0, Math.floor(Date.now() / 1000 - sec));
  if (d < 60) return `${d} 秒前`;
  if (d < 3600) return `${Math.floor(d / 60)} 分钟前`;
  return `${Math.floor(d / 3600)} 小时前`;
}
function fmtUptime(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h`;
  return `${Math.floor(sec / 86400)}d`;
}

/* 降级演示数据（对齐后端 DiagBundle，便于无后端时预览） */
const MOCK: DiagBundle = {
  // ★演示占位的版本身份**故意留空**：这份数据只在连不上后端时出现，
  // 而连不上后端恰恰不该被渲染成一个言之凿凿的版本号（页顶已有降级横幅）。
  generatedAt: '', component: 'baidi-control · 控制中心', version: '', build: '', env: 'dev', uptime: '—',
  score: 81, pass: 5, warn: 4, fail: 0, skip: 1,
  checks: [
    { key: 'version', category: 'control', name: '服务端版本身份', status: 'warn', summary: '控制面的语义版本未注入：当前版本不可判定', metric: '未注入 · 未注入', hint: '用 deploy/build.sh 重新构建并部署（语义版本取自仓库根的 VERSION 文件）。' },
    { key: 'control', category: 'control', name: '控制面 baidi-control', status: 'pass', summary: '控制中心进程运行正常，API 响应中', metric: 'v0.3.0 · 运行 —', hint: '' },
    { key: 'db', category: 'storage', name: '管理数据库 SQLite', status: 'pass', summary: '数据库连接正常，读写可用', metric: '往返 —', hint: '' },
    { key: 'audit-disk', category: 'storage', name: '审计日志留存', status: 'pass', summary: '审计日志留存正常，磁盘水位健康', metric: '审计 2040 行 · 库文件 1.6MB · 磁盘余 212.3GB / 494.4GB（占用 57%）· 留存 180 天', hint: '' },
    { key: 'gateways', category: 'dataplane', name: '数据面网关在线', status: 'warn', summary: '尚无数据面网关注册（控制面可独立运行）', metric: '在线 0 / 注册 0', hint: '以 -control 指向本控制面启动 baidi-gateway 即自动注册' },
    { key: 'spa', category: 'stealth', name: 'SPA 服务隐身', status: 'warn', summary: '无网关经 mTLS 注册，隐身状态未知', metric: '在线 0 / 注册 0', hint: '以 -control + mTLS 证书启动 baidi-gateway，注册后此处才有事实可报' },
    { key: 'cluster', category: 'cluster', name: '控制面温备（warm standby）', status: 'skip', summary: '未配置备机（当前为单机形态）', metric: '单机 · 1 进程 + SQLite', hint: '如需冗余：部署 baidi-standby 温备节点（周期拉加密备份），切换用 deploy/promote-standby.sh。温备不是双活，RPO = 同步间隔' },
    { key: 'authsrc', category: 'identity', name: '认证源配置', status: 'pass', summary: '已配置 1 个认证源（连通性以「测试连接」实测为准）', metric: '启用 1 / 配置 1', hint: '' },
    { key: 'posture', category: 'posture', name: '访问威胁压力', status: 'pass', summary: '访问态势平稳，拒绝/二次鉴权为策略正常拦截', metric: '拒绝 0 · 失败 0 · 二次鉴权 0 · 在线 —（无网关上报）', hint: '' },
    { key: 'secret', category: 'security', name: '密钥与传输安全', status: 'warn', summary: '令牌已切 Ed25519 非对称签名，但仍接受存量 HS256 令牌（升级兼容窗口）', metric: '迁移窗口开启', hint: '存量 8h 会话令牌全部自然过期后，置 BAIDI_ACCEPT_HS256=0 收口' }
  ]
};

const bundle = ref<DiagBundle>(MOCK);
const openItems = ref<Set<string>>(new Set());
function toggleItems(k: string) { const e = new Set(openItems.value); e.has(k) ? e.delete(k) : e.add(k); openItems.value = e; }
/**
 * 连接态**三态**：undefined = 还没体检过一次（判不出来）/ true 已连 / false 降级或被拒。
 *
 * ★初值必须是 undefined 而不是 false：false 的含义是「探过了，没连上」，把它当初值等于
 *   在第一个请求还在飞的时候就替控制面下结论。`load()` 的三条落定路径（成功 / 403 / 其它失败）
 *   逐条赋值——**漏一条会让标签永远不画**，那是这个改法唯一的失败形态。
 */
const live = ref<boolean | undefined>(undefined);
const loading = ref(false);
/** 首屏是否已完成第一次 load()：只决定骨架屏何时让位（成功 / 降级 / 403 都算完成），不改任何数据流。 */
const loaded = ref(false);
const denied = ref(false); // 后端 403（非 admin）：显式提示而非静默降级演示
/**
 * 本次失败的**后端原话**（failReason(e)，唯一收口）。
 *
 * ★改造前 load() 的 catch 把 e 整个丢掉：403 走 denied，其余分支直接把 bundle 置成 MOCK，
 *   于是 503「控制面维护中」与 502、与网络不通，在屏幕上是同一句话——没有任何一句。
 *   全文件 failReason 出现 0 次，而这一页恰好是唯一会拿绿卡替控制面背书的页。
 */
const loadErr = ref('');
/**
 * 「这一屏不是实测结果」——屏幕与 exportReport() **同一个判据**。
 *
 * ★live 三态在这里的方向恒定：只有**确定已连**才算实测，undefined（还没体检完第一次）
 *   与 false 一律算降级。此前只有导出报告有这个概念（它会在正文与文件名两处标注非实测），
 *   屏幕那一半反而没跟上，同一页两条路两种说法。
 */
const degraded = computed(() => live.value !== true);
/** 403 的说明文案：后端那句「需要权限：system」才指导得了下一步动作，不能丢。 */
const deniedDesc = computed(() =>
  '运维诊断仅对管理员开放。当前账号无权读取系统自检数据（控制面已拒绝 /diag 请求）。' +
  (loadErr.value ? `后端原话：${loadErr.value}` : '')
);

/* 问题优先排序：异常 → 关注 → 正常 → 跳过；未知枚举兜底排最后（别让 NaN 搅乱排序） */
const RANK: Record<DiagStatus, number> = { fail: 0, warn: 1, pass: 2, skip: 3 };
const sortedChecks = computed<DiagCheck[]>(() =>
  [...bundle.value.checks].sort((a, b) => (RANK[a.status] ?? 9) - (RANK[b.status] ?? 9))
);

/* 健康分环 */
const scoreCirc = 2 * Math.PI * 52;
const scoreOffset = computed(() => scoreCirc * (1 - Math.min(Math.max(bundle.value.score, 0), 100) / 100));
/** 健康分的语义档（同一阈值给环、数字、结论三处用），颜色走 --bd-* 语义色而不写十六进制。 */
const scoreTone = computed<'danger' | 'warning' | 'success'>(() => {
  const s = bundle.value.score;
  if (bundle.value.fail > 0 || s < 60) return 'danger';
  if (s < 85) return 'warning';
  return 'success';
});
const verdictText = computed(() => {
  // ★「读不到」既不是正常也不是异常，是第三态：拿演示数据给一台从未应答的控制面下
  //   「全部检查通过，系统健康」的结论，是这一页此前最刺眼的一句话。
  if (degraded.value) return '本次体检未执行 · 控制面没有应答';
  if (bundle.value.fail > 0) return '存在异常项，需立即处置';
  if (bundle.value.warn > 0) return '运行基本正常，有项需关注';
  return '全部检查通过，系统健康';
});
const envLabel = computed(() => (bundle.value.env === 'prod' ? '生产' : '开发'));
/**
 * 控制面语义版本的展示文案。
 *
 * ★空 = 未注入（这个二进制不是 deploy/build.sh 产出的交付件），不是取数失败，
 * 也不是某个数字——所以既不能补 "v" 前缀凑出个 "v"，也不能回落到任何常量。
 * 「服务端版本身份」那一项会把成因与处置说全，这里只负责不撒谎。
 */
const versionText = computed(() => (bundle.value.version ? 'v' + bundle.value.version : '未注入'));

const CAT: Record<DiagCategory, { label: string; icon: string }> = {
  control: { label: '控制面', icon: 'IconDashboard' },
  storage: { label: '存储', icon: 'IconStorage' },
  dataplane: { label: '数据面', icon: 'IconLink' },
  stealth: { label: '服务隐身', icon: 'IconSafe' },
  cluster: { label: '温备', icon: 'IconApps' },
  identity: { label: '身份', icon: 'IconUserGroup' },
  posture: { label: '态势', icon: 'IconExclamationCircle' },
  security: { label: '密钥安全', icon: 'IconLock' }
};
function catLabel(c: DiagCategory) { return CAT[c]?.label ?? c; }
function catIcon(c: DiagCategory) { return CAT[c]?.icon ?? 'IconInfoCircle'; }
/* 未知枚举原样显示（不误标成"异常"），后端加新状态时页面稳定降级 */
const STATUS_LABEL: Record<string, string> = { pass: '正常', warn: '关注', fail: '异常', skip: '跳过' };
function statusLabel(s: DiagStatus) { return STATUS_LABEL[s] ?? s; }
/** 徽标文案：降级态一律「演示占位」。屏幕上的徽标与导出报告的 `### [标签]` 共用它——
 *  只改一处的话，屏幕说「演示占位」而导出的 Markdown 仍逐条写「[正常]」，
 *  而那份文件会被转发、存档、当验收依据。 */
function badgeLabel(c: DiagCheck) { return degraded.value ? '演示占位' : statusLabel(c.status); }

function nowStamp() {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

async function load() {
  loading.value = true;
  try {
    bundle.value = await api<DiagBundle>('/diag');
    live.value = true;
    denied.value = false;
    loadErr.value = '';
    // 联动拉取网关明细（best-effort，不阻断体检）
    try { gateways.value = (await api<GatewaysResp>('/gateways')).gateways || []; } catch { gateways.value = []; }
  } catch (e) {
    gateways.value = [];
    // 后端原话先存下来：403 要它说清缺哪个权限，非 403 要它说清是维护中 / 502 / 网络不通——
    // 这三种处境下一步动作完全相反，而此前它们在屏幕上是同一句话（没有任何一句）。
    loadErr.value = failReason(e);
    // 403=已登录但非 admin：如实提示需管理员权限，不伪装成"健康"演示数据
    if (failStatus(e) === 403) {
      denied.value = true;
      live.value = false;
    } else {
      // ★不再把「现在」写进 generatedAt：那一栏的标签是「体检时间」，填上本地时刻会让
      //   一屏演示数据看起来像刚刚跑完的一次真体检。没跑就是没跑，页面与报告都显示「—」。
      bundle.value = { ...MOCK };
      live.value = false;
      denied.value = false;
    }
  } finally {
    loading.value = false;
    loaded.value = true;
  }
}

/**
 * 导出体检报告（Markdown）。
 *
 * ★降级演示态（bundle 退回 MOCK）导出的报告必须在正文开头与文件名两处都标明"非实测"：
 * 这种文件会被存档、转发、当成上线验收依据，收到它的人没有别的办法分辨真伪。
 */
function exportReport() {
  const b = bundle.value;
  // 判据与屏幕同源（computed degraded）：改造前只有这份报告知道"本次不是实测"，
  // 屏幕那一半照旧画绿卡打 81 分——同一页两条路两种说法，而报告是转发出去的那一份。
  const deg = degraded.value;
  const lines = [
    '# 白帝运维诊断报告',
    ''];
  if (deg) {
    // 归因也是三态，不许把"还没探过"写成"控制面不可达"——那是一句没有依据的结论，
    // 而收到报告的人会照着它去查网络。已探过的那两档一律转述 failReason(e) 的后端原话：
    // 「控制面不可达」把 503 维护中 / 502 / DNS 不通压成了同一句编造的归因。
    const why = denied.value
      ? `（当前账号无权读取 /diag，需管理员权限${loadErr.value ? `；后端原话：${loadErr.value}` : ''}）`
      : live.value === false
        ? `（后端原话：${loadErr.value || '控制面未返回体检数据'}）`
        : '（本页尚未完成第一次体检，导出时数据来源未确定）';
    lines.push(
      '> ⚠️ **本报告不是实测结果。**',
      '>',
      '> 导出时控制台没有从 baidi-control 取到体检数据' + why +
        '，下面的检查项是页面的**离线演示占位**，不代表这套部署的真实状态。',
      '> 请在控制面可达、且以管理员身份登录后重新导出。',
      '');
  }
  lines.push(
    `- 组件：${b.component}`,
    `- 版本：${versionText.value}（${envLabel.value}）`,
    `- 构建：${b.build || '未注入'}`,
    `- 运行时长：${b.uptime}`,
    `- 体检时间：${b.generatedAt || '—'}`,
    // 与屏幕上那个「—」同源：81 分是内置演示常量，印在一份会被存档的报告里最像实测值。
    deg
      ? '- 健康分：—（本次未取到实测数据，判不出来；下面每一项都是演示占位）'
      : `- 健康分：${b.score} / 100（正常 ${b.pass} · 关注 ${b.warn} · 异常 ${b.fail}）`,
    '',
    '## 检查项',
    ''
  );
  for (const c of sortedChecks.value) {
    lines.push(`### [${badgeLabel(c)}] ${c.name}（${catLabel(c.category)}）`);
    lines.push(`- 结论：${c.summary}`);
    if (c.metric) lines.push(`- 指标：${c.metric}`);
    if (c.hint) lines.push(`- 建议：${c.hint}`);
    if (c.items?.length) for (const it of c.items) lines.push(`  · ${it.label}：${it.value}`);
    lines.push('');
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const digits = (b.generatedAt || '').replace(/\D/g, '');
  const ts = digits.length === 14 ? digits : nowStamp(); // 后端 generatedAt=YYYY-MM-DD HH:MM:SS → 14 位；降级路径回退本地时戳
  a.href = url;
  // 文件名也要带上标记：报告常常只以文件名的形式出现在邮件列表或工单里。
  a.download = deg ? `白帝运维诊断-演示占位-非实测-${ts}.md` : `白帝运维诊断-${ts}.md`;
  a.click();
  URL.revokeObjectURL(url);
  if (deg) Message.warning('已导出，但本次是**降级演示占位**（未取到实测数据），报告开头已标注');
  else Message.success('诊断报告已导出');
}

function back() { router.push(FIRST_PATH); }

onMounted(load);
</script>

<style scoped>
/* 独立页：自带顶栏与居中内容区。卡片底/边/圆角/阴影来自全局 .bd-card，这里只写本页独有的布局与语义色。 */
.dg { min-height: 100vh; background: var(--bd-fill-1); display: flex; flex-direction: column; }

/* 顶栏 */
.dg-top {
  position: sticky; top: 0; z-index: var(--bd-z-top); height: var(--bd-header-h); flex: none; display: flex; align-items: center; gap: var(--bd-sp-3);
  padding: 0 var(--bd-sp-6); background: var(--bd-bg-1); border-bottom: 1px solid var(--bd-border);
}
.dg-logo { display: flex; align-items: center; gap: var(--bd-sp-3); }
.dg-logo__mark {
  width: 32px; height: 32px; border-radius: var(--bd-radius-s); flex: none; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d)); box-shadow: var(--bd-shadow-primary);
}
.dg-logo__txt { display: flex; flex-direction: column; line-height: 1.2; }
.dg-logo__txt b { font-size: var(--bd-fs-lg); font-weight: 700; letter-spacing: .3px; color: var(--bd-t1); }
.dg-logo__txt i { font-style: normal; font-size: var(--bd-fs-xs); color: var(--bd-t3); }
.dg-top__spacer { flex: 1; }

.dg-body { flex: 1; padding: var(--bd-page-y) var(--bd-sp-6) var(--bd-sp-7); max-width: 1200px; width: 100%; margin: 0 auto; }
.dg-body--center { display: flex; align-items: center; justify-content: center; }

/* 健康总览 */
.dg-hero {
  padding: var(--bd-sp-5) var(--bd-sp-6); display: grid; grid-template-columns: 140px 1fr 240px; gap: var(--bd-sp-7); align-items: center;
}
.dg-hero--sk { align-items: start; }
.dg-score { position: relative; width: 140px; height: 140px; }
.dg-score__svg { width: 140px; height: 140px; transform: rotate(-90deg); }
.dg-score__track { fill: none; stroke: var(--bd-fill-2); stroke-width: 10; }
.dg-score__val { fill: none; stroke-width: 10; stroke-linecap: round; transition: stroke-dashoffset .6s var(--bd-ease), stroke var(--bd-dur-slow) var(--bd-ease); }
.dg-score__val.is-danger { stroke: var(--bd-danger); }
.dg-score__val.is-warning { stroke: var(--bd-warning); }
.dg-score__val.is-success { stroke: var(--bd-success); }
.dg-score__c { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.dg-score__c b { font-size: 40px; font-weight: 800; line-height: 1; }
.dg-score__c i { font-style: normal; font-size: var(--bd-fs-sm); color: var(--bd-t3); margin-top: var(--bd-sp-1); }
.is-danger { color: var(--bd-danger); }
.is-warning { color: var(--bd-warning); }
.is-success { color: var(--bd-success); }
/* 第四档「判不出来」：走中性文本色，不借用三档语义色中的任何一档——
   把它涂成绿是说反话，涂成红是替一台没应答的机器编一个异常等级。 */
.is-unknown { color: var(--bd-t3); }
.dg-score__val.is-unknown { stroke: var(--bd-fill-2); }

.dg-hero__mid { display: flex; flex-direction: column; gap: var(--bd-sp-3); }
.dg-hero__verdict { font-size: 18px; font-weight: 700; }
.dg-hero__stats { display: flex; gap: var(--bd-sp-5); flex-wrap: wrap; }
.dg-stat { font-size: var(--bd-fs-md); color: var(--bd-t3); display: flex; align-items: baseline; gap: 6px; }
.dg-stat b { font-size: 22px; font-weight: 700; }
.dg-stat--pass b { color: var(--bd-success); }
.dg-stat--warn b { color: var(--bd-warning); }
.dg-stat--fail b { color: var(--bd-danger); }
.dg-stat--skip b { color: var(--bd-t3); }
.dg-hero__bar { display: flex; height: 8px; border-radius: var(--bd-radius-xs); overflow: hidden; background: var(--bd-fill-2); }
.dg-hero__bar .seg { display: block; }
.dg-hero__bar .pass { background: var(--bd-success); }
.dg-hero__bar .warn { background: var(--bd-warning); }
.dg-hero__bar .fail { background: var(--bd-danger); }

.dg-hero__unknown { font-size: var(--bd-fs-md); color: var(--bd-t3); line-height: var(--bd-lh); }
.dg-hero__unknown b { color: var(--bd-t2); font-weight: 600; }

.dg-hero__meta { display: flex; flex-direction: column; gap: 9px; border-left: 1px solid var(--bd-border-2); padding-left: var(--bd-sp-6); }
.mrow { display: flex; justify-content: space-between; font-size: var(--bd-fs-md); gap: var(--bd-sp-3); }
.mrow span { color: var(--bd-t3); }
.mrow b { color: var(--bd-t1); font-weight: 600; text-align: right; }

/* 检查项卡片：左侧 3px 色边表达状态 */
.dg-grid { margin-top: var(--bd-sp-4); display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: var(--bd-sp-4); }
.dg-card { padding: var(--bd-sp-4) var(--bd-sp-5); border-left-width: 3px; border-left-color: var(--bd-t4); }
.dg-card.is-pass { border-left-color: var(--bd-success); }
.dg-card.is-warn { border-left-color: var(--bd-warning); }
.dg-card.is-fail { border-left-color: var(--bd-danger); }
.dg-card.is-skip { border-left-color: var(--bd-t4); }
/* 降级态：九张卡一律中性边 + 中性徽标。留着绿边绿标，读者扫一眼卡片墙得到的结论
   与横幅上那句「本次体检未执行」正好相反，而人先看颜色。 */
.dg-card.is-demo { border-left-color: var(--bd-t4); }
.dg-card__head { display: flex; align-items: center; gap: var(--bd-sp-3); }
.dg-card__icon {
  width: 34px; height: 34px; border-radius: var(--bd-radius-s); flex: none; display: flex; align-items: center; justify-content: center;
  background: var(--bd-primary-1); color: var(--bd-primary); font-size: 18px;
}
.dg-card__t { flex: 1; min-width: 0; }
.dg-card__name { font-size: var(--bd-fs-base); font-weight: 600; color: var(--bd-t1); }
.dg-card__cat { font-size: var(--bd-fs-xs); color: var(--bd-t3); margin-top: 1px; }
.dg-badge { font-size: var(--bd-fs-sm); font-weight: 600; padding: 2px 10px; border-radius: var(--bd-radius-pill); flex: none; }
.dg-badge.pass { color: var(--bd-success-t); background: var(--bd-success-1); }
.dg-badge.warn { color: var(--bd-warning-t); background: var(--bd-warning-1); }
.dg-badge.fail { color: var(--bd-danger-t); background: var(--bd-danger-1); }
.dg-badge.skip { color: var(--bd-t2); background: var(--bd-fill-2); }
.dg-badge.demo { color: var(--bd-t2); background: var(--bd-fill-2); }
.dg-card__summary { font-size: var(--bd-fs-md); color: var(--bd-t2); line-height: var(--bd-lh); margin-top: var(--bd-sp-3); }
.dg-card__metric {
  display: flex; align-items: center; gap: 6px; font-size: var(--bd-fs-sm); color: var(--bd-t3);
  margin-top: var(--bd-sp-2); font-variant-numeric: tabular-nums;
}
.dg-card__hint {
  display: flex; align-items: flex-start; gap: 6px; font-size: var(--bd-fs-sm); color: var(--bd-warning-t); line-height: var(--bd-lh);
  margin-top: var(--bd-sp-2); padding: var(--bd-sp-2) 10px; background: var(--bd-warning-1); border-radius: var(--bd-radius-s);
}
.dg-card.is-fail .dg-card__hint { color: var(--bd-danger-t); background: var(--bd-danger-1); }
.dg-card__hint :deep(svg), .dg-card__metric :deep(svg) { flex: none; margin-top: 2px; }
.dg-card__more { margin-top: var(--bd-sp-3); }
.dg-card__more-h {
  display: inline-flex; align-items: center; gap: 5px; font-size: var(--bd-fs-sm); color: var(--bd-t2); cursor: pointer; user-select: none;
  border: none; background: transparent; padding: 0; font-family: inherit;
}
.dg-card__more-h:hover { color: var(--bd-primary); }
.dg-card__more-h :deep(svg) { font-size: 13px; transition: transform var(--bd-dur-base) var(--bd-ease); }
.dg-card__more-h :deep(svg.up) { transform: rotate(180deg); }
.dg-items { list-style: none; margin: var(--bd-sp-2) 0 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
.dg-item { display: flex; align-items: center; gap: var(--bd-sp-2); font-size: var(--bd-fs-sm); padding: 5px 0; border-top: 1px solid var(--bd-border-2); }
.dg-item__dot { width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--bd-t4); }
.dg-item__dot.is-pass { background: var(--bd-success); }
.dg-item__dot.is-warn { background: var(--bd-warning); }
.dg-item__dot.is-fail { background: var(--bd-danger); }
.dg-item__dot.is-skip { background: var(--bd-t4); }
.dg-item__l { font-weight: 600; color: var(--bd-t1); font-family: var(--bd-font-mono); }
.dg-item__v { margin-left: auto; color: var(--bd-t3); }

/* 数据面网关明细 */
.dg-gws { margin-top: var(--bd-sp-6); }
.dg-gws .bd-section-title { display: flex; align-items: center; gap: 7px; }
.dg-gws .bd-section-title__sub { margin-left: auto; }
.dg-gws__grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: var(--bd-sp-4); }
.dg-gw { padding: var(--bd-sp-4); border-left: 3px solid var(--bd-success); }
.dg-gw.off { border-left-color: var(--bd-t4); opacity: .85; }
.dg-gw__top { display: flex; align-items: center; gap: var(--bd-sp-2); }
.dg-gw__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--bd-t4); flex: none; }
.dg-gw__dot.on { background: var(--bd-success); box-shadow: 0 0 0 3px var(--bd-success-1); }
.dg-gw__id { font-size: var(--bd-fs-base); color: var(--bd-t1); }
.dg-gw__state { margin-left: auto; font-size: var(--bd-fs-sm); color: var(--bd-t3); }
.dg-gw.off .dg-gw__state { color: var(--bd-warning); }
.dg-gw__nums { display: flex; gap: var(--bd-sp-3); margin: var(--bd-sp-3) 0; }
.dg-gw__n { flex: 1; text-align: center; background: var(--bd-fill-1); border-radius: var(--bd-radius-s); padding: var(--bd-sp-2) var(--bd-sp-1); }
.dg-gw__n b { display: block; font-size: var(--bd-fs-xl); font-weight: 700; color: var(--bd-primary); }
.dg-gw__n i { font-style: normal; font-size: var(--bd-fs-xs); color: var(--bd-t3); }
.dg-gw__meta { display: flex; flex-direction: column; gap: var(--bd-sp-1); font-size: var(--bd-fs-sm); color: var(--bd-t3); }

@media (max-width: 880px) {
  .dg-hero { grid-template-columns: 1fr; justify-items: center; text-align: center; }
  .dg-hero__meta { border-left: none; border-top: 1px solid var(--bd-border-2); padding-left: 0; padding-top: var(--bd-sp-4); width: 100%; }
}
</style>
