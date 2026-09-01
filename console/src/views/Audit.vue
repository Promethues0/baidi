<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">审计中心</div>
        <div class="bd-page__sub">全链路留痕 · HMAC-SM3 防篡改链 · CSV 合规出口</div>
      </div>
      <div class="bd-head__right">
        <!-- 「降级演示」这个说法已经删掉：这一页现在没有演示数据可降级，
             拉不到就是拉不到，原因写在下面那条红条里。 -->
        <a-tag :color="live ? 'green' : 'red'" bordered>{{ live ? '已连 baidi-control' : '数据未读取' }}</a-tag>
        <button class="bd-btn" :disabled="!!loadErr" :title="loadErr ? '审计数据未读取，导出走的是同一道权限闸' : ''"
                :style="{ opacity: loadErr ? 0.5 : 1 }" @click="openExport"><icon-download />导出 CSV</button>
        <!-- 这里原先是一个「日志配置」弹窗：四个类别留痕开关 + 保留天数 + 「合规出口（Syslog 转发）」，
             全部是**显示层假配置**——后端既没有按类别开关留痕的能力，保留天数由
             BAIDI_AUDIT_RETENTION_DAYS 决定，Syslog 那一格更是压根没有实现。
             本轮把外送做成了真的（RFC 5424 over TCP/TLS + HTTP JSON，持久化队列 + 重试），
             配置在系统管理页，这个按钮直接指过去；剩下那几个假开关删掉而不是搬家。 -->
        <button class="bd-btn bd-btn--ghost" @click="gotoForward"><icon-export />日志外送</button>
      </div>
    </div>

    <!-- ★拉不到审计就**什么都不画**。
         这一页此前的初值是一整块 mock（18.4 万条访问决策 + 十条署名到人的流水），
         `/audit` 一失败就原样保留，右上角挂个「降级演示」——而 /audit 归 PermAudit，
         安全/系统管理员打开它拿到的是 403，页面却把权限拒绝说成"后端没起"，
         再配一屏看起来完全正常的审计。同仓「设备状态」「业务告警」两页已立这条例外，
         审计中心比那两页更该守它：编造的审计记录与真实留痕在页面上无法区分。 -->
    <div v-if="loadErr" class="bd-auditerr">
      <icon-exclamation-circle-fill class="bd-auditerr__ic" />
      <div>
        <div class="bd-auditerr__t">无法读取审计数据</div>
        <div class="bd-auditerr__m">{{ loadErr }}</div>
        <div class="bd-auditerr__n">
          本页不提供演示数据——编造的审计记录无法与真实留痕区分。
          审计读取归「审计」权限（PermAudit）：若上面写的是无权执行，请用具备审计权的管理员账号登录。
        </div>
      </div>
    </div>

    <template v-else>


    <!-- 审计写入失败（wave8 行动 6）：控制面没能把审计写进库。
         ★这条红条只在真出事时出现（后端零失败即整段不下发），常态零噪声。
         文案里必须说清"链校验查不出它们"——否则管理员看到防篡改链全绿会以为没事，
         而链重算的是**已存在行**的连续性，压根没写进去的行不在链上。 -->
    <div v-if="bundle?.writeHealth" class="bd-auditwarn">
      <icon-close-circle-fill />
      <span>
        控制面已有 <b>{{ bundle!.writeHealth!.failures }}</b> 条审计<b>未能写入数据库</b>（首次
        {{ tsText(bundle.writeHealth.firstAt) }}，最近 {{ tsText(bundle.writeHealth.lastAt) }}）。
        这些记录不在库里，防篡改链校验查不出它们的缺失——链重算的是已存在行的连续性。
        错误：{{ bundle!.writeHealth!.lastErr }}；最近一条丢失的记录：{{ bundle!.writeHealth!.lastEvent }}。
        完整内容只在控制面进程日志的「审计写入失败」行里，请立即取回并排查磁盘余量与库文件可写性。
      </span>
    </div>

    <!-- P10 聚合头 -->
    <div class="bd-aggrow">
      <!-- 四个分类计数卡 -->
      <div v-for="c in catCards" :key="c.key" class="bd-card bd-mcard">
        <div class="bd-mcard__top">
          <span class="bd-mcard__dot" :style="{ background: c.color }" />
          <span class="bd-mcard__label">{{ c.label }}</span>
        </div>
        <div class="bd-mcard__num" :style="{ color: c.color }">{{ fmtNum(c.value) }}</div>
        <div class="bd-mcard__sub">条 · 累计留痕</div>
      </div>

      <!-- 今日总量卡 -->
      <div class="bd-card bd-mcard bd-mcard--total">
        <div class="bd-mcard__top">
          <icon-clock-circle class="bd-mcard__ic" />
          <span class="bd-mcard__label">今日总量</span>
        </div>
        <div class="bd-mcard__num">{{ fmtNum(bundle?.todayTotal ?? 0) }}</div>
        <div class="bd-mcard__sub">条 · 今日累计</div>
      </div>

      <!-- 审计库占用卡。★主数是**审计库自己**有多大，不是文件系统占用率——
           在审计页上画一个「88%」，读到的人会以为是审计日志吃掉的，
           而这台机器上审计库只有 1.7 MB，那 88% 全是别的东西。
           两者的处置动作完全不同：前者缩留存，后者清磁盘。 -->
      <div class="bd-card bd-mcard bd-disk">
        <div class="bd-mcard__top">
          <icon-storage class="bd-mcard__ic" />
          <span class="bd-mcard__label">审计库占用</span>
          <span class="bd-disk__tag" :style="{ color: diskColor, background: diskColor + '14' }">所在磁盘{{ diskLabel }}</span>
        </div>
        <div class="bd-disk__main">
          <b>{{ dbSize }}</b>
          <span class="bd-disk__cap">占文件系统 {{ bundle?.disk.selfPct ?? 0 }}%</span>
        </div>
        <div class="bd-disk__track"><span class="bd-disk__fill" :style="{ width: (bundle?.disk.usedPct ?? 0) + '%', background: diskColor }" /></div>
        <div class="bd-mcard__sub">
          所在磁盘已用 {{ bundle?.disk.usedPct ?? 0 }}% / {{ bundle?.disk.totalGB ?? 0 }} GB · 保留 {{ bundle?.disk.retainDays ?? 0 }} 天
        </div>
      </div>
    </div>

    <!-- 日志表 -->
    <div class="bd-tablecard">
      <div class="bd-toolbar">
        <!-- 类别筛选 pill：已连控制面时是**服务端检索条件**（全表 WHERE），
             不再只是对最近 200 条的前端过滤 -->
        <div class="bd-pillrow">
          <span v-for="f in catFilters" :key="f.key" class="bd-pill2" :class="{ on: catSel === f.key }" @click="catSel = f.key; runSearch(true)">{{ f.label }}</span>
        </div>
        <div style="flex: 1" />
        <!-- 检索：账号精确（查证据链要精确，模糊会把 li 匹配到 alice）+ 事件关键词 -->
        <a-input v-model="q.actor" size="small" style="width: 140px" placeholder="账号（精确）"
          allow-clear @press-enter="runSearch(true)" @clear="runSearch(true)" />
        <!-- ★源 IP 维度：后端 SearchAudit 一直支持 srcIp，页面却没有入口。
             而 wave8 行动 8 专门修过一处「数据面事件的 src_ip 此前一律记成网关自己的地址，
             按 src_ip 检索审计永远找不到攻击者」——修好了那一半，检索这一半没接上，
             于是"按攻击源查"这件事在控制台上依然做不到。 -->
        <a-input v-model="q.srcIp" size="small" style="width: 150px" placeholder="源 IP（精确）"
          allow-clear @press-enter="runSearch(true)" @clear="runSearch(true)" />
        <a-input v-model="q.kw" size="small" style="width: 170px" placeholder="事件关键词 / 回车检索"
          allow-clear @press-enter="runSearch(true)" @clear="runSearch(true)" />
        <!-- 时间快选 pill：此前是装饰件（没接进任何过滤逻辑），现为服务端时间窗 -->
        <div class="bd-pillrow">
          <span v-for="t in timeFilters" :key="t.key" class="bd-pill2 bd-pill2--time" :class="{ on: timeSel === t.key }" @click="timeSel = t.key; runSearch(true)">{{ t.label }}</span>
        </div>
      </div>
      <table class="bd-table">
        <thead>
          <tr><th>时间</th><th>类别</th><th>用户</th><th>源 IP</th><th>事件</th><th class="r">判定</th></tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in shownLogs" :key="i">
            <td class="bd-mono">{{ e.time }}</td>
            <td><span class="bd-tg" :style="tagStyle(catMeta(e.category).color)">{{ catMeta(e.category).label }}</span></td>
            <td>{{ e.user }}</td>
            <td class="bd-mono">{{ e.srcIp }}</td>
            <td>{{ e.event }}</td>
            <td class="r"><span class="bd-tg" :style="tagStyle(verdictColor(e.verdict))">{{ verdictLabel(e.verdict) }}</span></td>
          </tr>
          <tr v-if="!shownLogs.length"><td colspan="6" style="text-align: center; color: var(--bd-t3); padding: 40px 0">当前筛选无匹配日志</td></tr>
        </tbody>
      </table>
      <div class="bd-pager">
        <template v-if="searchTotal >= 0">
          全表命中 {{ searchTotal }} 条，本页第 {{ shownLogs.length ? page * PAGE_SIZE + 1 : 0 }}–{{ page * PAGE_SIZE + shownLogs.length }} 条 · 时间范围「{{ timeFilters.find(t => t.key === timeSel)?.label }}」
          <div style="flex: 1" />
          <span class="bd-pgbtn" :class="{ off: page === 0 }" @click="prevPage">上一页</span>
          <span class="bd-pgnum">第 {{ page + 1 }} / {{ pageCount }} 页</span>
          <span class="bd-pgbtn" :class="{ off: page + 1 >= pageCount }" @click="nextPage">下一页</span>
        </template>
        <template v-else>共 {{ shownLogs.length }} 条记录（最近 200 条快照）· 时间范围「{{ timeFilters.find(t => t.key === timeSel)?.label }}」</template>
      </div>
    </div>

    <!-- 导出（真实调用 GET /api/v1/audit/export，流式 CSV 附件）。
         只暴露后端真支持的条件：类别 + 时间范围——此前向导里的设备多选 / 四元组 /
         日志类型（系统服务/监控/扫描）后端并不存在，留着只是假象，已删。 -->
    <a-modal v-model:visible="exp.open" :width="520" :footer="false" title="导出审计日志（CSV）" unmount-on-close>
      <div class="bd-wbody bd-wbody--slim">
        <div class="bd-wdesc">按条件从 baidi-control 导出全量审计日志（不限于页面上最近 200 条）。</div>
        <div class="bd-field">
          <label>日志类别</label>
          <a-select v-model="exp.category" style="width: 100%">
            <a-option value="all">全部类别</a-option>
            <a-option value="access">访问决策</a-option>
            <a-option value="auth">登录认证</a-option>
            <a-option value="admin">管理操作</a-option>
            <a-option value="security">安全事件</a-option>
            <a-option value="policy">策略变更</a-option>
            <a-option value="dataplane">数据面回执</a-option>
            <a-option value="system">系统运维</a-option>
          </a-select>
        </div>
        <!-- ★账号 / 源 IP / 关键词三维此前**导不出来**（后端只认类别+时间），
             而页面上刚筛过的正是这几维：筛出 12 条、导出 8 万条，管理员却以为
             这份 CSV 就是屏幕上那些行。现在两侧同一份 store.AuditQuery。 -->
        <div class="bd-field">
          <label>行为人账号（精确，留空 = 不限）</label>
          <a-input v-model="exp.actor" placeholder="如 li.fang" allow-clear />
        </div>
        <div class="bd-field">
          <label>源 IP（前缀匹配，留空 = 不限）</label>
          <a-input v-model="exp.srcIp" placeholder="如 10.8. 可查整段" allow-clear />
        </div>
        <div class="bd-field">
          <label>事件关键词（留空 = 不限）</label>
          <a-input v-model="exp.kw" placeholder="如 拒绝越权" allow-clear />
        </div>
        <div class="bd-field">
          <label>时间范围（留空 = 不限；可选到具体日期，不受页面上三个快选档约束）</label>
          <a-range-picker v-model="exp.range" style="width: 100%" />
        </div>
        <div class="bd-recap">
          <icon-info-circle />
          <span>
            导出「<b>{{ expCatLabel }}</b>」<template v-if="exp.actor.trim()"> · 账号 <b>{{ exp.actor.trim() }}</b></template
            ><template v-if="exp.srcIp.trim()"> · 源 IP <b>{{ exp.srcIp.trim() }}</b></template
            ><template v-if="exp.kw.trim()"> · 关键词 <b>{{ exp.kw.trim() }}</b></template
            >{{ exp.range?.length === 2 ? ` · ${exp.range[0]} 至 ${exp.range[1]}` : ' · 全部时间' }}
            <i class="bd-recap__hint">条件已按屏幕上当前的筛选带入，可在此调整。</i>
          </span>
        </div>
      </div>
      <div class="bd-wfoot">
        <button class="bd-btn bd-btn--ghost" @click="exp.open = false">取消</button>
        <div style="flex: 1" />
        <button class="bd-btn" :disabled="exp.busy" :style="{ opacity: exp.busy ? 0.6 : 1 }" @click="doExport">
          <icon-download />{{ exp.busy ? '导出中…' : '导出' }}
        </button>
      </div>
    </a-modal>
    </template>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, getToken, type AuditBundle, type AuditEntry, type KV, failReason } from '@/lib/api';

const live = ref(false);
const router = useRouter();
const route = useRoute();

/** 「日志外送」指到系统管理页的真配置区（syslog / SIEM 出口 + 队列积压 + 丢弃计数）。
 *  这一页上不再放任何外送开关：本地一个假开关、真配置在另一页，是最容易骗到人的形态。 */
function gotoForward() { void router.push({ path: '/system/manage', query: { tab: 'forward' } }); }

/**
 * ★这里原先是一整块 MOCK：18.4 万条「访问决策」、9.6 万条「登录认证」、
 * 十条署着真人姓名与内网 IP 的审计流水（「访问内部应用「OA 协同」」「检测到异常端口扫描行为」…），
 * 而 bundle 的初值就是它——`/audit` 一失败就整页保留这份编造数据，
 * 右上角挂一个「降级演示」的橙色标签了事。
 *
 * 两个理由让这块 mock 必须消失，而不是换个说法：
 *
 *  ① **审计页编造记录是所有假数据里最坏的一种**。它编的正是"谁在什么时候做了什么"——
 *     这一页存在的全部意义。同一个仓库里「设备状态」与「业务告警」两页已经立了这条例外
 *     （见 CLAUDE.md：连不上就说连不上，不画假曲线、不编假告警），审计中心却漏在外面，
 *     而它比那两页更该守这条。
 *
 *  ② 「降级演示」这个标签**说错了原因**。/audit 归 PermAudit，安全管理员与系统管理员
 *     打开这一页拿到的是 403；页面把一次**权限拒绝**说成"后端没起"，还配上一屏
 *     看起来完全正常的审计流水。管理员据此得出的结论会是"审计功能是好的"。
 *
 * 现在：拉不到就 bundle=null，整页只显示一条如实的错误（后端原话由 failReason 转述），
 * 一行编造的记录都不画。
 */
const bundle = ref<AuditBundle | null>(null);
const loadErr = ref('');


/* tsText Unix 秒 → 本地时刻；缺席回破折号（0/undefined 都是"没有这个时刻"）。 */
function tsText(sec?: number) {
  if (!sec) return '—';
  const d = new Date(sec * 1000);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/* ── P10 分类卡 ── */
/** 类别卡配色。★键是后端下发的中文名（bundle.categories 只有 name/value），
 *  必须覆盖 store.AuditCategories 的全部七项——漏一项那张卡就退回默认蓝，
 *  与「访问决策」同色而分不出来。 */
const CAT_COLOR: Record<string, string> = {
  '访问决策': '#165DFF', '登录认证': '#722ED1', '管理操作': '#00B42A', '策略变更': '#F7BA1E',
  '安全事件': '#FF7D00', '数据面回执': '#0FC6C2', '系统运维': '#86909C'
};
const catCards = computed(() =>
  (bundle.value?.categories ?? []).map((c: KV) => ({ key: c.name, label: c.name, value: c.value, color: CAT_COLOR[c.name] ?? '#165DFF' }))
);
function fmtNum(n: number) { return n.toLocaleString('en-US'); }

/* dbSize 审计库文件大小（人话）。 */
const dbSize = computed(() => {
  const b = bundle.value?.disk.dbBytes ?? 0;
  if (b <= 0) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
});

/* ── 所在磁盘水位上色（进度条与标签说的都是**文件系统**，不是审计库）── */
const diskColor = computed(() => {
  const p = bundle.value?.disk.usedPct ?? 0;
  return p >= 80 ? 'var(--bd-danger)' : p >= 60 ? 'var(--bd-warning)' : 'var(--bd-success)';
});
const diskLabel = computed(() => {
  const p = bundle.value?.disk.usedPct ?? 0;
  return p >= 80 ? '偏高' : p >= 60 ? '关注' : '健康';
});

/* ── 日志表筛选 ── */
/** 类别筛选条。★必须与**后端支持的类别**逐项对齐：dataplane（数据面回执）此前漏了，
 *  后端 SearchAudit 支持它、本页的导出下拉里也列着它，唯独列表筛不到——
 *  于是网关报上来的隧道放行/拒绝在这一页的筛选条上等于不存在，
 *  而 FR-AUDIT-05 要查的正是这一类。 */
const catFilters = [
  { key: 'all', label: '全部' }, { key: 'access', label: '访问' }, { key: 'auth', label: '认证' },
  { key: 'admin', label: '管理' }, { key: 'policy', label: '策略' }, { key: 'security', label: '安全' },
  { key: 'dataplane', label: '数据面' }, { key: 'system', label: '系统' }
];
const timeFilters = [{ key: 'today', label: '今天' }, { key: '7d', label: '7 天' }, { key: '30d', label: '30 天' }];
const catSel = ref('all');
const timeSel = ref('today');
/* 服务端检索态：results 非 null 时表格显示它（全表 WHERE 的结果），
 * 否则回落到首屏快照（最近 200 条）的前端过滤。未连控制面时永远走后者——
 * mock 数据上装一个"全表检索"是在演示假能力。 */
const q = reactive({ actor: '', srcIp: '', kw: '' });
const searchResults = ref<AuditEntry[] | null>(null);
const searchTotal = ref(-1);
const shownLogs = computed<AuditEntry[]>(() => {
  if (searchResults.value) return searchResults.value;
  const logs = bundle.value?.logs ?? [];
  return catSel.value === 'all' ? logs : logs.filter((l) => l.category === catSel.value);
});

/**
 * 时间快选的起始日（YYYY-MM-DD）。
 *
 * ★这里原来是 `d.toISOString().slice(0, 10)`——toISOString 先转 **UTC** 再取日期，
 * 而后端 parseAuditTime 走的是 `time.ParseInLocation(..., time.Local)`，按**服务器本地时间**解释。
 * 在 UTC+8 上，每天 00:00–07:59 这八个小时里 ISO 日期还停在前一天：
 * 选「今天」实际查的是**昨天到现在**，选「近 7 天」窗口整体前移一天。
 * 页面不会有任何异常表现——多出来的那些行看起来就是正常的审计记录。
 *
 * 改成按本地日期拼字符串。注意这里的"本地"是**浏览器所在时区**，而后端按服务器时区解释；
 * 两者不同区时窗口会差几小时——这是跨时区部署固有的，不是这个函数能消掉的，
 * 页面上的时间范围文案说的也是"按服务器时间"。
 */
function sinceOf(key: string): string {
  const d = new Date();
  if (key === '7d') d.setDate(d.getDate() - 6);
  else if (key === '30d') d.setDate(d.getDate() - 29);
  // today：就是今天
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** 每页条数。★后端 SearchAudit 一直支持 limit/offset 并回 total，页面却写死
 *  `limit=200` 且**从不发 offset**——于是命中 5000 条时页脚如实写着「全表命中 5000
 *  条」，而第 201 条之后没有任何入口能翻到。审计的用途就是查那一条，查不到等于没有。 */
const PAGE_SIZE = 200;
const page = ref(0);
const pageCount = computed(() => Math.max(1, Math.ceil(Math.max(searchTotal.value, 0) / PAGE_SIZE)));

/** reset=true 用于筛选条件变更。★必须归零：改了条件还停在第 3 页，
 *  新条件只命中 50 条时页面显示「无匹配日志」，而它明明有 50 条。 */
async function runSearch(reset = false) {
  if (reset) page.value = 0;
  if (!live.value) { searchResults.value = null; searchTotal.value = -1; page.value = 0; return; }
  // 全默认（全部类别 + 今天 + 无关键词）退回首屏快照：别让"什么都没筛"看起来像检索过
  const idle = catSel.value === 'all' && timeSel.value === 'today' && !q.actor.trim() && !q.srcIp.trim() && !q.kw.trim();
  if (idle) { searchResults.value = null; searchTotal.value = -1; page.value = 0; return; }
  const qs = new URLSearchParams();
  if (catSel.value !== 'all') qs.set('category', catSel.value);
  if (q.actor.trim()) qs.set('actor', q.actor.trim());
  if (q.srcIp.trim()) qs.set('srcIp', q.srcIp.trim());
  if (q.kw.trim()) qs.set('q', q.kw.trim());
  qs.set('from', sinceOf(timeSel.value));
  qs.set('limit', String(PAGE_SIZE));
  qs.set('offset', String(page.value * PAGE_SIZE));
  try {
    const r = await api<{ logs: AuditEntry[]; total: number }>(`/audit?${qs.toString()}`);
    searchResults.value = r.logs;
    searchTotal.value = r.total;
  } catch (e) {
    // 审计读端点归 PermAudit：安全/系统管理员在这里拿到的是一句
    // 「角色「系统管理员」无权执行该操作（需要权限：audit）」——那正是他要看到的话。
    Message.error(`审计检索失败：${failReason(e)}`);
  }
}

function prevPage() { if (page.value > 0) { page.value--; runSearch(); } }
function nextPage() { if (page.value + 1 < pageCount.value) { page.value++; runSearch(); } }

function catMeta(c: AuditEntry['category']) {
  // 未知分类兜底：后端新增分类时页面稳定降级（原样显示 key），而不是 undefined.color 崩掉整页
  return {
    access: { label: '访问决策', color: '#165DFF' },
    auth: { label: '登录认证', color: '#722ED1' },
    admin: { label: '管理操作', color: '#00B42A' },
    security: { label: '安全事件', color: '#FF7D00' },
    policy: { label: '策略变更', color: '#F7BA1E' },
    dataplane: { label: '数据面回执', color: '#0FC6C2' },
    system: { label: '系统运维', color: '#86909C' }
  }[c] ?? { label: c, color: '#86909C' };
}
function verdictColor(v: AuditEntry['verdict']) {
  if (v === 'allow' || v === 'ok') return '#00B42A';
  if (v === 'deny' || v === 'fail') return '#F53F3F';
  return '#FF7D00'; // mfa
}
function verdictLabel(v: AuditEntry['verdict']) {
  return { allow: '放行', deny: '拒绝', mfa: '二次认证', ok: '成功', fail: '失败' }[v];
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

/* ── CSV 导出（GET /api/v1/audit/export，admin） ── */
const exp = reactive({
  open: false,
  // 类别集合必须与筛选条同源（catFilters）——各写一份就会出现「列表能筛、导出没这一类」。
  category: 'all' as string,
  actor: '',
  srcIp: '',
  kw: '',
  range: [] as string[],
  busy: false
});
/** ★类别中文名走 catMeta（与列表、类别卡同一份），不再手抄一张表——
 *  手抄那份漏了 dataplane/policy/system，选中它们时确认行的类别是空白的。 */
const expCatLabel = computed(() => exp.category === 'all' ? '全部类别' : catMeta(exp.category as AuditEntry['category']).label);

/**
 * 打开导出弹窗。
 *
 * ★**继承屏幕上刚筛好的条件**，而不是清空重来。改造前这里把三项一律复位，
 * 于是管理员筛到某个账号的十几条记录、点「导出 CSV」，拿到的是**全表八万条**——
 * 而他会以为这份 CSV 就是刚才屏幕上那些行，直接拿去交差。
 * （后端那一半同批修好：导出此前只认 category/from/to，账号与源 IP 两维
 *   压根传不进去，见 store.auditWhere 的注释。）
 */
function openExport() {
  exp.open = true;
  exp.busy = false;
  exp.category = catSel.value;
  exp.actor = q.actor.trim();
  exp.srcIp = q.srcIp.trim();
  exp.kw = q.kw.trim();
  // 时间：把当前那个快选档换算成起始日；未筛时留空 = 全部时间。
  exp.range = timeSel.value === 'today' && !exp.actor && !exp.srcIp && !exp.kw
    ? []
    : [sinceOf(timeSel.value), todayStr()];
}

/** 今天（本地日期，与 sinceOf 同一口径）。 */
function todayStr(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/* 后端回 CSV 附件（非 JSON），api() 封装只吃 JSON，这里直接 fetch blob 触发下载。 */
async function doExport() {
  exp.busy = true;
  try {
    const qs = new URLSearchParams();
    if (exp.category !== 'all') qs.set('category', exp.category);
    // 账号 / 源 IP / 关键词三维与列表检索同名同义（后端 store.AuditQuery 同一份 WHERE）。
    if (exp.actor.trim()) qs.set('actor', exp.actor.trim());
    if (exp.srcIp.trim()) qs.set('srcIp', exp.srcIp.trim());
    if (exp.kw.trim()) qs.set('q', exp.kw.trim());
    if (exp.range?.[0]) qs.set('from', exp.range[0]);
    if (exp.range?.[1]) qs.set('to', exp.range[1]);
    const res = await fetch(`/api/v1/audit/export?${qs.toString()}`, {
      headers: { Authorization: `Bearer ${getToken()}` }
    });
    if (!res.ok) throw new Error(`${res.status}`);
    const blob = await res.blob();
    // 文件名跟随后端 Content-Disposition（带导出日期），解析失败再兜底
    const cd = res.headers.get('Content-Disposition') ?? '';
    const name = /filename="([^"]+)"/.exec(cd)?.[1] ?? `baidi-audit-${new Date().toISOString().slice(0, 10)}.csv`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
    exp.open = false;
    Message.success(`已导出 ${name}`);
  } catch (e) {
    Message.error(`导出失败：${failReason(e)}`);
  } finally {
    exp.busy = false;
  }
}

/* ── 拉取 ── */
onMounted(async () => {
  // 从别的页面带条件跳进来（如「用户状态 → 查审计」）：接住 query 并立刻检索。
  // ★不接的话，那个入口就是一条**看起来能用**的死链——落到一张未筛选的全量表，
  //   管理员还得手抄一遍账号名，而他点这个链接的全部目的就是省掉这一步。
  const qActor = String(route.query.actor ?? '').trim();
  const qSrcIp = String(route.query.srcIp ?? '').trim();
  const qKw = String(route.query.q ?? '').trim();
  if (qActor) q.actor = qActor;
  if (qSrcIp) q.srcIp = qSrcIp;
  if (qKw) q.kw = qKw;
  try {
    bundle.value = await api<AuditBundle>('/audit');
    live.value = true;
    loadErr.value = '';
    if (qActor || qSrcIp || qKw) await runSearch(true);
  } catch (e) {
    // 不回退演示数据：拉不到就说拉不到，并把后端原话原样带出来
    // （403 时那句话正是「角色「系统管理员」无权执行该操作（需要权限：audit）」）。
    bundle.value = null;
    live.value = false;
    loadErr.value = failReason(e);
  }
});
</script>

<style scoped>
.bd-recap__hint { display: block; font-style: normal; font-size: 11px; color: var(--bd-t3); margin-top: 4px; }

/* 审计读取失败：整页只留这一条，不画任何编造数据 */
.bd-auditerr {
  display: flex; gap: 12px; align-items: flex-start; padding: 18px 20px; margin-bottom: 16px;
  background: var(--bd-tag-red-bg); border: 1px solid #FFCDC7; border-radius: var(--bd-radius);
}
.bd-auditerr__ic { color: var(--bd-danger); font-size: 18px; flex: none; margin-top: 1px; }
.bd-auditerr__t { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-auditerr__m { font-size: 13px; color: var(--bd-danger); margin-top: 5px; line-height: 1.7; }
.bd-auditerr__n { font-size: 12px; color: var(--bd-t2); margin-top: 8px; line-height: 1.8; }

/* ── P10 聚合头 ── */
.bd-aggrow { display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
.bd-mcard { flex: 1; min-width: 168px; padding: 16px 18px; }
.bd-mcard__top { display: flex; align-items: center; gap: 8px; }
.bd-mcard__dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.bd-mcard__ic { font-size: 15px; color: var(--bd-t3); }
.bd-mcard__label { font-size: 12.5px; color: var(--bd-t3); font-weight: 500; }
.bd-mcard__num { font-size: 26px; font-weight: 700; color: var(--bd-t1); margin: 8px 0 2px; letter-spacing: .3px; }
.bd-mcard__sub { font-size: 11.5px; color: var(--bd-t3); }
.bd-mcard--total { background: linear-gradient(135deg, var(--bd-primary-1), #fff); }

/* 磁盘水位卡 */
.bd-disk { min-width: 210px; }
.bd-disk__tag { font-size: 11px; padding: 1px 7px; border-radius: 4px; font-weight: 500; margin-left: auto; }
.bd-disk__main { display: flex; align-items: baseline; gap: 6px; margin: 8px 0 8px; }
.bd-disk__main b { font-size: 26px; font-weight: 700; }
.bd-disk__cap { font-size: 13px; color: var(--bd-t3); }
.bd-disk__track { height: 8px; background: var(--bd-fill-2); border-radius: 6px; overflow: hidden; margin-bottom: 8px; }
.bd-disk__fill { display: block; height: 100%; border-radius: 6px; transition: width .3s; }

/* ── 日志表筛选 pill ── */
.bd-pillrow { display: flex; gap: 6px; }
.bd-pill2 { font-size: 12.5px; color: var(--bd-t2); padding: 5px 13px; border-radius: 14px; cursor: pointer; background: var(--bd-fill-1); border: 1px solid transparent; transition: all .12s; }
.bd-pill2:hover { background: var(--bd-fill-2); }
.bd-pill2.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-pill2--time.on { color: var(--bd-primary); }

/* ── 导出弹窗 ── */
.bd-wbody { min-height: 220px; }
.bd-wbody--slim { min-height: 0; }
.bd-wdesc { font-size: 12.5px; color: var(--bd-t3); margin: 4px 0 16px; }

.bd-field { margin-top: 14px; }
.bd-field label { display: block; font-size: 12.5px; color: var(--bd-t2); font-weight: 500; margin-bottom: 8px; }

.bd-recap { margin-top: 16px; display: flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--bd-t2); background: var(--bd-tag-blue-bg); border: 1px solid var(--bd-primary-b); border-radius: 8px; padding: 10px 13px; line-height: 1.6; }
.bd-recap b { color: var(--bd-primary); }

.bd-wfoot { display: flex; align-items: center; gap: 10px; margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--bd-fill-2); }
.bd-btn[disabled] { cursor: not-allowed; }

/* 审计写入失败红条：出现即代表已经丢了记录，用最强的告警色。 */
.bd-auditwarn {
  display: flex; align-items: flex-start; gap: 8px; margin-bottom: 12px; padding: 10px 12px;
  border-radius: 8px; font-size: 12.5px; line-height: 1.6;
  color: var(--bd-danger); background: var(--bd-tag-red-bg); border: 1px solid #FFC2C2;
}
.bd-auditwarn > :first-child { flex: none; margin-top: 2px; font-size: 14px; }
</style>
