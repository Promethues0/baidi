<template>
  <div class="bd-page">
    <!-- 本页没有演示数据可降级：拉不到就是拉不到，原因写在下面那条红条里。 -->
    <PageHeader title="审计中心" subtitle="全链路留痕 · HMAC-SM3 防篡改链 · CSV 合规出口" :live="live" off-text="数据未读取" off-color="red">
      <button class="bd-btn" :disabled="!!loadErr" :title="loadErr ? '审计数据未读取，导出走的是同一道权限闸' : ''"
              @click="openExport"><icon-download />导出 CSV</button>
      <!-- 审计外送的配置在系统管理页（保留天数由 BAIDI_AUDIT_RETENTION_DAYS 决定），
           这个按钮只负责指过去。本页不放任何外送开关。 -->
      <button class="bd-btn bd-btn--ghost" @click="gotoForward"><icon-export />日志外送</button>
    </PageHeader>

    <!-- ★拉不到审计就**什么都不画**：编造的审计记录与真实留痕在页面上无法区分。
         /audit 归 PermAudit，安全/系统管理员打开它拿到的是 403，
         这条红条必须原样转述后端那句话，不能笼统说成"后端没起"。 -->
    <div v-if="loadErr" class="bd-card">
      <EmptyState size="lg" tone="danger" title="无法读取审计数据">
        <div class="bd-auditerr__m">{{ loadErr }}</div>
        <div class="bd-auditerr__n">
          本页不提供演示数据——编造的审计记录无法与真实留痕区分。
          审计读取归「审计」权限（PermAudit）：若上面写的是无权执行，请用具备审计权的管理员账号登录。
        </div>
      </EmptyState>
    </div>

    <!-- 首屏骨架：第一次拉取回来之前不画空白的聚合头与表头，也不编任何数字。 -->
    <template v-else-if="!loaded">
      <div class="bd-aggrow">
        <div v-for="i in 5" :key="i" class="bd-card"><SkeletonBlock kind="stat" /></div>
      </div>
      <div class="bd-tablecard"><SkeletonBlock kind="table" :rows="8" :cols="6" /></div>
    </template>

    <template v-else>


    <!-- 审计写入失败：控制面没能把审计写进库（后端零失败即整段不下发，常态零噪声）。
         ★文案必须说清"链校验查不出它们"——链重算的是**已存在行**的连续性，
         压根没写进去的行不在链上，而防篡改链全绿会被读成"没事"。 -->
    <div v-if="bundle?.writeHealth" class="bd-notice bd-notice--danger">
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
      <!-- 分类计数卡：类别色只做左上角的色点（七类分类色多于语义色档数，属分类调色板而非语义色） -->
      <StatCard v-for="c in catCards" :key="c.key" :label="c.label" :value="fmtNum(c.value)" foot="条 · 累计留痕">
        <template #badge><span class="bd-catdot" :style="{ background: c.color }" /></template>
      </StatCard>

      <!-- 今日总量卡 -->
      <StatCard label="今日总量" :value="bundle ? fmtNum(bundle.todayTotal) : null" foot="条 · 今日累计" tone="primary">
        <template #badge><icon-clock-circle class="bd-mcard__ic" /></template>
      </StatCard>

      <!-- 审计库占用卡。★主数是**审计库自己**有多大，不是文件系统占用率：
           在审计页上把磁盘水位当主数，会被读成"审计日志吃掉的"，
           而两者的处置动作相反——前者缩留存，后者清磁盘。
           ★三态逐项判（判据见 script 里 dbKnown / fsKnown 的注释）：判不出来的字段一律「—」或整段不画，
           不许出现「占文件系统 0%」「已用 0% / 0 GB」「保留 0 天」，也不给一根 0% 的绿色水位条——
           此前 bundle 缺席 / 后端把"探测不到"折成 0 值时，主数「—」旁边配的正是这一整套言之凿凿的 0，
           徽标还写着「所在磁盘健康」。value 传 null（不是字符串 '—'）StatCard 才认它是不可判定。 -->
      <StatCard label="审计库占用" :value="dbSize" :unit="selfPctText" class="bd-disk"
        unknown-text="后端未上报磁盘用量：库文件大小与所在文件系统容量均不可判定（非 SQLite 持久化，或库文件 / 文件系统探测失败；/diag 的「审计磁盘水位」项有原话）">
        <template #badge><span class="bd-tg" :class="diskTagClass">{{ diskBadge }}</span></template>
        <!-- 水位条只在容量可判定时画：一根 0% 的绿条长得与"磁盘几乎是空的"一模一样 -->
        <template v-if="fsKnown" #extra>
          <div class="bd-disk__track"><span class="bd-disk__fill" :class="`bd-disk__fill--${diskTone}`" :style="{ width: disk!.usedPct + '%' }" /></div>
        </template>
        <!-- 脚注：判得出哪一半就写哪一半，另一半写明"未上报"；三项全判不出时不给这个插槽，让 unknown-text 说话 -->
        <template v-if="diskFootKnown" #foot>{{ diskFoot }}</template>
      </StatCard>
    </div>

    <!-- 日志表 -->
    <div class="bd-tablecard">
      <div class="bd-toolbar">
        <!-- 类别筛选 pill：已连控制面时是**服务端检索条件**（全表 WHERE），
             未连时退回对最近 200 条快照的前端过滤 -->
        <div class="bd-pillrow">
          <button v-for="f in catFilters" :key="f.key" type="button" class="bd-pill2" :class="{ on: catSel === f.key }" @click="catSel = f.key; runSearch(true)">{{ f.label }}</button>
        </div>
        <div class="bd-toolbar__spacer" />
        <!-- 检索：账号精确（查证据链要精确，模糊会把 li 匹配到 alice）+ 事件关键词 -->
        <a-input v-model="q.actor" size="small" class="bd-q bd-q--actor" placeholder="账号（精确）"
          allow-clear @press-enter="runSearch(true)" @clear="runSearch(true)" />
        <!-- 源 IP 精确检索：数据面事件记的是网关报来的攻击者地址，「按攻击源查」靠这一维。 -->
        <a-input v-model="q.srcIp" size="small" class="bd-q bd-q--ip" placeholder="源 IP（精确）"
          allow-clear @press-enter="runSearch(true)" @clear="runSearch(true)" />
        <a-input v-model="q.kw" size="small" class="bd-q bd-q--kw" placeholder="事件关键词 / 回车检索"
          allow-clear @press-enter="runSearch(true)" @clear="runSearch(true)" />
        <!-- 时间快选 pill：服务端时间窗（按服务器时间解释，见 sinceOf） -->
        <div class="bd-pillrow">
          <button v-for="t in timeFilters" :key="t.key" type="button" class="bd-pill2 bd-pill2--time" :class="{ on: timeSel === t.key }" @click="timeSel = t.key; runSearch(true)">{{ t.label }}</button>
        </div>
      </div>
      <table class="bd-table bd-table--dense">
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
            <td class="r"><span class="bd-tg" :class="verdictTag(e.verdict)">{{ verdictLabel(e.verdict) }}</span></td>
          </tr>
          <tr v-if="!shownLogs.length" class="bd-table__emptyrow">
            <td colspan="6"><EmptyState size="md" title="当前筛选无匹配日志" /></td>
          </tr>
        </tbody>
      </table>
      <div class="bd-pager">
        <template v-if="searchTotal >= 0">
          全表命中 {{ searchTotal }} 条，本页第 {{ shownLogs.length ? page * PAGE_SIZE + 1 : 0 }}–{{ page * PAGE_SIZE + shownLogs.length }} 条 · 时间范围「{{ timeFilters.find(t => t.key === timeSel)?.label }}」
          <div class="bd-toolbar__spacer" />
          <span class="bd-pgbtn" :class="{ off: page === 0 }" @click="prevPage">上一页</span>
          <span class="bd-pgnum">第 {{ page + 1 }} / {{ pageCount }} 页</span>
          <span class="bd-pgbtn" :class="{ off: page + 1 >= pageCount }" @click="nextPage">下一页</span>
        </template>
        <template v-else>共 {{ shownLogs.length }} 条记录（最近 200 条快照）· 时间范围「{{ timeFilters.find(t => t.key === timeSel)?.label }}」</template>
      </div>
    </div>

    <!-- 导出（GET /api/v1/audit/export，流式 CSV 附件）。
         只暴露后端真支持的条件：类别 + 账号 + 源 IP + 关键词 + 时间范围。 -->
    <a-modal v-model:visible="exp.open" :width="520" :footer="false" title="导出审计日志（CSV）" unmount-on-close>
      <div>
        <div class="bd-wdesc">按条件从 baidi-control 导出全量审计日志（不限于页面上最近 200 条）。</div>
        <div class="bd-fld">
          <label>日志类别</label>
          <a-select v-model="exp.category">
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
        <!-- ★账号 / 源 IP / 关键词三维必须与列表检索同维同义（两侧共用后端
             store.AuditQuery）：少一维就会出现「筛出 12 条、导出 8 万条」，
             而拿到 CSV 的人会以为它就是屏幕上那些行。 -->
        <div class="bd-fld">
          <label>行为人账号（精确，留空 = 不限）</label>
          <a-input v-model="exp.actor" placeholder="如 li.fang" allow-clear />
        </div>
        <div class="bd-fld">
          <label>源 IP（前缀匹配，留空 = 不限）</label>
          <a-input v-model="exp.srcIp" placeholder="如 10.8. 可查整段" allow-clear />
        </div>
        <div class="bd-fld">
          <label>事件关键词（留空 = 不限）</label>
          <a-input v-model="exp.kw" placeholder="如 拒绝越权" allow-clear />
        </div>
        <div class="bd-fld">
          <label>时间范围（留空 = 不限；可选到具体日期，不受页面上三个快选档约束）</label>
          <a-range-picker v-model="exp.range" />
        </div>
        <div class="bd-notice bd-recap">
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
      <div class="bd-drawer__foot">
        <button class="bd-btn bd-btn--ghost" @click="exp.open = false">取消</button>
        <div class="bd-drawer__foot-spacer" />
        <button class="bd-btn" :disabled="exp.busy" @click="doExport">
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
import PageHeader from '@/components/PageHeader.vue';
import StatCard from '@/components/StatCard.vue';
import EmptyState from '@/components/EmptyState.vue';
import SkeletonBlock from '@/components/SkeletonBlock.vue';

/* 连接态三态：undefined = 首轮读取还没回来，页头不画连接标签。
 * ★不能写 ref(false)：那会让红色「数据未读取」在第一次请求回来之前就画出来——
 *   它宣告的是一件**还没发生**的事，慢网 / 大表下能持续好几秒，与「真的读失败了」完全同形。
 * 落定点：onMounted 里那次 /audit 的 try 尾（true）与 catch（false）。两条路径都必须落定，漏一条标签就永远不画（比误报更难发现）。 */
const live = ref<boolean | undefined>(undefined);
const router = useRouter();
const route = useRoute();

/** 「日志外送」指到系统管理页的真配置区（syslog / SIEM 出口 + 队列积压 + 丢弃计数）。
 *  ★这一页上不放任何外送开关：本地一个开关、真配置在另一页，是最容易骗到人的形态。 */
function gotoForward() { void router.push({ path: '/system/manage', query: { tab: 'forward' } }); }

/**
 * ★本页**没有任何演示数据**：拉不到就 bundle=null，整页只显示一条如实的错误
 * （后端原话由 failReason 转述），一行编造的记录都不画。审计页编的正是
 * "谁在什么时候做了什么"，与真实留痕在页面上无法区分。
 */
const bundle = ref<AuditBundle | null>(null);
const loadErr = ref('');
/** 首屏是否已完成一次加载（成功或失败都算）——只决定骨架屏何时让位，不改任何数据流。 */
const loaded = ref(false);


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

/* ── 审计库占用卡：三态逐项判 ──
 * 后端 store.AuditDiskStat.ToDiskStat 把"判不出来"折成 0 值发下来（平台不支持 Statfs → usedPct/totalGB/selfPct
 * 三项为 0；库文件 os.Stat 失败 → dbBytes 为 0；AuditDiskStat 整个出错 → Disk 是零值），报文里没有
 * "可判定"标志，前端只能按字段回推：
 *   fsKnown = totalGB > 0  容量可判定（真实文件系统不足 1 GB 的情形接受为"不可判定"，比把 Windows 画成 0 GB 强）
 *   dbKnown = dbBytes > 0  库文件大小可判定（空库也至少有若干 KB 的页，0 只会是 stat 失败）
 *   retainDays = 0 是「未配置滚动清理」（PurgeExpiredAudit 对 ≤0 直接返回），不是"保留 0 天"——措辞与 /diag 同一句。
 * ★这里刻意一个 `?? 0` 都不写：判定写成「有 disk 且该字段 > 0」，判不出来的就是判不出来。 */
const disk = computed(() => bundle.value?.disk ?? null);
const fsKnown = computed(() => !!disk.value && disk.value.totalGB > 0);
const dbKnown = computed(() => !!disk.value && disk.value.dbBytes > 0);

/* dbSize 审计库文件大小（人话）。★不可判定时回 null 而不是字符串 '—'：StatCard 只认 null/undefined 为
 * 不可判定（灰细「—」+ unknown-text），字符串 '—' 会被当成一个已知值——单位、徽标照常渲染在它旁边。 */
const dbSize = computed<string | null>(() => {
  if (!dbKnown.value) return null;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = disk.value!.dbBytes;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
});
/* 主数旁的单位：审计库占文件系统的比例。两项都判得出才写；后端按整数四舍五入，4.7 MB / 460 GB 得 0——
 * 写成「0%」会被读成"没占"，如实写「不足 1%」。 */
const selfPctText = computed(() => {
  if (!dbKnown.value || !fsKnown.value) return undefined;
  const p = disk.value!.selfPct;
  return p > 0 ? `占文件系统 ${p}%` : '占文件系统不足 1%';
});

/* ── 所在磁盘水位上色（进度条与标签说的都是**文件系统**，不是审计库）── */
const diskTone = computed<'danger' | 'warning' | 'success' | 'unknown'>(() => {
  if (!fsKnown.value) return 'unknown';
  const p = disk.value!.usedPct;
  return p >= 80 ? 'danger' : p >= 60 ? 'warning' : 'success';
});
const diskTagClass = computed(() => ({ danger: 'bd-tg--red', warning: 'bd-tg--gold', success: 'bd-tg--green', unknown: 'bd-tg--grey' })[diskTone.value]);
const diskBadge = computed(() => ({ danger: '所在磁盘偏高', warning: '所在磁盘关注', success: '所在磁盘健康', unknown: '磁盘容量不可判定' })[diskTone.value]);
/* 脚注三段：库文件大小（只在判不出时写一句）· 文件系统水位 · 留存天数。三项全判不出时插槽不给，走 unknown-text。 */
const diskFootKnown = computed(() => dbKnown.value || fsKnown.value || (!!disk.value && disk.value.retainDays > 0));
const diskFoot = computed(() => {
  const d = disk.value;
  if (!d) return '';
  const parts: string[] = [];
  if (!dbKnown.value) parts.push('库文件大小未上报');
  parts.push(fsKnown.value ? `所在磁盘已用 ${d.usedPct}% / ${d.totalGB} GB` : '所在磁盘容量未上报（当前平台不支持文件系统探测）');
  parts.push(d.retainDays > 0 ? `保留 ${d.retainDays} 天` : '未配置滚动清理');
  return parts.join(' · ');
});

/* ── 日志表筛选 ── */
/** 类别筛选条。★必须与后端支持的类别、以及导出下拉逐项对齐：漏一类，
 *  那一类事件（如 dataplane 的隧道放行/拒绝）在这一页的筛选条上等于不存在。 */
const catFilters = [
  { key: 'all', label: '全部' }, { key: 'access', label: '访问' }, { key: 'auth', label: '认证' },
  { key: 'admin', label: '管理' }, { key: 'policy', label: '策略' }, { key: 'security', label: '安全' },
  { key: 'dataplane', label: '数据面' }, { key: 'system', label: '系统' }
];
const timeFilters = [{ key: 'today', label: '今天' }, { key: '7d', label: '7 天' }, { key: '30d', label: '30 天' }];
const catSel = ref('all');
const timeSel = ref('today');
/* 服务端检索态：results 非 null 时表格显示它（全表 WHERE 的结果），
 * 否则回落到首屏快照（最近 200 条）的前端过滤。未连控制面时永远走后者。 */
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
 * ★必须按本地日期逐段拼字符串，不能用 `toISOString().slice(0,10)`：那是先转 UTC
 * 再取日期，在 UTC+8 上每天 00:00–07:59 会把「今天」查成昨天到现在，而多出来的行
 * 看起来就是正常的审计记录，页面零异常。
 * 这里的"本地"是浏览器时区，后端按服务器时区解释——跨时区部署时窗口会差几小时，
 * 故页面文案说的是"按服务器时间"。
 */
function sinceOf(key: string): string {
  const d = new Date();
  if (key === '7d') d.setDate(d.getDate() - 6);
  else if (key === '30d') d.setDate(d.getDate() - 29);
  // today：就是今天
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** 每页条数。★分页必须真发 offset：只发 limit 的话，页脚写着「全表命中 5000 条」
 *  而第 201 条之后没有任何入口能翻到——审计的用途就是查那一条。 */
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
function verdictTag(v: AuditEntry['verdict']) {
  if (v === 'allow' || v === 'ok') return 'bd-tg--green';
  if (v === 'deny' || v === 'fail') return 'bd-tg--red';
  return 'bd-tg--gold'; // mfa
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
/** ★类别中文名走 catMeta（与列表、类别卡同一份），不另抄一张表：
 *  抄漏一项时，选中它确认行的类别就是空白的。 */
const expCatLabel = computed(() => exp.category === 'all' ? '全部类别' : catMeta(exp.category as AuditEntry['category']).label);

/**
 * 打开导出弹窗。★**继承屏幕上刚筛好的条件**，不清空重来：清空会让筛到十几条的人
 * 导出到全表，而他会以为这份 CSV 就是刚才屏幕上那些行，直接拿去交差。
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
  } finally {
    loaded.value = true;
  }
});
</script>

<style scoped>
/* 本页独有：聚合头排布、类别色点、磁盘水位条、筛选 pill。KPI 卡 / 空态 / 提示条 / 表单节奏都在共享件与 app.css 里。 */
.bd-recap__hint { display: block; font-style: normal; font-size: var(--bd-fs-xs); color: var(--bd-t3); margin-top: var(--bd-sp-1); }
.bd-recap b { color: var(--bd-primary); }

/* 审计读取失败：整页只留这一条，不画任何编造数据。后端原话用告警色，口径说明用正文色。 */
.bd-auditerr__m { color: var(--bd-danger); font-size: var(--bd-fs-md); }
.bd-auditerr__n { color: var(--bd-t2); font-size: var(--bd-fs-sm); margin-top: var(--bd-sp-2); }

/* ── P10 聚合头：flex 换行而不是 grid，末行的卡按原样撑满 ── */
.bd-aggrow { display: flex; gap: var(--bd-sp-4); margin-bottom: var(--bd-sp-4); flex-wrap: wrap; }
.bd-aggrow > * { flex: 1 1 168px; min-width: 0; }
.bd-catdot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.bd-mcard__ic { font-size: 15px; color: var(--bd-t3); }

/* 磁盘水位卡：进度条与标签说的都是**文件系统**，不是审计库 */
.bd-disk { flex-basis: 210px; }
.bd-disk__track { height: 8px; background: var(--bd-fill-2); border-radius: var(--bd-radius-xs); overflow: hidden; }
.bd-disk__fill { display: block; height: 100%; border-radius: var(--bd-radius-xs); transition: width var(--bd-dur-slow) var(--bd-ease); }
.bd-disk__fill--success { background: var(--bd-success); }
.bd-disk__fill--warning { background: var(--bd-warning); }
.bd-disk__fill--danger { background: var(--bd-danger); }

/* ── 日志表筛选 pill ── */
.bd-pillrow { display: flex; gap: 6px; }
.bd-pill2 {
  font-size: var(--bd-fs-sm); color: var(--bd-t2); padding: 5px 13px; border-radius: var(--bd-radius-pill); cursor: pointer;
  background: var(--bd-fill-1); border: 1px solid transparent; font: inherit; font-size: var(--bd-fs-sm); line-height: var(--bd-lh);
  transition: background var(--bd-dur-fast) var(--bd-ease), color var(--bd-dur-fast) var(--bd-ease), border-color var(--bd-dur-fast) var(--bd-ease);
}
.bd-pill2:hover { background: var(--bd-fill-2); }
.bd-pill2.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-q--actor { width: 140px; }
.bd-q--ip { width: 150px; }
.bd-q--kw { width: 170px; }

/* ── 导出弹窗 ── */
.bd-wdesc { font-size: var(--bd-fs-sm); color: var(--bd-t3); margin: var(--bd-sp-1) 0 var(--bd-sp-4); }

@media (max-width: 1320px) {
  .bd-q--actor { width: 120px; }
  .bd-q--ip { width: 130px; }
  .bd-q--kw { width: 150px; }
}
</style>
