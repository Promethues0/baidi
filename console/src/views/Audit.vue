<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">审计中心</div>
        <div class="bd-page__sub">全链路留痕 · HMAC-SM3 防篡改链 · CSV 合规出口</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
        <button class="bd-btn" @click="openExport"><icon-download />导出 CSV</button>
        <!-- 这里原先是一个「日志配置」弹窗：四个类别留痕开关 + 保留天数 + 「合规出口（Syslog 转发）」，
             全部是**显示层假配置**——后端既没有按类别开关留痕的能力，保留天数由
             BAIDI_AUDIT_RETENTION_DAYS 决定，Syslog 那一格更是压根没有实现。
             本轮把外送做成了真的（RFC 5424 over TCP/TLS + HTTP JSON，持久化队列 + 重试），
             配置在系统管理页，这个按钮直接指过去；剩下那几个假开关删掉而不是搬家。 -->
        <button class="bd-btn bd-btn--ghost" @click="gotoForward"><icon-export />日志外送</button>
      </div>
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
        <div class="bd-mcard__num">{{ fmtNum(bundle.todayTotal) }}</div>
        <div class="bd-mcard__sub">条 · 较昨日 <span style="color: var(--bd-success)">+6.2%</span></div>
      </div>

      <!-- 磁盘水位卡 -->
      <div class="bd-card bd-mcard bd-disk">
        <div class="bd-mcard__top">
          <icon-storage class="bd-mcard__ic" />
          <span class="bd-mcard__label">磁盘水位</span>
          <span class="bd-disk__tag" :style="{ color: diskColor, background: diskColor + '14' }">{{ diskLabel }}</span>
        </div>
        <div class="bd-disk__main">
          <b :style="{ color: diskColor }">{{ bundle.disk.usedPct }}%</b>
          <span class="bd-disk__cap">/ {{ bundle.disk.totalGB }} GB</span>
        </div>
        <div class="bd-disk__track"><span class="bd-disk__fill" :style="{ width: bundle.disk.usedPct + '%', background: diskColor }" /></div>
        <div class="bd-mcard__sub">保留 {{ bundle.disk.retainDays }} 天 · 滚动清理</div>
      </div>
    </div>

    <!-- 日志表 -->
    <div class="bd-tablecard">
      <div class="bd-toolbar">
        <!-- 类别筛选 pill：已连控制面时是**服务端检索条件**（全表 WHERE），
             不再只是对最近 200 条的前端过滤 -->
        <div class="bd-pillrow">
          <span v-for="f in catFilters" :key="f.key" class="bd-pill2" :class="{ on: catSel === f.key }" @click="catSel = f.key; runSearch()">{{ f.label }}</span>
        </div>
        <div style="flex: 1" />
        <!-- 检索：账号精确（查证据链要精确，模糊会把 li 匹配到 alice）+ 事件关键词 -->
        <a-input v-model="q.actor" size="small" style="width: 140px" placeholder="账号（精确）"
          allow-clear @press-enter="runSearch" @clear="runSearch" />
        <a-input v-model="q.kw" size="small" style="width: 170px" placeholder="事件关键词 / 回车检索"
          allow-clear @press-enter="runSearch" @clear="runSearch" />
        <!-- 时间快选 pill：此前是装饰件（没接进任何过滤逻辑），现为服务端时间窗 -->
        <div class="bd-pillrow">
          <span v-for="t in timeFilters" :key="t.key" class="bd-pill2 bd-pill2--time" :class="{ on: timeSel === t.key }" @click="timeSel = t.key; runSearch()">{{ t.label }}</span>
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
        <template v-if="searchTotal >= 0">全表命中 {{ searchTotal }} 条，显示前 {{ shownLogs.length }} 条 · 时间范围「{{ timeFilters.find(t => t.key === timeSel)?.label }}」</template>
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
            <a-option value="dataplane">数据面回执</a-option>
          </a-select>
        </div>
        <div class="bd-field">
          <label>时间范围（留空 = 不限）</label>
          <a-range-picker v-model="exp.range" show-time style="width: 100%" />
        </div>
        <div class="bd-recap">
          <icon-info-circle />
          导出「<b>{{ expCatLabel }}</b>」{{ exp.range?.length === 2 ? ` · ${exp.range[0]} 至 ${exp.range[1]}` : ' · 全部时间' }}
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

  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, getToken, type AuditBundle, type AuditEntry, type KV } from '@/lib/api';

const live = ref(false);
const router = useRouter();

/** 「日志外送」指到系统管理页的真配置区（syslog / SIEM 出口 + 队列积压 + 丢弃计数）。
 *  这一页上不再放任何外送开关：本地一个假开关、真配置在另一页，是最容易骗到人的形态。 */
function gotoForward() { void router.push({ path: '/system/manage', query: { tab: 'forward' } }); }

/* ── mock fallback（结构同 store.AuditBundle）── */
const MOCK: AuditBundle = {
  categories: [
    { name: '访问决策', value: 184320 },
    { name: '登录认证', value: 96240 },
    { name: '管理操作', value: 12880 },
    { name: '安全事件', value: 2360 }
  ],
  todayTotal: 8642,
  disk: { usedPct: 72, totalGB: 512, retainDays: 90 },
  logs: [
    { time: '2026-06-22 14:32:08', category: 'access', user: '张伟', srcIp: '192.168.10.24', event: '访问内部应用「OA 协同」', verdict: 'allow' },
    { time: '2026-06-22 14:31:55', category: 'auth', user: '李娜', srcIp: '10.1.2.33', event: '客户端登录 · 设备指纹校验', verdict: 'mfa' },
    { time: '2026-06-22 14:30:42', category: 'access', user: '王强', srcIp: '203.0.113.8', event: '访问「财务系统」未授权资源', verdict: 'deny' },
    { time: '2026-06-22 14:29:17', category: 'security', user: '系统', srcIp: '192.168.10.99', event: '检测到异常端口扫描行为', verdict: 'fail' },
    { time: '2026-06-22 14:28:03', category: 'admin', user: 'admin', srcIp: '10.0.0.2', event: '修改全局策略「禁止浏览器登录」', verdict: 'ok' },
    { time: '2026-06-22 14:26:41', category: 'auth', user: '赵敏', srcIp: '172.16.4.18', event: '短信验证码二次认证', verdict: 'ok' },
    { time: '2026-06-22 14:25:12', category: 'access', user: '刘洋', srcIp: '192.168.20.7', event: '访问隧道应用「研发 Git」', verdict: 'allow' },
    { time: '2026-06-22 14:23:58', category: 'security', user: '陈静', srcIp: '198.51.100.5', event: '连续密码错误触发 IP 锁定', verdict: 'deny' },
    { time: '2026-06-22 14:22:30', category: 'admin', user: 'admin', srcIp: '10.0.0.2', event: '新增访问者「外包-周磊」', verdict: 'ok' },
    { time: '2026-06-22 14:20:11', category: 'auth', user: '孙浩', srcIp: '10.1.5.66', event: '浏览器登录被客户端强管控拦截', verdict: 'fail' }
  ]
};
const bundle = ref<AuditBundle>(MOCK);

/* ── P10 分类卡 ── */
const CAT_COLOR: Record<string, string> = { '访问决策': '#165DFF', '登录认证': '#722ED1', '管理操作': '#00B42A', '安全事件': '#FF7D00' };
const catCards = computed(() =>
  bundle.value.categories.map((c: KV) => ({ key: c.name, label: c.name, value: c.value, color: CAT_COLOR[c.name] ?? '#165DFF' }))
);
function fmtNum(n: number) { return n.toLocaleString('en-US'); }

/* ── 磁盘水位上色 ── */
const diskColor = computed(() => {
  const p = bundle.value.disk.usedPct;
  return p >= 80 ? 'var(--bd-danger)' : p >= 60 ? 'var(--bd-warning)' : 'var(--bd-success)';
});
const diskLabel = computed(() => {
  const p = bundle.value.disk.usedPct;
  return p >= 80 ? '偏高' : p >= 60 ? '关注' : '健康';
});

/* ── 日志表筛选 ── */
const catFilters = [
  { key: 'all', label: '全部' }, { key: 'access', label: '访问' }, { key: 'auth', label: '认证' },
  { key: 'admin', label: '管理' }, { key: 'security', label: '安全' }
];
const timeFilters = [{ key: 'today', label: '今天' }, { key: '7d', label: '7 天' }, { key: '30d', label: '30 天' }];
const catSel = ref('all');
const timeSel = ref('today');
/* 服务端检索态：results 非 null 时表格显示它（全表 WHERE 的结果），
 * 否则回落到首屏快照（最近 200 条）的前端过滤。未连控制面时永远走后者——
 * mock 数据上装一个"全表检索"是在演示假能力。 */
const q = reactive({ actor: '', kw: '' });
const searchResults = ref<AuditEntry[] | null>(null);
const searchTotal = ref(-1);
const shownLogs = computed<AuditEntry[]>(() => {
  if (searchResults.value) return searchResults.value;
  return catSel.value === 'all' ? bundle.value.logs : bundle.value.logs.filter((l) => l.category === catSel.value);
});

function sinceOf(key: string): string {
  const d = new Date();
  if (key === '7d') d.setDate(d.getDate() - 6);
  else if (key === '30d') d.setDate(d.getDate() - 29);
  // today：就是今天
  return d.toISOString().slice(0, 10);
}

async function runSearch() {
  if (!live.value) { searchResults.value = null; searchTotal.value = -1; return; }
  // 全默认（全部类别 + 今天 + 无关键词）退回首屏快照：别让"什么都没筛"看起来像检索过
  const idle = catSel.value === 'all' && timeSel.value === 'today' && !q.actor.trim() && !q.kw.trim();
  if (idle) { searchResults.value = null; searchTotal.value = -1; return; }
  const qs = new URLSearchParams();
  if (catSel.value !== 'all') qs.set('category', catSel.value);
  if (q.actor.trim()) qs.set('actor', q.actor.trim());
  if (q.kw.trim()) qs.set('q', q.kw.trim());
  qs.set('from', sinceOf(timeSel.value));
  qs.set('limit', '200');
  try {
    const r = await api<{ logs: AuditEntry[]; total: number }>(`/audit?${qs.toString()}`);
    searchResults.value = r.logs;
    searchTotal.value = r.total;
  } catch {
    Message.error('审计检索失败（需已连 baidi-control）');
  }
}

function catMeta(c: AuditEntry['category']) {
  // 未知分类兜底：后端新增分类时页面稳定降级（原样显示 key），而不是 undefined.color 崩掉整页
  return {
    access: { label: '访问决策', color: '#165DFF' },
    auth: { label: '登录认证', color: '#722ED1' },
    admin: { label: '管理操作', color: '#00B42A' },
    security: { label: '安全事件', color: '#FF7D00' },
    dataplane: { label: '数据面回执', color: '#0FC6C2' }
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
  category: 'all' as 'all' | 'access' | 'auth' | 'admin' | 'security',
  range: [] as string[],
  busy: false
});
const expCatLabel = computed(
  () => ({ all: '全部类别', access: '访问决策', auth: '登录认证', admin: '管理操作', security: '安全事件' }[exp.category])
);

function openExport() {
  exp.open = true;
  exp.category = 'all';
  exp.range = [];
  exp.busy = false;
}

/* 后端回 CSV 附件（非 JSON），api() 封装只吃 JSON，这里直接 fetch blob 触发下载。 */
async function doExport() {
  exp.busy = true;
  try {
    const qs = new URLSearchParams();
    if (exp.category !== 'all') qs.set('category', exp.category);
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
  } catch {
    Message.error('导出失败：需已连 baidi-control 且以管理员登录');
  } finally {
    exp.busy = false;
  }
}

/* ── 拉取 ── */
onMounted(async () => {
  try {
    const b = await api<AuditBundle>('/audit');
    bundle.value = b; live.value = true;
  } catch { live.value = false; }
});
</script>

<style scoped>
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
</style>
