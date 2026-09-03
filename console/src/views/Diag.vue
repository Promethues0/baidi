<template>
  <div class="dg">
    <!-- 顶栏 -->
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
      <a-tag :color="live ? 'green' : denied ? 'red' : 'orange'" bordered>
        <template #icon><icon-cloud /></template>
        {{ live ? '已连 baidi-control' : denied ? '需管理员权限' : '降级演示 · 内置数据' }}
      </a-tag>
      <a-button type="primary" :loading="loading" @click="load">
        <template #icon><icon-refresh /></template>重新体检
      </a-button>
      <a-button @click="exportReport"><template #icon><icon-download /></template>导出报告</a-button>
      <a-button @click="back"><template #icon><icon-export /></template>返回控制台</a-button>
    </header>

    <!-- 非管理员（后端 403）：如实告知，不展示演示数据 -->
    <div v-if="denied" class="dg-deny">
      <span class="dg-deny__icon"><icon-lock /></span>
      <div class="dg-deny__t">需要管理员权限</div>
      <div class="dg-deny__d">运维诊断仅对管理员开放。当前账号无权读取系统自检数据（控制面已拒绝 /diag 请求）。</div>
      <a-button type="primary" @click="back"><template #icon><icon-export /></template>返回控制台</a-button>
    </div>

    <div v-else class="dg-body">
      <!-- 健康总览 -->
      <section class="dg-hero">
        <div class="dg-score">
          <svg viewBox="0 0 120 120" class="dg-score__svg">
            <circle cx="60" cy="60" r="52" class="dg-score__track" />
            <circle
              cx="60" cy="60" r="52" class="dg-score__val" :stroke="scoreHex"
              :stroke-dasharray="scoreCirc" :stroke-dashoffset="scoreOffset"
            />
          </svg>
          <div class="dg-score__c">
            <b :style="{ color: scoreHex }">{{ bundle.score }}</b>
            <i>健康分</i>
          </div>
        </div>
        <div class="dg-hero__mid">
          <div class="dg-hero__verdict" :style="{ color: scoreHex }">{{ verdictText }}</div>
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
        </div>
        <div class="dg-hero__meta">
          <div class="mrow"><span>组件</span><b>{{ bundle.component }}</b></div>
          <div class="mrow"><span>版本</span><b>v{{ bundle.version }} · {{ envLabel }}</b></div>
          <div class="mrow"><span>运行时长</span><b>{{ bundle.uptime }}</b></div>
          <div class="mrow"><span>体检时间</span><b>{{ bundle.generatedAt || '—' }}</b></div>
        </div>
      </section>

      <!-- 检查项（问题优先：异常 → 关注 → 正常） -->
      <section class="dg-grid">
        <article v-for="c in sortedChecks" :key="c.key" class="dg-card" :class="'is-' + c.status">
          <div class="dg-card__head">
            <span class="dg-card__icon"><component :is="catIcon(c.category)" /></span>
            <div class="dg-card__t">
              <div class="dg-card__name">{{ c.name }}</div>
              <div class="dg-card__cat">{{ catLabel(c.category) }}</div>
            </div>
            <span class="dg-badge" :class="c.status">{{ statusLabel(c.status) }}</span>
          </div>
          <div class="dg-card__summary">{{ c.summary }}</div>
          <div v-if="c.metric" class="dg-card__metric"><icon-info-circle />{{ c.metric }}</div>
          <div v-if="c.hint" class="dg-card__hint"><icon-bulb />{{ c.hint }}</div>
          <div v-if="c.items?.length" class="dg-card__more">
            <div class="dg-card__more-h" @click="toggleItems(c.key)">
              <icon-down :class="{ up: openItems.has(c.key) }" />{{ c.items.length }} 项明细
            </div>
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
        <div class="dg-gws__h"><icon-link /> 数据面网关明细<span class="dg-gws__sub">{{ gateways.length }} 台已注册 · 网关每 15s 上报活性</span></div>
        <div class="dg-gws__grid">
          <div v-for="g in gateways" :key="g.id" class="dg-gw" :class="{ off: !gwOnline(g) }">
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
              <span class="dk-mono">代理 {{ g.proxy }}</span>
              <span class="dk-mono">SPA {{ g.spa }}</span>
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
import { api, type DiagBundle, type DiagCheck, type DiagCategory, type DiagStatus, type GatewaysResp, type GatewayReg, failStatus } from '@/lib/api';
import { FIRST_PATH } from '@/nav';

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
  generatedAt: '', component: 'baidi-control · 控制中心', version: '0.3.0', env: 'dev', uptime: '—',
  score: 81, pass: 5, warn: 3, fail: 0, skip: 1,
  checks: [
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
const live = ref(false);
const loading = ref(false);
const denied = ref(false); // 后端 403（非 admin）：显式提示而非静默降级演示

/* 问题优先排序：异常 → 关注 → 正常 → 跳过；未知枚举兜底排最后（别让 NaN 搅乱排序） */
const RANK: Record<DiagStatus, number> = { fail: 0, warn: 1, pass: 2, skip: 3 };
const sortedChecks = computed<DiagCheck[]>(() =>
  [...bundle.value.checks].sort((a, b) => (RANK[a.status] ?? 9) - (RANK[b.status] ?? 9))
);

/* 健康分环 */
const scoreCirc = 2 * Math.PI * 52;
const scoreOffset = computed(() => scoreCirc * (1 - Math.min(Math.max(bundle.value.score, 0), 100) / 100));
const scoreHex = computed(() => {
  const s = bundle.value.score;
  if (bundle.value.fail > 0 || s < 60) return '#F53F3F';
  if (s < 85) return '#FF7D00';
  return '#00B42A';
});
const verdictText = computed(() => {
  if (bundle.value.fail > 0) return '存在异常项，需立即处置';
  if (bundle.value.warn > 0) return '运行基本正常，有项需关注';
  return '全部检查通过，系统健康';
});
const envLabel = computed(() => (bundle.value.env === 'prod' ? '生产' : '开发'));

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
    // 联动拉取网关明细（best-effort，不阻断体检）
    try { gateways.value = (await api<GatewaysResp>('/gateways')).gateways || []; } catch { gateways.value = []; }
  } catch (e) {
    gateways.value = [];
    // 403=已登录但非 admin：如实提示需管理员权限，不伪装成"健康"演示数据
    if (failStatus(e) === 403) {
      denied.value = true;
      live.value = false;
    } else {
      bundle.value = { ...MOCK, generatedAt: new Date().toLocaleString('zh-CN') };
      live.value = false;
      denied.value = false;
    }
  } finally {
    loading.value = false;
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
  const degraded = !live.value;
  const lines = [
    '# 白帝运维诊断报告',
    ''];
  if (degraded) {
    lines.push(
      '> ⚠️ **本报告不是实测结果。**',
      '>',
      '> 导出时控制台没有从 baidi-control 取到体检数据' +
        (denied.value ? '（当前账号无权读取 /diag，需管理员权限）' : '（控制面不可达）') +
        '，下面的检查项是页面的**离线演示占位**，不代表这套部署的真实状态。',
      '> 请在控制面可达、且以管理员身份登录后重新导出。',
      '');
  }
  lines.push(
    `- 组件：${b.component}`,
    `- 版本：v${b.version}（${envLabel.value}）`,
    `- 运行时长：${b.uptime}`,
    `- 体检时间：${b.generatedAt || '—'}`,
    `- 健康分：${b.score} / 100（正常 ${b.pass} · 关注 ${b.warn} · 异常 ${b.fail}）`,
    '',
    '## 检查项',
    ''
  );
  for (const c of sortedChecks.value) {
    lines.push(`### [${statusLabel(c.status)}] ${c.name}（${catLabel(c.category)}）`);
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
  a.download = degraded ? `白帝运维诊断-演示占位-非实测-${ts}.md` : `白帝运维诊断-${ts}.md`;
  a.click();
  URL.revokeObjectURL(url);
  if (degraded) Message.warning('已导出，但本次是**降级演示占位**（未取到实测数据），报告开头已标注');
  else Message.success('诊断报告已导出');
}

function back() { router.push(FIRST_PATH); }

onMounted(load);
</script>

<style scoped>
.dg { min-height: 100vh; background: var(--bd-fill-1); display: flex; flex-direction: column; }

/* 顶栏 */
.dg-top {
  position: sticky; top: 0; z-index: 10; height: 60px; flex: none; display: flex; align-items: center; gap: 12px;
  padding: 0 24px; background: #fff; border-bottom: 1px solid var(--bd-border);
}
.dg-logo { display: flex; align-items: center; gap: 11px; }
.dg-logo__mark {
  width: 32px; height: 32px; border-radius: 8px; flex: none; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d)); box-shadow: 0 2px 6px rgba(22, 93, 255, .35);
}
.dg-logo__txt { display: flex; flex-direction: column; line-height: 1.2; }
.dg-logo__txt b { font-size: 16px; font-weight: 700; letter-spacing: .3px; color: var(--bd-t1); }
.dg-logo__txt i { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.dg-top__spacer { flex: 1; }

.dg-body { flex: 1; padding: 22px 24px 32px; max-width: 1200px; width: 100%; margin: 0 auto; }

/* 非管理员提示 */
.dg-deny {
  flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px;
  padding: 60px 24px; text-align: center;
}
.dg-deny__icon {
  width: 56px; height: 56px; border-radius: 14px; display: flex; align-items: center; justify-content: center;
  background: var(--bd-tag-red-bg); color: var(--bd-danger); font-size: 28px; margin-bottom: 4px;
}
.dg-deny__t { font-size: 18px; font-weight: 700; color: var(--bd-t1); }
.dg-deny__d { font-size: 13px; color: var(--bd-t3); max-width: 420px; line-height: 1.7; margin-bottom: 8px; }

/* 健康总览 */
.dg-hero {
  background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  padding: 22px 26px; display: grid; grid-template-columns: 140px 1fr 240px; gap: 28px; align-items: center;
}
.dg-score { position: relative; width: 140px; height: 140px; }
.dg-score__svg { width: 140px; height: 140px; transform: rotate(-90deg); }
.dg-score__track { fill: none; stroke: var(--bd-fill-2); stroke-width: 10; }
.dg-score__val { fill: none; stroke-width: 10; stroke-linecap: round; transition: stroke-dashoffset .6s, stroke .3s; }
.dg-score__c { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.dg-score__c b { font-size: 40px; font-weight: 800; line-height: 1; }
.dg-score__c i { font-style: normal; font-size: 12px; color: var(--bd-t3); margin-top: 4px; }

.dg-hero__mid { display: flex; flex-direction: column; gap: 12px; }
.dg-hero__verdict { font-size: 18px; font-weight: 700; }
.dg-hero__stats { display: flex; gap: 22px; }
.dg-stat { font-size: 13px; color: var(--bd-t3); display: flex; align-items: baseline; gap: 6px; }
.dg-stat b { font-size: 22px; font-weight: 700; }
.dg-stat--pass b { color: var(--bd-success); }
.dg-stat--warn b { color: var(--bd-warning); }
.dg-stat--fail b { color: var(--bd-danger); }
.dg-stat--skip b { color: var(--bd-t3); }
.dg-hero__bar { display: flex; height: 8px; border-radius: 5px; overflow: hidden; background: var(--bd-fill-2); }
.dg-hero__bar .seg { display: block; }
.dg-hero__bar .pass { background: var(--bd-success); }
.dg-hero__bar .warn { background: var(--bd-warning); }
.dg-hero__bar .fail { background: var(--bd-danger); }

.dg-hero__meta { display: flex; flex-direction: column; gap: 9px; border-left: 1px solid var(--bd-fill-2); padding-left: 24px; }
.mrow { display: flex; justify-content: space-between; font-size: 13px; gap: 12px; }
.mrow span { color: var(--bd-t3); }
.mrow b { color: var(--bd-t1); font-weight: 600; }

/* 检查项卡片 */
.dg-grid { margin-top: 18px; display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 14px; }
.dg-card {
  background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius); padding: 16px 18px;
  border-left-width: 3px; border-left-color: var(--bd-t4);
}
.dg-card.is-pass { border-left-color: var(--bd-success); }
.dg-card.is-warn { border-left-color: var(--bd-warning); }
.dg-card.is-fail { border-left-color: var(--bd-danger); }
.dg-card.is-skip { border-left-color: var(--bd-t4); }
.dg-card__head { display: flex; align-items: center; gap: 11px; }
.dg-card__icon {
  width: 34px; height: 34px; border-radius: 8px; flex: none; display: flex; align-items: center; justify-content: center;
  background: var(--bd-primary-1); color: var(--bd-primary); font-size: 18px;
}
.dg-card__t { flex: 1; min-width: 0; }
.dg-card__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.dg-card__cat { font-size: 11px; color: var(--bd-t3); margin-top: 1px; }
.dg-badge { font-size: 12px; font-weight: 600; padding: 2px 10px; border-radius: 20px; flex: none; }
.dg-badge.pass { color: var(--bd-success); background: var(--bd-tag-green-bg); }
.dg-badge.warn { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.dg-badge.fail { color: var(--bd-danger); background: var(--bd-tag-red-bg); }
.dg-badge.skip { color: var(--bd-t2); background: var(--bd-fill-2); }
.dg-card__summary { font-size: 13px; color: var(--bd-t2); line-height: 1.6; margin-top: 11px; }
.dg-card__metric {
  display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--bd-t3);
  margin-top: 9px; font-variant-numeric: tabular-nums;
}
.dg-card__hint {
  display: flex; align-items: flex-start; gap: 6px; font-size: 12.5px; color: var(--bd-warning); line-height: 1.5;
  margin-top: 9px; padding: 8px 10px; background: var(--bd-tag-gold-bg); border-radius: 7px;
}
.dg-card.is-fail .dg-card__hint { color: var(--bd-danger); background: var(--bd-tag-red-bg); }
.dg-card__hint :deep(svg), .dg-card__metric :deep(svg) { flex: none; margin-top: 2px; }
.dg-card__more { margin-top: 10px; }
.dg-card__more-h { display: flex; align-items: center; gap: 5px; font-size: 12.5px; color: var(--bd-t2); cursor: pointer; user-select: none; }
.dg-card__more-h :deep(svg) { font-size: 13px; transition: transform 0.2s; }
.dg-card__more-h :deep(svg.up) { transform: rotate(180deg); }
.dg-items { list-style: none; margin: 8px 0 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
.dg-item { display: flex; align-items: center; gap: 8px; font-size: 12.5px; padding: 5px 0; border-top: 1px solid var(--bd-fill-2); }
.dg-item__dot { width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--bd-t4); }
.dg-item__dot.is-pass { background: var(--bd-success); }
.dg-item__dot.is-warn { background: var(--bd-warning); }
.dg-item__dot.is-fail { background: var(--bd-danger); }
.dg-item__dot.is-skip { background: var(--bd-t4); }
.dg-item__l { font-weight: 600; color: var(--bd-t1); font-family: ui-monospace, monospace; }
.dg-item__v { margin-left: auto; color: var(--bd-t3); }

/* 数据面网关明细 */
.dg-gws { margin-top: 22px; }
.dg-gws__h { display: flex; align-items: center; gap: 7px; font-size: 15px; font-weight: 700; color: var(--bd-t1); margin-bottom: 12px; }
.dg-gws__sub { margin-left: auto; font-size: 12px; font-weight: 400; color: var(--bd-t3); }
.dg-gws__grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; }
.dg-gw { background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius); padding: 15px 16px; border-left: 3px solid var(--bd-success); }
.dg-gw.off { border-left-color: var(--bd-t4); opacity: .85; }
.dg-gw__top { display: flex; align-items: center; gap: 8px; }
.dg-gw__dot { width: 8px; height: 8px; border-radius: 50%; background: var(--bd-t4); flex: none; }
.dg-gw__dot.on { background: var(--bd-success); box-shadow: 0 0 0 3px rgba(0, 180, 42, .18); }
.dg-gw__id { font-size: 14px; color: var(--bd-t1); }
.dg-gw__state { margin-left: auto; font-size: 12px; color: var(--bd-t3); }
.dg-gw.off .dg-gw__state { color: var(--bd-warning); }
.dg-gw__nums { display: flex; gap: 10px; margin: 13px 0; }
.dg-gw__n { flex: 1; text-align: center; background: var(--bd-fill-1); border-radius: 8px; padding: 8px 4px; }
.dg-gw__n b { display: block; font-size: 20px; font-weight: 700; color: var(--bd-primary); }
.dg-gw__n i { font-style: normal; font-size: 11px; color: var(--bd-t3); }
.dg-gw__meta { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--bd-t3); }

@media (max-width: 880px) {
  .dg-hero { grid-template-columns: 1fr; justify-items: center; text-align: center; }
  .dg-hero__meta { border-left: none; border-top: 1px solid var(--bd-fill-2); padding-left: 0; padding-top: 16px; width: 100%; }
}
</style>
