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
        </article>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { api, type DiagBundle, type DiagCheck, type DiagCategory, type DiagStatus } from '@/lib/api';
import { FIRST_PATH } from '@/nav';

const router = useRouter();

/* 降级演示数据（对齐后端 DiagBundle，便于无后端时预览） */
const MOCK: DiagBundle = {
  generatedAt: '', component: 'baidi-control · 控制中心', version: '0.3.0', env: 'dev', uptime: '—',
  score: 72, pass: 4, warn: 5, fail: 0,
  checks: [
    { key: 'control', category: 'control', name: '控制面 baidi-control', status: 'pass', summary: '控制中心进程运行正常，API 响应中', metric: 'v0.3.0 · 运行 —', hint: '' },
    { key: 'db', category: 'storage', name: '管理数据库 SQLite', status: 'pass', summary: '数据库连接正常，读写可用', metric: '往返 —', hint: '' },
    { key: 'audit-disk', category: 'storage', name: '审计日志留存', status: 'pass', summary: '审计日志留存正常，磁盘水位健康', metric: '占用 62% · 512GB · 留存 180 天', hint: '' },
    { key: 'gateways', category: 'dataplane', name: '数据面网关在线', status: 'warn', summary: '尚无数据面网关注册（控制面可独立运行）', metric: '在线 0 / 注册 0', hint: '以 -control 指向本控制面启动 baidi-gateway 即自动注册' },
    { key: 'spa', category: 'stealth', name: 'SPA 服务隐身', status: 'pass', summary: 'SPA 单包授权生效，受保护端口对未授权源不可见', metric: 'G3 · 守护 3 端口', hint: '' },
    { key: 'cluster', category: 'cluster', name: '集群高可用', status: 'warn', summary: '1 个集群节点降级', metric: '健康 4 · 降级 1 · 故障 0 / 共 5', hint: '关注降级节点负载与链路' },
    { key: 'authsrc', category: 'identity', name: '认证源可达', status: 'warn', summary: '1 个认证源异常：商密证书 (SM2)', metric: '在线 5 / 接入 6', hint: '核对异常认证源的连通与凭据' },
    { key: 'posture', category: 'posture', name: '访问威胁压力', status: 'warn', summary: '登录失败数偏高，关注异常登录', metric: '拒绝 173 · 失败 62 · 二次鉴权 53 · 在线 186', hint: '结合用户状态页排查锁定账号' },
    { key: 'secret', category: 'security', name: '密钥与传输安全', status: 'warn', summary: '使用开发默认 JWT 密钥（控制面回环 HTTP，前置 nginx 终止 TLS）', metric: '默认密钥 · 开发', hint: '上线前经 BAIDI_JWT_SECRET 注入随机密钥' }
  ]
};

const bundle = ref<DiagBundle>(MOCK);
const live = ref(false);
const loading = ref(false);
const denied = ref(false); // 后端 403（非 admin）：显式提示而非静默降级演示

/* 问题优先排序：异常 → 关注 → 正常 */
const RANK: Record<DiagStatus, number> = { fail: 0, warn: 1, pass: 2 };
const sortedChecks = computed<DiagCheck[]>(() =>
  [...bundle.value.checks].sort((a, b) => RANK[a.status] - RANK[b.status])
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
  cluster: { label: '集群', icon: 'IconApps' },
  identity: { label: '身份', icon: 'IconUserGroup' },
  posture: { label: '态势', icon: 'IconExclamationCircle' },
  security: { label: '密钥安全', icon: 'IconLock' }
};
function catLabel(c: DiagCategory) { return CAT[c]?.label ?? c; }
function catIcon(c: DiagCategory) { return CAT[c]?.icon ?? 'IconInfoCircle'; }
function statusLabel(s: DiagStatus) { return s === 'pass' ? '正常' : s === 'warn' ? '关注' : '异常'; }

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
  } catch (e) {
    // 403=已登录但非 admin：如实提示需管理员权限，不伪装成"健康"演示数据
    if (String((e as Error)?.message ?? e).startsWith('403')) {
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

function exportReport() {
  const b = bundle.value;
  const lines = [
    '# 白帝运维诊断报告',
    '',
    `- 组件：${b.component}`,
    `- 版本：v${b.version}（${envLabel.value}）`,
    `- 运行时长：${b.uptime}`,
    `- 体检时间：${b.generatedAt || '—'}`,
    `- 健康分：${b.score} / 100（正常 ${b.pass} · 关注 ${b.warn} · 异常 ${b.fail}）`,
    '',
    '## 检查项',
    ''
  ];
  for (const c of sortedChecks.value) {
    lines.push(`### [${statusLabel(c.status)}] ${c.name}（${catLabel(c.category)}）`);
    lines.push(`- 结论：${c.summary}`);
    if (c.metric) lines.push(`- 指标：${c.metric}`);
    if (c.hint) lines.push(`- 建议：${c.hint}`);
    lines.push('');
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const digits = (b.generatedAt || '').replace(/\D/g, '');
  const ts = digits.length === 14 ? digits : nowStamp(); // 后端 generatedAt=YYYY-MM-DD HH:MM:SS → 14 位；降级路径回退本地时戳
  a.href = url;
  a.download = `白帝运维诊断-${ts}.md`;
  a.click();
  URL.revokeObjectURL(url);
  Message.success('诊断报告已导出');
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

@media (max-width: 880px) {
  .dg-hero { grid-template-columns: 1fr; justify-items: center; text-align: center; }
  .dg-hero__meta { border-left: none; border-top: 1px solid var(--bd-fill-2); padding-left: 0; padding-top: 16px; width: 100%; }
}
</style>
