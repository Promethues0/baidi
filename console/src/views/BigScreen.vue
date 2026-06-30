<template>
  <div class="scr">
    <!-- 动态背景层 -->
    <div class="scr-bg scr-bg--grid" />
    <div class="scr-bg scr-bg--blob b1" />
    <div class="scr-bg scr-bg--blob b2" />
    <div class="scr-bg scr-bg--scan" />

    <!-- 顶栏 -->
    <header class="scr-top">
      <div class="scr-top__l">
        <span class="scr-mark">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#2fe6ff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#06122e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        <div class="scr-brand"><b>白帝 · 零信任</b><i>ZTNA / SDP Security Posture</i></div>
      </div>
      <h1 class="scr-title"><span>零信任安全态势感知中心</span></h1>
      <div class="scr-top__r">
        <div class="scr-clock"><b>{{ clock }}</b><i>{{ today }}</i></div>
        <span class="scr-live" :class="{ off: !live }"><span class="scr-live__dot" />{{ live ? '实时' : '降级' }}</span>
        <button class="scr-act" title="全屏" @click="toggleFs"><icon-fullscreen /></button>
        <button class="scr-act" title="返回控制台" @click="back"><icon-export /></button>
      </div>
    </header>

    <div class="scr-grid">
      <!-- 左列 -->
      <section class="scr-col">
        <div class="panel pop" style="--d: .05s">
          <div class="panel__h"><i class="panel__bar" />核心指标</div>
          <div class="kpis">
            <div class="kpi">
              <div class="kpi__v">{{ nDevOnline }}<small>/{{ ov.devices.total }}</small></div>
              <div class="kpi__l">在线设备 · {{ (ov.devices.rate * 100).toFixed(0) }}%</div>
            </div>
            <div class="kpi">
              <div class="kpi__v">{{ nSessions }}</div>
              <div class="kpi__l">活跃会话</div>
            </div>
            <div class="kpi">
              <div class="kpi__v">{{ nUsers }}</div>
              <div class="kpi__l">纳管用户 · 禁{{ ov.users.disabled }}锁{{ ov.users.locked }}</div>
            </div>
            <div class="kpi kpi--danger">
              <div class="kpi__v">{{ nThreat }}</div>
              <div class="kpi__l">今日威胁事件</div>
            </div>
          </div>
        </div>

        <div class="panel pop" style="--d: .12s">
          <div class="panel__h"><i class="panel__bar" />访问判定分布</div>
          <div class="donut">
            <svg viewBox="0 0 120 120" class="donut__svg">
              <circle cx="60" cy="60" r="46" class="donut__track" />
              <circle
                v-for="(s, i) in donutSegs" :key="i"
                cx="60" cy="60" r="46" class="donut__seg"
                :stroke="s.color" :stroke-dasharray="`${s.len} ${donutCirc - s.len}`"
                :stroke-dashoffset="-s.offset"
              />
            </svg>
            <div class="donut__c"><b>{{ nVerdict }}</b><i>今日判定</i></div>
            <ul class="donut__legend">
              <li v-for="b in ov.verdicts" :key="b.name">
                <span class="dot" :style="{ background: verdictColor(b.name) }" />
                <span class="lg-n">{{ b.name }}</span>
                <span class="lg-v">{{ b.value }}</span>
                <span class="lg-p">{{ pctOf(b.value, verdictTotal) }}%</span>
              </li>
            </ul>
          </div>
        </div>

        <div class="panel panel--grow pop" style="--d: .19s">
          <div class="panel__h"><i class="panel__bar" />审计类别分布</div>
          <div class="bars">
            <div v-for="b in ov.auditByKind" :key="b.name" class="bar">
              <span class="bar__l">{{ b.name }}</span>
              <span class="bar__track"><span class="bar__fill" :style="{ width: pct(b.value, auditMax) }" /></span>
              <span class="bar__v">{{ b.value }}</span>
            </div>
          </div>
        </div>
      </section>

      <!-- 中列 -->
      <section class="scr-col scr-col--c">
        <div class="panel panel--radar pop" style="--d: .1s">
          <div class="panel__h">
            <i class="panel__bar" />实时威胁雷达
            <span class="panel__sub">{{ blips.length }} 个风险实体 · 持续监测中</span>
          </div>
          <div class="radar">
            <div class="radar-sweep" />
            <svg viewBox="0 0 400 400" class="radar-svg">
              <!-- 外圈刻度环（缓慢反向旋转） -->
              <g class="radar-bezel">
                <circle cx="200" cy="200" r="192" class="r-bezel-line" />
                <circle cx="200" cy="200" r="184" class="r-bezel-ticks" />
              </g>
              <circle cx="200" cy="200" r="60" class="r-ring" />
              <circle cx="200" cy="200" r="120" class="r-ring" />
              <circle cx="200" cy="200" r="180" class="r-ring" />
              <line x1="200" y1="20" x2="200" y2="380" class="r-cross" />
              <line x1="20" y1="200" x2="380" y2="200" class="r-cross" />
              <line x1="73" y1="73" x2="327" y2="327" class="r-cross" />
              <line x1="327" y1="73" x2="73" y2="327" class="r-cross" />
              <!-- 目标锁定连线 + 光点 -->
              <g v-for="(p, i) in blips" :key="i">
                <line x1="200" y1="200" :x2="p.x" :y2="p.y" class="lock-line" :style="{ stroke: p.color }" />
                <circle :cx="p.x" :cy="p.y" :r="p.r" :fill="p.color" class="blip">
                  <animate attributeName="opacity" values="1;.35;1" :dur="`${p.dur}s`" repeatCount="indefinite" />
                </circle>
                <circle :cx="p.x" :cy="p.y" :r="p.r" :stroke="p.color" class="blip-ring">
                  <animate attributeName="r" :values="`${p.r};${p.r + 16}`" :dur="`${p.dur}s`" repeatCount="indefinite" />
                  <animate attributeName="opacity" values=".75;0" :dur="`${p.dur}s`" repeatCount="indefinite" />
                </circle>
              </g>
              <circle cx="200" cy="200" r="3" class="r-core" />
            </svg>
            <div class="radar-tags">
              <span v-for="(p, i) in blips" :key="i" class="rtag" :style="{ left: p.lx + '%', top: p.ly + '%', color: p.color }">{{ p.label }}</span>
            </div>
          </div>
        </div>

        <div class="panel panel--lines pop" style="--d: .17s">
          <div class="panel__h"><i class="panel__bar" />三道防线 · 风险态势</div>
          <div class="gauges">
            <div v-for="(d, i) in ov.defense" :key="d.key" class="gauge">
              <svg viewBox="0 0 120 110" class="gauge__svg">
                <path d="M16 96 A52 52 0 1 1 104 96" class="gauge__track" />
                <path
                  d="M16 96 A52 52 0 1 1 104 96" class="gauge__val"
                  :stroke="riskHex(d.risk)"
                  :stroke-dasharray="gaugeLen"
                  :stroke-dashoffset="gaugeOffset(d.risk)"
                />
              </svg>
              <div class="gauge__c">
                <b :style="{ color: riskHex(d.risk) }">{{ gaugeShown[i] }}</b>
                <component :is="trendIcon(d.trend)" class="gauge__tr" :style="{ color: trendHex(d.trend) }" />
              </div>
              <div class="gauge__n">{{ d.name }}</div>
              <div class="gauge__tag" :style="{ color: riskHex(d.risk), borderColor: riskHex(d.risk) }">{{ riskLabel(d.risk) }}</div>
            </div>
          </div>
        </div>
      </section>

      <!-- 右列 -->
      <section class="scr-col">
        <div class="panel panel--grow pop" style="--d: .15s">
          <div class="panel__h"><i class="panel__bar" />实时安全事件<span class="panel__sub">滚动播报</span></div>
          <div class="ticker">
            <div class="ticker__roll">
              <div v-for="(e, i) in tickerLoop" :key="i" class="ev" :class="'ev--' + e.verdict">
                <span class="ev__t">{{ e.time }}</span>
                <span class="ev__body">
                  <span class="ev__top"><b>{{ e.user }}</b><span class="ev__vd">{{ verdictText(e.verdict) }}</span></span>
                  <span class="ev__sub">{{ e.event }} · {{ e.srcIp }}</span>
                </span>
              </div>
            </div>
          </div>
        </div>

        <div class="panel panel--regions pop" style="--d: .22s">
          <div class="panel__h"><i class="panel__bar" />接入来源 TOP 地域</div>
          <div class="regions">
            <div v-for="(r, i) in topRegions" :key="r.name" class="rg">
              <span class="rg__rk" :class="{ hot: i < 3 }">{{ i + 1 }}</span>
              <span class="rg__n">{{ r.name }}</span>
              <span class="rg__track"><span class="rg__fill" :style="{ width: pct(r.count, regionMax) }" /></span>
              <span class="rg__v">{{ r.count }}</span>
            </div>
            <div v-if="!topRegions.length" class="regions__empty">暂无在线接入</div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue';
import { useRouter } from 'vue-router';
import { api, type Overview, type OnlineResp, type OnlineSession, type AuditBundle, type AuditEntry } from '@/lib/api';
import { FIRST_PATH } from '@/nav';

const router = useRouter();

/* ── 降级演示数据 ── */
const MOCK_OV: Overview = {
  generatedAt: '',
  devices: { online: 186, total: 240, rate: 0.775 },
  users: { total: 312, disabled: 7, locked: 4 },
  threats: { rejected: 173, failed: 62, secondary: 53 },
  sessions: 186,
  auditByKind: [
    { name: '访问决策', value: 1284 }, { name: '登录认证', value: 642 },
    { name: '策略变更', value: 73 }, { name: '配置变更', value: 41 }
  ],
  verdicts: [
    { name: '允许', value: 1102 }, { name: '二次鉴权', value: 128 },
    { name: '拒绝', value: 173 }, { name: '降权', value: 39 }
  ],
  defense: [
    { key: 'device', name: '设备防线', risk: 28, trend: 'down', top: ['203.0.113.7', '198.51.100.22', '203.0.113.91'] },
    { key: 'account', name: '账号防线', risk: 41, trend: 'up', top: ['li.fang', '外包-zhao', 'svc-bot-04'] },
    { key: 'endpoint', name: '终端防线', risk: 19, trend: 'flat', top: ['WIN-诊室-12', 'MAC-研发-08', '未授信-Android-3'] }
  ]
};
const MOCK_SESS: OnlineSession[] = [
  { id: 's1', user: '张-研发', account: 'zhang', org: '研发部', ip: '10.2.3.4', location: '杭州', device: 'MAC-08', os: 'macOS', auth: 'AD', app: 'GitLab', gateway: 'GW-1', loginAt: '', duration: '2h', trust: 'trusted', risk: 'none', status: 'online' },
  { id: 's2', user: 'li.fang', account: 'li.fang', org: '财务部', ip: '203.0.113.7', location: '北京', device: 'WIN-12', os: 'Windows', auth: 'LDAP', app: 'ERP', gateway: 'GW-1', loginAt: '', duration: '11m', trust: 'untrusted', risk: 'high', status: 'online' },
  { id: 's3', user: '外包-zhao', account: 'zhao', org: '外包', ip: '198.51.100.22', location: '深圳', device: 'Android-3', os: 'Android', auth: 'SMS', app: 'OA', gateway: 'GW-2', loginAt: '', duration: '34m', trust: 'unknown', risk: 'low', status: 'online' }
];
const MOCK_AUDIT: AuditEntry[] = [
  { time: '19:24:31', category: 'access', user: 'li.fang', srcIp: '203.0.113.7', event: '访问 ERP·财务报表', verdict: 'deny' },
  { time: '19:24:18', category: 'auth', user: '外包-zhao', srcIp: '198.51.100.22', event: 'SMS 二次鉴权', verdict: 'mfa' },
  { time: '19:23:55', category: 'access', user: '张-研发', srcIp: '10.2.3.4', event: '访问 GitLab', verdict: 'allow' },
  { time: '19:23:40', category: 'security', user: 'svc-bot-04', srcIp: '203.0.113.91', event: '触发暴力破解阈值', verdict: 'deny' },
  { time: '19:23:12', category: 'auth', user: 'wang.li', srcIp: '10.2.5.9', event: 'AD 域账号登录', verdict: 'ok' }
];

const ov = ref<Overview>(MOCK_OV);
const sessions = ref<OnlineSession[]>(MOCK_SESS);
const audit = ref<AuditEntry[]>(MOCK_AUDIT);
const live = ref(false);

/* ── 时钟 ── */
const clock = ref('');
const today = ref('');
const WD = ['日', '一', '二', '三', '四', '五', '六'];
function tick() {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  clock.value = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  today.value = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} 周${WD[d.getDay()]}`;
}

/* ── 数字滚动递增（easeOutCubic，requestAnimationFrame） ── */
function useCountUp(getter: () => number, dur = 1000) {
  const cur = ref(0);
  let raf = 0;
  function run() {
    const to = getter() || 0;
    const from = cur.value;
    const start = performance.now();
    cancelAnimationFrame(raf);
    const step = (t: number) => {
      const p = Math.min((t - start) / dur, 1);
      const e = 1 - Math.pow(1 - p, 3);
      cur.value = from + (to - from) * e;
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
  }
  watch(getter, run);
  onMounted(run);
  onBeforeUnmount(() => cancelAnimationFrame(raf));
  return computed(() => Math.round(cur.value));
}

/* ── 派生量 ── */
const threatTotal = computed(() => ov.value.threats.rejected + ov.value.threats.failed + ov.value.threats.secondary);
const verdictTotal = computed(() => ov.value.verdicts.reduce((s, b) => s + b.value, 0));
const auditMax = computed(() => Math.max(...ov.value.auditByKind.map((b) => b.value), 1));

const nDevOnline = useCountUp(() => ov.value.devices.online);
const nSessions = useCountUp(() => ov.value.sessions);
const nUsers = useCountUp(() => ov.value.users.total);
const nThreat = useCountUp(() => threatTotal.value);
const nVerdict = useCountUp(() => verdictTotal.value);
const d0 = useCountUp(() => ov.value.defense[0]?.risk ?? 0, 1100);
const d1 = useCountUp(() => ov.value.defense[1]?.risk ?? 0, 1100);
const d2 = useCountUp(() => ov.value.defense[2]?.risk ?? 0, 1100);
const gaugeShown = computed(() => [d0.value, d1.value, d2.value]);

function pct(v: number, max: number) { return `${Math.round((v / max) * 100)}%`; }
function pctOf(v: number, total: number) { return total ? Math.round((v / total) * 100) : 0; }

/* 判定环图分段 */
const donutCirc = 2 * Math.PI * 46;
const donutSegs = computed(() => {
  const total = verdictTotal.value || 1;
  let acc = 0;
  return ov.value.verdicts.map((b) => {
    const len = (b.value / total) * donutCirc;
    const seg = { color: verdictColor(b.name), len, offset: acc };
    acc += len;
    return seg;
  });
});
function verdictColor(name: string) {
  return name === '拒绝' ? '#ff4d4f' : name === '二次鉴权' ? '#ffa940' : name === '降权' ? '#ffd666' : '#2fe6ff';
}
function verdictText(v: string) {
  return v === 'allow' ? '允许' : v === 'deny' ? '拒绝' : v === 'mfa' ? '二次鉴权' : v === 'fail' ? '失败' : '通过';
}

/* 三道防线仪表（270° 弧） */
const gaugeR = 52;
const gaugeLen = (gaugeR * Math.PI * 270) / 180;
function gaugeOffset(risk: number) { return gaugeLen * (1 - Math.min(risk, 100) / 100); }
function riskHex(r: number) { return r >= 40 ? '#ff4d4f' : r >= 25 ? '#ffa940' : '#36e29b'; }
function riskLabel(r: number) { return r >= 40 ? '高风险' : r >= 25 ? '关注' : '良好'; }
function trendIcon(t: string) { return t === 'up' ? 'IconArrowRise' : t === 'down' ? 'IconArrowFall' : 'IconMinus'; }
function trendHex(t: string) { return t === 'up' ? '#ff4d4f' : t === 'down' ? '#36e29b' : '#7e93c4'; }

/* 雷达光点：三道防线 TOP 实体 + 高风险会话 */
interface Blip { x: number; y: number; r: number; color: string; label: string; lx: number; ly: number; dur: number }
const blips = computed<Blip[]>(() => {
  const items: { label: string; sev: 'high' | 'mid' | 'low' }[] = [];
  ov.value.defense.forEach((d) => {
    const sev: 'high' | 'mid' | 'low' = d.risk >= 40 ? 'high' : d.risk >= 25 ? 'mid' : 'low';
    d.top.forEach((t) => items.push({ label: t, sev }));
  });
  sessions.value.filter((s) => s.risk === 'high').forEach((s) => items.push({ label: s.user, sev: 'high' }));
  const seen = new Set<string>();
  const uniq = items.filter((it) => (seen.has(it.label) ? false : (seen.add(it.label), true))).slice(0, 9);
  const cx = 200, cy = 200;
  return uniq.map((it, i) => {
    const ang = (i * 137.508 + 18) * (Math.PI / 180);
    const rad = 50 + ((i * 53) % 120);
    const x = cx + Math.cos(ang) * rad;
    const y = cy + Math.sin(ang) * rad;
    const color = it.sev === 'high' ? '#ff4d4f' : it.sev === 'mid' ? '#ffa940' : '#36e29b';
    const r = it.sev === 'high' ? 5 : 4;
    return { x, y, r, color, label: it.label, lx: (x / 400) * 100, ly: (y / 400) * 100, dur: 1.6 + (i % 4) * 0.4 };
  });
});

/* 实时事件滚动（数据 < 6 条不滚） */
const tickerLoop = computed<AuditEntry[]>(() => {
  const a = audit.value.slice(0, 14);
  return a.length >= 6 ? [...a, ...a] : a;
});

/* 接入来源 TOP 地域 */
const topRegions = computed(() => {
  const m = new Map<string, number>();
  sessions.value.forEach((s) => {
    const k = (s.location || '未知').trim() || '未知';
    m.set(k, (m.get(k) || 0) + 1);
  });
  return [...m.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 7);
});
const regionMax = computed(() => Math.max(...topRegions.value.map((r) => r.count), 1));

/* ── 取数 ── */
async function load() {
  try {
    const [o, on, au] = await Promise.all([
      api<Overview>('/overview'),
      api<OnlineResp>('/online').catch(() => null),
      api<AuditBundle>('/audit').catch(() => null)
    ]);
    ov.value = o;
    if (on?.sessions?.length) sessions.value = on.sessions.filter((s) => s.status === 'online');
    if (au?.logs?.length) audit.value = au.logs;
    live.value = true;
  } catch {
    live.value = false;
  }
}

/* ── 操作 ── */
function back() { router.push(FIRST_PATH); }
function toggleFs() {
  const el = document.documentElement;
  if (!document.fullscreenElement) el.requestFullscreen?.().catch(() => {});
  else document.exitFullscreen?.().catch(() => {});
}

let clockTimer = 0;
let dataTimer = 0;
onMounted(() => {
  tick();
  clockTimer = window.setInterval(tick, 1000);
  load();
  dataTimer = window.setInterval(load, 15000);
});
onBeforeUnmount(() => { clearInterval(clockTimer); clearInterval(dataTimer); });
</script>

<style scoped>
/* 暗色 NOC 主题（局部，不影响控制台暖色系） */
.scr {
  --c-bg0: #050a1c; --c-bg1: #0a1838; --c-cyan: #2fe6ff; --c-blue: #4080ff;
  --c-line: rgba(96, 150, 255, .16); --c-panel: rgba(20, 44, 96, .34);
  --c-t1: #e6f0ff; --c-t2: #9db4e6; --c-t3: #6a82b8;
  position: fixed; inset: 0; height: 100vh; width: 100vw; overflow: hidden;
  background: linear-gradient(160deg, var(--c-bg1), var(--c-bg0));
  color: var(--c-t1); display: flex; flex-direction: column;
  font-variant-numeric: tabular-nums; letter-spacing: .2px;
}

/* ── 动态背景 ── */
.scr-bg { position: absolute; inset: 0; pointer-events: none; z-index: 0; }
.scr-bg--grid {
  background-image:
    linear-gradient(rgba(96, 150, 255, .07) 1px, transparent 1px),
    linear-gradient(90deg, rgba(96, 150, 255, .07) 1px, transparent 1px);
  background-size: 46px 46px;
  -webkit-mask: radial-gradient(ellipse 80% 70% at 50% 40%, #000 40%, transparent 100%);
  mask: radial-gradient(ellipse 80% 70% at 50% 40%, #000 40%, transparent 100%);
  animation: gridDrift 26s linear infinite;
}
@keyframes gridDrift { from { background-position: 0 0; } to { background-position: 46px 46px; } }
.scr-bg--blob { width: 720px; height: 720px; border-radius: 50%; filter: blur(80px); opacity: .5; }
.scr-bg--blob.b1 { top: -260px; left: 30%; background: radial-gradient(circle, rgba(47, 230, 255, .22), transparent 65%); animation: blob1 18s ease-in-out infinite; }
.scr-bg--blob.b2 { bottom: -300px; right: 8%; background: radial-gradient(circle, rgba(64, 128, 255, .22), transparent 65%); animation: blob2 22s ease-in-out infinite; }
@keyframes blob1 { 0%, 100% { transform: translate(0, 0); } 50% { transform: translate(-60px, 40px); } }
@keyframes blob2 { 0%, 100% { transform: translate(0, 0); } 50% { transform: translate(50px, -40px); } }
.scr-bg--scan {
  background: linear-gradient(180deg, transparent, rgba(47, 230, 255, .06) 50%, transparent);
  height: 38%; animation: scan 7s linear infinite;
}
@keyframes scan { 0% { transform: translateY(-100%); } 100% { transform: translateY(330%); } }

.scr-top, .scr-grid { position: relative; z-index: 1; }

/* 顶栏 */
.scr-top {
  flex: none; height: 64px; display: flex; align-items: center; padding: 0 24px; gap: 16px;
  border-bottom: 1px solid var(--c-line);
  background: linear-gradient(180deg, rgba(47, 230, 255, .06), transparent);
}
.scr-top__l { display: flex; align-items: center; gap: 11px; width: 320px; }
.scr-mark {
  width: 34px; height: 34px; border-radius: 8px; flex: none; display: flex; align-items: center; justify-content: center;
  background: rgba(47, 230, 255, .12); border: 1px solid rgba(47, 230, 255, .35);
  box-shadow: 0 0 16px rgba(47, 230, 255, .25);
}
.scr-brand { display: flex; flex-direction: column; line-height: 1.2; }
.scr-brand b { font-size: 16px; font-weight: 700; }
.scr-brand i { font-style: normal; font-size: 11px; color: var(--c-t3); letter-spacing: .5px; }
.scr-title {
  flex: 1; text-align: center; margin: 0; font-size: 26px; font-weight: 800; letter-spacing: 4px;
}
.scr-title span {
  background: linear-gradient(90deg, #4aa8ff, #9fe9ff 25%, #ffffff 50%, #9fe9ff 75%, #4aa8ff);
  background-size: 220% 100%;
  -webkit-background-clip: text; background-clip: text; color: transparent;
  text-shadow: 0 0 28px rgba(47, 230, 255, .3);
  animation: shimmer 6s linear infinite;
}
@keyframes shimmer { from { background-position: 220% 0; } to { background-position: -20% 0; } }
.scr-top__r { width: 320px; display: flex; align-items: center; justify-content: flex-end; gap: 14px; }
.scr-clock { text-align: right; line-height: 1.15; }
.scr-clock b { font-size: 20px; font-weight: 700; letter-spacing: 1px; }
.scr-clock i { display: block; font-style: normal; font-size: 11px; color: var(--c-t3); }
.scr-live {
  display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: #36e29b; font-weight: 600;
  padding: 4px 10px; border-radius: 20px; border: 1px solid rgba(54, 226, 155, .4); background: rgba(54, 226, 155, .08);
}
.scr-live.off { color: #ffa940; border-color: rgba(255, 169, 64, .4); background: rgba(255, 169, 64, .08); }
.scr-live__dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; box-shadow: 0 0 0 0 currentColor; animation: pulse 1.6s infinite; }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(54, 226, 155, .5); } 70% { box-shadow: 0 0 0 7px rgba(54, 226, 155, 0); } 100% { box-shadow: 0 0 0 0 rgba(54, 226, 155, 0); } }
.scr-act {
  width: 34px; height: 34px; border-radius: 8px; border: 1px solid var(--c-line); background: var(--c-panel);
  color: var(--c-t2); cursor: pointer; font-size: 16px; display: flex; align-items: center; justify-content: center; transition: .15s;
}
.scr-act:hover { color: var(--c-cyan); border-color: rgba(47, 230, 255, .5); box-shadow: 0 0 12px rgba(47, 230, 255, .3); }

/* 三列栅格 */
.scr-grid { flex: 1; display: grid; grid-template-columns: 1fr 1.5fr 1fr; gap: 16px; padding: 16px 20px 20px; min-height: 0; }
.scr-col { display: flex; flex-direction: column; gap: 16px; min-height: 0; }

/* 面板 */
.panel {
  background: var(--c-panel); border: 1px solid var(--c-line); border-radius: 12px; padding: 14px 16px;
  display: flex; flex-direction: column; min-height: 0; position: relative; overflow: hidden;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, .04), 0 8px 30px rgba(0, 0, 0, .25);
  backdrop-filter: blur(2px);
}
.panel::before, .panel::after { content: ''; position: absolute; width: 14px; height: 14px; border-color: rgba(47, 230, 255, .55); z-index: 2; }
.panel::before { left: 0; top: 0; border-left: 2px solid; border-top: 2px solid; border-top-left-radius: 4px; }
.panel::after { right: 0; bottom: 0; border-right: 2px solid; border-bottom: 2px solid; border-bottom-right-radius: 4px; }
.panel--grow { flex: 1; }
.panel__h { display: flex; align-items: center; gap: 9px; font-size: 14px; font-weight: 700; color: var(--c-t1); margin-bottom: 12px; position: relative; }
/* 标题下流光 */
.panel__h::after {
  content: ''; position: absolute; left: -16px; right: -16px; bottom: -7px; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(47, 230, 255, .5), transparent);
  background-size: 50% 100%; background-repeat: no-repeat; animation: beam 4s linear infinite;
}
@keyframes beam { from { background-position: -60% 0; } to { background-position: 160% 0; } }
.panel__bar { width: 4px; height: 14px; border-radius: 2px; background: linear-gradient(180deg, var(--c-cyan), var(--c-blue)); box-shadow: 0 0 8px rgba(47, 230, 255, .6); }
.panel__sub { margin-left: auto; font-size: 11px; font-weight: 500; color: var(--c-t3); }

/* 入场动画 */
.pop { opacity: 0; animation: pop .6s cubic-bezier(.2, .8, .2, 1) forwards; animation-delay: var(--d, 0s); }
@keyframes pop { from { opacity: 0; transform: translateY(16px) scale(.99); } to { opacity: 1; transform: none; } }

/* KPI */
.kpis { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.kpi {
  background: linear-gradient(160deg, rgba(47, 230, 255, .08), rgba(64, 128, 255, .03)); border: 1px solid var(--c-line);
  border-radius: 10px; padding: 12px 14px; transition: .2s;
}
.kpi:hover { border-color: rgba(47, 230, 255, .4); box-shadow: 0 0 18px rgba(47, 230, 255, .12); }
.kpi__v { font-size: 30px; font-weight: 800; line-height: 1.1; color: #fff; text-shadow: 0 0 16px rgba(47, 230, 255, .4); }
.kpi__v small { font-size: 14px; font-weight: 500; color: var(--c-t3); margin-left: 2px; }
.kpi__l { font-size: 12px; color: var(--c-t2); margin-top: 5px; }
.kpi--danger .kpi__v { color: #ff6b6b; text-shadow: 0 0 16px rgba(255, 77, 79, .45); }

/* 判定环图 */
.donut { display: grid; grid-template-columns: 130px 1fr; align-items: center; gap: 6px; position: relative; }
.donut__svg { width: 130px; height: 130px; transform: rotate(-90deg); filter: drop-shadow(0 0 6px rgba(47, 230, 255, .25)); }
.donut__track { fill: none; stroke: rgba(96, 150, 255, .12); stroke-width: 11; }
.donut__seg { fill: none; stroke-width: 11; stroke-linecap: butt; transition: stroke-dasharray .6s; }
.donut__c { position: absolute; left: 65px; top: 50%; transform: translate(-50%, -50%); text-align: center; }
.donut__c b { display: block; font-size: 24px; font-weight: 800; color: #fff; }
.donut__c i { font-style: normal; font-size: 11px; color: var(--c-t3); }
.donut__legend { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 7px; }
.donut__legend li { display: flex; align-items: center; gap: 7px; font-size: 12.5px; }
.dot { width: 8px; height: 8px; border-radius: 2px; flex: none; }
.lg-n { color: var(--c-t2); width: 56px; }
.lg-v { color: var(--c-t1); font-weight: 600; margin-left: auto; }
.lg-p { color: var(--c-t3); width: 38px; text-align: right; }

/* 条形 */
.bars { display: flex; flex-direction: column; gap: 12px; justify-content: center; flex: 1; }
.bar { display: flex; align-items: center; gap: 10px; }
.bar__l { width: 64px; font-size: 12.5px; color: var(--c-t2); flex: none; }
.bar__track { flex: 1; height: 8px; background: rgba(96, 150, 255, .12); border-radius: 5px; overflow: hidden; }
.bar__fill { display: block; height: 100%; border-radius: 5px; background: linear-gradient(90deg, var(--c-blue), var(--c-cyan)); transition: width .6s; box-shadow: 0 0 10px rgba(47, 230, 255, .5); }
.bar__v { width: 42px; text-align: right; font-size: 12.5px; font-weight: 600; }

/* 雷达 */
.panel--radar { flex: 1.4; }
.radar { flex: 1; position: relative; display: flex; align-items: center; justify-content: center; min-height: 0; }
.radar-svg, .radar-sweep { position: absolute; aspect-ratio: 1; height: 100%; max-height: 100%; left: 50%; top: 50%; transform: translate(-50%, -50%); }
.radar-sweep {
  border-radius: 50%;
  background: conic-gradient(from 0deg, rgba(47, 230, 255, .5), rgba(47, 230, 255, .06) 50deg, transparent 110deg, transparent 360deg);
  animation: sweep 4s linear infinite;
  -webkit-mask: radial-gradient(circle, #000 0 90%, transparent 91%);
  mask: radial-gradient(circle, #000 0 90%, transparent 91%);
  filter: drop-shadow(0 0 10px rgba(47, 230, 255, .3));
}
@keyframes sweep { to { transform: translate(-50%, -50%) rotate(360deg); } }
.radar-bezel { transform-origin: 200px 200px; animation: bezelSpin 40s linear infinite; }
@keyframes bezelSpin { to { transform: rotate(-360deg); } }
.r-bezel-line { fill: none; stroke: rgba(47, 230, 255, .25); stroke-width: 1; }
.r-bezel-ticks { fill: none; stroke: rgba(47, 230, 255, .4); stroke-width: 6; stroke-dasharray: 1.5 11; }
.r-ring { fill: none; stroke: rgba(96, 150, 255, .22); stroke-width: 1; }
.r-cross { stroke: rgba(96, 150, 255, .14); stroke-width: 1; }
.r-core { fill: var(--c-cyan); filter: drop-shadow(0 0 6px var(--c-cyan)); }
.lock-line { stroke-width: 1; opacity: .28; stroke-dasharray: 3 4; }
.blip { filter: drop-shadow(0 0 6px currentColor); }
.blip-ring { fill: none; stroke-width: 1.5; }
.radar-tags { position: absolute; inset: 0; pointer-events: none; }
.rtag {
  position: absolute; transform: translate(8px, -50%); font-size: 11px; font-weight: 600; white-space: nowrap;
  text-shadow: 0 0 6px rgba(0, 0, 0, .8);
}

/* 三道防线仪表 */
.panel--lines { flex: none; }
.gauges { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.gauge { position: relative; display: flex; flex-direction: column; align-items: center; }
.gauge__svg { width: 100%; max-width: 132px; }
.gauge__track { fill: none; stroke: rgba(96, 150, 255, .14); stroke-width: 9; stroke-linecap: round; }
.gauge__val { fill: none; stroke-width: 9; stroke-linecap: round; transition: stroke-dashoffset .8s cubic-bezier(.2, .8, .2, 1); filter: drop-shadow(0 0 5px currentColor); }
.gauge__c { position: absolute; top: 44px; left: 0; right: 0; text-align: center; }
.gauge__c b { font-size: 30px; font-weight: 800; }
.gauge__tr { font-size: 14px; margin-left: 2px; vertical-align: middle; }
.gauge__n { font-size: 13px; font-weight: 600; color: var(--c-t1); margin-top: 2px; }
.gauge__tag { font-size: 11px; font-weight: 600; padding: 1px 8px; border: 1px solid; border-radius: 20px; margin-top: 4px; }

/* 实时事件滚动 */
.ticker {
  flex: 1; overflow: hidden; position: relative; min-height: 0;
  -webkit-mask: linear-gradient(180deg, transparent, #000 9%, #000 91%, transparent);
  mask: linear-gradient(180deg, transparent, #000 9%, #000 91%, transparent);
}
.ticker__roll { display: flex; flex-direction: column; gap: 9px; animation: roll 26s linear infinite; }
.ticker:hover .ticker__roll { animation-play-state: paused; }
@keyframes roll { from { transform: translateY(0); } to { transform: translateY(-50%); } }
.ev { display: flex; gap: 9px; align-items: flex-start; padding: 8px 10px; border-radius: 8px; background: rgba(96, 150, 255, .05); border-left: 2px solid var(--c-t3); }
.ev--deny { border-left-color: #ff4d4f; }
.ev--mfa { border-left-color: #ffa940; }
.ev--allow, .ev--ok { border-left-color: #36e29b; }
.ev--fail { border-left-color: #ff4d4f; }
.ev__t { font-size: 11px; color: var(--c-t3); padding-top: 2px; width: 52px; flex: none; }
.ev__body { display: flex; flex-direction: column; gap: 2px; min-width: 0; flex: 1; }
.ev__top { display: flex; align-items: center; gap: 8px; }
.ev__top b { font-size: 13px; color: var(--c-t1); }
.ev__vd { font-size: 11px; color: var(--c-t2); margin-left: auto; }
.ev--deny .ev__vd, .ev--fail .ev__vd { color: #ff6b6b; }
.ev--mfa .ev__vd { color: #ffc069; }
.ev--allow .ev__vd, .ev--ok .ev__vd { color: #36e29b; }
.ev__sub { font-size: 11.5px; color: var(--c-t3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* TOP 地域 */
.panel--regions { flex: none; }
.regions { display: flex; flex-direction: column; gap: 11px; }
.rg { display: flex; align-items: center; gap: 10px; }
.rg__rk { width: 18px; height: 18px; border-radius: 5px; flex: none; font-size: 11px; font-weight: 700; display: flex; align-items: center; justify-content: center; background: rgba(96, 150, 255, .15); color: var(--c-t2); }
.rg__rk.hot { background: linear-gradient(135deg, var(--c-cyan), var(--c-blue)); color: #06122e; box-shadow: 0 0 10px rgba(47, 230, 255, .4); }
.rg__n { width: 84px; font-size: 13px; color: var(--c-t1); flex: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rg__track { flex: 1; height: 8px; background: rgba(96, 150, 255, .12); border-radius: 5px; overflow: hidden; }
.rg__fill { display: block; height: 100%; border-radius: 5px; background: linear-gradient(90deg, var(--c-blue), var(--c-cyan)); transition: width .6s; box-shadow: 0 0 10px rgba(47, 230, 255, .5); }
.rg__v { width: 34px; text-align: right; font-size: 13px; font-weight: 600; }
.regions__empty { text-align: center; color: var(--c-t3); font-size: 13px; padding: 20px 0; }
</style>
