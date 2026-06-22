<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">策略仿真器<LiveBadge :live="live" live-text="控制面引擎" mock-text="本地引擎（降级）" /></h1>
        <div class="zl-page__sub">访问门预演：假设已通过登录门（auth_strength 由〈登录流仿真〉签发）· 输入（主体, 资源, 环境）→ 三执行点判定（ZL-FR-108 / ZL-FR-104）</div>
      </div>
      <router-link to="/policy/login-sim" class="sim-xlink">← 登录门 · 登录流仿真</router-link>
    </div>

    <!-- 预置场景 -->
    <div class="sim-presets">
      <span class="sim-presets__label">预置场景：</span>
      <button v-for="p in presets" :key="p.label" class="sim-chip" @click="apply(p)">{{ p.label }}</button>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1fr 1.5fr;">
      <!-- 输入 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">仿真输入</div>

        <div class="sim-f">
          <label>主体</label>
          <a-select v-model="subjectKey" size="small">
            <a-option v-for="s in subjects" :key="s.key" :value="s.key">{{ s.label }}</a-option>
          </a-select>
          <div class="sim-expand data" v-if="subject">展开 → {{ subject.memberOf.join(' · ') }}</div>
        </div>

        <div class="sim-f">
          <label>资源</label>
          <a-select v-model="resourceKey" size="small">
            <a-option v-for="r in simResources" :key="r.key" :value="r.key">{{ r.name }}（{{ r.key }}）</a-option>
          </a-select>
        </div>

        <div class="sim-f">
          <label>认证与时间</label>
          <div class="sim-ctx">
            <div class="sim-ctx__row" v-for="c in authItems" :key="c.k">
              <span>{{ c.label }}</span>
              <a-switch v-model="ctx[c.k]" size="small" />
            </div>
          </div>
        </div>

        <div class="sim-f">
          <label>来源网络</label>
          <a-select v-model="ctx.network" size="small">
            <a-option v-for="[v, l] in networks" :key="v" :value="v">{{ l }}</a-option>
          </a-select>
        </div>

        <div class="sim-f">
          <label>设备态势（→ 信任分）</label>
          <div class="sim-ctx">
            <div class="sim-ctx__row" v-for="c in deviceItems" :key="c.k">
              <span>{{ c.label }}</span>
              <a-switch v-model="ctx[c.k]" size="small" />
            </div>
          </div>
        </div>
      </div>

      <!-- 结果 -->
      <div style="display:flex;flex-direction:column;gap:16px">
        <!-- 判定横幅（allow / step-up / deny 三态） -->
        <div class="zl-card zl-card__pad sim-verdict" :class="result.decision">
          <span class="sim-verdict__glyph">{{ { allow: '✓', 'step-up': '!', deny: '✕' }[result.decision] }}</span>
          <div>
            <div class="sim-verdict__t">{{ { allow: '放行 ALLOW', 'step-up': '二次鉴权 STEP-UP', deny: '拒绝 DENY' }[result.decision] }}</div>
            <div class="sim-verdict__d">{{ result.reason }}</div>
          </div>
          <span v-if="result.policy" class="sim-pol data">{{ result.policy }}</span>
        </div>

        <!-- 信任 / 风险评分（资质自适应核心） -->
        <div class="zl-card zl-card__pad" v-if="live">
          <div class="zl-card__title" style="margin-bottom:12px">资质自适应评分</div>
          <div class="sim-gauge">
            <div class="sim-gauge__head"><span>设备信任分</span><b class="data">{{ result.trust }}/100</b></div>
            <div class="sim-bar"><div class="sim-bar__fill" :class="result.trust>=80?'ok':result.trust>=50?'warn':'bad'" :style="{width: result.trust + '%'}" /></div>
          </div>
          <div class="sim-gauge">
            <div class="sim-gauge__head"><span>会话风险分</span><b class="data">{{ result.risk }}/100</b></div>
            <div class="sim-bar"><div class="sim-bar__fill" :class="result.risk<=30?'ok':result.risk<=60?'warn':'bad'" :style="{width: result.risk + '%'}" /></div>
          </div>
          <div class="sim-gauge__note data">信任分由设备态势算出；风险分综合信任/网络/MFA/工时。风险超策略上限或资源高敏 → STEP-UP。</div>
        </div>

        <!-- 求值轨迹 -->
        <div class="zl-card zl-card__pad">
          <div class="zl-card__title" style="margin-bottom:10px">求值轨迹（deny &gt; allow &gt; 默认拒绝）</div>
          <div class="sim-trace">
            <div v-for="(t, i) in result.trace" :key="i" class="sim-trace__row" :class="t.tone">
              <span class="sim-trace__g">{{ traceGlyph(t.tone) }}</span>
              <span v-html="t.text" />
            </div>
          </div>
        </div>

        <!-- 三执行点 -->
        <div class="zl-card zl-card__pad">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
            <div class="zl-card__title" style="margin:0">三执行点编译预览</div>
            <span class="zl-badge" :class="result.consistent ? 'zl-badge--ok' : 'zl-badge--danger'">
              {{ result.consistent ? '判定一致 ✓ ZL-FR-104' : '判定不一致 ⚠' }}
            </span>
          </div>
          <div class="sim-points">
            <div v-for="pt in result.points" :key="pt.name" class="sim-point" :class="{ na: !pt.applicable }">
              <div class="sim-point__head">
                <span class="zl-mode-pill" :class="'zl-mode--' + pt.mode">{{ pt.name }}</span>
                <span v-if="pt.applicable" class="zl-badge" :class="result.decision === 'allow' ? 'zl-badge--ok' : result.decision === 'step-up' ? 'zl-badge--warn' : 'zl-badge--danger'">
                  {{ { allow: 'ALLOW', 'step-up': 'STEP-UP', deny: 'DENY' }[result.decision] }}
                </span>
                <span v-else class="zl-badge zl-badge--idle">不适用</span>
              </div>
              <div class="sim-point__body data">{{ pt.detail }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { simSubjects as subjects, simResources, evaluate, netmapState } from '@/policy-store';

const subjectKey = ref('zhang.wei');
const resourceKey = ref('app:gitlab');
const ctx = reactive({
  mfa: true, posture: true, workhours: true,
  network: 'office', diskEncrypted: true, osCurrent: true, edr: true, jailbroken: false
});
const authItems = [
  { k: 'mfa' as const, label: '已完成 MFA（auth_strength）' },
  { k: 'posture' as const, label: '终端基线通过（posture）' },
  { k: 'workhours' as const, label: '工作时间内（time）' }
];
const deviceItems = [
  { k: 'diskEncrypted' as const, label: '磁盘加密' },
  { k: 'osCurrent' as const, label: '系统版本达标' },
  { k: 'edr' as const, label: 'EDR 安全软件在位' },
  { k: 'jailbroken' as const, label: '越狱 / Root（风险）' }
];
const networks: [string, string][] = [['office', '办公网 · 可信'], ['vpn', 'VPN'], ['home', '家庭网'], ['untrusted', '不可信 / 公网']];

const HEALTHY = { mfa: true, posture: true, workhours: true, network: 'office', diskEncrypted: true, osCurrent: true, edr: true, jailbroken: false };
const presets = [
  { label: '健康设备 · 办公网 → GitLab（ALLOW）', s: 'zhang.wei', r: 'app:gitlab', c: { ...HEALTHY } },
  { label: '不可信网络 → 风险触发 STEP-UP', s: 'zhang.wei', r: 'app:gitlab', c: { ...HEALTHY, network: 'untrusted' } },
  { label: '越狱设备 → 信任跌破阈值 DENY', s: 'zhang.wei', r: 'app:gitlab', c: { ...HEALTHY, jailbroken: true } },
  { label: '研发 → 核心数据库（高敏 STEP-UP）', s: 'zhang.wei', r: 'service:db.corp:5432', c: { ...HEALTHY } },
  { label: 'BYOD → 财务系统（显式拒绝）', s: 'byod.pad', r: 'app:finance', c: { ...HEALTHY } }
];
const apply = (p: any) => { subjectKey.value = p.s; resourceKey.value = p.r; Object.assign(ctx, p.c); };

// 求值轨迹图标（trace 来自后端为 any[]，用 Record 索引避免隐式 any 报错）。
const traceGlyph = (tone: string) => (({ ok: '✓', skip: '○', fail: '✕', info: 'ⅰ', warn: '!' } as Record<string, string>)[tone] ?? '·');

const subject = computed(() => subjects.find((s) => s.key === subjectKey.value)!);
const resource = computed(() => simResources.find((r) => r.key === resourceKey.value)!);

/* ── 核心求值：控制面 /api/policy/simulate（与真实下发同一后端 netmap 引擎，
   消除前后端双引擎漂移，ZL-FR-108 一致性的真义）；控制面不可达时降级本地 evaluate。 ── */
const live = ref(false);
const core = ref<{ decision: string; matched: string; reason: string; trust: number; risk: number; trace: any[]; effModes: string[] }>(
  { decision: 'deny', matched: '', reason: '', trust: 0, risk: 0, trace: [], effModes: ['ssl'] }
);
async function loadSimulate() {
  const s = subject.value, r = resource.value;
  try {
    const res = await fetch('/ctl/api/policy/simulate', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        memberOf: s.memberOf, resource: r.key, modes: r.modes, stepup: !!r.stepup,
        ctx: {
          mfa: ctx.mfa, posture: ctx.posture, workhours: ctx.workhours, network: ctx.network, nowMin: -1,
          diskEncrypted: ctx.diskEncrypted, osCurrent: ctx.osCurrent, edr: ctx.edr, jailbroken: ctx.jailbroken
        }
      })
    });
    if (res.ok) { core.value = await res.json(); live.value = true; return; }
  } catch { /* 控制面不可达，降级 */ }
  live.value = false;
  const v = evaluate(s, r, ctx); // 降级本地引擎（与后端同语义，无信任/风险维度）
  core.value = { decision: v.decision, matched: v.matched, reason: v.reason, trust: 0, risk: 0, trace: v.trace, effModes: v.effModes };
}
onMounted(loadSimulate);
watch([subjectKey, resourceKey, ctx], loadSimulate, { deep: true });

const result = computed(() => {
  const s = subject.value, r = resource.value;
  const decision = core.value.decision, matched = core.value.matched, reason = core.value.reason, trace = core.value.trace, effModes = core.value.effModes;
  const allowed = decision !== 'deny'; // allow 或 step-up 均为放行（step-up 需二次鉴权）

  /* ── 编译到三执行点 ── */
  const isSite = s.kind === 'site' || r.type === 'subnet';

  const points = [
    {
      name: 'SSL', mode: 'ssl',
      applicable: s.kind === 'user' && (effModes.includes('ssl') || !allowed) && r.type !== 'subnet',
      detail: s.kind !== 'user' || r.type === 'subnet'
        ? '站点/子网资源不经代理'
        : allowed && effModes.includes('ssl')
          ? `授权表 + (${s.key}, ${s.device}) → ${r.key.split(':').slice(1).join(':')} · SPA 放行 zl-gw-hq-01`
          : allowed
            ? `本资源锁定 ${effModes.join('/')} 模式 · 授权表无此行（≠ 不一致，模式不适用）`
            : `授权表无匹配行 · SPA 不放行 → DENY`
    },
    {
      name: 'Mesh', mode: 'mesh',
      applicable: s.kind === 'user' && (effModes.includes('mesh') || !allowed) && r.type !== 'subnet',
      detail: s.kind !== 'user' || r.type === 'subnet'
        ? '站点互联不走端侧 netmap'
        : allowed && effModes.includes('mesh')
          ? `netmap + ${s.device} → ${r.key.split(':').slice(1).join(':')} ACCEPT · v218 下发 ≤60s`
          : allowed
            ? `本资源锁定 ${effModes.join('/')} 模式 · netmap 不含该路由（模式不适用）`
            : `netmap 无该目的 · 包过滤缺省 DROP → DENY`
    },
    {
      name: 'IPSEC', mode: 'ipsec',
      applicable: isSite,
      detail: isSite
        ? allowed
          ? `selector 10.20.0.0/16 ↔ 10.8.0.0/16 · SA: tun-hq-sh · 站点粒度`
          : `无匹配 selector → 不建 SA`
        : '用户级主体不在本执行点求值（站点/子网粒度）；与用户级策略冲突时取交集，不放大权限（ZL-FR-107）'
    }
  ];

  return { decision, allowed, policy: matched, reason, trust: core.value.trust, risk: core.value.risk, trace, points, consistent: true, netmapV: netmapState.version };
});
</script>

<style scoped>
.zl-grid > * { min-width: 0; }
.sim-xlink { flex: none; font-size: 12px; font-weight: 600; color: var(--accent-2); text-decoration: none; }
.sim-xlink:hover { text-decoration: underline; }
.sim-presets { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.sim-presets__label { font-size: 12px; color: var(--ink-3); }
.sim-chip {
  border: 1px solid var(--line-2); background: var(--surface); color: var(--ink-2); cursor: pointer;
  border-radius: var(--r-pill); padding: 5px 13px; font-size: 12px; font-weight: 600; transition: all .15s;
}
.sim-chip:hover { border-color: var(--accent-line); color: var(--accent-2); background: var(--accent-soft); }

.sim-f { margin-top: 14px; }
.sim-f > label { display: block; font-size: 11.5px; font-weight: 600; color: var(--ink-2); margin-bottom: 6px; }
.sim-f :deep(.arco-select) { width: 100%; }
.sim-expand { font-size: 11px; color: var(--ink-3); margin-top: 6px; line-height: 1.5; }
.sim-ctx { border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; }
.sim-ctx__row {
  display: flex; align-items: center; justify-content: space-between; padding: 9px 12px;
  font-size: 12.5px; color: var(--ink-2);
}
.sim-ctx__row + .sim-ctx__row { border-top: 1px solid var(--line); }

.sim-verdict { display: flex; align-items: center; gap: 14px; }
.sim-verdict.allow { border-color: var(--ok); }
.sim-verdict.step-up { border-color: var(--warn); background: var(--warn-soft); }
.sim-verdict.deny { border-color: var(--danger); background: var(--danger-soft); }
.sim-verdict__glyph {
  width: 38px; height: 38px; border-radius: 50%; display: grid; place-items: center; flex: none;
  font-size: 18px; font-weight: 800;
}
.sim-verdict.allow .sim-verdict__glyph { background: var(--ok-soft); color: var(--ok); }
.sim-verdict.step-up .sim-verdict__glyph { background: var(--warn); color: #fff; }
.sim-verdict.deny .sim-verdict__glyph { background: var(--danger); color: #fff; }

/* 信任/风险评分 */
.sim-gauge { margin-bottom: 12px; }
.sim-gauge:last-of-type { margin-bottom: 8px; }
.sim-gauge__head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 5px; font-size: 12.5px; color: var(--ink-2); }
.sim-gauge__head b { font-size: 14px; color: var(--ink); }
.sim-bar { height: 8px; border-radius: 4px; background: var(--surface-2); overflow: hidden; }
.sim-bar__fill { height: 100%; border-radius: 4px; transition: width .35s; }
.sim-bar__fill.ok { background: var(--ok); } .sim-bar__fill.warn { background: var(--warn); } .sim-bar__fill.bad { background: var(--danger); }
.sim-gauge__note { font-size: 10.5px; color: var(--ink-3); line-height: 1.5; margin-top: 8px; }
.sim-verdict__t { font-size: 15px; font-weight: 750; color: var(--ink); }
.sim-verdict__d { font-size: 12.5px; color: var(--ink-2); margin-top: 2px; }
.sim-pol { margin-left: auto; font-size: 12px; color: var(--accent-2); background: var(--accent-soft); border-radius: var(--r-pill); padding: 4px 12px; }

.sim-trace { display: flex; flex-direction: column; gap: 7px; }
.sim-trace__row { display: flex; gap: 9px; font-size: 12.5px; color: var(--ink-2); line-height: 1.55; }
.sim-trace__g { width: 17px; height: 17px; border-radius: 50%; flex: none; display: grid; place-items: center; font-size: 10px; font-weight: 800; margin-top: 1px; background: var(--surface-3); color: var(--ink-3); }
.sim-trace__row.ok .sim-trace__g { background: var(--ok-soft); color: var(--ok); }
.sim-trace__row.fail .sim-trace__g { background: var(--danger-soft); color: var(--danger); }
.sim-trace__row.warn .sim-trace__g { background: var(--warn-soft); color: var(--warn); }
.sim-trace__row.info .sim-trace__g { background: var(--accent-soft); color: var(--accent-2); }
.sim-trace__row :deep(b) { color: var(--ink); font-weight: 650; }

.sim-points { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.sim-point { border: 1px solid var(--line); border-radius: var(--r-md); padding: 12px 14px; min-width: 0; }
.sim-point.na { opacity: .62; border-style: dashed; }
.sim-point__head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
.sim-point__body { font-size: 11.5px; color: var(--ink-2); line-height: 1.6; word-break: break-all; white-space: normal; }
</style>
