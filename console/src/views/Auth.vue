<template>
  <div class="bd-page">
    <div class="bd-page__head">
      <div>
        <div class="bd-page__title">认证源接入</div>
        <div class="bd-page__sub">统一身份源 · 自适应认证：身份 × 终端 × 行为动态定级</div>
      </div>
      <div class="bd-head__right">
        <a-tag :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连 baidi-control' : '降级演示' }}</a-tag>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="bd-tabs">
      <span class="bd-tab" :class="{ on: tab === 'source' }" @click="tab = 'source'">认证源</span>
      <span class="bd-tab" :class="{ on: tab === 'rule' }" @click="tab = 'rule'">自适应认证规则</span>
    </div>

    <!-- ============ 认证源 ============ -->
    <div v-show="tab === 'source'">
      <div class="bd-srctoolbar">
        <div class="bd-srctoolbar__sub">
          已接入 <b>{{ sources.length }}</b> 个身份源 · 纳管 <b>{{ totalUsers.toLocaleString() }}</b> 名访问者
        </div>
        <button class="bd-btn" @click="addSource"><icon-plus />接入认证源</button>
      </div>

      <div class="bd-srcgrid">
        <div v-for="s in sources" :key="s.key" class="bd-card bd-srccard">
          <div class="bd-srccard__top">
            <span class="bd-srcicon" :style="srcIconStyle(s.type)">
              <component :is="srcIcon(s.type)" />
            </span>
            <div class="bd-srccard__id">
              <div class="bd-srccard__name">
                {{ s.name }}
                <span v-if="s.primary" class="bd-primarytag"><icon-star-fill />主认证</span>
              </div>
              <span class="bd-tg" :style="tagStyle(typeColor(s.type))">{{ typeLabel(s.type) }}</span>
            </div>
            <span class="bd-st bd-srccard__st">
              <span class="d" :style="{ background: statusColor(s.status) }" />{{ statusLabel(s.status) }}
            </span>
          </div>
          <div class="bd-srccard__foot">
            <div class="bd-srccard__kv"><span>纳管用户</span><b>{{ s.users.toLocaleString() }}</b></div>
            <div class="bd-srccard__acts">
              <span class="bd-link bd-link--grey">详情</span>
              <span class="bd-link">同步</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ============ 自适应认证规则（P6 可视化规则构建器）============ -->
    <div v-show="tab === 'rule'" class="bd-rulewrap">
      <div class="bd-rulemain">
        <div class="bd-ruleintro bd-card">
          <icon-safe class="bd-ruleintro__ic" />
          <div>
            按 <b>优先级从上至下</b>逐条求值，命中第一条规则即采用其动作。拖拽手柄可调整优先级；
            条件以「身份 × 终端 × 行为」信号组合，替代手写 JSON 编排。
          </div>
        </div>

        <div
          v-for="(r, ri) in rules"
          :key="r.id"
          class="bd-card bd-rule"
          :class="{ off: !r.enabled }"
        >
          <span class="bd-rule__handle" title="拖拽调整优先级"><icon-drag-dot-vertical /></span>
          <span class="bd-rule__pri">{{ ri + 1 }}</span>

          <div class="bd-rule__body">
            <div class="bd-rule__head">
              <span class="bd-rule__name">{{ r.name }}</span>
              <a-switch v-model="r.enabled" size="small" class="bd-rule__sw" />
            </div>

            <div class="bd-rule__flow">
              <!-- IF 区 -->
              <div class="bd-if">
                <span class="bd-clause">IF</span>
                <template v-for="(c, ci) in r.conditions" :key="ci">
                  <span class="bd-chip">
                    {{ condText(c) }}
                    <icon-close class="bd-chip__x" @click="removeCond(r, ci)" />
                  </span>
                  <span
                    v-if="ci < r.conditions.length - 1"
                    class="bd-logic"
                    :class="r.logic === 'AND' ? 'and' : 'or'"
                    @click="r.logic = r.logic === 'AND' ? 'OR' : 'AND'"
                  >{{ r.logic }}</span>
                </template>
                <button class="bd-addcond" @click="addCond(r)"><icon-plus-circle />条件</button>
              </div>

              <icon-right class="bd-flow__arrow" />

              <!-- THEN 区 -->
              <div class="bd-then">
                <span class="bd-clause">THEN</span>
                <div class="bd-actionwrap" :class="evalClass(r.action)">
                  <span class="bd-actiondot" />
                  <a-select v-model="r.action" size="small" class="bd-actionsel">
                    <a-option v-for="a in ACTIONS" :key="a.value" :value="a.value">{{ a.label }}</a-option>
                  </a-select>
                </div>
              </div>
            </div>
          </div>
        </div>

        <button class="bd-btn--ghost bd-btn bd-addrule" @click="addRule"><icon-plus />新增规则</button>
      </div>

      <!-- 规则求值预览 -->
      <div class="bd-rulepreview">
        <div class="bd-card bd-preview">
          <div class="bd-section-title">规则求值预览</div>
          <div class="bd-preview__sub">勾选模拟上下文，实时按优先级取第一条命中规则</div>

          <div class="bd-ctxlist">
            <label v-for="cx in CTX" :key="cx.field" class="bd-ctxrow">
              <a-checkbox v-model="ctx[cx.field]" />
              <span class="bd-ctxrow__t">{{ cx.label }}</span>
              <span class="bd-ctxrow__d">{{ cx.detail }}</span>
            </label>
          </div>

          <div class="bd-evalout" :class="evalResult.action ? evalClass(evalResult.action) : 'none'">
            <template v-if="evalResult.rule">
              <div class="bd-evalout__l">命中规则</div>
              <div class="bd-evalout__rule">{{ evalResult.rule.name }}</div>
              <div class="bd-evalout__arrow"><icon-arrow-down /></div>
              <div class="bd-evalout__l">最终动作</div>
              <div class="bd-evalout__act">{{ actionLabel(evalResult.action!) }}</div>
            </template>
            <template v-else>
              <div class="bd-evalout__l">无规则命中</div>
              <div class="bd-evalout__rule muted">采用默认动作</div>
              <div class="bd-evalout__arrow"><icon-arrow-down /></div>
              <div class="bd-evalout__l">最终动作</div>
              <div class="bd-evalout__act muted">放行（默认）</div>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type AuthSrcBundle, type AuthSource, type AdaptiveRule, type RuleCond } from '@/lib/api';

type SrcType = AuthSource['type'];
type CondField = RuleCond['field'];
type Action = AdaptiveRule['action'];

const tab = ref<'source' | 'rule'>('source');
const live = ref(false);

/* ── 内置 mock（结构同后端 AuthSrcBundle）── */
const MOCK_SOURCES: AuthSource[] = [
  { key: 'local', name: '本地账号库', type: 'local', status: 'online', users: 312, primary: true },
  { key: 'ad', name: '总部 AD 域', type: 'ad', status: 'online', users: 1846, primary: false },
  { key: 'ldap', name: 'OpenLDAP 目录', type: 'ldap', status: 'online', users: 524, primary: false },
  { key: 'radius', name: 'RADIUS 接入', type: 'radius', status: 'warning', users: 96, primary: false },
  { key: 'oauth', name: '企业微信 OAuth', type: 'oauth', status: 'online', users: 738, primary: false },
  { key: 'sms', name: '短信验证码', type: 'sms', status: 'online', users: 0, primary: false },
  { key: 'cert', name: 'USB-Key 证书', type: 'cert', status: 'warning', users: 64, primary: false }
];
const MOCK_RULES: AdaptiveRule[] = [
  {
    id: 'r1', name: '弱口令 + 异地登录 → 阻断', enabled: true, logic: 'AND', action: 'block', priority: 1,
    conditions: [
      { field: 'weakPwd', op: 'is', value: 'true' },
      { field: 'geoAnomaly', op: 'is', value: 'true' }
    ]
  },
  {
    id: 'r2', name: '高风险分或未授信终端 → 升级认证', enabled: true, logic: 'OR', action: 'stepup', priority: 2,
    conditions: [
      { field: 'riskScore', op: 'gt', value: '70' },
      { field: 'untrustedDevice', op: 'is', value: 'true' }
    ]
  },
  {
    id: 'r3', name: '新设备或异常时段 → 二次认证', enabled: true, logic: 'OR', action: 'mfa', priority: 3,
    conditions: [
      { field: 'newDevice', op: 'is', value: 'true' },
      { field: 'offHours', op: 'in', value: '22:00-06:00' }
    ]
  },
  {
    id: 'r4', name: '低风险授信终端 → 直接放行', enabled: true, logic: 'AND', action: 'allow', priority: 4,
    conditions: [
      { field: 'riskScore', op: 'gt', value: '0' }
    ]
  }
];

const sources = ref<AuthSource[]>(MOCK_SOURCES);
const rules = ref<AdaptiveRule[]>(MOCK_RULES);

const totalUsers = computed(() => sources.value.reduce((s, x) => s + x.users, 0));

/* ── 认证源映射 ── */
const TYPE_LABEL: Record<SrcType, string> = {
  local: '本地账号', ad: 'AD 域', ldap: 'LDAP', radius: 'RADIUS', oauth: 'OAuth', sms: '短信', cert: '证书'
};
const TYPE_COLOR: Record<SrcType, string> = {
  local: '#165DFF', ad: '#165DFF', ldap: '#722ED1', radius: '#FF7D00', oauth: '#00B42A', sms: '#FF7D00', cert: '#722ED1'
};
const TYPE_ICON: Record<SrcType, string> = {
  local: 'icon-user', ad: 'icon-storage', ldap: 'icon-mind-mapping', radius: 'icon-wifi',
  oauth: 'icon-link', sms: 'icon-message', cert: 'icon-lock'
};
function typeLabel(t: SrcType) { return TYPE_LABEL[t]; }
function typeColor(t: SrcType) { return TYPE_COLOR[t]; }
function srcIcon(t: SrcType) { return TYPE_ICON[t]; }
function srcIconStyle(t: SrcType) {
  const c = TYPE_COLOR[t];
  return { color: c, background: c + '14' };
}
function statusColor(status: string) {
  return status === 'online' ? 'var(--bd-success)' : status === 'warning' ? 'var(--bd-warning)' : 'var(--bd-danger)';
}
function statusLabel(status: string) {
  return status === 'online' ? '在线' : status === 'warning' ? '告警' : '离线';
}
function tagStyle(color: string) { return { color, background: color + '14' }; }

/* ── 规则：动作 ── */
const ACTIONS: { value: Action; label: string }[] = [
  { value: 'allow', label: '放行' },
  { value: 'mfa', label: '二次认证（MFA）' },
  { value: 'stepup', label: '升级认证强度' },
  { value: 'block', label: '阻断' }
];
const ACTION_LABEL: Record<Action, string> = {
  allow: '放行', mfa: '二次认证（MFA）', stepup: '升级认证强度', block: '阻断'
};
function actionLabel(a: Action) { return ACTION_LABEL[a]; }
function evalClass(a: Action) {
  return a === 'block' ? 'block' : a === 'allow' ? 'allow' : 'warn';
}

/* ── 规则：条件文案 ── */
const FIELD_LABEL: Record<CondField, string> = {
  weakPwd: '弱口令', geoAnomaly: '异地登录', offHours: '异常时段',
  riskScore: '风险分', untrustedDevice: '未授信终端', newDevice: '新设备'
};
const OP_SYMBOL: Record<RuleCond['op'], string> = { is: '=', gt: '>', in: '∈' };
function condText(c: RuleCond): string {
  const f = FIELD_LABEL[c.field];
  // 布尔类信号直接展示名称
  if (c.op === 'is' && (c.value === 'true' || c.value === 'false')) {
    return c.value === 'true' ? f : `非${f}`;
  }
  return `${f} ${OP_SYMBOL[c.op]} ${c.value}`;
}

function removeCond(r: AdaptiveRule, idx: number) {
  if (r.conditions.length <= 1) { Message.warning('每条规则至少保留一个条件'); return; }
  r.conditions.splice(idx, 1);
}
function addCond(r: AdaptiveRule) {
  r.conditions.push({ field: 'riskScore', op: 'gt', value: '60' });
}
function addRule() {
  const n = rules.value.length + 1;
  rules.value.push({
    id: 'r' + Date.now(), name: `新增规则 ${n}`, enabled: true, logic: 'AND', action: 'mfa', priority: n,
    conditions: [{ field: 'newDevice', op: 'is', value: 'true' }]
  });
}
function addSource() { Message.info('接入认证源向导（演示）'); }

/* ── 规则求值预览 ── */
type CtxKey = CondField | 'highRisk';
const CTX: { field: CtxKey; label: string; detail: string }[] = [
  { field: 'weakPwd', label: '弱口令', detail: '口令命中弱密码字典' },
  { field: 'geoAnomaly', label: '异地登录', detail: '登录地与常用地不符' },
  { field: 'untrustedDevice', label: '未授信终端', detail: '设备未纳管或未绑定' },
  { field: 'newDevice', label: '新设备', detail: '首次出现的设备指纹' },
  { field: 'offHours', label: '异常时段', detail: '处于 22:00-06:00 时段' },
  { field: 'highRisk', label: '风险分偏高', detail: '综合风险分 > 70' }
];

const ctx = reactive<Record<string, boolean>>({
  weakPwd: false, geoAnomaly: false, untrustedDevice: false, newDevice: false, offHours: false, highRisk: false
});

/** 单条件求值：把模拟上下文映射到条件命中与否 */
function condHit(c: RuleCond): boolean {
  switch (c.field) {
    case 'weakPwd': return ctx.weakPwd;
    case 'geoAnomaly': return ctx.geoAnomaly;
    case 'untrustedDevice': return ctx.untrustedDevice;
    case 'newDevice': return ctx.newDevice;
    case 'offHours': return ctx.offHours;
    case 'riskScore': {
      // gt：上下文风险分高视为 ~85，否则 ~20
      const score = ctx.highRisk ? 85 : 20;
      return score > Number(c.value);
    }
    default: return false;
  }
}
function ruleHit(r: AdaptiveRule): boolean {
  if (!r.enabled) return false;
  return r.logic === 'AND'
    ? r.conditions.every(condHit)
    : r.conditions.some(condHit);
}
const evalResult = computed<{ rule: AdaptiveRule | null; action: Action | null }>(() => {
  for (const r of rules.value) {
    if (ruleHit(r)) return { rule: r, action: r.action };
  }
  return { rule: null, action: null };
});

/* ── 拉取 ── */
onMounted(async () => {
  try {
    const b = await api<AuthSrcBundle>('/authsrc');
    sources.value = b.sources;
    rules.value = b.rules;
    live.value = true;
  } catch { live.value = false; }
});
</script>

<style scoped>
/* tabs */
.bd-tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.bd-tab { font-size: 13px; color: var(--bd-t2); padding: 7px 14px; border-radius: 7px; cursor: pointer; }
.bd-tab:hover { background: var(--bd-fill-2); }
.bd-tab.on { color: var(--bd-primary); font-weight: 600; background: var(--bd-primary-1); }

.bd-section-title { font-size: 15px; font-weight: 600; color: var(--bd-t1); margin-bottom: 4px; }

/* ── 认证源 ── */
.bd-srctoolbar { display: flex; align-items: center; margin-bottom: 16px; }
.bd-srctoolbar__sub { font-size: 13px; color: var(--bd-t3); }
.bd-srctoolbar__sub b { color: var(--bd-t1); font-weight: 600; }
.bd-srctoolbar .bd-btn { margin-left: auto; }

.bd-srcgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(312px, 1fr)); gap: 16px; }
.bd-srccard { padding: 16px 18px; transition: border-color .15s, box-shadow .15s; }
.bd-srccard:hover { border-color: var(--bd-primary-b); box-shadow: 0 4px 14px rgba(22, 93, 255, .06); }
.bd-srccard__top { display: flex; align-items: flex-start; gap: 12px; }
.bd-srcicon { width: 40px; height: 40px; border-radius: 10px; flex: none; display: inline-flex; align-items: center; justify-content: center; font-size: 20px; }
.bd-srccard__id { flex: 1; min-width: 0; }
.bd-srccard__name { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.bd-primarytag { display: inline-flex; align-items: center; gap: 3px; font-size: 11px; font-weight: 500; color: var(--bd-warning); background: var(--bd-tag-gold-bg); padding: 1px 7px; border-radius: 10px; }
.bd-srccard__st { margin-left: auto; flex: none; }
.bd-srccard__foot { display: flex; align-items: center; margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--bd-fill-2); }
.bd-srccard__kv { display: flex; flex-direction: column; gap: 2px; }
.bd-srccard__kv span { font-size: 11.5px; color: var(--bd-t3); }
.bd-srccard__kv b { font-size: 18px; font-weight: 700; color: var(--bd-t1); line-height: 1; }
.bd-srccard__acts { margin-left: auto; display: flex; gap: 14px; font-size: 12.5px; }

/* ── 自适应认证规则 ── */
.bd-rulewrap { display: flex; gap: 16px; align-items: flex-start; }
.bd-rulemain { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 14px; }
.bd-rulepreview { width: 316px; flex: none; position: sticky; top: 18px; }

.bd-ruleintro { display: flex; gap: 12px; padding: 14px 16px; font-size: 13px; line-height: 1.7; color: var(--bd-t2); background: var(--bd-primary-1); border-color: var(--bd-primary-b); }
.bd-ruleintro__ic { color: var(--bd-primary); font-size: 18px; flex: none; margin-top: 2px; }
.bd-ruleintro b { color: var(--bd-t1); font-weight: 600; }

/* 规则行 */
.bd-rule { display: flex; align-items: stretch; padding: 14px 16px 14px 8px; gap: 10px; transition: opacity .15s; }
.bd-rule.off { opacity: .58; }
.bd-rule__handle { display: flex; align-items: center; color: var(--bd-t4); cursor: grab; font-size: 16px; }
.bd-rule__handle:active { cursor: grabbing; }
.bd-rule__pri { width: 22px; height: 22px; border-radius: 6px; flex: none; align-self: center; display: inline-flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-rule__body { flex: 1; min-width: 0; }
.bd-rule__head { display: flex; align-items: center; margin-bottom: 12px; }
.bd-rule__name { font-size: 13.5px; font-weight: 600; color: var(--bd-t1); }
.bd-rule__sw { margin-left: auto; }

.bd-rule__flow { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.bd-clause { font-size: 11px; font-weight: 700; letter-spacing: .5px; color: var(--bd-t3); font-family: ui-monospace, monospace; }

.bd-if { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; flex: 1; min-width: 0; }
.bd-chip { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--bd-t1); background: #fff; border: 1px solid var(--bd-border); border-radius: 14px; padding: 4px 10px; font-weight: 500; }
.bd-chip__x { font-size: 11px; color: var(--bd-t4); cursor: pointer; }
.bd-chip__x:hover { color: var(--bd-danger); }
.bd-logic { font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 12px; cursor: pointer; user-select: none; transition: background .12s; }
.bd-logic.and { color: var(--bd-primary); background: var(--bd-primary-1); }
.bd-logic.or { color: var(--bd-purple); background: var(--bd-tag-purple-bg); }
.bd-logic:hover { filter: brightness(.96); }
.bd-addcond { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--bd-primary); background: transparent; border: 1px dashed var(--bd-primary-b); border-radius: 14px; padding: 3px 10px; cursor: pointer; }
.bd-addcond:hover { background: var(--bd-primary-1); }

.bd-flow__arrow { color: var(--bd-t4); font-size: 16px; flex: none; }

.bd-then { display: flex; align-items: center; gap: 8px; flex: none; }
/* 动作下拉：用自管 wrapper 着色，避开 Arco view 内部样式优先级 */
.bd-actionwrap { display: inline-flex; align-items: center; gap: 7px; height: 30px; padding: 0 8px 0 11px; border: 1px solid var(--bd-border); border-radius: 7px; --bd-act: var(--bd-t2); }
.bd-actionwrap.block { --bd-act: var(--bd-danger); border-color: var(--bd-danger); background: var(--bd-tag-red-bg); }
.bd-actionwrap.warn { --bd-act: var(--bd-warning); border-color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.bd-actionwrap.allow { --bd-act: var(--bd-success); border-color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-actiondot { width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--bd-act); }
.bd-actionsel { width: 142px; }
/* 经带 scope 的 wrapper 用 :deep 穿透到 Arco view（select 根无 scope 属性） */
.bd-actionwrap :deep(.arco-select-view) { background: transparent !important; border: none !important; box-shadow: none !important; padding: 0; color: var(--bd-act) !important; }
.bd-actionwrap :deep(.arco-select-view-value) { color: var(--bd-act); font-weight: 600; }
.bd-actionwrap :deep(.arco-select-view-icon) { color: var(--bd-act); }

.bd-addrule { align-self: flex-start; border-style: dashed; }

/* ── 求值预览 ── */
.bd-preview { padding: 16px 18px 18px; }
.bd-preview__sub { font-size: 12px; color: var(--bd-t3); margin-bottom: 14px; }
.bd-ctxlist { display: flex; flex-direction: column; gap: 2px; margin-bottom: 16px; }
.bd-ctxrow { display: flex; align-items: center; gap: 9px; padding: 8px 8px; border-radius: 7px; cursor: pointer; transition: background .12s; }
.bd-ctxrow:hover { background: var(--bd-fill-1); }
.bd-ctxrow__t { font-size: 13px; font-weight: 500; color: var(--bd-t1); }
.bd-ctxrow__d { margin-left: auto; font-size: 11px; color: var(--bd-t3); text-align: right; }

.bd-evalout { border-radius: var(--bd-radius); padding: 16px; text-align: center; border: 1px solid var(--bd-border); background: var(--bd-fill-1); }
.bd-evalout__l { font-size: 11px; color: var(--bd-t3); }
.bd-evalout__rule { font-size: 13.5px; font-weight: 600; color: var(--bd-t1); margin-top: 4px; }
.bd-evalout__rule.muted { color: var(--bd-t3); font-weight: 500; }
.bd-evalout__arrow { color: var(--bd-t4); font-size: 14px; margin: 6px 0; }
.bd-evalout__act { font-size: 20px; font-weight: 700; margin-top: 4px; }
.bd-evalout__act.muted { color: var(--bd-t3); font-weight: 600; }
/* 按动作着色边框 + 文字 */
.bd-evalout.block { border-color: var(--bd-danger); background: var(--bd-tag-red-bg); }
.bd-evalout.block .bd-evalout__act { color: var(--bd-danger); }
.bd-evalout.warn { border-color: var(--bd-warning); background: var(--bd-tag-gold-bg); }
.bd-evalout.warn .bd-evalout__act { color: var(--bd-warning); }
.bd-evalout.allow { border-color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-evalout.allow .bd-evalout__act { color: var(--bd-success); }
</style>
