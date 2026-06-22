<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">登录流仿真<LiveBadge :live="live" live-text="控制面登录门" mock-text="本地演示（降级）" /></h1>
        <div class="zl-page__sub">登录门预演：把口令策略 / 认证策略 / 账号安全 / 认证豁免 / IP 信誉 / 账号生命周期编织成统一登录判定（S8），产出 auth_strength · 放行后由访问门（策略仿真器）评估资源可达性。</div>
      </div>
      <router-link to="/policy/simulator" class="lf-xlink">访问门 · 策略仿真器 →</router-link>
    </div>

    <!-- 预置场景 -->
    <div class="lf-presets">
      <span class="lf-presets__label">预置场景：</span>
      <button v-for="p in presets" :key="p.label" class="lf-chip" @click="apply(p)">{{ p.label }}</button>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1fr 1.4fr; align-items:start;">
      <!-- 输入 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title">登录上下文</div>
        <a-form :model="form" layout="vertical" class="lf-form">
          <a-form-item label="账号（account）">
            <a-input v-model="form.account" placeholder="例如：zhang.wei" allow-clear />
          </a-form-item>
          <a-grid :cols="2" :col-gap="14">
            <a-grid-item>
              <a-form-item label="来源网络（network）">
                <a-select v-model="form.network">
                  <a-option v-for="n in networks" :key="n.value" :value="n.value">{{ n.label }}</a-option>
                </a-select>
              </a-form-item>
            </a-grid-item>
            <a-grid-item>
              <a-form-item label="来源 IP（sourceIp）">
                <a-input v-model="form.sourceIp" placeholder="例如：10.20.3.18" allow-clear />
              </a-form-item>
            </a-grid-item>
          </a-grid>
          <a-form-item label="设备码（deviceCode）">
            <a-input v-model="form.deviceCode" placeholder="设备唯一指纹" allow-clear />
          </a-form-item>

          <div class="lf-switches">
            <div class="lf-sw" v-for="s in switches" :key="s.k">
              <div class="lf-sw__lab">{{ s.label }}<span class="lf-sw__hint">{{ s.hint }}</span></div>
              <a-switch v-model="form[s.k]" size="small" />
            </div>
          </div>

          <a-button type="primary" long :loading="loading" style="margin-top:16px" @click="evaluate">评估登录门</a-button>
        </a-form>
      </div>

      <!-- 结果 -->
      <div style="display:flex;flex-direction:column;gap:16px">
        <!-- 判定横幅 -->
        <div class="zl-card zl-card__pad lf-verdict" :class="tone">
          <span class="lf-verdict__glyph">{{ glyph }}</span>
          <div class="lf-verdict__main">
            <div class="lf-verdict__t">{{ outcomeLabel }}</div>
            <div class="lf-verdict__sub">{{ outcomeDesc }}</div>
          </div>
          <span class="zl-badge" :class="badge">{{ result.outcome }}</span>
        </div>

        <!-- 原因清单 -->
        <div class="zl-card zl-card__pad">
          <div class="zl-card__title" style="margin-bottom:10px">判定原因（按 S8 编织顺序）</div>
          <div v-if="result.reasons.length" class="lf-reasons">
            <div v-for="(r, i) in result.reasons" :key="i" class="lf-reason" :class="r.tone">
              <span class="lf-reason__g">{{ { ok:'✓', warn:'!', fail:'✕', info:'ⅰ' }[r.tone] }}</span>
              <div class="lf-reason__body">
                <span class="lf-reason__stage">{{ r.stage }}</span>
                <span class="lf-reason__txt">{{ r.text }}</span>
              </div>
            </div>
          </div>
          <div v-else class="lf-empty">无命中规则 · 各策略门均放行</div>
        </div>

        <!-- 建议因子 -->
        <div class="zl-card zl-card__pad">
          <div class="zl-card__title" style="margin-bottom:10px">建议补充因子（factors）</div>
          <div v-if="result.factors.length" class="lf-factors">
            <span v-for="f in result.factors" :key="f" class="zl-badge zl-badge--accent lf-factor">{{ factorLabel(f) }}</span>
          </div>
          <div v-else class="lf-empty">无需补充因子 · 主认证已足够</div>
          <div class="lf-note">登录门判定 = 口令策略 → 账号生命周期 → 账号安全（防爆破 / 时段 / 并发）→ IP 信誉 → 认证策略（MFA / 二次鉴权）→ 认证豁免。任一前置门拒绝即终止，后置门按风险升级处置。</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';

// 登录上下文表单：与端点 POST /ctl/auth/login/evaluate 的 body 对齐。
type Network = 'office' | 'trusted' | 'vpn' | 'home' | 'untrusted';
interface LoginForm {
  account: string;
  network: Network;
  sourceIp: string;
  deviceCode: string;
  newDevice: boolean;
  abnormalTime: boolean;
  weakPassword: boolean;
  mfaPassed: boolean;
}
// 后端返回：outcome 终判 + reasons 原因清单 + factors 建议因子。
type Outcome = 'allow' | 'must-change-password' | 'need-mfa' | 'step-up' | 'deny';
interface Reason { stage: string; text: string; tone: 'ok' | 'warn' | 'fail' | 'info' }
interface EvalResult { outcome: Outcome; reasons: Reason[]; factors: string[] }

const networks: { value: Network; label: string }[] = [
  { value: 'office', label: '办公网 · 可信' },
  { value: 'trusted', label: '可信网络' },
  { value: 'vpn', label: 'VPN' },
  { value: 'home', label: '家庭网' },
  { value: 'untrusted', label: '不可信 / 公网' }
];
const switches: { k: keyof LoginForm; label: string; hint: string }[] = [
  { k: 'newDevice', label: '新设备', hint: '未登记的设备指纹' },
  { k: 'abnormalTime', label: '非常用时段', hint: '偏离历史活跃时间' },
  { k: 'weakPassword', label: '弱口令命中', hint: '触发口令策略红线' },
  { k: 'mfaPassed', label: '已过 MFA', hint: '本次已完成多因子' }
];

const form = reactive<LoginForm>({
  account: 'zhang.wei',
  network: 'office',
  sourceIp: '10.20.3.18',
  deviceCode: 'WIN-7F3A-9C21',
  newDevice: false,
  abnormalTime: false,
  weakPassword: false,
  mfaPassed: true
});

// 预置场景：一键铺设典型登录态势，演示各门联动。
const presets: { label: string; v: Partial<LoginForm> }[] = [
  { label: '办公网 · 已过 MFA（放行）', v: { network: 'office', sourceIp: '10.20.3.18', newDevice: false, abnormalTime: false, weakPassword: false, mfaPassed: true } },
  { label: '弱口令命中（强制改密）', v: { weakPassword: true } },
  { label: '未过 MFA（需多因子）', v: { mfaPassed: false } },
  { label: '新设备 + 非常用时段（二次鉴权）', v: { newDevice: true, abnormalTime: true, mfaPassed: true } },
  { label: '不可信公网 IP（拒绝）', v: { network: 'untrusted', sourceIp: '203.0.113.66', mfaPassed: false } }
];
const apply = (p: { v: Partial<LoginForm> }) => { Object.assign(form, p.v); evaluate(); };

const live = ref(false);
const loading = ref(false);
const result = ref<EvalResult>({ outcome: 'allow', reasons: [], factors: [] });

// 中文化映射：allow=放行 / must-change-password=强制改密 / need-mfa=需多因子 / step-up=二次鉴权 / deny=拒绝。
const OUTCOME_META: Record<Outcome, { label: string; desc: string; tone: string; glyph: string; badge: string }> = {
  'allow': { label: '放行', desc: '通过全部登录门，建立会话', tone: 'allow', glyph: '✓', badge: 'zl-badge--ok' },
  'must-change-password': { label: '强制改密', desc: '口令策略未满足，须先修改口令', tone: 'warn', glyph: '⟳', badge: 'zl-badge--warn' },
  'need-mfa': { label: '需多因子', desc: '认证策略要求补全 MFA 后放行', tone: 'warn', glyph: '⊕', badge: 'zl-badge--warn' },
  'step-up': { label: '二次鉴权', desc: '风险升高，需追加更强因子核验', tone: 'warn', glyph: '!', badge: 'zl-badge--warn' },
  'deny': { label: '拒绝', desc: '命中红线规则，本次登录被拒', tone: 'deny', glyph: '✕', badge: 'zl-badge--danger' }
};
const meta = computed(() => OUTCOME_META[result.value.outcome] ?? OUTCOME_META.allow);
const outcomeLabel = computed(() => meta.value.label);
const outcomeDesc = computed(() => meta.value.desc);
const tone = computed(() => meta.value.tone);
const glyph = computed(() => meta.value.glyph);
const badge = computed(() => meta.value.badge);

// 建议因子中文化（后端可返回任意因子键，未知键原样回显）。
const FACTOR_LABEL: Record<string, string> = {
  'mfa-totp': '动态口令（TOTP）',
  'mfa-sms': '短信验证码',
  'mfa-push': 'App 推送确认',
  'sm2-cert': 'SM2 证书核验',
  'face': '人脸核身',
  'device-bind': '设备绑定确认',
  'change-password': '修改口令',
  'admin-review': '管理员人工复核'
};
const factorLabel = (f: string) => FACTOR_LABEL[f] ?? f;

// 端点求值：POST /ctl/auth/login/evaluate；控制面不可达 → 本地静态演示。
async function evaluate() {
  loading.value = true;
  try {
    const r = await fetch('/ctl/auth/login/evaluate', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        account: form.account, network: form.network, sourceIp: form.sourceIp, deviceCode: form.deviceCode,
        newDevice: form.newDevice, abnormalTime: form.abnormalTime, weakPassword: form.weakPassword, mfaPassed: form.mfaPassed
      })
    });
    if (r.ok) {
      const d = await r.json();
      result.value = normalize(d);
      live.value = true;
      loading.value = false;
      return;
    }
  } catch { /* 控制面不可达，降级本地引擎 */ }
  live.value = false;
  result.value = localEvaluate();
  loading.value = false;
}

// 规整后端返回：outcome 落到合法枚举，reasons/factors 兜底为数组。
function normalize(d: any): EvalResult {
  const valid: Outcome[] = ['allow', 'must-change-password', 'need-mfa', 'step-up', 'deny'];
  const outcome: Outcome = valid.includes(d?.outcome) ? d.outcome : 'allow';
  const reasons: Reason[] = Array.isArray(d?.reasons)
    ? d.reasons.map((x: any) => typeof x === 'string'
        ? { stage: '控制面', text: x, tone: 'info' as const }
        : { stage: x?.stage ?? '控制面', text: x?.text ?? '', tone: (['ok', 'warn', 'fail', 'info'].includes(x?.tone) ? x.tone : 'info') })
    : [];
  const factors: string[] = Array.isArray(d?.factors) ? d.factors.map((x: any) => String(x)) : [];
  return { outcome, reasons, factors };
}

/* 本地演示引擎：复刻 S8 登录门编织顺序（与后端同语义，前置门拒绝即短路）。
   口令策略 → 账号生命周期 → 账号安全（防爆破/时段/并发）→ IP 信誉 → 认证策略（MFA/二次鉴权）→ 认证豁免。 */
function localEvaluate(): EvalResult {
  const reasons: Reason[] = [];
  const factors: string[] = [];
  const untrusted = form.network === 'untrusted';

  // 1) 口令策略：弱口令命中 → 强制改密（红线，短路）。
  if (form.weakPassword) {
    reasons.push({ stage: '口令策略', text: '命中弱口令字典 / 复杂度红线，须先修改口令', tone: 'fail' });
    return { outcome: 'must-change-password', reasons, factors: ['change-password'] };
  }
  reasons.push({ stage: '口令策略', text: '口令复杂度与有效期校验通过', tone: 'ok' });

  // 2) IP 信誉：不可信公网直接拒绝（最高优先级红线，短路）。
  if (untrusted) {
    reasons.push({ stage: 'IP 信誉', text: `来源 ${form.sourceIp || '公网 IP'} 命中不可信网络 / 黑名单，拒绝接入`, tone: 'fail' });
    return { outcome: 'deny', reasons, factors: ['admin-review'] };
  }
  reasons.push({ stage: 'IP 信誉', text: `来源网络「${networkLabel(form.network)}」信誉正常`, tone: 'ok' });

  // 3) 账号安全：非常用时段 → 风险升级（不短路，记风险）。
  let risk = 0;
  if (form.abnormalTime) {
    reasons.push({ stage: '账号安全', text: '当前为非常用登录时段，风险升级', tone: 'warn' });
    risk += 1;
  } else {
    reasons.push({ stage: '账号安全', text: '登录时段处于常用区间', tone: 'ok' });
  }

  // 4) 设备态势：新设备 → 需设备绑定并升级风险。
  if (form.newDevice) {
    reasons.push({ stage: '设备态势', text: `新设备「${form.deviceCode || '未知指纹'}」首次登录，需确认绑定`, tone: 'warn' });
    factors.push('device-bind');
    risk += 1;
  } else {
    reasons.push({ stage: '设备态势', text: '已登记设备，指纹匹配', tone: 'ok' });
  }

  // 5) 认证策略：未过 MFA → 需补全多因子（短路于风险升级前）。
  if (!form.mfaPassed) {
    reasons.push({ stage: '认证策略', text: '主认证通过但缺少多因子，需补全 MFA', tone: 'warn' });
    factors.push('mfa-totp', 'mfa-push');
    return { outcome: 'need-mfa', reasons, factors: dedupe(factors) };
  }
  reasons.push({ stage: '认证策略', text: '多因子认证已通过', tone: 'ok' });

  // 6) 风险综合：MFA 已过但风险累积（新设备 + 非常用时段等）→ 二次鉴权。
  if (risk >= 2) {
    reasons.push({ stage: '风险综合', text: '风险因子叠加（新设备 + 非常用时段），要求二次鉴权', tone: 'warn' });
    factors.push('sm2-cert', 'face');
    return { outcome: 'step-up', reasons, factors: dedupe(factors) };
  }

  // 7) 认证豁免：低风险且全门通过 → 放行。
  reasons.push({ stage: '认证豁免', text: '低风险登录，命中豁免规则，免追加因子放行', tone: 'ok' });
  return { outcome: 'allow', reasons, factors: dedupe(factors) };
}

const networkLabel = (n: Network) => networks.find((x) => x.value === n)?.label ?? n;
const dedupe = (a: string[]) => Array.from(new Set(a));

onMounted(evaluate);
</script>

<style scoped>
.zl-grid > * { min-width: 0; }
.lf-xlink { flex: none; font-size: 12px; font-weight: 600; color: var(--accent-2); text-decoration: none; }
.lf-xlink:hover { text-decoration: underline; }
.lf-presets { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.lf-presets__label { font-size: 12px; color: var(--ink-3); }
.lf-chip {
  border: 1px solid var(--line-2, var(--line)); background: var(--surface); color: var(--ink-2); cursor: pointer;
  border-radius: var(--r-pill, 999px); padding: 5px 13px; font-size: 12px; font-weight: 600; transition: all .15s;
}
.lf-chip:hover { border-color: var(--accent); color: var(--accent-2); background: var(--accent-soft); }

.lf-form :deep(.arco-form-item) { margin-bottom: 14px; }
.lf-form :deep(.arco-select), .lf-form :deep(.arco-input-wrapper) { width: 100%; }

.lf-switches { border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; margin-top: 4px; }
.lf-sw { display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; }
.lf-sw + .lf-sw { border-top: 1px solid var(--line); }
.lf-sw__lab { font-size: 13px; font-weight: 600; color: var(--ink); display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.lf-sw__hint { font-size: 10.5px; color: var(--ink-3); font-weight: 400; }

/* 判定横幅 */
.lf-verdict { display: flex; align-items: center; gap: 14px; }
.lf-verdict.allow { border-color: var(--ok); }
.lf-verdict.warn { border-color: var(--warn); background: var(--warn-soft); }
.lf-verdict.deny { border-color: var(--danger); background: var(--danger-soft); }
.lf-verdict__glyph { width: 42px; height: 42px; border-radius: 50%; display: grid; place-items: center; flex: none; font-size: 20px; font-weight: 800; }
.lf-verdict.allow .lf-verdict__glyph { background: var(--ok-soft); color: var(--ok); }
.lf-verdict.warn .lf-verdict__glyph { background: var(--warn); color: #fff; }
.lf-verdict.deny .lf-verdict__glyph { background: var(--danger); color: #fff; }
.lf-verdict__main { flex: 1; min-width: 0; }
.lf-verdict__t { font-size: 20px; font-weight: 800; color: var(--ink); }
.lf-verdict__sub { font-size: 12.5px; color: var(--ink-2); margin-top: 3px; }

/* 原因清单 */
.lf-reasons { display: flex; flex-direction: column; gap: 8px; }
.lf-reason { display: flex; gap: 10px; align-items: flex-start; }
.lf-reason__g { width: 18px; height: 18px; border-radius: 50%; flex: none; display: grid; place-items: center; font-size: 10px; font-weight: 800; margin-top: 1px; background: var(--surface-3, var(--surface-2)); color: var(--ink-3); }
.lf-reason.ok .lf-reason__g { background: var(--ok-soft); color: var(--ok); }
.lf-reason.warn .lf-reason__g { background: var(--warn-soft); color: var(--warn); }
.lf-reason.fail .lf-reason__g { background: var(--danger-soft); color: var(--danger); }
.lf-reason.info .lf-reason__g { background: var(--accent-soft); color: var(--accent-2); }
.lf-reason__body { font-size: 12.5px; line-height: 1.55; }
.lf-reason__stage { display: inline-block; font-weight: 700; color: var(--accent-2); margin-right: 8px; }
.lf-reason__txt { color: var(--ink-2); }

.lf-factors { display: flex; flex-wrap: wrap; gap: 8px; }
.lf-factor { font-size: 12px; padding: 4px 12px; }
.lf-empty { font-size: 12.5px; color: var(--ink-3); padding: 4px 0; }
.lf-note { margin-top: 14px; padding: 10px 12px; border-radius: var(--r-md); background: var(--accent-soft); font-size: 11px; color: var(--ink-2); line-height: 1.6; }
</style>
