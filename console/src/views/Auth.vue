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
      <span class="bd-tab" :class="{ on: tab === 'policy' }" @click="tab = 'policy'">认证策略</span>
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

    <!-- ============ 认证策略（FR-AUTH-12：PC/WEB 与 移动端 分栏认证）============ -->
    <div v-show="tab === 'policy'">
      <div class="bd-srctoolbar">
        <div class="bd-srctoolbar__sub">
          按<b>用户目录</b>分组编排 · 共 <b>{{ policies.length }}</b> 条策略 · PC/WEB 端与移动端 APP 分别配置主认证 / 二次认证
        </div>
        <button class="bd-btn" @click="openCreate"><icon-plus />新增策略</button>
      </div>

      <div v-for="g in grouped" :key="g.dir" class="bd-pgroup">
        <div class="bd-pgroup__head">
          <span class="bd-srcicon bd-pgroup__ic" :style="srcIconStyle(g.dir as any)"><component :is="srcIcon(g.dir as any)" /></span>
          <span class="bd-pgroup__name">{{ g.name }}</span>
          <span class="bd-pgroup__cnt">{{ g.list.length }} 条策略</span>
        </div>

        <div class="bd-card bd-pcard" :class="{ off: !p.enabled }" v-for="p in g.list" :key="p.id">
          <!-- 行头：名称 + 范围 + 默认/优先级 -->
          <div class="bd-pcard__head">
            <div class="bd-pcard__title">
              <span class="bd-pcard__name">{{ p.name }}</span>
              <span v-if="p.isDefault" class="bd-tg bd-tg--default">默认策略</span>
              <span class="bd-tg bd-tg--pri">优先级 {{ p.priority }}</span>
              <span v-if="!p.enabled" class="bd-tg bd-tg--off">已停用</span>
            </div>
            <div class="bd-pcard__acts">
              <span class="bd-link" @click="openEdit(p)"><icon-edit />编辑</span>
              <span
                v-if="!p.isDefault"
                class="bd-link bd-link--danger"
                @click="removePolicy(p)"
              ><icon-delete />删除</span>
              <span v-else class="bd-link bd-link--disabled" title="默认策略不可删除"><icon-lock />默认</span>
            </div>
          </div>
          <div class="bd-pcard__scope">{{ p.scope }}</div>

          <!-- 两端分栏 -->
          <div class="bd-platgrid">
            <div class="bd-plat">
              <div class="bd-plat__h"><icon-desktop /> PC / WEB 端</div>
              <div class="bd-plat__row">
                <span class="bd-plat__k">主认证</span>
                <span class="bd-tg" :style="tagStyle(primaryColor(p.pc.primary))">{{ primaryLabel(p.pc.primary) }}</span>
              </div>
              <div class="bd-plat__row">
                <span class="bd-plat__k">二次认证</span>
                <template v-if="p.pc.secondary.length">
                  <span v-for="s in p.pc.secondary" :key="s" class="bd-tg bd-tg--sec">{{ secondaryLabel(s) }}</span>
                </template>
                <span v-else class="bd-plat__none">无（单因素）</span>
              </div>
            </div>
            <div class="bd-plat">
              <div class="bd-plat__h"><icon-mobile /> 移动端 APP</div>
              <div class="bd-plat__row">
                <span class="bd-plat__k">主认证</span>
                <span class="bd-tg" :style="tagStyle(primaryColor(p.mobile.primary))">{{ primaryLabel(p.mobile.primary) }}</span>
              </div>
              <div class="bd-plat__row">
                <span class="bd-plat__k">二次认证</span>
                <template v-if="p.mobile.secondary.length">
                  <span v-for="s in p.mobile.secondary" :key="s" class="bd-tg bd-tg--sec">{{ secondaryLabel(s) }}</span>
                </template>
                <span v-else class="bd-plat__none">无（单因素）</span>
              </div>
            </div>
          </div>

          <!-- 自适应摘要 -->
          <div class="bd-pcard__foot">
            <span class="bd-foot__k">自适应</span>
            <span v-for="e in exemptChips(p)" :key="'ex-' + e" class="bd-mtg bd-mtg--ok"><icon-check-circle />{{ e }}</span>
            <span v-if="p.oneClick" class="bd-mtg bd-mtg--ok"><icon-thunderbolt />一键上线</span>
            <span v-for="e in enhanceChips(p)" :key="'en-' + e" class="bd-mtg bd-mtg--warn"><icon-exclamation-circle />{{ e }}</span>
            <span v-if="!hasAdaptive(p)" class="bd-plat__none">未启用自适应</span>
            <span class="bd-foot__authz"><icon-apps />{{ p.authzApps || '不授权' }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 认证策略 编辑抽屉 -->
    <a-drawer
      v-model:visible="editVisible"
      :width="560"
      :title="editing.id ? '编辑认证策略' : '新增认证策略'"
      ok-text="保存"
      :on-before-ok="savePolicy"
      @cancel="editVisible = false"
    >
      <div class="bd-form">
        <div class="bd-form__row">
          <label class="bd-form__lab">策略名称 <em>*</em></label>
          <a-input v-model="editing.name" placeholder="如：财务部 · 高敏加严" allow-clear />
        </div>
        <div class="bd-form__2col">
          <div class="bd-form__row">
            <label class="bd-form__lab">所属用户目录 <em>*</em></label>
            <a-select v-model="editing.directory" placeholder="选择目录" :disabled="editing.isDefault">
              <a-option v-for="s in directorySources" :key="s.key" :value="s.key">{{ s.name }}</a-option>
            </a-select>
          </div>
          <div class="bd-form__row">
            <label class="bd-form__lab">优先级（小者先匹配）</label>
            <a-input-number v-model="editing.priority" :min="1" :max="999" :disabled="editing.isDefault" />
          </div>
        </div>
        <div class="bd-form__row">
          <label class="bd-form__lab">适用范围</label>
          <a-input v-model="editing.scope" placeholder="如：研发中心 / 架构组、外部协作安全组" allow-clear />
        </div>

        <!-- 两端认证方式 -->
        <div class="bd-form__platgrid">
          <div class="bd-form__plat">
            <div class="bd-form__plath"><icon-desktop /> PC / WEB 端</div>
            <label class="bd-form__lab">主认证 <em>*</em></label>
            <a-select v-model="editing.pc.primary" placeholder="选择主认证方式">
              <a-option v-for="m in PRIMARY_OPTS" :key="m.value" :value="m.value">{{ m.label }}</a-option>
            </a-select>
            <label class="bd-form__lab" style="margin-top: 10px">二次认证（可多选）</label>
            <a-select v-model="editing.pc.secondary" multiple placeholder="无则单因素登录" :max-tag-count="3">
              <a-option v-for="m in SECONDARY_OPTS" :key="m.value" :value="m.value">{{ m.label }}</a-option>
            </a-select>
          </div>
          <div class="bd-form__plat">
            <div class="bd-form__plath"><icon-mobile /> 移动端 APP</div>
            <label class="bd-form__lab">主认证 <em>*</em></label>
            <a-select v-model="editing.mobile.primary" placeholder="选择主认证方式">
              <a-option v-for="m in PRIMARY_OPTS" :key="m.value" :value="m.value">{{ m.label }}</a-option>
            </a-select>
            <label class="bd-form__lab" style="margin-top: 10px">二次认证（可多选）</label>
            <a-select v-model="editing.mobile.secondary" multiple placeholder="无则单因素登录" :max-tag-count="3">
              <a-option v-for="m in SECONDARY_OPTS" :key="m.value" :value="m.value">{{ m.label }}</a-option>
            </a-select>
          </div>
        </div>

        <!-- 自适应认证 -->
        <div class="bd-form__sec">
          <div class="bd-form__sech">自适应 · 免二次认证 / 一键上线</div>
          <div class="bd-form__checks">
            <a-checkbox v-model="editing.exempt.trustedDevice">使用授信终端时</a-checkbox>
            <a-checkbox v-model="editing.exempt.trustedNetwork">满足可信网络时</a-checkbox>
            <a-checkbox v-model="editing.exempt.winDomain">Windows 域环境时</a-checkbox>
            <a-checkbox v-model="editing.oneClick">一键上线（保存票据，下次免认证）</a-checkbox>
          </div>
        </div>
        <div class="bd-form__sec">
          <div class="bd-form__sech">自适应 · 增强认证（命中则强制追加）</div>
          <div class="bd-form__checks">
            <a-checkbox v-model="editing.enhance.weakPwd">弱密码</a-checkbox>
            <a-checkbox v-model="editing.enhance.offHours">异常时间段</a-checkbox>
            <a-checkbox v-model="editing.enhance.geoAnomaly">异地登录</a-checkbox>
          </div>
        </div>

        <div class="bd-form__2col">
          <div class="bd-form__row">
            <label class="bd-form__lab">默认授权应用</label>
            <a-input v-model="editing.authzApps" placeholder="如：默认授权全部应用 / 仅 OA / 不授权" allow-clear />
          </div>
          <div class="bd-form__row">
            <label class="bd-form__lab">启用策略</label>
            <a-switch v-model="editing.enabled" />
          </div>
        </div>
      </div>
    </a-drawer>

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
import { Message, Modal } from '@arco-design/web-vue';
import {
  api, type AuthSrcBundle, type AuthSource, type AdaptiveRule, type RuleCond,
  type AuthPolicy, type AuthPolicyResp, type PrimaryMethod, type SecondaryMethod
} from '@/lib/api';

type SrcType = AuthSource['type'];
type CondField = RuleCond['field'];
type Action = AdaptiveRule['action'];

const tab = ref<'source' | 'policy' | 'rule'>('source');
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

/* ── 认证策略（FR-AUTH-12）── */
const policies = ref<AuthPolicy[]>([]);

const PRIMARY_OPTS: { value: PrimaryMethod; label: string }[] = [
  { value: 'local', label: '本地账号密码' },
  { value: 'ad', label: 'AD 域' },
  { value: 'ldap', label: 'LDAP 目录' },
  { value: 'radius', label: 'RADIUS 账号' },
  { value: 'oauth', label: '企微/钉钉/飞书' },
  { value: 'sms', label: '短信验证码' },
  { value: 'cert', label: '证书 / USB-Key' }
];
const SECONDARY_OPTS: { value: SecondaryMethod; label: string }[] = [
  { value: 'sms', label: '短信' },
  { value: 'totp', label: 'TOTP 令牌' },
  { value: 'radius', label: 'Radius 动态令牌' },
  { value: 'cert', label: '证书 / USB-Key' },
  { value: 'http', label: 'HTTP(S) 令牌' }
];
const PRIMARY_LABEL: Record<string, string> = Object.fromEntries(PRIMARY_OPTS.map((o) => [o.value, o.label]));
const SECONDARY_LABEL: Record<string, string> = Object.fromEntries(SECONDARY_OPTS.map((o) => [o.value, o.label]));
const PRIMARY_COLOR: Record<string, string> = {
  local: '#165DFF', ad: '#165DFF', ldap: '#722ED1', radius: '#FF7D00', oauth: '#00B42A', sms: '#FF7D00', cert: '#722ED1'
};
function primaryLabel(m: string) { return PRIMARY_LABEL[m] ?? m ?? '—'; }
function primaryColor(m: string) { return PRIMARY_COLOR[m] ?? '#86909C'; }
function secondaryLabel(m: string) { return SECONDARY_LABEL[m] ?? m; }

/** 目录 key → 友好名（取自认证源；缺失回退到类型名或 key） */
function dirName(dir: string) {
  const src = sources.value.find((s) => s.key === dir);
  return src ? src.name : (TYPE_LABEL[dir as SrcType] ?? dir);
}
/** 可作为「用户目录」被策略绑定的认证源：仅主认证类（本地/AD/LDAP），排除纯二次因子源 */
const directorySources = computed(() =>
  sources.value.filter((s) => ['local', 'ad', 'ldap'].includes(s.type)).map((s) => ({ key: s.key, name: s.name }))
);

/** 按目录分组，组内按优先级升序（小者先匹配，默认策略优先级 100 自然沉底） */
const grouped = computed(() => {
  const map = new Map<string, AuthPolicy[]>();
  for (const p of policies.value) {
    if (!map.has(p.directory)) map.set(p.directory, []);
    map.get(p.directory)!.push(p);
  }
  return [...map.entries()].map(([dir, list]) => ({
    dir, name: dirName(dir),
    list: [...list].sort((a, b) => a.priority - b.priority)
  }));
});

function exemptChips(p: AuthPolicy): string[] {
  const out: string[] = [];
  if (p.exempt.trustedDevice) out.push('授信终端免二次');
  if (p.exempt.trustedNetwork) out.push('可信网络免二次');
  if (p.exempt.winDomain) out.push('Windows 域免二次');
  return out;
}
function enhanceChips(p: AuthPolicy): string[] {
  const out: string[] = [];
  if (p.enhance.weakPwd) out.push('弱密码增强');
  if (p.enhance.offHours) out.push('异常时段增强');
  if (p.enhance.geoAnomaly) out.push('异地登录增强');
  return out;
}
function hasAdaptive(p: AuthPolicy): boolean {
  return p.oneClick || exemptChips(p).length > 0 || enhanceChips(p).length > 0;
}

/* 编辑抽屉 */
const editVisible = ref(false);
function blankPolicy(): AuthPolicy {
  return {
    id: '', name: '', directory: directorySources.value[0]?.key ?? 'local', isDefault: false,
    scope: '', priority: 50, enabled: true,
    pc: { primary: 'ad', secondary: [] }, mobile: { primary: 'ad', secondary: [] },
    exempt: { trustedDevice: false, trustedNetwork: false, winDomain: false },
    oneClick: false, enhance: { weakPwd: false, offHours: false, geoAnomaly: false }, authzApps: ''
  };
}
const editing = ref<AuthPolicy>(blankPolicy());
function openCreate() { editing.value = blankPolicy(); editVisible.value = true; }
function openEdit(p: AuthPolicy) {
  // 深拷贝，避免抽屉里编辑直接改到列表（取消时还能回滚）
  editing.value = JSON.parse(JSON.stringify(p));
  editVisible.value = true;
}
async function savePolicy(): Promise<boolean> {
  const p = editing.value;
  if (!p.name.trim()) { Message.warning('请填写策略名称'); return false; }
  if (!p.directory) { Message.warning('请选择所属用户目录'); return false; }
  if (!p.pc.primary || !p.mobile.primary) { Message.warning('PC 端与移动端均须配置主认证方式'); return false; }
  try {
    await api<{ ok: boolean; policy: AuthPolicy }>('/authpolicy', { method: 'POST', body: JSON.stringify(p) });
    Message.success(p.id ? '策略已更新' : '策略已新增');
    await loadPolicies();
    return true;
  } catch (e) {
    Message.error('保存失败：' + (e as Error).message);
    return false;
  }
}
function removePolicy(p: AuthPolicy) {
  Modal.warning({
    title: '删除认证策略',
    content: `确认删除「${p.name}」？该范围用户将回落到所属目录的默认策略。`,
    hideCancel: false,
    onOk: async () => {
      try {
        await api(`/authpolicy/${p.id}`, { method: 'DELETE' });
        Message.success('策略已删除');
        await loadPolicies();
      } catch (e) {
        Message.error('删除失败：' + (e as Error).message);
      }
    }
  });
}
async function loadPolicies() {
  try {
    const r = await api<AuthPolicyResp>('/authpolicy');
    policies.value = r.policies;
  } catch { /* 后端不可用时保持空列表 */ }
}

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
  await loadPolicies();
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

/* ── 认证策略 ── */
.bd-pgroup { margin-bottom: 22px; }
.bd-pgroup__head { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
.bd-pgroup__ic { width: 30px; height: 30px; border-radius: 8px; font-size: 16px; }
.bd-pgroup__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.bd-pgroup__cnt { font-size: 12px; color: var(--bd-t3); background: var(--bd-fill-2); padding: 2px 9px; border-radius: 10px; }

.bd-pcard { padding: 16px 18px; margin-bottom: 12px; transition: opacity .15s, box-shadow .15s; }
.bd-pcard:hover { box-shadow: 0 4px 14px rgba(22, 93, 255, .06); }
.bd-pcard.off { opacity: .62; }
.bd-pcard__head { display: flex; align-items: flex-start; gap: 12px; }
.bd-pcard__title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; flex: 1; min-width: 0; }
.bd-pcard__name { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); }
.bd-tg--default { color: var(--bd-primary); background: var(--bd-primary-1); font-weight: 600; }
.bd-tg--pri { color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-tg--off { color: var(--bd-t3); background: var(--bd-fill-2); }
.bd-tg--sec { color: var(--bd-purple); background: var(--bd-tag-purple-bg); }
.bd-pcard__acts { display: flex; gap: 14px; flex: none; }
.bd-pcard__acts .bd-link { display: inline-flex; align-items: center; gap: 4px; font-size: 12.5px; }
.bd-link--danger { color: var(--bd-danger); }
.bd-link--disabled { color: var(--bd-t4); cursor: default; }
.bd-pcard__scope { font-size: 12.5px; color: var(--bd-t3); margin: 4px 0 14px; }

.bd-platgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.bd-plat { border: 1px solid var(--bd-fill-2); border-radius: 9px; padding: 12px 14px; background: var(--bd-fill-1); }
.bd-plat__h { display: flex; align-items: center; gap: 6px; font-size: 12.5px; font-weight: 600; color: var(--bd-t2); margin-bottom: 10px; }
.bd-plat__row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 7px; }
.bd-plat__k { font-size: 12px; color: var(--bd-t3); width: 56px; flex: none; }
.bd-plat__none { font-size: 12px; color: var(--bd-t4); }

.bd-pcard__foot { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--bd-fill-2); }
.bd-foot__k { font-size: 12px; color: var(--bd-t3); }
.bd-foot__authz { margin-left: auto; display: inline-flex; align-items: center; gap: 5px; font-size: 12px; color: var(--bd-t2); }
.bd-mtg { display: inline-flex; align-items: center; gap: 4px; font-size: 11.5px; font-weight: 500; padding: 2px 9px; border-radius: 11px; }
.bd-mtg--ok { color: var(--bd-success); background: var(--bd-tag-green-bg); }
.bd-mtg--warn { color: var(--bd-warning); background: var(--bd-tag-gold-bg); }

/* ── 编辑抽屉表单 ── */
.bd-form { display: flex; flex-direction: column; gap: 16px; }
.bd-form__row { display: flex; flex-direction: column; gap: 6px; }
.bd-form__lab { font-size: 12.5px; color: var(--bd-t2); font-weight: 500; }
.bd-form__lab em { color: var(--bd-danger); font-style: normal; }
.bd-form__2col { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.bd-form__platgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.bd-form__plat { border: 1px solid var(--bd-border); border-radius: 9px; padding: 14px; display: flex; flex-direction: column; gap: 6px; }
.bd-form__plath { display: flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 600; color: var(--bd-t1); margin-bottom: 6px; padding-bottom: 8px; border-bottom: 1px solid var(--bd-fill-2); }
.bd-form__sec { border: 1px solid var(--bd-fill-2); border-radius: 9px; padding: 12px 14px; background: var(--bd-fill-1); }
.bd-form__sech { font-size: 12.5px; font-weight: 600; color: var(--bd-t2); margin-bottom: 10px; }
.bd-form__checks { display: flex; flex-wrap: wrap; gap: 10px 18px; }
</style>
